import Foundation
import XCTest
@testable import AgentReins

final class MCPFirewallAdapterTests: XCTestCase {
    func event(_ phase: String = "request_received", correlated: Bool = true) throws -> MCPFirewallEvent {
        let json = """
        {"schema_version":1,"id":"00000000-0000-4000-8000-000000000001",
        "session_id":"00000000-0000-4000-8000-000000000002",
        "call_id":"00000000-0000-4000-8000-000000000003","sequence":1,
        "timestamp":1788950400,"phase":"\(phase)","correlated":\(correlated),
        "tool":"status","agent":"codex","action":null,"severity":"info","stage":null,
        "reason":"","response_is_error":false}
        """
        let value = try JSONDecoder().decode(MCPFirewallEvent.self, from: Data(json.utf8))
        try value.validate()
        return value
    }

    func testProjectionUsesActualUpstreamTypesWithoutInventingEvidence() throws {
        let start = try event().guardEvent
        let end = try event("response_allowed").guardEvent
        XCTAssertEqual(start.id, try event().id)
        XCTAssertEqual(start.sessionId, "mcp-firewall:00000000-0000-4000-8000-000000000002")
        XCTAssertNil(start.turnId)
        XCTAssertNil(start.traceId)
        XCTAssertNil(start.model)
        XCTAssertNil(start.command)
        XCTAssertNil(end.modelResponse)
        XCTAssertEqual(start.path, "-")
        XCTAssertEqual(end.action, "Response passed scanning; execution unverified")
        let snapshot = try XCTUnwrap(AgentSessionSnapshot.build(from: [start, end]).first)
        XCTAssertNil(snapshot.workspace)
        XCTAssertEqual(snapshot.turns.first?.toolCalls.first?.status, end.action)
        XCTAssertNil(snapshot.turns.first?.finalResponse)
    }

    func testUnknownResponsesNeverJoinAnObservedToolCall() throws {
        XCTAssertNil(try event("response_denied", correlated: false).guardEvent.toolCallId)
        XCTAssertEqual(try event("request_unknown").guardEvent.action, "Outcome unknown")
        XCTAssertEqual(try event("request_denied").guardEvent.action, "Denied before forwarding")
    }

    func testClientRejectsRemoteOrCredentialBearingEndpoints() throws {
        for url in ["https://example.com", "http://127.0.0.1.evil.example", "http://user@localhost",
                    "http://127.0.0.1/path", "http://127.0.0.1?token=bad", "http://127.0.0.1#fragment"] {
            XCTAssertThrowsError(try MCPFirewallClient(baseURL: XCTUnwrap(URL(string: url)),
                                                       token: String(repeating: "a", count: 32)))
        }
        XCTAssertThrowsError(try MCPFirewallClient(baseURL: URL(string: "http://127.0.0.1")!, token: "short"))
    }

    func testMalformedEventSchemaAndFieldsAreRejected() throws {
        let encoded = try JSONEncoder().encode(event())
        var value = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        for (key, invalid) in [("schema_version", 2 as Any), ("sequence", 0 as Any),
                               ("tool", String(repeating: "x", count: 1025) as Any),
                               ("phase", "filesystem_restored" as Any)] {
            var invalidValue = value
            invalidValue[key] = invalid
            XCTAssertThrowsError(try {
                let data = try JSONSerialization.data(withJSONObject: invalidValue)
                let parsed = try JSONDecoder().decode(MCPFirewallEvent.self, from: data)
                try parsed.validate()
            }())
        }
        value["tool"] = "<img src=x onerror=alert(1)>"
        let parsed = try JSONDecoder().decode(MCPFirewallEvent.self,
            from: JSONSerialization.data(withJSONObject: value))
        XCTAssertEqual(parsed.guardEvent.toolName, "<img src=x onerror=alert(1)>")
    }
}

extension MCPFirewallAdapterTests {
    @MainActor
    func testLiveProxyAndNativeController() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let address = environment["MCP_FIREWALL_TEST_URL"],
              let token = environment["MCP_FIREWALL_TEST_TOKEN"],
              let directory = environment["MCP_FIREWALL_TEST_DIRECTORY"] else {
            throw XCTSkip("Run integrations/agentreins/verify.py for real HTTP/stdio verification")
        }
        let root = URL(fileURLWithPath: directory)
        func signal(_ name: String) throws {
            try Data().write(to: root.appendingPathComponent(name), options: .atomic)
        }
        func executed() -> Int {
            let text = (try? String(contentsOf: root.appendingPathComponent("executed.jsonl"), encoding: .utf8)) ?? ""
            return text.split(separator: "\n").count
        }
        func wait(_ predicate: @escaping @MainActor () -> Bool, timeout: TimeInterval = 15) async throws {
            let deadline = Date().addingTimeInterval(timeout)
            while !predicate() {
                if Date() >= deadline { throw MCPFirewallError.disconnected }
                try await Task.sleep(nanoseconds: 25_000_000)
            }
        }
        let url = try XCTUnwrap(URL(string: address))
        let invalid = try MCPFirewallClient(baseURL: url, token: String(repeating: "x", count: 40))
        do { _ = try await invalid.pending(); XCTFail("Wrong token accepted") }
        catch MCPFirewallError.http(401) { }
        await invalid.close()
        let sight = MCPFirewallSight()
        var recorded: [GuardEvent] = []
        sight.onEvents = { recorded.append(contentsOf: $0) }
        await sight.connect(endpoint: address, token: token)
        XCTAssertTrue(sight.connected, sight.status)
        try signal("ready")
        try await wait { sight.pending.contains { $0.tool == "status" } }
        let first = try XCTUnwrap(sight.pending.first { $0.tool == "status" })
        XCTAssertEqual(executed(), 0)
        XCTAssertFalse(first.arguments_preview.contains("private-test-value"))
        XCTAssertTrue(first.redacted)
        await sight.decide(first, allow: true)
        try await wait { sight.events.contains { $0.tool == "status" && $0.phase == .response_redacted } }
        XCTAssertEqual(executed(), 1)
        let statusEvents = sight.events.filter { $0.tool == "status" }
        XCTAssertTrue(statusEvents.contains { $0.phase == .request_forwarded })
        XCTAssertFalse(statusEvents.contains { $0.reason.contains("AKIAIOSFODNN7EXAMPLE") })
        let session = try XCTUnwrap(AgentSessionSnapshot.build(from: recorded).first)
        XCTAssertEqual(session.turns.first?.toolCalls.first?.status, "Response redacted; execution unverified")
        XCTAssertNil(session.workspace)
        let control = try MCPFirewallClient(baseURL: url, token: token)
        do { try await control.decide(first, allow: true); XCTFail("Replayed approval accepted") }
        catch MCPFirewallError.http(409) { }
        try signal("allowed-verified")
        try await wait { sight.events.contains { $0.tool == "danger" && $0.phase == .request_denied } }
        XCTAssertFalse(sight.pending.contains { $0.tool == "danger" })
        XCTAssertEqual(executed(), 1)
        try signal("hard-denial-verified")
        try await wait { sight.pending.contains { $0.tool == "rejectable" } }
        await sight.decide(try XCTUnwrap(sight.pending.first { $0.tool == "rejectable" }), allow: false)
        try await wait { sight.events.contains { $0.tool == "rejectable" && $0.phase == .request_denied } }
        XCTAssertEqual(executed(), 1)
        try signal("denied-verified")
        try await wait { sight.pending.contains { $0.tool == "disconnectable" } }
        await sight.disconnect()
        XCTAssertFalse(sight.connected)
        XCTAssertTrue(sight.pending.isEmpty)
        try signal("disconnected")
        try await wait { FileManager.default.fileExists(atPath: root.appendingPathComponent("disconnect-verified").path) }
        // Open then abruptly drop a controller without the disconnect endpoint.
        _ = try await control.pending()
        try signal("lease-ready")
        var lost: MCPFirewallPending?
        for _ in 0..<100 {
            lost = try await control.pending().first { $0.tool == "lease_lost" }
            if lost != nil { break }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        XCTAssertNotNil(lost)
        await control.close()
        try signal("lease-dropped")
        try await wait { FileManager.default.fileExists(atPath: root.appendingPathComponent("lease-verified").path) }
        XCTAssertEqual(executed(), 1)
        let observer = try MCPFirewallClient(baseURL: url, token: token)
        let final = try await observer.events()
        XCTAssertTrue(final.events.contains { $0.tool == "lease_lost" && $0.phase == .request_denied })
        XCTAssertFalse(final.events.contains { $0.tool != "status" && $0.phase == .request_forwarded })
        await observer.close()
        try signal("finished")
    }
}

extension MCPFirewallAdapterTests {
    func testPageRejectsInvalidCursorsAndDuplicateEvents() throws {
        let fixture = try JSONSerialization.jsonObject(with: JSONEncoder().encode(event()))
        let base: [String: Any] = ["stream_id": UUID().uuidString, "cursor": 1, "oldest_cursor": 1,
                                  "gap": false, "has_more": false, "events": [fixture]]
        for (key, invalid) in [("cursor", 2 as Any), ("gap", true as Any),
                               ("oldest_cursor", Int64.max as Any), ("events", [fixture, fixture] as Any)] {
            var page = base
            page[key] = invalid
            XCTAssertThrowsError(try {
                let value = try JSONDecoder().decode(MCPFirewallPage.self,
                    from: JSONSerialization.data(withJSONObject: page))
                try value.validate(after: 0, streamID: nil)
            }())
        }
    }

    func testLiveTransportRejectsRedirectsAndOversizedBodies() async throws {
        guard let address = ProcessInfo.processInfo.environment["MCP_FIREWALL_TEST_FAULT_URL"],
              let url = URL(string: address) else { throw XCTSkip("Run verify.py") }
        let client = try MCPFirewallClient(baseURL: url, token: String(repeating: "x", count: 40))
        do { _ = try await client.events(); XCTFail("Redirect followed") }
        catch MCPFirewallError.http(302) { }
        do { _ = try await client.events(after: 1); XCTFail("Oversized body accepted") }
        catch MCPFirewallError.tooLarge { }
        await client.close()
    }
}

extension MCPFirewallAdapterTests {
    func testUpstreamViewsDoNotPromoteProtocolResultsIntoExecutionEvidence() throws {
        let start = try event().guardEvent
        let blocked = try event("response_denied").guardEvent
        let session = try XCTUnwrap(AgentSessionSnapshot.build(from: [start, blocked]).first)
        let turn = try XCTUnwrap(session.turns.first)
        XCTAssertNil(turn.toolCalls.first?.completedAt)
        let trace = DevelopmentTaskTrace.build(session: session, turn: turn,
                                               journal: nil, verificationState: nil)
        XCTAssertFalse(trace.nodes.contains { $0.status == .completed || $0.status == .running })
        let incident = try XCTUnwrap(SecurityIncident.correlate([blocked]).first)
        XCTAssertTrue(incident.wasBlocked)
        XCTAssertTrue(incident.title.contains("Response blocked"))
        XCTAssertFalse(incident.causalChain.contains { $0.id == "agent" && $0.captured })
        XCTAssertFalse(incident.causalChain.contains { $0.id == "kernel" && $0.captured })
    }
}
