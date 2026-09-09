// MCP Firewall integration, maintained in ressl/mcp-firewall. No upstream sources vendored.
import Foundation

enum MCPFirewallError: Error, LocalizedError {
    case invalidConfiguration, invalidData, disconnected, tooLarge, http(Int)
    var errorDescription: String? {
        switch self {
        case .invalidConfiguration: return "Use a loopback HTTP address and a token of 32–1024 visible ASCII characters."
        case .invalidData: return "The firewall returned invalid or unsupported evidence. Reconnect after checking compatibility."
        case .disconnected: return "Connection lost. Pending approvals will be denied when the controller lease expires."
        case .tooLarge: return "The firewall response exceeded the adapter's size limit."
        case .http(401): return "Authentication failed. Check the controller token."
        case .http(409): return "The request expired or the event stream restarted. Reconnect to continue."
        case .http: return "The firewall rejected the request. Check that dashboard approvals are enabled."
        }
    }
}

enum MCPFirewallPhase: String, Codable {
    case request_received, policy_decision, request_allowed, request_denied, request_forwarded
    case response_received, response_finding, response_allowed, response_redacted, response_denied
    case response_error, request_unknown

    var terminal: Bool {
        switch self {
        case .request_denied, .response_allowed, .response_redacted, .response_denied,
             .response_error, .request_unknown: return true
        default: return false
        }
    }
    var label: String {
        switch self {
        case .request_received: return "Awaiting policy"
        case .policy_decision: return "Policy observation; admission not final"
        case .request_allowed: return "Admitted; execution unverified"
        case .request_denied: return "Denied before forwarding"
        case .request_forwarded: return "Queued to server; execution unverified"
        case .response_received: return "Response observed; scanning pending"
        case .response_finding: return "Response scan finding"
        case .response_allowed: return "Response passed scanning; execution unverified"
        case .response_redacted: return "Response redacted; execution unverified"
        case .response_denied: return "Response blocked; side effects unknown"
        case .response_error: return "Protocol error; side effects unknown"
        case .request_unknown: return "Outcome unknown"
        }
    }
}

struct MCPFirewallEvent: Codable, Identifiable {
    let schema_version: Int
    let id: UUID
    let session_id: UUID
    let call_id: UUID
    let sequence: Int64
    let timestamp: Double
    let phase: MCPFirewallPhase
    let correlated: Bool
    let tool: String
    let agent: String
    let action: String?
    let severity: String
    let stage: String?
    let reason: String
    let response_is_error: Bool?

    func validate() throws {
        guard schema_version == 1, sequence > 0, sequence <= 9_007_199_254_740_991,
              timestamp.isFinite, (-62_135_596_800...253_402_300_799).contains(timestamp),
              [tool, agent, reason].allSatisfy({ $0.unicodeScalars.count <= 1024 }),
              ["info", "low", "medium", "high", "critical"].contains(severity),
              action == nil || ["allow", "deny", "prompt", "redact", "alert"].contains(action!),
              (stage?.utf8.count ?? 0) <= 100 else { throw MCPFirewallError.invalidData }
    }

    var status: String {
        if response_is_error == true && phase.terminal {
            return phase.label + "; server reported a tool error"
        }
        return phase.label
    }

    // Use upstream's actual type. Do not manufacture workspace, user turn, model
    // reasoning, tool output, process attribution or filesystem recovery evidence.
    var guardEvent: GuardEvent {
        GuardEvent(id: id, kind: "tool", ruleId: "mcp_firewall_" + phase.rawValue,
            path: "-", command: nil, agent: agent + " (client label)",
            op: phase.terminal ? "firewall_outcome" : (phase == .request_received ? "call" : phase.rawValue),
            severity: severity, ts: Date(timeIntervalSince1970: timestamp), action: status,
            sessionId: "mcp-firewall:" + session_id.uuidString.lowercased(),
            toolCallId: correlated ? call_id.uuidString.lowercased() : nil,
            toolName: tool, source: "mcp-firewall:v1")
    }
}

struct MCPFirewallPage: Decodable {
    let stream_id: UUID
    let cursor: Int64
    let oldest_cursor: Int64
    let gap: Bool
    let has_more: Bool
    let events: [MCPFirewallEvent]

    func validate(after: Int64, streamID: UUID?) throws {
        guard streamID == nil || streamID == stream_id, cursor >= after,
              oldest_cursor > 0, oldest_cursor <= 9_007_199_254_740_992, events.count <= 256,
              cursor <= 9_007_199_254_740_991,
              gap == (after < oldest_cursor - 1),
              cursor == (events.isEmpty ? after : max(after, oldest_cursor - 1) + Int64(events.count)),
              !has_more || !events.isEmpty,
              Set(events.map(\.id)).count == events.count else { throw MCPFirewallError.invalidData }
        for event in events { try event.validate() }
    }
}

struct MCPFirewallPending: Codable, Identifiable {
    let id: UUID
    let session_id: UUID
    let call_id: UUID
    let request_hash: String
    let tool: String
    let agent: String
    let arguments_preview: String
    let redacted: Bool
    let created_at: Double
    let expires_at: Double

    func validate() throws {
        guard request_hash.count == 64,
              request_hash.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
              tool.unicodeScalars.count <= 1024, agent.unicodeScalars.count <= 1024,
              arguments_preview.utf8.count <= 16_384,
              created_at.isFinite, expires_at.isFinite,
              (-62_135_596_800...253_402_300_799).contains(created_at),
              expires_at <= 253_402_300_799, expires_at >= created_at, expires_at - created_at <= 301
              else { throw MCPFirewallError.invalidData }
    }
}
