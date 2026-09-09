import Foundation

extension GuardEvent {
    var isMCPFirewall: Bool { source == "mcp-firewall:v1" }
    var isMCPFirewallBlock: Bool {
        isMCPFirewall && ["mcp_firewall_request_denied", "mcp_firewall_response_denied"].contains(ruleId)
    }
}

extension SecurityIncident {
    private var firewallEvent: GuardEvent? {
        guard !events.isEmpty, events.allSatisfy(\.isMCPFirewall) else { return nil }
        let ordered = events.sorted { $0.ts < $1.ts }
        return ordered.last { $0.op == "firewall_outcome" } ?? ordered.last
    }
    var mcpFirewallTitle: String? {
        firewallEvent.map { "MCP Firewall · \($0.action) · \($0.toolName ?? "Unknown tool")" }
    }
    var mcpFirewallSummary: String? {
        firewallEvent.map { _ in "Observed protocol evidence. Execution, process identity and file effects are unverified." }
    }
    var mcpFirewallChain: [Stage]? {
        guard let event = firewallEvent else { return nil }
        return [
            Stage(id: "agent", title: "Client label", value: event.agent ?? "Not provided",
                  evidence: "Reported by the MCP client; not authenticated process identity", captured: false),
            Stage(id: "protocol", title: "Protocol observation", value: event.action,
                  evidence: "Observed by mcp-firewall; correlated using generated session/call IDs", captured: true),
            Stage(id: "tool", title: "Execution", value: "Unverified",
                  evidence: "Forwarding and response scanning do not prove successful execution", captured: false),
            Stage(id: "kernel", title: "File and process effects", value: "Unknown",
                  evidence: "The firewall event stream contains no OS evidence", captured: false)
        ]
    }
}

extension DevelopmentTaskTrace {
    static func mcpFirewallTrace(session: AgentSessionSnapshot, turn: AgentTurn) -> DevelopmentTaskTrace? {
        guard !session.events.isEmpty, session.events.allSatisfy(\.isMCPFirewall) else { return nil }
        let observations = session.events.sorted { $0.ts < $1.ts }
        let evidence = observations.map {
            DevelopmentTraceEvidence(id: $0.id.uuidString, title: $0.action,
                value: "\($0.toolName ?? "Unknown tool") · Source: mcp-firewall · \($0.ruleId)")
        }
        let node = DevelopmentTraceNode(id: "firewall", kind: .build,
            title: "Firewall protocol evidence",
            summary: "Admission and response inspection were observed. Execution and file effects are unverified.",
            status: .attention, confidence: .unknown, timestamp: observations.last?.ts,
            activities: [], context: [], tools: turn.toolCalls, evidence: evidence)
        return DevelopmentTaskTrace(id: "\(session.id):\(turn.id)", nodes: [node])
    }
}
