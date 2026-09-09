import SwiftUI

struct MCPFirewallView: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var sight: MCPFirewallSight
    @State private var endpoint = "http://127.0.0.1:9090"
    @State private var token = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("MCP Firewall").font(.title2.bold())
                Spacer()
                Button("Close") { dismiss() }.keyboardShortcut(.cancelAction)
            }
            Text(sight.status).foregroundStyle(sight.connected ? .primary : .secondary)
                .accessibilityIdentifier("firewall-status")
            HStack {
                TextField("Local firewall address", text: $endpoint)
                    .disabled(sight.connected || sight.connecting)
                SecureField("Controller token", text: $token)
                    .disabled(sight.connected || sight.connecting)
                if sight.connected || sight.connecting || sight.disconnecting {
                    Button("Disconnect") { Task { await sight.disconnect() } }
                        .disabled(sight.disconnecting)
                } else {
                    Button("Connect") {
                        let credential = token
                        token = ""
                        Task { await sight.connect(endpoint: endpoint, token: credential) }
                    }.disabled(token.isEmpty)
                }
            }
            Text("Approvals apply once. Remaining firewall checks still run. Keep AgentReins running to renew the controller lease.")
                .font(.caption).foregroundStyle(.secondary)
            if sight.evidenceGap {
                Label("Some events are missing. This view is incomplete evidence.", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
            }
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 16) {
                    ForEach(sight.pending) { item in
                        GroupBox {
                            VStack(alignment: .leading, spacing: 8) {
                                Text(verbatim: item.tool).font(.headline)
                                Text(verbatim: "Agent: " + item.agent).font(.caption)
                                Text("Expires \(Date(timeIntervalSince1970: item.expires_at), style: .time)")
                                    .font(.caption)
                                Text(verbatim: item.arguments_preview).font(.system(.body, design: .monospaced))
                                    .textSelection(.enabled)
                                if item.redacted {
                                    Text("Sensitive values are redacted. Deny if you cannot assess this call.")
                                        .foregroundStyle(.orange).font(.caption)
                                }
                                HStack {
                                    Button("Allow once") { Task { await sight.decide(item, allow: true) } }
                                    Button("Deny") { Task { await sight.decide(item, allow: false) } }
                                }.disabled(sight.deciding.contains(item.id))
                            }.frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                    Divider()
                    if sight.connected {
                        MCPFirewallWorkspaceView(sight: sight)
                        Divider()
                    }
                    Text("Observed firewall activity").font(.headline)
                    Text("Protocol evidence does not prove file changes or successful execution.")
                        .font(.caption).foregroundStyle(.secondary)
                    ForEach(sight.events) { event in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(verbatim: event.tool + " · " + event.status).font(.subheadline)
                            if !event.reason.isEmpty { Text(verbatim: event.reason).font(.caption) }
                            Text(Date(timeIntervalSince1970: event.timestamp), style: .time)
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            }
        }.padding(24).frame(minWidth: 720, minHeight: 560)
    }
}
