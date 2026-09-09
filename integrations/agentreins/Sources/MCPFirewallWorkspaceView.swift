import SwiftUI

struct MCPFirewallWorkspaceView: View {
    @ObservedObject var sight: MCPFirewallSight
    @State private var restoreConfirmation: MCPFirewallFilePreview?
    @State private var discardConfirmation: MCPFirewallSnapshot?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Workspace snapshots").font(.headline)
                Spacer()
                Button("Refresh snapshots") { Task { await sight.refreshWorkspace() } }
            }
            if let workspace = sight.workspace, workspace.enabled {
                Text(verbatim: workspace.workspace).font(.caption).textSelection(.enabled)
                Text("Local file contents may contain secrets. Snapshots last until the proxy exits. Pause editors, agents and background writers before restoring.")
                    .font(.caption).foregroundStyle(.secondary)
                if workspace.busy { Text("Tool call in flight. Restore is unavailable.").foregroundStyle(.orange) }
                if !sight.workspaceStatus.isEmpty {
                    Text(verbatim: sight.workspaceStatus).accessibilityIdentifier("workspace-status")
                }
                ForEach(workspace.snapshots) { snapshot in
                    HStack {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(verbatim: "\(snapshot.tool) · \(snapshot.state) · \(snapshot.file_count) changed files")
                            HStack {
                                Text(Date(timeIntervalSince1970: snapshot.created_at), style: .time)
                                Text(verbatim: "Call " + snapshot.call_id.uuidString.prefix(8))
                            }.font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button("Review snapshot") { Task { await sight.inspect(snapshot) } }
                        Button("Discard…") { discardConfirmation = snapshot }
                            .disabled(snapshot.state == "inflight")
                    }
                }
                if workspace.snapshots.isEmpty { Text("No snapshots captured yet.").font(.caption) }
                if let snapshot = sight.workspaceDetail {
                    Divider()
                    Text(verbatim: snapshot.tool + " · Call " + snapshot.call_id.uuidString.prefix(8)).font(.subheadline.bold())
                    Text(verbatim: snapshot.message).font(.caption)
                    ForEach(snapshot.files) { file in
                        HStack {
                            Text(verbatim: file.path + " · " + (file.restored ? "restored" : file.kind))
                            Spacer()
                            if !file.restored {
                                Button("View diff") { Task { await sight.inspect(snapshot, file: file) } }
                            }
                        }
                    }
                }
                if let preview = sight.filePreview {
                    Text(verbatim: preview.path).font(.headline)
                    ScrollView([.horizontal, .vertical]) {
                        Text(verbatim: preview.diff).font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                    }.frame(height: 180)
                    Button("Restore this file…") { restoreConfirmation = preview }
                        .disabled(workspace.busy)
                    Text("Restores file bytes and permissions only. Later edits cause a conflict; external actions and directory trees cannot be undone.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            } else {
                Text("Snapshots are disabled or unavailable for this proxy.").font(.caption)
            }
        }
        .disabled(!sight.connected || sight.workspaceWorking)
        .confirmationDialog("Restore the selected file?", isPresented: Binding(
            get: { restoreConfirmation != nil }, set: { if !$0 { restoreConfirmation = nil } }),
            titleVisibility: .visible, presenting: restoreConfirmation) { preview in
                Button("Restore selected file", role: .destructive) {
                    Task { await sight.restoreFile(preview) }
                    restoreConfirmation = nil
                }
                Button("Cancel", role: .cancel) { restoreConfirmation = nil }
            } message: { preview in
                Text(verbatim: preview.path + "\nPause all external writers first. This replaces or removes this file only if it still matches the captured state.")
            }
        .confirmationDialog("Discard this snapshot?", isPresented: Binding(
            get: { discardConfirmation != nil }, set: { if !$0 { discardConfirmation = nil } }),
            titleVisibility: .visible, presenting: discardConfirmation) { snapshot in
                Button("Discard snapshot", role: .destructive) {
                    Task { await sight.discardSnapshot(snapshot) }
                    discardConfirmation = nil
                }
                Button("Cancel", role: .cancel) { discardConfirmation = nil }
            } message: { _ in
                Text("This releases its recovery bytes. Workspace files stay as they are.")
            }
    }
}
