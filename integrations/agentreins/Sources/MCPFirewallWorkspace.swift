import Foundation

struct MCPFirewallFileChange: Codable, Identifiable {
    let id: UUID
    let path: String
    let kind: String
    let restored: Bool

    func validate() throws {
        let parts = path.split(separator: "/", omittingEmptySubsequences: false)
        guard !path.isEmpty, path.utf8.count <= 1024, parts.count <= 32,
              !parts.contains(where: { ["", ".", "..", ".git", ".venv", "node_modules", "__pycache__", ".DS_Store"].contains(String($0)) }),
              !path.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
              ["added", "modified", "deleted"].contains(kind) else { throw MCPFirewallError.invalidData }
    }
}

struct MCPFirewallSnapshot: Codable, Identifiable {
    let id: UUID
    let revision: UUID
    let session_id: UUID
    let call_id: UUID
    let tool: String
    let created_at: Double
    let state: String
    let message: String
    let files: [MCPFirewallFileChange]
    let file_count: Int

    func validate(detail: Bool = false) throws {
        guard tool.unicodeScalars.count <= 1024, message.utf8.count <= 1024,
              created_at.isFinite, (0...253_402_300_799).contains(created_at),
              ["inflight", "complete", "incomplete"].contains(state),
              (0...2000).contains(file_count), files.count <= 2000,
              Set(files.map(\.id)).count == files.count,
              Set(files.map(\.path)).count == files.count,
              !detail || files.count == file_count else { throw MCPFirewallError.invalidData }
        for file in files { try file.validate() }
    }
}

struct MCPFirewallWorkspace: Codable {
    let enabled: Bool
    let workspace: String
    let busy: Bool
    let snapshots: [MCPFirewallSnapshot]

    func validate() throws {
        guard workspace.utf8.count <= 4096, snapshots.count <= 8,
              Set(snapshots.map(\.id)).count == snapshots.count,
              enabled || (workspace.isEmpty && !busy && snapshots.isEmpty) else {
            throw MCPFirewallError.invalidData
        }
        for snapshot in snapshots { try snapshot.validate() }
    }
}

struct MCPFirewallFilePreview: Codable, Identifiable {
    var id: UUID { file_id }
    let snapshot_id: UUID
    let revision: UUID
    let file_id: UUID
    let path: String
    let diff: String
    let omitted: Bool

    func validate(snapshot: MCPFirewallSnapshot, file: MCPFirewallFileChange) throws {
        guard snapshot_id == snapshot.id, revision == snapshot.revision,
              file_id == file.id, path == file.path, diff.utf8.count <= 65536 else {
            throw MCPFirewallError.invalidData
        }
    }
}
