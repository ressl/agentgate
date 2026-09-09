import Foundation
import SwiftUI

@MainActor
final class MCPFirewallSight: ObservableObject {
    @Published private(set) var connected = false
    @Published private(set) var connecting = false
    @Published private(set) var disconnecting = false
    @Published private(set) var pending: [MCPFirewallPending] = []
    @Published private(set) var events: [MCPFirewallEvent] = []
    @Published private(set) var deciding: Set<UUID> = []
    @Published private(set) var evidenceGap = false
    @Published private(set) var status = "Disconnected. Calls requiring approval are denied."
    var onEvents: (([GuardEvent]) -> Void)?

    private var client: MCPFirewallClient?
    private var pollTask: Task<Void, Never>?
    private var generation = UUID()
    private var polling = false
    private var cursor: Int64 = 0
    private var streamID: UUID?
    private var seen: Set<UUID> = []
    private var seenOrder: [UUID] = []
    private var sequences: [UUID: Int64] = [:]

    func connect(endpoint: String, token: String) async {
        guard !connecting && !connected && !disconnecting else { return }
        guard let url = URL(string: endpoint) else {
            status = MCPFirewallError.invalidConfiguration.localizedDescription
            return
        }
        let connection: MCPFirewallClient
        do { connection = try MCPFirewallClient(baseURL: url, token: token) }
        catch { status = MCPFirewallError.invalidConfiguration.localizedDescription; return }
        let version = UUID()
        generation = version
        connecting = true
        client = connection
        cursor = 0
        streamID = nil
        status = "Connecting…"
        defer { if generation == version { connecting = false } }
        do {
            let page = try await connection.events()
            guard generation == version else { return }
            let requests = try await connection.pending()
            guard generation == version else { return }
            apply(page)
            pending = requests
            connected = true
            status = "Connected. Review each call before allowing it once."
            pollTask = Task { [weak self] in
                while !Task.isCancelled {
                    do { try await Task.sleep(nanoseconds: 2_000_000_000) }
                    catch { return }
                    guard let self, self.generation == version else { return }
                    await self.poll(version: version)
                }
            }
        } catch {
            if generation == version { await disconnect(message: Self.message(error)) }
        }
    }

    private func poll(version: UUID) async {
        guard let client, connected, !polling else { return }
        polling = true
        defer { if generation == version { polling = false } }
        do {
            let requests = try await client.pending()
            guard generation == version else { return }
            pending = requests
            for _ in 0..<4 {
                let page = try await client.events(after: cursor, streamID: streamID)
                guard generation == version else { return }
                apply(page)
                if !page.has_more { break }
            }
        } catch {
            if generation == version { await disconnect(message: Self.message(error)) }
        }
    }

    private func apply(_ page: MCPFirewallPage) {
        streamID = page.stream_id
        cursor = page.cursor
        evidenceGap = evidenceGap || page.gap
        var fresh: [MCPFirewallEvent] = []
        for event in page.events where seen.insert(event.id).inserted {
            seenOrder.append(event.id)
            if let previous = sequences[event.session_id], event.sequence != previous + 1 {
                evidenceGap = true
            } else if sequences[event.session_id] == nil && event.sequence > 1 {
                evidenceGap = true
            }
            if sequences.count >= 128 && sequences[event.session_id] == nil { sequences.removeAll() }
            sequences[event.session_id] = event.sequence
            fresh.append(event)
        }
        while seenOrder.count > 10_000 { seen.remove(seenOrder.removeFirst()) }
        events = Array((fresh.reversed() + events).prefix(200))
        if !fresh.isEmpty { onEvents?(fresh.map(\.guardEvent)) }
    }

    func decide(_ item: MCPFirewallPending, allow: Bool) async {
        guard let client, connected, !deciding.contains(item.id),
              pending.contains(where: { $0.id == item.id && $0.request_hash == item.request_hash })
              else { return }
        let version = generation
        deciding.insert(item.id)
        defer { if generation == version { deciding.remove(item.id) } }
        do {
            try await client.decide(item, allow: allow)
            guard generation == version else { return }
            pending.removeAll { $0.id == item.id }
        } catch MCPFirewallError.http(409) {
            guard generation == version else { return }
            status = "This request expired or changed. Review the refreshed list."
            await poll(version: version)
        } catch {
            if generation == version { await disconnect(message: Self.message(error)) }
        }
    }

    func disconnect(message: String = "Disconnected. Calls requiring approval are denied.") async {
        guard !disconnecting else { return }
        disconnecting = true
        defer { disconnecting = false }
        generation = UUID()
        polling = false
        pollTask?.cancel()
        pollTask = nil
        let old = client
        client = nil
        connected = false
        connecting = false
        pending = []
        deciding = []
        status = message
        await old?.disconnect()
    }

    private static func message(_ error: Error) -> String {
        (error as? MCPFirewallError)?.localizedDescription ?? MCPFirewallError.disconnected.localizedDescription
    }
}
