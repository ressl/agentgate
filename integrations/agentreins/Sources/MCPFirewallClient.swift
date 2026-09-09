import Foundation

private final class MCPFirewallRedirects: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

actor MCPFirewallClient {
    private let baseURL: URL
    private var token: String
    private let session: URLSession
    private let maximumBytes = 4 * 1024 * 1024

    init(baseURL: URL, token: String) throws {
        guard baseURL.scheme == "http",
              ["127.0.0.1", "localhost", "::1", "[::1]"].contains(baseURL.host?.lowercased() ?? ""),
              baseURL.user == nil, baseURL.password == nil, baseURL.query == nil,
              baseURL.fragment == nil, ["", "/"].contains(baseURL.path),
              (32...1024).contains(token.utf8.count),
              token.utf8.allSatisfy({ (33...126).contains($0) })
              else { throw MCPFirewallError.invalidConfiguration }
        self.baseURL = baseURL
        self.token = token
        let configuration = URLSessionConfiguration.ephemeral
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = 3
        configuration.timeoutIntervalForResource = 5
        configuration.connectionProxyDictionary = ["HTTPEnable": 0, "HTTPSEnable": 0,
            "SOCKSEnable": 0, "ProxyAutoConfigEnable": 0, "ProxyAutoDiscoveryEnable": 0]
        self.session = URLSession(configuration: configuration, delegate: MCPFirewallRedirects(),
                                  delegateQueue: nil)
    }

    private func request(_ path: String, query: [URLQueryItem] = [], body: Data? = nil) async throws -> Data {
        guard !token.isEmpty else { throw MCPFirewallError.disconnected }
        var components = URLComponents(url: baseURL.appendingPathComponent(path), resolvingAgainstBaseURL: false)!
        components.queryItems = query.isEmpty ? nil : query
        var request = URLRequest(url: components.url!)
        request.httpMethod = body == nil ? "GET" : "POST"
        request.setValue("Bearer " + token, forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = body
        do {
            let (bytes, response) = try await session.bytes(for: request)
            defer { bytes.task.cancel() }
            guard let http = response as? HTTPURLResponse else { throw MCPFirewallError.invalidData }
            guard (200...299).contains(http.statusCode) else { throw MCPFirewallError.http(http.statusCode) }
            guard response.expectedContentLength <= maximumBytes else { throw MCPFirewallError.tooLarge }
            var data = Data()
            for try await byte in bytes {
                if data.count >= maximumBytes { throw MCPFirewallError.tooLarge }
                data.append(byte)
            }
            return data
        } catch let error as MCPFirewallError { throw error }
        catch is CancellationError { throw CancellationError() }
        catch { throw MCPFirewallError.disconnected }
    }

    func events(after: Int64 = 0, streamID: UUID? = nil) async throws -> MCPFirewallPage {
        var query = [URLQueryItem(name: "after", value: String(after))]
        if let streamID { query.append(URLQueryItem(name: "stream_id", value: streamID.uuidString.lowercased())) }
        let data = try await request("api/integration-events", query: query)
        do {
            let page = try JSONDecoder().decode(MCPFirewallPage.self, from: data)
            try page.validate(after: after, streamID: streamID)
            return page
        } catch { throw MCPFirewallError.invalidData }
    }

    func pending() async throws -> [MCPFirewallPending] {
        let data = try await request("api/approvals")
        do {
            let items = try JSONDecoder().decode([MCPFirewallPending].self, from: data)
            guard items.count <= 1000, Set(items.map(\.id)).count == items.count else {
                throw MCPFirewallError.invalidData
            }
            for item in items { try item.validate() }
            return items
        } catch { throw MCPFirewallError.invalidData }
    }

    func decide(_ item: MCPFirewallPending, allow: Bool) async throws {
        try item.validate()
        let body = try JSONSerialization.data(withJSONObject: ["request_hash": item.request_hash, "allow": allow])
        let data = try await request("api/approvals/" + item.id.uuidString.lowercased(), body: body)
        struct Acknowledgment: Decodable { let accepted: Bool }
        guard let acknowledgment = try? JSONDecoder().decode(Acknowledgment.self, from: data),
              acknowledgment.accepted else { throw MCPFirewallError.invalidData }
    }

    func workspace() async throws -> MCPFirewallWorkspace {
        let data = try await request("api/workspace")
        guard let workspace = try? JSONDecoder().decode(MCPFirewallWorkspace.self, from: data) else {
            throw MCPFirewallError.invalidData
        }
        try workspace.validate()
        return workspace
    }

    func snapshot(_ id: UUID) async throws -> MCPFirewallSnapshot {
        let data = try await request("api/workspace/" + id.uuidString.lowercased())
        guard let snapshot = try? JSONDecoder().decode(MCPFirewallSnapshot.self, from: data),
              snapshot.id == id else { throw MCPFirewallError.invalidData }
        try snapshot.validate(detail: true)
        return snapshot
    }

    func preview(_ snapshot: MCPFirewallSnapshot, file: MCPFirewallFileChange) async throws -> MCPFirewallFilePreview {
        let data = try await request("api/workspace/" + snapshot.id.uuidString.lowercased()
                                    + "/files/" + file.id.uuidString.lowercased())
        guard let preview = try? JSONDecoder().decode(MCPFirewallFilePreview.self, from: data) else {
            throw MCPFirewallError.invalidData
        }
        try preview.validate(snapshot: snapshot, file: file)
        return preview
    }

    func restore(_ preview: MCPFirewallFilePreview) async throws -> MCPFirewallSnapshot {
        let body = try JSONSerialization.data(withJSONObject: ["revision": preview.revision.uuidString.lowercased()])
        let data = try await request("api/workspace/" + preview.snapshot_id.uuidString.lowercased()
                                    + "/files/" + preview.file_id.uuidString.lowercased() + "/restore", body: body)
        guard let snapshot = try? JSONDecoder().decode(MCPFirewallSnapshot.self, from: data),
              snapshot.id == preview.snapshot_id,
              snapshot.revision != preview.revision,
              snapshot.files.contains(where: { $0.id == preview.file_id && $0.restored }) else {
            throw MCPFirewallError.invalidData
        }
        try snapshot.validate(detail: true)
        return snapshot
    }

    func discard(_ snapshot: MCPFirewallSnapshot) async throws {
        let body = try JSONSerialization.data(withJSONObject: ["revision": snapshot.revision.uuidString.lowercased()])
        let data = try await request("api/workspace/" + snapshot.id.uuidString.lowercased() + "/discard", body: body)
        struct Acknowledgment: Decodable { let discarded: Bool }
        guard let result = try? JSONDecoder().decode(Acknowledgment.self, from: data), result.discarded else {
            throw MCPFirewallError.invalidData
        }
    }

    func disconnect() async {
        _ = try? await request("api/approvals/disconnect", body: Data("{}".utf8))
        token = ""
        session.invalidateAndCancel()
    }

    func close() {
        token = ""
        session.invalidateAndCancel()
    }
}
