import Foundation

/// A client for the Zcash Name System (ZNS) JSON-RPC API.
public final class ZNSClient: @unchecked Sendable {
    public let url: String
    public private(set) var verified: Bool

    private let session: URLSession
    private let _nextId: SendableCounter

    // MARK: - Initialization

    private init(url: String, verified: Bool, session: URLSession) {
        self.url = url
        self.verified = verified
        self.session = session
        self._nextId = SendableCounter()
    }

    /// Create a new ZNS client, optionally verifying the server's UIVK against known values.
    ///
    /// - Parameters:
    ///   - url: The JSON-RPC endpoint URL. Defaults to `ZNSConstants.defaultURL`.
    ///   - skipVerify: If `true`, skip UIVK verification on creation.
    /// - Returns: A configured `ZNSClient` instance.
    /// - Throws: `ZNSError` with `.uivkMismatch` if verification fails.
    public static func create(
        url: String = ZNSConstants.defaultURL,
        skipVerify: Bool = false
    ) async throws -> ZNSClient {
        let session = URLSession.shared
        let client = ZNSClient(url: url, verified: false, session: session)

        if !skipVerify {
            let s: StatusResult = try await rpc(url: url, method: "status", id: client.nextId(), session: session)
            guard ZNSConstants.knownUIVKs.contains(s.uivk) else {
                let prefix = String(s.uivk.prefix(20))
                throw ZNSError(
                    type: .uivkMismatch,
                    message: "UIVK mismatch: indexer returned \"\(prefix)...\" which is not a known ZNS instance"
                )
            }
            client.verified = true
        }

        return client
    }

    // MARK: - Private helpers

    private func nextId() -> Int {
        _nextId.increment()
    }

    private func call<T: Decodable>(method: String, params: [String: Any] = [:]) async throws -> T {
        try await rpc(url: url, method: method, params: params, id: nextId(), session: session)
    }

    private func callOptional<T: Decodable>(method: String, params: [String: Any] = [:]) async throws -> T? {
        try await rpcOptional(url: url, method: method, params: params, id: nextId(), session: session)
    }

    // MARK: - Public API

    /// Resolve a name or query. Returns `.single`, `.multiple`, or `.notFound`.
    ///
    /// - Parameter query: The name to resolve (e.g. "alice").
    /// - Returns: A `ResolveResponse` enum case.
    public func resolve(query: String) async throws -> ResolveResponse {
        // The server returns either a single object, an array, or null.
        // We try to decode as a single result first, then as an array.
        guard let requestURL = URL(string: url) else {
            throw ZNSError(type: .httpError, message: "Invalid URL: \(url)")
        }

        var request = URLRequest(url: requestURL)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let rpcRequest = RPCRequest(
            id: nextId(),
            method: "resolve",
            params: ["query": AnyCodable(query)]
        )

        let encoder = JSONEncoder()
        request.httpBody = try encoder.encode(rpcRequest)

        let (data, response) = try await session.data(for: request)

        if let httpResponse = response as? HTTPURLResponse, !(200...299).contains(httpResponse.statusCode) {
            throw ZNSError(type: .httpError, message: "HTTP \(httpResponse.statusCode)")
        }

        let decoder = JSONDecoder()

        // Check for RPC-level errors.
        let check = try decoder.decode(RPCErrorCheck.self, from: data)
        if let error = check.error {
            throw ZNSError.fromRPCError(code: error.code, message: error.message)
        }

        // Try decoding as single result.
        if let single = try? decoder.decode(RPCResponse<ResolveResult>.self, from: data),
           let result = single.result {
            return .single(result)
        }

        // Try decoding as array result.
        if let multi = try? decoder.decode(RPCResponse<[ResolveResult]>.self, from: data),
           let results = multi.result {
            return .multiple(results)
        }

        // Null result means not found.
        return .notFound
    }

    /// Fetch all current marketplace listings.
    public func listings() async throws -> [Listing] {
        let result: ListForSaleResult = try await call(method: "list_for_sale")
        return result.listings
    }

    /// Fetch the current indexer status.
    public func status() async throws -> StatusResult {
        try await call(method: "status")
    }

    /// Fetch events with optional filtering.
    public func events(filter: EventsFilter = EventsFilter()) async throws -> EventsResult {
        try await call(method: "events", params: filter.toParams())
    }

    /// Check if a name is available for registration.
    ///
    /// - Parameter name: The name to check.
    /// - Returns: `true` if the name is not registered.
    public func isAvailable(name: String) async throws -> Bool {
        let result = try await resolve(query: name)
        switch result {
        case .notFound:
            return true
        case .single, .multiple:
            return false
        }
    }

    /// Get the current nonce for a registered name, or `nil` if the name is not registered.
    public func getNonce(name: String) async throws -> Int? {
        let result = try await resolve(query: name)
        switch result {
        case .single(let r):
            return r.nonce
        case .multiple, .notFound:
            return nil
        }
    }
}

// MARK: - SendableCounter

/// A simple thread-safe incrementing counter.
private final class SendableCounter: @unchecked Sendable {
    private var value: Int = 0
    private let lock = NSLock()

    func increment() -> Int {
        lock.lock()
        defer { lock.unlock() }
        value += 1
        return value
    }
}
