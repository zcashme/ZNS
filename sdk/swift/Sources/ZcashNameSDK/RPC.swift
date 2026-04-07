import Foundation

// MARK: - JSON-RPC request / response structures

struct RPCRequest: Encodable {
    let jsonrpc: String = "2.0"
    let id: Int
    let method: String
    let params: [String: AnyCodable]
}

struct RPCResponse<T: Decodable>: Decodable {
    let result: T?
    let error: RPCError?
}

struct RPCError: Decodable {
    let code: Int
    let message: String
}

/// Used to check for RPC-level errors before attempting typed decoding.
struct RPCErrorCheck: Decodable {
    let error: RPCError?
}

// MARK: - AnyCodable

/// A lightweight type-erased Codable wrapper for JSON-RPC params.
struct AnyCodable: Encodable {
    private let value: Any

    init(_ value: Any) {
        self.value = value
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch value {
        case let v as String:
            try container.encode(v)
        case let v as Int:
            try container.encode(v)
        case let v as Double:
            try container.encode(v)
        case let v as Bool:
            try container.encode(v)
        case let v as [Any]:
            try container.encode(v.map { AnyCodable($0) })
        case let v as [String: Any]:
            try container.encode(v.mapValues { AnyCodable($0) })
        default:
            try container.encodeNil()
        }
    }
}

// MARK: - rpc function

/// Perform a JSON-RPC call and decode the result.
func rpc<T: Decodable>(
    url: String,
    method: String,
    params: [String: Any] = [:],
    id: Int = 1,
    session: URLSession = .shared
) async throws -> T {
    guard let requestURL = URL(string: url) else {
        throw ZNSError(type: .httpError, message: "Invalid URL: \(url)")
    }

    var request = URLRequest(url: requestURL)
    request.httpMethod = "POST"
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")

    let rpcRequest = RPCRequest(
        id: id,
        method: method,
        params: params.mapValues { AnyCodable($0) }
    )

    let encoder = JSONEncoder()
    request.httpBody = try encoder.encode(rpcRequest)

    let (data, response) = try await session.data(for: request)

    if let httpResponse = response as? HTTPURLResponse, !(200...299).contains(httpResponse.statusCode) {
        throw ZNSError(type: .httpError, message: "HTTP \(httpResponse.statusCode)")
    }

    let decoder = JSONDecoder()
    let rpcResponse = try decoder.decode(RPCResponse<T>.self, from: data)

    if let error = rpcResponse.error {
        throw ZNSError.fromRPCError(code: error.code, message: error.message)
    }

    guard let result = rpcResponse.result else {
        // For resolve, null result is valid -- handled by caller via optional decoding.
        // If T is Optional, the decoder handles it. For non-optional T, this is an error.
        throw ZNSError(type: .internalError, message: "No result in response")
    }

    return result
}

/// Variant that allows nil results (used by resolve).
func rpcOptional<T: Decodable>(
    url: String,
    method: String,
    params: [String: Any] = [:],
    id: Int = 1,
    session: URLSession = .shared
) async throws -> T? {
    guard let requestURL = URL(string: url) else {
        throw ZNSError(type: .httpError, message: "Invalid URL: \(url)")
    }

    var request = URLRequest(url: requestURL)
    request.httpMethod = "POST"
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")

    let rpcRequest = RPCRequest(
        id: id,
        method: method,
        params: params.mapValues { AnyCodable($0) }
    )

    let encoder = JSONEncoder()
    request.httpBody = try encoder.encode(rpcRequest)

    let (data, response) = try await session.data(for: request)

    if let httpResponse = response as? HTTPURLResponse, !(200...299).contains(httpResponse.statusCode) {
        throw ZNSError(type: .httpError, message: "HTTP \(httpResponse.statusCode)")
    }

    // First check for RPC-level errors using a raw JSON approach.
    let decoder = JSONDecoder()

    let rawResponse = try decoder.decode(RPCErrorCheck.self, from: data)
    if let error = rawResponse.error {
        throw ZNSError.fromRPCError(code: error.code, message: error.message)
    }

    // Try to decode the full response with the typed result.
    let rpcResponse = try decoder.decode(RPCResponse<T>.self, from: data)
    return rpcResponse.result
}
