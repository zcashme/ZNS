import Foundation

// MARK: - ZNSErrorType

public enum ZNSErrorType: Int, Sendable {
    case parseError = -32700
    case invalidRequest = -32600
    case methodNotFound = -32601
    case invalidParams = -32602
    case internalError = -32603
    case httpError = -1
    case uivkMismatch = -2
}

// MARK: - ZNSError

public struct ZNSError: Error, LocalizedError, Sendable {
    public let type: ZNSErrorType
    public let message: String

    public var errorDescription: String? { message }

    public init(type: ZNSErrorType, message: String) {
        self.type = type
        self.message = message
    }

    /// Attempt to map a JSON-RPC error code to a known error type.
    /// Falls back to `.internalError` for unrecognized codes.
    static func fromRPCError(code: Int, message: String) -> ZNSError {
        let errorType = ZNSErrorType(rawValue: code) ?? .internalError
        return ZNSError(type: errorType, message: message)
    }
}
