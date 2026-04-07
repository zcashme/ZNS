/// Standard JSON-RPC and custom SDK error codes.
enum ZnsErrorType {
  parseError(-32700),
  invalidRequest(-32600),
  methodNotFound(-32601),
  invalidParams(-32602),
  internalError(-32603),
  httpError(-1),
  uivkMismatch(-2);

  final int code;
  const ZnsErrorType(this.code);

  /// Look up an error type by its integer code.
  /// Returns [internalError] if the code is not recognized.
  static ZnsErrorType fromCode(int code) {
    for (final type in ZnsErrorType.values) {
      if (type.code == code) return type;
    }
    return ZnsErrorType.internalError;
  }
}

/// Exception thrown by ZNS SDK operations.
class ZnsError implements Exception {
  final ZnsErrorType type;
  final String message;

  ZnsError(this.type, this.message);

  @override
  String toString() => 'ZnsError(${type.name}): $message';
}
