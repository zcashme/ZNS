/// Exceptions thrown by the public ZNS SDK surface.
///
/// All exceptions implement [Exception] and carry the offending value so
/// callers can recover it without parsing [toString].

/// Thrown when a string is not a valid ZNS name (1–62 lowercase alphanumeric).
class InvalidNameException implements Exception {
  final String name;
  const InvalidNameException(this.name);

  @override
  String toString() =>
      'InvalidNameException: "$name" is not a valid ZNS name '
      '(1-62 lowercase a-z and 0-9 characters).';
}

/// Type of Zcash address that failed validation.
enum ZcashAddressKind { unified, transparent }

/// Thrown when a string is not a valid Zcash address of the expected kind.
class InvalidAddressException implements Exception {
  final String address;
  final ZcashAddressKind kind;
  const InvalidAddressException(this.address, this.kind);

  @override
  String toString() {
    final label = kind == ZcashAddressKind.unified ? 'unified' : 'transparent';
    return 'InvalidAddressException: "$address" is not a valid Zcash '
        '$label address.';
  }
}
