import 'dart:convert';

/// Parsed components of a `zcash:` payment URI.
class Zip321Parts {
  final String address;
  final String amount;
  final String memoRaw;
  final String memoDecoded;

  Zip321Parts({
    required this.address,
    required this.amount,
    required this.memoRaw,
    required this.memoDecoded,
  });
}

/// Base64url-encode a UTF-8 string (no padding).
String toBase64Url(String text) {
  try {
    final bytes = utf8.encode(text);
    final encoded = base64Url.encode(bytes);
    // Strip padding
    return encoded.replaceAll('=', '');
  } catch (_) {
    return '';
  }
}

/// Decode a base64url-encoded string back to UTF-8.
String decodeBase64Url(String value) {
  try {
    var normalized = value.replaceAll('-', '+').replaceAll('_', '/');
    final padding = (4 - normalized.length % 4) % 4;
    normalized += '=' * padding;
    final bytes = base64.decode(normalized);
    return utf8.decode(bytes);
  } catch (_) {
    return '';
  }
}

/// Build a `zcash:` payment URI following ZIP-321.
String buildZcashUri(String address, {String? amount, String? memo}) {
  if (address.isEmpty) return '';
  final base = 'zcash:$address';
  final params = <String>[];
  if (amount != null && double.tryParse(amount) != null && double.parse(amount) > 0) {
    params.add('amount=$amount');
  }
  if (memo != null && memo.isNotEmpty) {
    params.add('memo=${toBase64Url(memo)}');
  }
  return params.isEmpty ? base : '$base?${params.join('&')}';
}

/// Parse a `zcash:` payment URI into its constituent parts.
Zip321Parts parseZip321Uri(String uri) {
  var withoutScheme = uri;
  if (withoutScheme.startsWith('zcash:')) {
    withoutScheme = withoutScheme.substring(6);
  } else if (withoutScheme.startsWith('ZCASH:')) {
    withoutScheme = withoutScheme.substring(6);
  }

  final parts = withoutScheme.split('?');
  final address = parts[0].trim();
  final query = parts.length > 1 ? parts.sublist(1).join('?') : '';

  final queryParams = Uri.splitQueryString(query);
  final amount = (queryParams['amount'] ?? '').trim();
  final memoRaw = (queryParams['memo'] ?? '').trim();
  final memoDecoded = memoRaw.isNotEmpty ? decodeBase64Url(memoRaw) : '';

  return Zip321Parts(
    address: address,
    amount: amount,
    memoRaw: memoRaw,
    memoDecoded: memoDecoded,
  );
}
