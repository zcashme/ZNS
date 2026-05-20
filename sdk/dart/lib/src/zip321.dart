import 'dart:convert';

import 'package:meta/meta.dart';

/// Parsed components of a `zcash:` ZIP-321 payment URI.
@immutable
class Zip321Parts {
  final String address;
  final String amount;
  final String memoRaw;
  final String memoDecoded;

  const Zip321Parts({
    required this.address,
    required this.amount,
    required this.memoRaw,
    required this.memoDecoded,
  });

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is Zip321Parts &&
          other.address == address &&
          other.amount == amount &&
          other.memoRaw == memoRaw &&
          other.memoDecoded == memoDecoded;

  @override
  int get hashCode => Object.hash(address, amount, memoRaw, memoDecoded);

  @override
  String toString() =>
      'Zip321Parts(address: $address, amount: $amount, memo: $memoDecoded)';
}

/// Base64url-encode a UTF-8 string with no padding.
String toBase64Url(String text) {
  try {
    return base64Url.encode(utf8.encode(text)).replaceAll('=', '');
  } catch (_) {
    return '';
  }
}

/// Decode a base64url-encoded string (with or without padding) back to UTF-8.
/// Returns an empty string on any decode failure.
String decodeBase64Url(String value) {
  try {
    var normalized = value.replaceAll('-', '+').replaceAll('_', '/');
    final padLen = normalized.length % 4 == 0 ? 0 : 4 - (normalized.length % 4);
    normalized += '=' * padLen;
    return utf8.decode(base64.decode(normalized));
  } catch (_) {
    return '';
  }
}

/// Format zatoshis as a ZEC decimal string with no trailing zeros, suitable
/// for ZIP-321 `amount=` parameters. Uses integer arithmetic to avoid
/// floating-point representation errors.
String _zatsToZec(int zats) {
  final whole = zats ~/ 100000000;
  final frac = zats % 100000000;
  if (frac == 0) return '$whole';
  final fracStr =
      frac.toString().padLeft(8, '0').replaceAll(RegExp(r'0+$'), '');
  return '$whole.$fracStr';
}

/// Build a ZIP-321 URI for [address]. [amountZats] is in zatoshis (omitted if
/// null or 0); [memo] is plain text and gets base64url-encoded.
String buildZcashUri(String address, {int? amountZats, String? memo}) {
  if (address.isEmpty) return '';
  final base = 'zcash:$address';
  final params = <String>[];
  if (amountZats != null && amountZats > 0) {
    params.add('amount=${_zatsToZec(amountZats)}');
  }
  if (memo != null && memo.isNotEmpty) {
    params.add('memo=${toBase64Url(memo)}');
  }
  return params.isEmpty ? base : '$base?${params.join('&')}';
}

/// Parse a `zcash:` URI into its constituent parts. Scheme match is
/// case-insensitive; missing fields yield empty strings.
Zip321Parts parseZip321Uri(String uri) {
  var withoutScheme = uri;
  if (withoutScheme.toLowerCase().startsWith('zcash:')) {
    withoutScheme = withoutScheme.substring(6);
  }

  final qIdx = withoutScheme.indexOf('?');
  final addressPart =
      qIdx == -1 ? withoutScheme : withoutScheme.substring(0, qIdx);
  final query = qIdx == -1 ? '' : withoutScheme.substring(qIdx + 1);

  final params = Uri.splitQueryString(query);
  final amount = (params['amount'] ?? '').trim();
  final memoRaw = (params['memo'] ?? '').trim();
  final memoDecoded = memoRaw.isEmpty ? '' : decodeBase64Url(memoRaw);

  return Zip321Parts(
    address: addressPart.trim(),
    amount: amount,
    memoRaw: memoRaw,
    memoDecoded: memoDecoded,
  );
}
