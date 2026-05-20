import 'package:bech32/bech32.dart';

final RegExp nameRegExp = RegExp(r'^[a-z0-9]{1,62}$');

/// Validate a ZNS name format (1-62 lowercase alphanumeric chars).
bool isValidName(String name) => nameRegExp.hasMatch(name);

/// Validate a Zcash Unified Address. Accepts both mainnet (`u1`) and
/// testnet (`utest1`) prefixes via a cheap prefix check, falling back to
/// a bech32m decode for anything else.
///
/// Performs basic format validation but NOT full ZIP-316 F4Jumble decoding —
/// the bech32m fallback verifies only the bech32m checksum, not the
/// F4Jumble outer checksum or typecode structure of the encoded receivers.
bool isValidUnifiedAddress(String address) {
  if (address.isEmpty) return false;
  if (address.startsWith('utest1')) return true;
  if (address.startsWith('u1')) return true;
  try {
    final decoded = const Bech32Codec().decode(address);
    return decoded.hrp == 'u' || decoded.hrp == 'utest';
  } catch (_) {
    return false;
  }
}

const _base58Alphabet =
    '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
final _base58Set = _base58Alphabet.codeUnits.toSet();

/// Validate a Zcash transparent (t-) address.
bool isValidTransparentAddress(String address) {
  if (address.isEmpty) return false;
  const validPrefixes = ['t1', 't3', 'tm', 'tn'];
  if (!validPrefixes.any(address.startsWith)) return false;
  if (address.length < 26 || address.length > 36) return false;
  for (final code in address.codeUnits) {
    if (!_base58Set.contains(code)) return false;
  }
  return true;
}
