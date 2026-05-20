import 'dart:convert';

import 'package:cryptography/cryptography.dart';

/// Verify an Ed25519 signature over [payload] (a UTF-8 string).
///
/// All inputs are base64-encoded. Returns `false` on any decode error or
/// length mismatch; never throws.
Future<bool> verifyEd25519(
  String payload,
  String signatureBase64,
  String pubkeyBase64,
) async {
  try {
    final sigBytes = base64.decode(signatureBase64);
    final pkBytes = base64.decode(pubkeyBase64);
    if (sigBytes.length != 64 || pkBytes.length != 32) return false;

    final algo = Ed25519();
    final pubkey =
        SimplePublicKey(pkBytes, type: KeyPairType.ed25519);
    final signature = Signature(sigBytes, publicKey: pubkey);
    return await algo.verify(utf8.encode(payload), signature: signature);
  } catch (_) {
    return false;
  }
}
