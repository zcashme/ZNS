import 'validation.dart';

// ---------------------------------------------------------------------------
// Signing payloads
// ---------------------------------------------------------------------------

/// Build the signing payload for a CLAIM action.
String claimPayload(String name, String ua) => 'CLAIM:$name:$ua';

/// Build the signing payload for a BUY action.
String buyPayload(String name, String buyerUa) => 'BUY:$name:$buyerUa';

/// Build the signing payload for a LIST action.
String listPayload(String name, int price, int nonce) =>
    'LIST:$name:$price:$nonce';

/// Build the signing payload for a DELIST action.
String delistPayload(String name, int nonce) => 'DELIST:$name:$nonce';

/// Build the signing payload for an UPDATE action.
String updatePayload(String name, String newUa, int nonce) =>
    'UPDATE:$name:$newUa:$nonce';

/// Build the signing payload for a SETPRICE action.
String setPricePayload(List<int> prices, int nonce) {
  final joined = prices.join(':');
  return 'SETPRICE:${prices.length}:$joined:$nonce';
}

// ---------------------------------------------------------------------------
// Memo builders
// ---------------------------------------------------------------------------

void _requireValid(String name) {
  if (!isValidName(name)) {
    throw ArgumentError('Invalid name: $name');
  }
}

/// Build the memo for a CLAIM transaction.
String buildClaimMemo(String name, String ua, String signature) {
  _requireValid(name);
  return 'ZNS:CLAIM:$name:$ua:$signature';
}

/// Build the memo for a BUY transaction.
String buildBuyMemo(String name, String buyerUa, String signature) {
  _requireValid(name);
  return 'ZNS:BUY:$name:$buyerUa:$signature';
}

/// Build the memo for a LIST transaction.
String buildListMemo(String name, int price, int nonce, String signature) {
  _requireValid(name);
  return 'ZNS:LIST:$name:$price:$nonce:$signature';
}

/// Build the memo for a DELIST transaction.
String buildDelistMemo(String name, int nonce, String signature) {
  _requireValid(name);
  return 'ZNS:DELIST:$name:$nonce:$signature';
}

/// Build the memo for an UPDATE transaction.
String buildUpdateMemo(
    String name, String newUa, int nonce, String signature) {
  _requireValid(name);
  return 'ZNS:UPDATE:$name:$newUa:$nonce:$signature';
}

/// Build the memo for a SETPRICE transaction.
String buildSetPriceMemo(List<int> prices, int nonce, String signature) {
  final joined = prices.join(':');
  return 'ZNS:SETPRICE:${prices.length}:$joined:$nonce:$signature';
}
