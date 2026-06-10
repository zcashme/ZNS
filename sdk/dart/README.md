# zcashname_sdk

Dart SDK for the Zcash Name System (ZNS).

ZNS maps human-readable names to Zcash shielded addresses. Names are registered on-chain via Orchard memos and indexed into a queryable API. This SDK mirrors the TypeScript SDK's surface — single `ZNS` class, no codegen, no consumer-side boilerplate.

## Install

```yaml
dependencies:
  zcashname_sdk:
    path: ../path/to/sdk/dart
```

## Quick start

```dart
import 'package:zcashname_sdk/zcashname_sdk.dart';

Future<void> main() async {
  final zns = ZNS(network: Network.testnet);
  await zns.verify(); // checks the indexer UIVK

  final reg = await zns.resolveName('alice');
  print(reg?.address);

  final available = await zns.isAvailable('myname');
  print('Available: $available');

  zns.close();
}
```

## Resolve a name

```dart
final reg = await zns.resolveName('alice');
// Registration(name: 'alice', address: 'utest1...', ...)
```

Returns `null` if the name is not registered.

## Reverse resolve

```dart
final results = await zns.resolveAddress('utest1...');
```

## Check availability

```dart
if (await zns.isAvailable('myname')) {
  // free to claim
}
```

## Name history

```dart
final history = await zns.events(EventsFilter(name: 'alice'));
for (final e in history.events) {
  // e.action is a ZnsAction enum; switch on it for type-safe handling.
  print('${e.action} at height ${e.height}');
}
```

Filter by action with the enum:

```dart
final claims = await zns.events(EventsFilter(action: ZnsAction.claim));
```

## Claim a name

Prepared actions return a `payload` to sign, plus a `complete(signature)` method that builds the memo and ZIP-321 URI.

```dart
final s = await zns.status();
final cost = zns.claimCost('alice'.length, s.pricing!);
final claim = zns.prepareClaim('alice', 'utest1abc...', cost!);

// 1. sign claim.payload with your Ed25519 key
final sig = base64.encode(await mySigner.sign(utf8.encode(claim.payload)));

// 2. produce a transaction-ready URI + memo
final action = claim.complete(sig);
print(action.uri);  // zcash:utest1...?amount=...&memo=...
```

## Marketplace

```dart
// List
final list = zns.prepareList('alice', 50000000, 'tm...', nonce);

// Buy
final buy = zns.prepareBuy('alice', buyerUa, price);

// Delist / Release / Update
final delist  = zns.prepareDelist('alice', nonce);
final release = zns.prepareRelease('alice', nonce);
final update  = zns.prepareUpdate('alice', newUa, nonce);
```

Each returned `Prepared*` carries the action fields and a `complete()` that produces the memo + `zcash:` URI for the wallet.

`PreparedAction` is a sealed type — you can exhaustively switch on subtypes:

```dart
final action = zns.prepareClaim('alice', ua, cost!);
final memoBody = switch (action) {
  PreparedClaim(:final name)   => 'claiming $name',
  PreparedList(:final price)   => 'listing for $price',
  PreparedDelist(:final name)  => 'delisting $name',
  PreparedUpdate(:final name)  => 'updating $name',
  PreparedBuy(:final price)    => 'buying for $price',
  PreparedRelease(:final name) => 'releasing $name',
  PreparedSetPrice()           => 'setting prices',
};
```

Invalid arguments throw typed exceptions: `InvalidNameException`, `InvalidAddressException`.

## Validation

Both `ZNS` and top-level functions are exported:

```dart
isValidName('alice');                             // true
isValidUnifiedAddress('utest1...');                // true
isValidTransparentAddress('tm...');                // true
validatePayload('CLAIM:alice:utest1...');          // PayloadValidationResult
```

`validatePayload` mirrors the indexer's `parse_memo` — same source of truth as the TS SDK.

## Signature verification

```dart
final ok = await zns.verifySignature(payload, signatureB64, pubkeyB64);
final regOk     = await zns.verifyRegistration(reg, s.adminPubkey);
final listingOk = await zns.verifyListing(listing, s.adminPubkey);
```

Returns `false` on any decode error or length mismatch; never throws.

## Custom endpoint

```dart
final zns = ZNS(url: Uri.parse('http://localhost:3000'));
```

Skip `verify()` if you trust the endpoint.
