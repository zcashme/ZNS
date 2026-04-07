# zcashname_sdk

Dart SDK for the Zcash Name System (ZNS) JSON-RPC API.

ZNS maps human-readable names to Zcash shielded addresses. Names are registered on-chain via Orchard memos and indexed into a queryable API. This SDK talks to that API.

## Installation

Add to your `pubspec.yaml`:

```yaml
dependencies:
  zcashname_sdk:
    path: ../path/to/sdk/dart
```

## Quick start

```dart
import 'package:zcashname_sdk/zcashname_sdk.dart';

void main() async {
  final client = await ZnsClient.create();

  // Resolve a name
  final result = await client.resolveName('alice');
  print(result?.address);

  // Check availability
  final available = await client.isAvailable('myname');
  print('Available: $available');

  client.dispose();
}
```

## Resolve a name

The primary use case. A wallet has a name, needs an address.

```dart
final result = await client.resolveName('alice');
// ResolveResult(name: 'alice', address: 'utest1...', ...)
```

Returns `null` if the name is not registered.

## Reverse resolve

A wallet or explorer has an address, wants to show the name.

```dart
final results = await client.resolveAddress('utest1...');
// [ResolveResult(name: 'alice', ...)]
```

## Check availability

```dart
if (await client.isAvailable('myname')) {
  // name is not registered
}
```

## Name history

```dart
final history = await client.events(EventsFilter(name: 'alice'));
for (final event in history.events) {
  print('${event.action} at height ${event.height}');
}
```

## Register a name

Registration is a two-step process: build the memo, then send a Zcash transaction with that memo and the correct payment amount.

```dart
final name = 'alice';
final ua = 'utest1abc...';

// 1. Build the memo
final memo = buildClaimMemo(name, ua, signature);

// 2. Get the cost
final s = await client.status();
final cost = claimCost(s.pricing!.tiers, name.length);

// 3. Build a payment URI
final uri = buildZcashUri(ua, amount: '0.75', memo: memo);
```

## Marketplace actions

### List a name for sale

```dart
final nonce = (await client.getNonce('alice'))! + 1;
final payload = listPayload('alice', 50000000, nonce);
final sig = sign(payload); // your Ed25519 signing logic
final memo = buildListMemo('alice', 50000000, nonce, sig);
```

### Buy a listed name

```dart
final memo = buildBuyMemo('alice', 'utest1buyer...', signature);
```

### Delist / Update

```dart
final nonce = (await client.getNonce('alice'))! + 1;
final memo = buildDelistMemo('alice', nonce, signature);
final memo = buildUpdateMemo('alice', 'utest1new...', nonce, signature);
```

## Name validation

Names must be 1-62 characters. Lowercase letters, digits, and hyphens only. No leading/trailing hyphens, no double hyphens.

```dart
isValidName('alice');     // true
isValidName('my-name');   // true
isValidName('Alice');     // false (uppercase)
isValidName('my--name');  // false (double hyphen)
isValidName('-name');     // false (leading hyphen)
```

## Custom endpoint

```dart
final client = await ZnsClient.create(url: 'http://localhost:3000');
```

Skip UIVK verification if you trust the endpoint:

```dart
final client = await ZnsClient.create(
  url: 'http://localhost:3000',
  skipVerify: true,
);
```
