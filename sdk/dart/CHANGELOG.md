# Changelog

## 0.5.2

- Fix: `resolveName` now normalizes the input to lowercase before querying the
  indexer, so `resolveName('Alice')` and `resolveName('alice')` are equivalent.
- Fix: all RPC calls now enforce a configurable timeout (default 10 s) via
  `RpcClient`, preventing indefinite hangs when the indexer is slow or
  unreachable. The `ZNS` factory accepts an optional `timeout` parameter to
  override the default.

## 0.5.1

- Fix: expose correct UIVK strings for testnet and mainnet networks.

## 0.5.0

- Initial public release.
- `ZNS` client with full read surface: `resolveName`, `resolveAddress`, `listAllRegistrations`, `isAvailable`, `listings`, `events`.
- Prepared actions (`prepareClaim`, `prepareList`, `prepareBuy`, `prepareUpdate`, `prepareDelist`, `prepareRelease`, `prepareSetPrice`) with sealed `PreparedAction` hierarchy for exhaustive switching.
- Ed25519 signature verification via `verifyEd25519`, `verifyRegistration`, `verifyListing`, `verifySovereignSignature`.
- ZIP-321 URI builder and parser (`buildZcashUri`, `parseZip321Uri`).
- Payload validation mirroring the indexer's `parse_memo` logic.
- Typed exceptions: `InvalidNameException`, `InvalidAddressException`, `ZnsRpcException`.
- Testnet and mainnet network configs with UIVK pinning via `verify()`.
