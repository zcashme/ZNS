# Changelog

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
