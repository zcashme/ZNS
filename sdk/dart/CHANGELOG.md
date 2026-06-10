# Changelog

## 0.7.0

- BREAKING: sovereign signatures removed, matching the indexer (all actions
  are now strictly admin-signed). `Registration`, `Listing`, and `Event` no
  longer carry a `pubkey` field; `complete()` no longer accepts a
  `userPubkey` and never emits the `:<pubkey>` memo suffix;
  `verifyRegistration`/`verifyListing` verify strictly against the admin
  pubkey; `verifySovereignSignature` is renamed to `verifySignature`;
  `hashLeaf` matches the indexer's new Merkle leaf pre-image (no pubkey
  bytes).

## 0.6.0

- Feat: Merkle inclusion proofs. `resolveNameWithProof` returns a
  `RegistrationWithProof` carrying a `MerkleProof` against the indexer's
  committed state root, and `verifyProof` checks the binding offline by
  recomputing the BLAKE2b leaf/path (`hashLeaf` and `hashInternal` are also
  exported).
- Feat: lenient name input. All name-taking methods (`resolveName`,
  `resolveNameWithProof`, `isAvailable`, and every `prepare*` action) now
  normalize their input: trim, lowercase, and strip one trailing
  `.zcash`/`.zec` suffix (case-insensitive), so `Alice.zcash`, `aLice.Zec`,
  and `alice` are equivalent. The normalizer is exported as `normalizeName`.
- Names that are invalid after normalization resolve to `null` (or `false`
  from `isAvailable`) locally, without a server round trip; `prepare*`
  actions still throw `InvalidNameException`.

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
