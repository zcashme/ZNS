# ZNS — Zcash Name Service (Testnet)

> **This is experimental software under active development. Testnet only — not production ready.**

ZNS maps human-readable names to Zcash Unified Addresses, registered on-chain via shielded Orchard memos. It includes a marketplace for buying and selling names, with admin actions authenticated by Ed25519 signatures.

## How it works

1. A user sends a shielded Orchard note to the ZNS registry address with a protocol memo.
2. The ZNS indexer scans the Zcash testnet blockchain, trial-decrypts Orchard notes using the registry's incoming viewing key, validates the memo, and applies the action to a local SQLite database.
3. Registrations are **first-come-first-served** by block height. One name per address, one address per name.

## Protocol

All memos are UTF-8 strings in the 512-byte Orchard memo field.

| Action | Memo format | Auth |
|--------|------------|------|
| Register | `ZNS:REGISTER:<name>:<ua>` | None (FCFS) |
| List for sale | `ZNS:LIST:<name>:<price>:<nonce>:<sig>` | Ed25519 signature |
| Delist | `ZNS:DELIST:<name>:<nonce>:<sig>` | Ed25519 signature |
| Update address | `ZNS:UPDATE:<name>:<new_ua>:<nonce>:<sig>` | Ed25519 signature |
| Buy | `ZNS:BUY:<name>:<buyer_ua>` | Payment >= listing price |

### Signatures

Admin actions (LIST, DELIST, UPDATE) require an Ed25519 signature over a canonical payload:

- `LIST:<name>:<price>:<nonce>`
- `DELIST:<name>:<nonce>`
- `UPDATE:<name>:<new_ua>:<nonce>`

The signature is base64-encoded and appended as the final field in the memo. Nonces are per-name and must be strictly increasing to prevent replay attacks. Signatures are stored in the database for independent verification.

### Name rules

- 1–62 characters
- Lowercase alphanumeric and hyphens only (`a-z`, `0-9`, `-`)
- No leading, trailing, or consecutive hyphens

## Status

- All 5 actions (REGISTER, LIST, BUY, UPDATE, DELIST) tested end-to-end on testnet
- No gRPC API yet
- No automated tests yet
- Signing key is a throwaway test key

## Running

```sh
cargo run --release
```

Connects to lightwalletd at `testnet.zec.rocks:443` and syncs blocks continuously.
