# ZNS - Zcash Name Service

> **[This is experimental software under active development. Not production ready.]**

ZNS maps human-readable names to Zcash Unified Addresses, claimed on-chain via shielded Orchard memos. It includes a marketplace for buying and selling names, with all actions authenticated by Ed25519 signatures.

## How it works

1. A user sends a shielded Orchard note to the ZNS registry address with a protocol memo.
2. The ZNS indexer scans the Zcash blockchain, trial-decrypts Orchard notes using the registry's incoming viewing key, validates the memo, and applies the action to a local SQLite database.
3. Registrations are **first-come-first-served** by block height. One name per address, one address per name.

## Protocol

All memos are UTF-8 strings in the 512-byte Orchard memo field.

| Action | Memo format | Auth |
|--------|------------|------|
| Claim | `ZNS:CLAIM:<name>:<ua>:<sig>` | Payment >= claim cost (FCFS) |
| List for sale | `ZNS:LIST:<name>:<price>:<nonce>:<sig>` | Ed25519 signature |
| Delist | `ZNS:DELIST:<name>:<nonce>:<sig>` | Ed25519 signature |
| Release | `ZNS:RELEASE:<name>:<nonce>:<sig>` | Ed25519 signature |
| Update address | `ZNS:UPDATE:<name>:<new_ua>:<nonce>:<sig>` | Ed25519 signature |
| Buy | `ZNS:BUY:<name>:<buyer_ua>:<sig>` | Payment >= listing price |
| Set pricing | `ZNS:SETPRICE:<count>:<p1>:...:<pN>:<nonce>:<sig>` | Ed25519 signature |

### Signatures

Admin actions (LIST, DELIST, RELEASE, UPDATE, SETPRICE) require an Ed25519 signature over a canonical payload:

- `LIST:<name>:<price>:<nonce>`
- `DELIST:<name>:<nonce>`
- `RELEASE:<name>:<nonce>`
- `UPDATE:<name>:<new_ua>:<nonce>`
- `SETPRICE:<count>:<p1>:...:<pN>:<nonce>`

The signature is base64-encoded and appended as the final field in the memo. Nonces are per-name and must be strictly increasing to prevent replay attacks. Signatures are stored in the database for independent verification.

### Name rules

- 1-62 characters
- Lowercase alphanumeric and hyphens only (`a-z`, `0-9`, `-`)
- No leading, trailing, or consecutive hyphens

## API

The indexer exposes a JSON-RPC 2.0 API on port 3000 with four read-only methods:

| Method | Description |
|--------|-------------|
| `resolve` | Look up a registration by name or by Zcash unified address |
| `list_for_sale` | Get all names currently listed for sale |
| `status` | Indexer sync height, admin pubkey, UIVK, counts, and pricing tiers |
| `events` | Query activity log with optional filters (name, action, since_height, limit, offset) |

See [openrpc.json](openrpc.json) for the full specification.

## Running

```sh
cargo run --release
```

Connects to lightwalletd and syncs blocks continuously. Defaults to `https://zec.rocks:443` for mainnet and `https://testnet.zec.rocks:443` for testnet. Override with `ZNS_LWD_URL`.
