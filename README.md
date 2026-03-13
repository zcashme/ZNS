# ZNS — Zcash Name Service

ZNS maps human-readable names to Zcash Unified Addresses, registered on-chain via shielded Orchard memos.

## How it works

1. A user sends a shielded Orchard note to the ZNS registry address with a memo in the format:

   ```
   zns:register:<name>:<unified-address>
   ```

2. The ZNS indexer scans the Zcash blockchain, trial-decrypts Orchard notes using the registry's incoming viewing key, and stores valid registrations in SQLite.

3. Registrations are **first-come-first-served** by block height and tx index. One name per address, one address per name.

## Name rules

- 1–63 characters
- Lowercase alphanumeric and hyphens only
- No leading, trailing, or consecutive hyphens

## gRPC API

The indexer exposes a gRPC endpoint for resolving names and addresses.

**Service:** `zns.v1.ZnsService`

```protobuf
rpc GetZnsRecord (ZnsQuery) returns (ZnsRecord);
```

**Forward lookup** (name → address):
```json
{ "name": "alice" }
```

**Reverse lookup** (address → name):
```json
{ "address": "u1..." }
```

**Response:**
```json
{ "name": "alice", "address": "u1..." }
```

Name input accepts `alice`, `alice.zec`, or `alice.zcash` — all resolve identically. Returns `NOT_FOUND` if no record exists.

## Running

```sh
cargo run --release
```

Requires a reachable lightwalletd instance (default: `light.zcash.me:443`).
