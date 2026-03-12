# ZNS Indexer API

## Overview

The ZNS indexer exposes a gRPC interface for resolving Zcash Name Service records.
Names are registered as Orchard shielded memos sent to a known registry address,
using the format `zns:register:<name>:<ua>`.

The indexer decrypts memos using the registry's published incoming viewing key (IVK),
indexes all valid registrations (first-come-first-served by block height + tx index),
and serves them via gRPC.

---

## Service: ZnsService

### RPC: GetZnsRecord

Resolves a ZNS record by name or by Unified Address. A single call handles both
forward lookup (name → address) and reverse lookup (address → name).

```protobuf
service ZnsService {
  rpc GetZnsRecord(ZnsRequest) returns (ZnsResponse);
}

message ZnsRequest {
  oneof identifier {
    string name    = 1;  // e.g. "alice.zec"
    string address = 2;  // e.g. "ua1..."
  }
}

message ZnsResponse {
  string name         = 1;
  string address      = 2;
  uint64 block_height = 3;  // block at which the name was registered
}
```

#### Behavior

- If `name` is provided: returns the UA registered to that name.
- If `address` is provided: returns the name registered to that UA.
- If no record is found: returns a gRPC `NOT_FOUND` status.
- Name matching is case-insensitive.
- First-come-first-served: only the registration at the lowest block height
  (and lowest tx index within that block) is canonical.

---

## Planned

- `GetZnsProof(ZnsRequest) → ZnsProof` — merkle inclusion proof for trustless verification.
