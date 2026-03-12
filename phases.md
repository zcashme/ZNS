# ZNS Indexer — Build Plan

## Architecture

```
lightwalletd (gRPC)
      │
      │  CompactBlocks (streaming)
      ▼
  Scanner
      │
      ├── for each CompactBlock:
      │     ├── for each Orchard action:
      │     │     ├── try_compact_note_decryption(orchard_ivk, action)
      │     │     └── if match → fetch full tx → try_note_decryption → memo bytes
      │     └── update last_scanned_height
      │
      ▼
  Memo Parser
      │  "zns:register:<name>:<ua>"
      ▼
   SQLite
      ├── registrations(name, address, block_height, tx_index)
      └── scan_state(last_height)
      │
      ▼  (loaded into memory at startup)
  Arc<RwLock<HashMap>> (name→record, address→record)
      │
      ▼
  tonic gRPC Server
      └── GetZnsRecord(name | address) → ZnsResponse
```

## Project Structure

```
src/
├── main.rs          # startup, load IVK from config, spawn scanner + gRPC server
├── scanner.rs       # streams CompactBlocks from lightwalletd, drives decryption
├── decrypt.rs       # try_compact_note_decryption, fetch full tx, try_note_decryption
├── parser.rs        # parse memo → zns:register:<name>:<ua>
├── db.rs            # sqlx sqlite: store/query registrations, scan state
└── server.rs        # tonic gRPC: GetZnsRecord handler

proto/
└── zns.proto        # ZnsService definition
build.rs             # compile proto with tonic-build
```

---

## Phase 1 — Scaffold

1. Fill out `Cargo.toml` with all dependencies
2. Write `proto/zns.proto` (ZnsService, ZnsRequest, ZnsResponse)
3. Write `build.rs` to compile proto with `tonic-build`
4. Stub `server.rs` — tonic service that returns `UNIMPLEMENTED`
5. Wire `main.rs` to start the gRPC server and verify it boots

## Phase 2 — Database

6. Write `db.rs` — connect to sqlite with `sqlx`
7. Write migration: `registrations(name TEXT, address TEXT, block_height INTEGER, tx_index INTEGER)`
8. Write migration: `scan_state(last_height INTEGER)`
9. Implement `db::insert_registration` (INSERT OR IGNORE on name)
10. Implement `db::get_last_height` / `db::set_last_height`
11. Implement `db::load_all` — load into two `HashMap`s at startup (name→record, address→record)

## Phase 3 — lightwalletd Client

12. Add lightwalletd proto types (from `zcash_client_backend` or vendor the proto)
13. Write `scanner.rs` — connect to lightwalletd via gRPC
14. Implement `get_latest_height` call
15. Implement `stream_compact_blocks(start, end)` — iterate `CompactBlock`s
16. Implement `fetch_full_tx(txid)` — `GetTransaction` call for matched outputs

## Phase 4 — Decryption

17. Parse the registry IVK from config/env (bech32 encoded `ivk`)
18. Write `decrypt.rs` — `try_compact_note_decryption` on each Orchard action
19. On match: call `fetch_full_tx`, then `try_note_decryption` for full memo bytes
20. Return the 512-byte memo

## Phase 5 — Memo Parser

21. Write `parser.rs` — strip trailing null bytes from memo
22. Parse `zns:register:<name>:<ua>` format
23. Validate the `ua` is a valid Zcash unified address
24. Validate the `name` format (e.g. `alice.zec`)

## Phase 6 — Wire It Up

25. In `scanner.rs`: for each matched + parsed memo → call `db::insert_registration`
26. Update `scan_state` after each block
27. In `main.rs`: load `HashMap`s from DB at startup, wrap in `Arc<RwLock<...>>`
28. Implement `GetZnsRecord` in `server.rs` — forward + reverse lookup from the `HashMap`
29. Spawn scanner loop + gRPC server as concurrent tokio tasks

## Phase 7 — Polish

30. Config struct (lightwalletd URL, IVK, sqlite path, gRPC listen addr, start height)
31. Logging with `tracing`
32. Graceful shutdown on SIGTERM
