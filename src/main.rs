// ZNS Indexer
//
// 1. Load config (IVK, lightwalletd URL, sqlite path, grpc addr, start height)
// 2. Connect to sqlite, run migrations
// 3. Load all registrations from DB into two HashMaps (name → record, address → record)
//    wrapped in Arc<RwLock> so scanner and gRPC server share it
// 4. Parse the registry IVK from bech32
// 5. Spawn scanner task:
//    - resume from last scanned height in DB (or start_height if first run)
//    - stream CompactBlocks from lightwalletd
//    - for each Orchard action in each block:
//        - try_compact_note_decryption(ivk, action)
//        - if match: fetch full tx via GetTransaction, try_note_decryption for memo
//        - parse memo: "zns:register:<name>:<ua>"
//        - if valid: insert into DB (INSERT OR IGNORE on name = first-come-first-served)
//                    and update in-memory index
//    - after each block: persist last_scanned_height to DB
// 6. Start tonic gRPC server:
//    - GetZnsRecord(name) → lookup by_name HashMap → ZnsResponse
//    - GetZnsRecord(address) → lookup by_address HashMap → ZnsResponse
//    - not found → gRPC NOT_FOUND status

fn main() {
    todo!()
}
