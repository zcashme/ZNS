// ZNS Indexer
//
// Scans confirmed blocks, trial-decrypts incoming Orchard notes,
// and writes ZNS registrations and listings to SQLite.

use std::time::Duration;

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use orchard::keys::PreparedIncomingViewingKey;
use orchard::note_encryption::{CompactAction, OrchardDomain};
use rusqlite::Connection;
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;
use zcash_client_backend::proto::service::{BlockId, BlockRange, ChainSpec, TxFilter};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::consensus::BranchId;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, Network};
use zip32::Scope;

// ── Config ───────────────────────────────────────────────────────────────────

const LWD_URL: &str = "https://testnet.zec.rocks:443";
const DB_PATH: &str = "zns.db";
const BIRTHDAY: u64 = 3_901_175;
const UFVK_STR: &str = "uviewtest1h075nwxk0s66hyw0gmy5l2gmr37eahe9ewzgu2lff90rc85mazdhc66udklmd2p7cqm3mg2up8487pusvh78dh89y7mzlfgdl57tncqxrwshhc2kf26js0ymdwd476r0v7qn6es0etgjeg3g0y3pngvvf8zdawg6nlwca7jqy2fv82rc5skauw05ptfuf5twj67u0gzzvhakvkxpvx8rvf2rlh5yh560fdr6p28368kjxez5gu9azam5cm08ygre0uqwhvrkz7sr7ld0nyv05a0xrqeffdvhujafq3ke860skmxzshtjlrlew72vycu54pkgjtyp2phr6fmmkqlxvsan54jh7mc59r7kazgwwrcfnmqjm5pt40kjeafp6lwtx2lp4gm5pzg9c9ugphrsclfnz50spnsrersk34ht5mrevw9yvspkfjg9mjhusc588d855hdch0z82pr5fhkvaz3p4cmjlxujxqw2w20tpgyt3rzkwuuwl4r7";
const POLL_INTERVAL: Duration = Duration::from_secs(10);

// Placeholder — replace with real pubkey from tools/zns-keygen
const ZNS_LISTING_PUBKEY: [u8; 32] = [0u8; 32];

// ── Types ────────────────────────────────────────────────────────────────────

struct Listing {
    price: u64,
}

enum MemoAction {
    Register { name: String, ua: String },
    List { name: String, price: u64, signature: Vec<u8> },
    Buy { name: String, buyer_ua: String },
}

// ── Database ─────────────────────────────────────────────────────────────────

fn open_db(path: &str) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS registrations (
            name    TEXT PRIMARY KEY,
            ua      TEXT NOT NULL UNIQUE,
            txid    TEXT NOT NULL,
            height  INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS listings (
            name    TEXT PRIMARY KEY REFERENCES registrations(name),
            price   INTEGER NOT NULL,
            txid    TEXT NOT NULL,
            height  INTEGER NOT NULL
        );",
    )?;
    Ok(conn)
}

fn is_registered(db: &Connection, name: &str, ua: &str) -> bool {
    db.query_row(
        "SELECT 1 FROM registrations WHERE name = ?1 OR ua = ?2",
        rusqlite::params![name, ua],
        |_| Ok(()),
    )
    .is_ok()
}

fn name_exists(db: &Connection, name: &str) -> bool {
    db.query_row(
        "SELECT 1 FROM registrations WHERE name = ?1",
        [name],
        |_| Ok(()),
    )
    .is_ok()
}

fn create_registration(
    db: &Connection,
    name: &str,
    ua: &str,
    txid: &[u8],
    height: u64,
) -> rusqlite::Result<()> {
    let txid_hex = txid.iter().rev().map(|b| format!("{b:02x}")).collect::<String>();
    db.execute(
        "INSERT OR IGNORE INTO registrations (name, ua, txid, height) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![name, ua, txid_hex, height as i64],
    )?;
    Ok(())
}

fn create_listing(
    db: &Connection,
    name: &str,
    price: u64,
    txid: &[u8],
    height: u64,
) -> rusqlite::Result<()> {
    let txid_hex = txid.iter().rev().map(|b| format!("{b:02x}")).collect::<String>();
    db.execute(
        "INSERT OR REPLACE INTO listings (name, price, txid, height) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![name, price as i64, txid_hex, height as i64],
    )?;
    Ok(())
}

fn get_listing(db: &Connection, name: &str) -> Option<Listing> {
    db.query_row(
        "SELECT price FROM listings WHERE name = ?1",
        [name],
        |row| Ok(Listing { price: row.get::<_, i64>(0)? as u64 }),
    )
    .ok()
}

fn process_buy(
    db: &Connection,
    name: &str,
    new_ua: &str,
    txid: &[u8],
    height: u64,
) -> rusqlite::Result<()> {
    let txid_hex = txid.iter().rev().map(|b| format!("{b:02x}")).collect::<String>();
    let tx = db.unchecked_transaction()?;
    tx.execute(
        "UPDATE registrations SET ua = ?1, txid = ?2, height = ?3 WHERE name = ?4",
        rusqlite::params![new_ua, txid_hex, height as i64, name],
    )?;
    tx.execute("DELETE FROM listings WHERE name = ?1", [name])?;
    tx.commit()
}

// ── Memo parsing ─────────────────────────────────────────────────────────────

fn validate_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 62
        && !name.starts_with('-')
        && !name.ends_with('-')
        && !name.contains("--")
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

fn parse_memo(memo: &[u8; 512]) -> Option<MemoAction> {
    let s = std::str::from_utf8(memo).ok()?;
    let s = s.trim_end_matches('\0');

    if let Some(rest) = s.strip_prefix("ZNS:REGISTER:") {
        let parts: Vec<&str> = rest.splitn(2, ':').collect();
        if parts.len() != 2 { return None; }
        let (name, ua) = (parts[0], parts[1]);
        if !validate_name(name) || ua.is_empty() { return None; }
        return Some(MemoAction::Register { name: name.into(), ua: ua.into() });
    }

    if let Some(rest) = s.strip_prefix("ZNS:LIST:") {
        let parts: Vec<&str> = rest.splitn(3, ':').collect();
        if parts.len() != 3 { return None; }
        let (name, price_str, sig_b64) = (parts[0], parts[1], parts[2]);
        if !validate_name(name) { return None; }
        let price: u64 = price_str.parse().ok()?;
        let signature = base64::engine::general_purpose::STANDARD.decode(sig_b64).ok()?;
        return Some(MemoAction::List { name: name.into(), price, signature });
    }

    if let Some(rest) = s.strip_prefix("ZNS:BUY:") {
        let parts: Vec<&str> = rest.splitn(2, ':').collect();
        if parts.len() != 2 { return None; }
        let (name, buyer_ua) = (parts[0], parts[1]);
        if !validate_name(name) || buyer_ua.is_empty() { return None; }
        return Some(MemoAction::Buy { name: name.into(), buyer_ua: buyer_ua.into() });
    }

    None
}

// ── Signature verification ──────────────────────────────────────────────────

fn verify_list_signature(name: &str, price: u64, sig_bytes: &[u8]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(&ZNS_LISTING_PUBKEY) else { return false };
    verify_signature_with_key(&vk, name, price, sig_bytes)
}

fn verify_signature_with_key(vk: &VerifyingKey, name: &str, price: u64, sig_bytes: &[u8]) -> bool {
    let payload = format!("{name}:{price}");
    let Ok(sig) = Signature::from_slice(sig_bytes) else { return false };
    vk.verify(payload.as_bytes(), &sig).is_ok()
}

// ── Block scanner ─────────────────────────────────────────────────────────────

type Client = CompactTxStreamerClient<tonic::transport::Channel>;

/// Scan one block: compact-decrypt to find matching txids, fetch full txs for memos.
async fn scan_block(
    client: &mut Client,
    db: &Connection,
    pivk: &PreparedIncomingViewingKey,
    block: &zcash_client_backend::proto::compact_formats::CompactBlock,
) {
    let height = block.height;

    // Phase 1: compact trial decryption — no network I/O
    let candidates: Vec<_> = block.vtx.iter()
        .flat_map(|tx| tx.actions.iter()
            .filter_map(|a| CompactAction::try_from(a).ok().map(|ca| (ca, tx.hash.clone()))))
        .collect();
    if candidates.is_empty() { return; }

    let pairs: Vec<_> = candidates.iter()
        .map(|(ca, _)| (OrchardDomain::for_compact_action(ca), ca.clone()))
        .collect();
    let results = zcash_note_encryption::batch::try_compact_note_decryption(
        std::slice::from_ref(pivk), &pairs,
    );
    let matched: std::collections::HashSet<_> = results.iter().zip(&candidates)
        .filter_map(|(r, (_, txid))| r.as_ref().map(|_| txid.clone()))
        .collect();

    // Phase 2: fetch full tx, decrypt memos, process actions
    let branch = BranchId::for_height(&Network::TestNetwork, BlockHeight::from_u32(height as u32));
    for txid in &matched {
        let Ok(data) = client.get_transaction(TxFilter { block: None, index: 0, hash: txid.clone() })
            .await.map(|r| r.into_inner().data) else { continue };
        let Ok(tx) = Transaction::read(&data[..], branch) else { continue };
        let Some(bundle) = tx.orchard_bundle() else { continue };

        for action in bundle.actions() {
            let domain = OrchardDomain::for_action(action);
            let Some((note, _, memo)) = zcash_note_encryption::try_note_decryption(&domain, pivk, action) else { continue };
            let Some(memo_action) = parse_memo(&memo) else { continue };

            match memo_action {
                MemoAction::Register { name, ua } => {
                    if is_registered(db, &name, &ua) { continue; }
                    match create_registration(db, &name, &ua, txid, height) {
                        Ok(()) => println!("Registered: {name} → {ua} (height {height})"),
                        Err(e) => eprintln!("DB error (register): {e}"),
                    }
                }
                MemoAction::List { name, price, signature } => {
                    if !verify_list_signature(&name, price, &signature) {
                        eprintln!("Invalid LIST signature for {name}");
                        continue;
                    }
                    if !name_exists(db, &name) {
                        eprintln!("LIST for unregistered name {name}");
                        continue;
                    }
                    match create_listing(db, &name, price, txid, height) {
                        Ok(()) => println!("Listed: {name} for {price} zats (height {height})"),
                        Err(e) => eprintln!("DB error (list): {e}"),
                    }
                }
                MemoAction::Buy { name, buyer_ua } => {
                    let Some(listing) = get_listing(db, &name) else {
                        eprintln!("BUY for unlisted name {name}");
                        continue;
                    };
                    let note_value: u64 = note.value().inner();
                    if note_value < listing.price {
                        eprintln!("BUY underpayment for {name}: {note_value} < {}", listing.price);
                        continue;
                    }
                    match process_buy(db, &name, &buyer_ua, txid, height) {
                        Ok(()) => println!("Sold: {name} → {buyer_ua} for {} zats (height {height})", listing.price),
                        Err(e) => eprintln!("DB error (buy): {e}"),
                    }
                }
            }
        }
    }
}

async fn run_block_sync(mut client: Client, db: &Connection, ufvk: &UnifiedFullViewingKey) {
    let orchard_fvk = ufvk.orchard().expect("UFVK has no Orchard key");
    let pivk = PreparedIncomingViewingKey::new(&orchard_fvk.to_ivk(Scope::External));
    let mut last_scanned = BIRTHDAY - 100;

    loop {
        let Ok(tip) = client.get_latest_block(ChainSpec {}).await.map(|r| r.into_inner().height) else {
            tokio::time::sleep(POLL_INTERVAL).await; continue;
        };
        if last_scanned >= tip { tokio::time::sleep(POLL_INTERVAL).await; continue; }

        let start = last_scanned + 1;
        println!("Scanning {start}..={tip}");

        let range = BlockRange {
            start: Some(BlockId { height: start, hash: vec![] }),
            end: Some(BlockId { height: tip, hash: vec![] }),
        };
        let Ok(mut stream) = client.get_block_range(range).await.map(|r| r.into_inner()) else {
            tokio::time::sleep(POLL_INTERVAL).await; continue;
        };

        while let Ok(Some(block)) = stream.message().await {
            scan_block(&mut client, db, &pivk, &block).await;
            last_scanned = block.height;
        }
        println!("Synced to {tip}.");
    }
}

// ── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ufvk = UnifiedFullViewingKey::decode(&Network::TestNetwork, UFVK_STR)
        .map_err(|e| format!("Failed to decode UFVK: {e}"))?;

    let scanner_db = open_db(DB_PATH)?;

    println!("Connecting to {LWD_URL}...");
    let client = CompactTxStreamerClient::connect(LWD_URL).await?;
    run_block_sync(client, &scanner_db, &ufvk).await;

    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn make_memo(s: &str) -> [u8; 512] {
        let mut buf = [0u8; 512];
        buf[..s.len()].copy_from_slice(s.as_bytes());
        buf
    }

    fn test_db() -> Connection {
        open_db(":memory:").unwrap()
    }

    fn test_txid() -> Vec<u8> {
        vec![0xab; 32]
    }

    // ── Name validation ──────────────────────────────────────────────────────

    #[test]
    fn name_valid_lowercase_digits_hyphens() {
        assert!(validate_name("alice-99"));
    }

    #[test]
    fn name_rejected_uppercase() {
        assert!(!validate_name("Alice"));
    }

    #[test]
    fn name_rejected_leading_hyphen() {
        assert!(!validate_name("-alice"));
    }

    #[test]
    fn name_rejected_trailing_hyphen() {
        assert!(!validate_name("alice-"));
    }

    #[test]
    fn name_rejected_double_hyphen() {
        assert!(!validate_name("al--ice"));
    }

    #[test]
    fn name_rejected_too_long() {
        let long = "a".repeat(63);
        assert!(!validate_name(&long));
    }

    #[test]
    fn name_rejected_empty() {
        assert!(!validate_name(""));
    }

    // ── Memo parsing ─────────────────────────────────────────────────────────

    #[test]
    fn parse_register_valid() {
        let memo = make_memo("ZNS:REGISTER:alice:utest1abc");
        let action = parse_memo(&memo).unwrap();
        let MemoAction::Register { name, ua } = action else { panic!("expected Register") };
        assert_eq!(name, "alice");
        assert_eq!(ua, "utest1abc");
    }

    #[test]
    fn parse_buy_valid() {
        let memo = make_memo("ZNS:BUY:alice:utest1buyer");
        let action = parse_memo(&memo).unwrap();
        let MemoAction::Buy { name, buyer_ua } = action else { panic!("expected Buy") };
        assert_eq!(name, "alice");
        assert_eq!(buyer_ua, "utest1buyer");
    }

    #[test]
    fn parse_list_valid() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let payload = "alice:100000";
        let sig = sk.sign(payload.as_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
        let memo_str = format!("ZNS:LIST:alice:100000:{sig_b64}");
        let memo = make_memo(&memo_str);
        let action = parse_memo(&memo).unwrap();
        let MemoAction::List { name, price, signature } = action else { panic!("expected List") };
        assert_eq!(name, "alice");
        assert_eq!(price, 100000);
        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn parse_unknown_prefix_ignored() {
        let memo = make_memo("ZNS:TRANSFER:alice:utest1abc");
        assert!(parse_memo(&memo).is_none());
    }

    #[test]
    fn parse_malformed_memo_ignored() {
        let memo = make_memo("not a zns memo at all");
        assert!(parse_memo(&memo).is_none());
    }

    // ── Signature verification ───────────────────────────────────────────────

    #[test]
    fn verify_valid_signature() {
        let sk = SigningKey::from_bytes(&[2u8; 32]);
        let vk = sk.verifying_key();
        let payload = "alice:100000";
        let sig = sk.sign(payload.as_bytes());
        assert!(verify_signature_with_key(&vk, "alice", 100000, &sig.to_bytes()));
    }

    #[test]
    fn verify_invalid_signature_rejected() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let vk = sk.verifying_key();
        let bad_sig = [0u8; 64];
        assert!(!verify_signature_with_key(&vk, "alice", 100000, &bad_sig));
    }

    #[test]
    fn verify_tampered_payload_rejected() {
        let sk = SigningKey::from_bytes(&[4u8; 32]);
        let vk = sk.verifying_key();
        let sig = sk.sign(b"alice:100000");
        // Verify against different price
        assert!(!verify_signature_with_key(&vk, "alice", 200000, &sig.to_bytes()));
    }

    // ── Database operations ──────────────────────────────────────────────────

    #[test]
    fn db_create_registration_succeeds() {
        let db = test_db();
        create_registration(&db, "alice", "utest1alice", &test_txid(), 100).unwrap();
        assert!(name_exists(&db, "alice"));
    }

    #[test]
    fn db_duplicate_name_rejected() {
        let db = test_db();
        create_registration(&db, "alice", "utest1alice", &test_txid(), 100).unwrap();
        create_registration(&db, "alice", "utest1other", &test_txid(), 101).unwrap();
        // Should still be the original UA
        let ua: String = db.query_row(
            "SELECT ua FROM registrations WHERE name = 'alice'", [], |r| r.get(0),
        ).unwrap();
        assert_eq!(ua, "utest1alice");
    }

    #[test]
    fn db_duplicate_ua_rejected() {
        let db = test_db();
        create_registration(&db, "alice", "utest1same", &test_txid(), 100).unwrap();
        create_registration(&db, "bob", "utest1same", &test_txid(), 101).unwrap();
        assert!(!name_exists(&db, "bob"));
    }

    #[test]
    fn db_create_listing_succeeds() {
        let db = test_db();
        create_registration(&db, "alice", "utest1alice", &test_txid(), 100).unwrap();
        create_listing(&db, "alice", 500_000, &test_txid(), 101).unwrap();
        let listing = get_listing(&db, "alice").unwrap();
        assert_eq!(listing.price, 500_000);
    }

    #[test]
    fn db_get_listing_returns_none_for_unlisted() {
        let db = test_db();
        create_registration(&db, "alice", "utest1alice", &test_txid(), 100).unwrap();
        assert!(get_listing(&db, "alice").is_none());
    }

    #[test]
    fn db_process_buy_transfers_ownership() {
        let db = test_db();
        create_registration(&db, "alice", "utest1seller", &test_txid(), 100).unwrap();
        create_listing(&db, "alice", 500_000, &test_txid(), 101).unwrap();
        process_buy(&db, "alice", "utest1buyer", &test_txid(), 102).unwrap();
        let ua: String = db.query_row(
            "SELECT ua FROM registrations WHERE name = 'alice'", [], |r| r.get(0),
        ).unwrap();
        assert_eq!(ua, "utest1buyer");
    }

    #[test]
    fn db_process_buy_deletes_listing() {
        let db = test_db();
        create_registration(&db, "alice", "utest1seller", &test_txid(), 100).unwrap();
        create_listing(&db, "alice", 500_000, &test_txid(), 101).unwrap();
        process_buy(&db, "alice", "utest1buyer", &test_txid(), 102).unwrap();
        assert!(get_listing(&db, "alice").is_none());
    }
}
