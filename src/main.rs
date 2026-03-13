// ZNS Indexer v1
//
// A single-loop async service that scans the Zcash blockchain for name
// registration memos, validates them, and stores them in SQLite.

use std::time::Duration;

use orchard::keys::PreparedIncomingViewingKey;
use orchard::note_encryption::OrchardDomain;
use rusqlite::Connection;
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;
use zcash_client_backend::proto::service::{BlockId, BlockRange, ChainSpec, Empty, TxFilter};
use zcash_keys::keys::UnifiedIncomingViewingKey;
use zcash_primitives::consensus::BranchId;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, Network};

// ── Config ───────────────────────────────────────────────────────────────────

const LWD_URL: &str = "https://light.zcash.me:443";
const DB_PATH: &str = "zns.db";
const BIRTHDAY: u64 = 3_265_357;
const UIVK_STR: &str = "uivk1cpxzaa8rck580qfekjd3xma32zzk4mwm0p4c99qglpy4atgw74up0lexqvz5tq2wwj7s980c8fe9s98x7g9t9l603pjj6rsp44ufdj6dh0u3d28xm8rmcjdlej40unnvjrwtex45er8uxy3jk6tt22gu9a36t546kplsy280qq92ssz4sscev8529k347r8v2x3xzduuldjdltjjjy02sgv59hgjx2fud6u6y70nvu6g3h9p4n20gtcmmhjwsvqv2ykr2jlc3ert3qa4n99d7p0mg8g743jm5y96frmnu4aheyh6wf3wh9g4hz8jhy70s9xda9rmyg0aqdnec44j84hwjwxar9";
const POLL_INTERVAL: Duration = Duration::from_secs(10);

// ── Database ─────────────────────────────────────────────────────────────────

fn open_db() -> rusqlite::Result<Connection> {
    let conn = Connection::open(DB_PATH)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS registrations (
            name    TEXT PRIMARY KEY,
            ua      TEXT NOT NULL,
            txid    BLOB NOT NULL,
            height  INTEGER NOT NULL
        );",
    )?;
    Ok(conn)
}

fn name_exists(db: &Connection, name: &str) -> bool {
    db.query_row(
        "SELECT 1 FROM registrations WHERE name = ?1",
        rusqlite::params![name],
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
    db.execute(
        "INSERT OR IGNORE INTO registrations (name, ua, txid, height) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![name, ua, txid, height as i64],
    )?;
    Ok(())
}

// ── Memo parsing ─────────────────────────────────────────────────────────────

struct Registration {
    name: String,
    ua: String,
}

/// Parse a ZNS registration memo. Returns None for non-ZNS memos.
/// Format: zns:register:<name>:<ua>
fn parse_memo(memo: &[u8; 512]) -> Option<Registration> {
    let s = std::str::from_utf8(memo).ok()?;
    let s = s.trim_end_matches('\0');
    let rest = s.strip_prefix("zns:register:")?;
    let mut parts = rest.splitn(2, ':');
    let name = parts.next().filter(|n| !n.is_empty())?;
    let ua = parts.next().filter(|u| !u.is_empty())?;

    // Name validation: lowercase alphanumeric + hyphens, 1-63 chars,
    // no leading/trailing hyphens, no consecutive hyphens
    if name.len() > 63 { return None; }
    if name.starts_with('-') || name.ends_with('-') { return None; }
    if name.contains("--") { return None; }
    if !name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return None;
    }

    Some(Registration { name: name.to_string(), ua: ua.to_string() })
}

// ── Block processing ─────────────────────────────────────────────────────────

async fn process_block(
    block: &zcash_client_backend::proto::compact_formats::CompactBlock,
    client: &mut CompactTxStreamerClient<tonic::transport::Channel>,
    pivk: &PreparedIncomingViewingKey,
    db: &Connection,
) -> Result<(), Box<dyn std::error::Error>> {
    let height = block.height;

    for ctx in &block.vtx {
        if ctx.actions.is_empty() { continue; }

        let raw = client
            .get_transaction(TxFilter {
                block: None,
                index: 0,
                hash: ctx.hash.clone(),
            })
            .await?
            .into_inner();

        let branch = BranchId::for_height(
            &Network::MainNetwork,
            BlockHeight::from_u32(height as u32),
        );
        let tx = Transaction::read(&raw.data[..], branch)?;

        if let Some(bundle) = tx.orchard_bundle() {
            for action in bundle.actions() {
                let domain = OrchardDomain::for_action(action);
                if let Some((_note, _addr, memo)) =
                    zcash_note_encryption::try_note_decryption(&domain, pivk, action)
                {
                    if let Some(reg) = parse_memo(&memo) {
                        if !name_exists(db, &reg.name) {
                            create_registration(db, &reg.name, &reg.ua, &ctx.hash, height)?;
                            println!("Registered: {} → {} (height {})", reg.name, reg.ua, height);
                        }
                    }
                }
            }
        }
    }

    if height % 1_000 == 0 {
        println!("Scanned height {height}");
    }

    Ok(())
}

fn process_mempool_tx(
    raw_tx: &zcash_client_backend::proto::service::RawTransaction,
    pivk: &PreparedIncomingViewingKey,
) {
    let Ok(tx) = Transaction::read(&raw_tx.data[..], BranchId::Nu6) else { return };
    let Some(bundle) = tx.orchard_bundle() else { return };

    for action in bundle.actions() {
        let domain = OrchardDomain::for_action(action);
        if let Some((_note, _addr, memo)) =
            zcash_note_encryption::try_note_decryption(&domain, pivk, action)
        {
            if let Some(reg) = parse_memo(&memo) {
                println!("mempool pending: {} → {}", reg.name, reg.ua);
            }
        }
    }
}

// ── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Parse UIVK → extract Orchard IVK → prepare for trial decryption
    let uivk = UnifiedIncomingViewingKey::decode(&Network::MainNetwork, UIVK_STR)
        .map_err(|e| format!("Failed to decode UIVK: {e}"))?;
    let orchard_ivk = uivk.orchard().as_ref().ok_or("UIVK has no Orchard key")?;
    let pivk = PreparedIncomingViewingKey::new(orchard_ivk);

    // Open DB
    let db = open_db()?;

    // Connect to lightwalletd
    println!("Connecting to {LWD_URL}...");
    let mut client = CompactTxStreamerClient::connect(LWD_URL).await?;

    let mut last_scanned_height = BIRTHDAY;

    loop {
        let tip = client
            .get_latest_block(ChainSpec {})
            .await?
            .into_inner()
            .height;

        if last_scanned_height >= tip {
            println!("Caught up at {tip}. Waiting...");
            tokio::time::sleep(POLL_INTERVAL).await;
            continue;
        }

        let start = last_scanned_height + 1;
        println!("Scanning {start}..={tip}");

        let mut block_stream = client
            .get_block_range(BlockRange {
                start: Some(BlockId { height: start, hash: vec![] }),
                end: Some(BlockId { height: tip, hash: vec![] }),
            })
            .await?
            .into_inner();

        let mut mempool_stream = client
            .get_mempool_stream(Empty {})
            .await?
            .into_inner();

        let mut blocks_done = false;
        let mut mempool_done = false;

        while !blocks_done || !mempool_done {
            tokio::select! {
                msg = block_stream.message(), if !blocks_done => {
                    match msg? {
                        Some(block) => {
                            last_scanned_height = block.height;
                            process_block(&block, &mut client, &pivk, &db).await?;
                        }
                        None => {
                            blocks_done = true;
                            println!("Block stream complete at tip {tip}.");
                        }
                    }
                }
                msg = mempool_stream.message(), if !mempool_done => {
                    match msg? {
                        Some(raw_tx) => {
                            process_mempool_tx(&raw_tx, &pivk);
                        }
                        None => {
                            mempool_done = true;
                        }
                    }
                }
            }
        }

        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn init_tls() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    // ── Memo parsing tests ───────────────────────────────────────────────────

    fn make_memo(s: &str) -> [u8; 512] {
        let mut buf = [0u8; 512];
        buf[..s.len()].copy_from_slice(s.as_bytes());
        buf
    }

    #[test]
    fn test_parse_valid_memo() {
        let memo = make_memo("zns:register:alice:u1someaddress");
        let reg = parse_memo(&memo).unwrap();
        assert_eq!(reg.name, "alice");
        assert_eq!(reg.ua, "u1someaddress");
    }

    #[test]
    fn test_parse_memo_not_zns() {
        let memo = make_memo("hello world");
        assert!(parse_memo(&memo).is_none());
    }

    #[test]
    fn test_parse_memo_empty_name() {
        let memo = make_memo("zns:register::u1addr");
        assert!(parse_memo(&memo).is_none());
    }

    #[test]
    fn test_parse_memo_empty_ua() {
        let memo = make_memo("zns:register:alice:");
        assert!(parse_memo(&memo).is_none());
    }

    #[test]
    fn test_parse_memo_uppercase_rejected() {
        let memo = make_memo("zns:register:Alice:u1addr");
        assert!(parse_memo(&memo).is_none());
    }

    #[test]
    fn test_parse_memo_leading_hyphen() {
        let memo = make_memo("zns:register:-alice:u1addr");
        assert!(parse_memo(&memo).is_none());
    }

    #[test]
    fn test_parse_memo_trailing_hyphen() {
        let memo = make_memo("zns:register:alice-:u1addr");
        assert!(parse_memo(&memo).is_none());
    }

    #[test]
    fn test_parse_memo_double_hyphen() {
        let memo = make_memo("zns:register:al--ice:u1addr");
        assert!(parse_memo(&memo).is_none());
    }

    #[test]
    fn test_parse_memo_hyphen_ok() {
        let memo = make_memo("zns:register:my-name:u1addr");
        let reg = parse_memo(&memo).unwrap();
        assert_eq!(reg.name, "my-name");
    }

    #[test]
    fn test_parse_memo_digits_ok() {
        let memo = make_memo("zns:register:user42:u1addr");
        let reg = parse_memo(&memo).unwrap();
        assert_eq!(reg.name, "user42");
    }

    #[test]
    fn test_parse_memo_too_long_name() {
        let long = "a".repeat(64);
        let memo = make_memo(&format!("zns:register:{long}:u1addr"));
        assert!(parse_memo(&memo).is_none());
    }

    #[test]
    fn test_parse_memo_63_char_name() {
        let name = "a".repeat(63);
        let memo = make_memo(&format!("zns:register:{name}:u1addr"));
        let reg = parse_memo(&memo).unwrap();
        assert_eq!(reg.name, name);
    }

    #[test]
    fn test_ua_with_colons() {
        let memo = make_memo("zns:register:alice:u1some:thing:here");
        let reg = parse_memo(&memo).unwrap();
        assert_eq!(reg.name, "alice");
        assert_eq!(reg.ua, "u1some:thing:here");
    }

    // ── DB tests ─────────────────────────────────────────────────────────────

    #[test]
    fn test_db_round_trip() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE registrations (
                name TEXT PRIMARY KEY, ua TEXT NOT NULL,
                txid BLOB NOT NULL, height INTEGER NOT NULL
            );",
        ).unwrap();

        assert!(!name_exists(&db, "alice"));
        create_registration(&db, "alice", "u1addr", b"txid", 100).unwrap();
        assert!(name_exists(&db, "alice"));
    }

    // ── Network tests ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_connect() -> Result<(), Box<dyn std::error::Error>> {
        init_tls();
        CompactTxStreamerClient::connect(LWD_URL).await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_get_latest_height() -> Result<(), Box<dyn std::error::Error>> {
        init_tls();
        let mut client = CompactTxStreamerClient::connect(LWD_URL).await?;
        let block_id = client.get_latest_block(ChainSpec {}).await?.into_inner();
        assert!(block_id.height > 1_687_104);
        Ok(())
    }

    #[tokio::test]
    async fn test_get_block_range() -> Result<(), Box<dyn std::error::Error>> {
        init_tls();
        let mut client = CompactTxStreamerClient::connect(LWD_URL).await?;
        let range = BlockRange {
            start: Some(BlockId { height: 2_500_000, hash: vec![] }),
            end:   Some(BlockId { height: 2_500_001, hash: vec![] }),
        };
        let mut stream = client.get_block_range(range).await?.into_inner();
        let mut blocks = vec![];
        while let Some(block) = stream.message().await? {
            blocks.push(block);
        }
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].height, 2_500_000);
        assert_eq!(blocks[1].height, 2_500_001);
        Ok(())
    }

    #[tokio::test]
    async fn test_get_transaction() -> Result<(), Box<dyn std::error::Error>> {
        init_tls();
        let mut client = CompactTxStreamerClient::connect(LWD_URL).await?;
        let hash = hex::decode("3e12cd4942dd15205ebe4d5c4a624e2b4edce42e2346ff1ebe74f3afe107443c")?;
        let raw_tx = client
            .get_transaction(TxFilter { block: None, index: 0, hash })
            .await?
            .into_inner();
        assert!(!raw_tx.data.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn test_trial_decrypt_no_match() -> Result<(), Box<dyn std::error::Error>> {
        init_tls();
        let mut client = CompactTxStreamerClient::connect(LWD_URL).await?;

        let range = BlockRange {
            start: Some(BlockId { height: 2_500_000, hash: vec![] }),
            end:   Some(BlockId { height: 2_500_000, hash: vec![] }),
        };
        let mut stream = client.get_block_range(range).await?.into_inner();
        let block = stream.message().await?.expect("block");

        use zcash_keys::keys::UnifiedSpendingKey;
        use zip32::AccountId;
        let usk = UnifiedSpendingKey::from_seed(&Network::MainNetwork, &[0u8; 32], AccountId::ZERO)
            .expect("valid usk");
        let ufvk = usk.to_unified_full_viewing_key();
        let orchard_ivk = ufvk.orchard().expect("has orchard").to_ivk(zip32::Scope::External);
        let prepared = PreparedIncomingViewingKey::new(&orchard_ivk);

        let mut matches = 0usize;
        for compact_tx in &block.vtx {
            if compact_tx.actions.is_empty() { continue }
            let raw = client
                .get_transaction(TxFilter { block: None, index: 0, hash: compact_tx.hash.clone() })
                .await?
                .into_inner();
            let branch = BranchId::for_height(&Network::MainNetwork, BlockHeight::from_u32(2_500_000));
            let full_tx = Transaction::read(&raw.data[..], branch)?;
            if let Some(bundle) = full_tx.orchard_bundle() {
                for action in bundle.actions() {
                    let domain = OrchardDomain::for_action(action);
                    if zcash_note_encryption::try_note_decryption(&domain, &prepared, action).is_some() {
                        matches += 1;
                    }
                }
            }
        }
        assert_eq!(matches, 0);
        Ok(())
    }
}
