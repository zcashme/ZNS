// ZNS Indexer
//
// Scans confirmed blocks, trial-decrypts Orchard notes, and writes
// ZNS registrations to SQLite.

mod service;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use orchard::keys::PreparedIncomingViewingKey;
use orchard::note_encryption::{CompactAction, OrchardDomain};
use rusqlite::Connection;
use tonic::transport::Server;
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;
use zcash_client_backend::proto::service::{BlockId, BlockRange, ChainSpec, TxFilter};
use zcash_keys::keys::UnifiedIncomingViewingKey;
use zcash_primitives::consensus::BranchId;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, Network};

use service::{ZnsServer, ZnsServiceServer};

// ── Config ───────────────────────────────────────────────────────────────────

const LWD_URL: &str = "https://light.zcash.me:443";
const DB_PATH: &str = "zns.db";
const BIRTHDAY: u64 = 3_265_357;
const UIVK_STR: &str = "uivk1cpxzaa8rck580qfekjd3xma32zzk4mwm0p4c99qglpy4atgw74up0lexqvz5tq2wwj7s980c8fe9s98x7g9t9l603pjj6rsp44ufdj6dh0u3d28xm8rmcjdlej40unnvjrwtex45er8uxy3jk6tt22gu9a36t546kplsy280qq92ssz4sscev8529k347r8v2x3xzduuldjdltjjjy02sgv59hgjx2fud6u6y70nvu6g3h9p4n20gtcmmhjwsvqv2ykr2jlc3ert3qa4n99d7p0mg8g743jm5y96frmnu4aheyh6wf3wh9g4hz8jhy70s9xda9rmyg0aqdnec44j84hwjwxar9";
const POLL_INTERVAL: Duration = Duration::from_secs(10);
const GRPC_PORT: u16 = 50051;

// ── Database ─────────────────────────────────────────────────────────────────

fn open_db() -> rusqlite::Result<Arc<Mutex<Connection>>> {
    let conn = Connection::open(DB_PATH)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS registrations (
            name    TEXT PRIMARY KEY,
            ua      TEXT NOT NULL UNIQUE,
            txid    BLOB NOT NULL,
            height  INTEGER NOT NULL
        );",
    )?;
    Ok(Arc::new(Mutex::new(conn)))
}

fn is_registered(db: &Connection, name: &str, ua: &str) -> bool {
    db.query_row(
        "SELECT 1 FROM registrations WHERE name = ?1 OR ua = ?2",
        rusqlite::params![name, ua],
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
    if name.len() > 63 {
        return None;
    }
    if name.starts_with('-') || name.ends_with('-') {
        return None;
    }
    if name.contains("--") {
        return None;
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return None;
    }

    Some(Registration {
        name: name.to_string(),
        ua: ua.to_string(),
    })
}

// ── Block scanner ─────────────────────────────────────────────────────────────

async fn run_block_sync(
    mut client: CompactTxStreamerClient<tonic::transport::Channel>,
    db: Arc<Mutex<Connection>>,
    pivk: &PreparedIncomingViewingKey,
) {
    let mut last_scanned_height = BIRTHDAY - 100;

    loop {
        let tip = match client.get_latest_block(ChainSpec {}).await {
            Ok(r) => r.into_inner().height,
            Err(e) => {
                eprintln!("get_latest_block: {e}");
                tokio::time::sleep(POLL_INTERVAL).await;
                continue;
            }
        };

        if last_scanned_height >= tip {
            tokio::time::sleep(POLL_INTERVAL).await;
            continue;
        }

        let start = last_scanned_height + 1;
        println!("Scanning {start}..={tip}");

        let mut stream = match client
            .get_block_range(BlockRange {
                start: Some(BlockId {
                    height: start,
                    hash: vec![],
                }),
                end: Some(BlockId {
                    height: tip,
                    hash: vec![],
                }),
            })
            .await
        {
            Ok(r) => r.into_inner(),
            Err(e) => {
                eprintln!("get_block_range: {e}");
                tokio::time::sleep(POLL_INTERVAL).await;
                continue;
            }
        };

        loop {
            match stream.message().await {
                Ok(Some(block)) => {
                    let height = block.height;

                    // Phase 1: compact trial decryption — no network I/O.
                    let mut candidates: Vec<(CompactAction, Vec<u8>)> = Vec::new();
                    for ctx in &block.vtx {
                        for compact_action in &ctx.actions {
                            if let Ok(ca) = CompactAction::try_from(compact_action) {
                                candidates.push((ca, ctx.hash.clone()));
                            }
                        }
                    }

                    if !candidates.is_empty() {
                        let domains_and_outputs: Vec<_> = candidates
                            .iter()
                            .map(|(ca, _)| (OrchardDomain::for_compact_action(ca), ca.clone()))
                            .collect();

                        let results = zcash_note_encryption::batch::try_compact_note_decryption(
                            std::slice::from_ref(pivk),
                            &domains_and_outputs,
                        );

                        // Phase 2: fetch full tx only for matched txids.
                        let mut matched: std::collections::HashSet<Vec<u8>> =
                            std::collections::HashSet::new();
                        for (result, (_, txid_hash)) in results.iter().zip(candidates.iter()) {
                            if result.is_some() {
                                matched.insert(txid_hash.clone());
                            }
                        }

                        for txid_hash in matched {
                            match client
                                .get_transaction(TxFilter {
                                    block: None,
                                    index: 0,
                                    hash: txid_hash.clone(),
                                })
                                .await
                            {
                                Ok(r) => {
                                    let data = r.into_inner().data;
                                    let branch = BranchId::for_height(
                                        &Network::MainNetwork,
                                        BlockHeight::from_u32(height as u32),
                                    );
                                    let Ok(tx) = Transaction::read(&data[..], branch) else {
                                        continue;
                                    };
                                    let Some(bundle) = tx.orchard_bundle() else {
                                        continue;
                                    };
                                    for action in bundle.actions() {
                                        let domain = OrchardDomain::for_action(action);
                                        if let Some((_note, _addr, memo)) =
                                            zcash_note_encryption::try_note_decryption(
                                                &domain, pivk, action,
                                            )
                                            && let Some(reg) = parse_memo(&memo)
                                        {
                                            let db = db.lock().unwrap();
                                            if !is_registered(&db, &reg.name, &reg.ua) {
                                                if let Err(e) = create_registration(
                                                    &db, &reg.name, &reg.ua, &txid_hash, height,
                                                ) {
                                                    eprintln!("DB error: {e}");
                                                } else {
                                                    println!(
                                                        "Registered: {} → {} (height {})",
                                                        reg.name, reg.ua, height
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                                Err(e) => eprintln!("get_transaction: {e}"),
                            }
                        }
                    }

                    last_scanned_height = height;
                    if height % 10 == 0 {
                        println!("Scanned height {height}");
                    }
                }
                Ok(None) => {
                    println!("Block stream complete at {tip}.");
                    break;
                }
                Err(e) => {
                    eprintln!("block stream error: {e}");
                    break;
                }
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
    let client = CompactTxStreamerClient::connect(LWD_URL).await?;

    // Start gRPC server and block indexer concurrently
    let grpc_addr = format!("0.0.0.0:{GRPC_PORT}").parse()?;
    let grpc_server = Server::builder()
        .add_service(ZnsServiceServer::new(ZnsServer::new(Arc::clone(&db))))
        .serve(grpc_addr);

    println!("gRPC server listening on {grpc_addr}");

    tokio::select! {
        result = grpc_server => {
            eprintln!("gRPC server exited: {result:?}");
        }
        _ = run_block_sync(client, db, &pivk) => {
            eprintln!("Block sync exited unexpectedly");
        }
    }

    Ok(())
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
                name TEXT PRIMARY KEY, ua TEXT NOT NULL UNIQUE,
                txid BLOB NOT NULL, height INTEGER NOT NULL
            );",
        )
        .unwrap();

        assert!(!is_registered(&db, "alice", "u1addr"));
        create_registration(&db, "alice", "u1addr", b"txid", 100).unwrap();
        assert!(is_registered(&db, "alice", "u1addr"));
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
            start: Some(BlockId {
                height: 2_500_000,
                hash: vec![],
            }),
            end: Some(BlockId {
                height: 2_500_001,
                hash: vec![],
            }),
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
            .get_transaction(TxFilter {
                block: None,
                index: 0,
                hash,
            })
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
            start: Some(BlockId {
                height: 2_500_000,
                hash: vec![],
            }),
            end: Some(BlockId {
                height: 2_500_000,
                hash: vec![],
            }),
        };
        let mut stream = client.get_block_range(range).await?.into_inner();
        let block = stream.message().await?.expect("block");

        use zcash_keys::keys::UnifiedSpendingKey;
        use zip32::AccountId;
        let usk = UnifiedSpendingKey::from_seed(&Network::MainNetwork, &[0u8; 32], AccountId::ZERO)
            .expect("valid usk");
        let ufvk = usk.to_unified_full_viewing_key();
        let orchard_ivk = ufvk
            .orchard()
            .expect("has orchard")
            .to_ivk(zip32::Scope::External);
        let prepared = PreparedIncomingViewingKey::new(&orchard_ivk);

        let mut matches = 0usize;
        for compact_tx in &block.vtx {
            if compact_tx.actions.is_empty() {
                continue;
            }
            let raw = client
                .get_transaction(TxFilter {
                    block: None,
                    index: 0,
                    hash: compact_tx.hash.clone(),
                })
                .await?
                .into_inner();
            let branch =
                BranchId::for_height(&Network::MainNetwork, BlockHeight::from_u32(2_500_000));
            let full_tx = Transaction::read(&raw.data[..], branch)?;
            if let Some(bundle) = full_tx.orchard_bundle() {
                for action in bundle.actions() {
                    let domain = OrchardDomain::for_action(action);
                    if zcash_note_encryption::try_note_decryption(&domain, &prepared, action)
                        .is_some()
                    {
                        matches += 1;
                    }
                }
            }
        }
        assert_eq!(matches, 0);
        Ok(())
    }
}
