// ZNS Indexer
//
// Scans confirmed blocks, trial-decrypts incoming Orchard notes,
// and writes ZNS registrations to SQLite.

use std::time::Duration;

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

// ── Database ─────────────────────────────────────────────────────────────────

fn open_db() -> rusqlite::Result<Connection> {
    let conn = Connection::open(DB_PATH)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS registrations (
            name    TEXT PRIMARY KEY,
            ua      TEXT NOT NULL UNIQUE,
            txid    BLOB NOT NULL,
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

enum MemoAction {
    Register { name: String, ua: String },
}

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

    let rest = s.strip_prefix("ZNS:REGISTER:")?;
    let parts: Vec<&str> = rest.splitn(2, ':').collect();
    if parts.len() != 2 { return None; }
    let (name, ua) = (parts[0], parts[1]);
    if !validate_name(name) || ua.is_empty() { return None; }
    Some(MemoAction::Register { name: name.into(), ua: ua.into() })
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
            let Some((_, _, memo)) = zcash_note_encryption::try_note_decryption(&domain, pivk, action) else { continue };
            let Some(memo_action) = parse_memo(&memo) else { continue };

            let MemoAction::Register { name, ua } = memo_action;
            if is_registered(db, &name, &ua) { continue; }
            match create_registration(db, &name, &ua, txid, height) {
                Ok(()) => println!("Registered: {name} → {ua} (height {height})"),
                Err(e) => eprintln!("DB error (register): {e}"),
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

    // Scanner gets its own connection (runs on main task, !Send is fine)
    let scanner_db = open_db()?;

    // Block scanner runs on the main task
    println!("Connecting to {LWD_URL}...");
    let client = CompactTxStreamerClient::connect(LWD_URL).await?;
    run_block_sync(client, &scanner_db, &ufvk).await;

    Ok(())
}
