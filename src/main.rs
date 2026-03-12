// ZNS Indexer

use std::collections::HashMap;

use incrementalmerkletree::Position;
use orchard::keys::{IncomingViewingKey as OrchardIvk, PreparedIncomingViewingKey};
use orchard::note::Nullifier as OrchardNullifier;
use orchard::note_encryption::OrchardDomain;

use rusqlite::Connection;
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;
use zcash_client_backend::proto::service::{BlockId, BlockRange, ChainSpec, TxFilter};
use zcash_client_backend::scanning::{Nullifiers, ScanningKeyOps, ScanningKeys, scan_block};
use zcash_keys::keys::UnifiedIncomingViewingKey;
use zcash_primitives::consensus::BranchId;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, Network};
use zip32::AccountId;

// ── Config ────────────────────────────────────────────────────────────────────

const LWD_URL: &str = "https://light.zcash.me:443";
const DB_PATH: &str = "zns.db";
const BIRTHDAY: u64 = 3_265_357;
const UIVK_STR: &str = "uivk1cpxzaa8rck580qfekjd3xma32zzk4mwm0p4c99qglpy4atgw74up0lexqvz5tq2wwj7s980c8fe9s98x7g9t9l603pjj6rsp44ufdj6dh0u3d28xm8rmcjdlej40unnvjrwtex45er8uxy3jk6tt22gu9a36t546kplsy280qq92ssz4sscev8529k347r8v2x3xzduuldjdltjjjy02sgv59hgjx2fud6u6y70nvu6g3h9p4n20gtcmmhjwsvqv2ykr2jlc3ert3qa4n99d7p0mg8g743jm5y96frmnu4aheyh6wf3wh9g4hz8jhy70s9xda9rmyg0aqdnec44j84hwjwxar9";
const CHUNK_SIZE: u64 = 1_000;

// ── Orchard IVK scanning key ──────────────────────────────────────────────────
//
// ScanningKey<Ivk, Nk, AccountId> has private fields, so we implement
// ScanningKeyOps directly on a newtype around the Orchard IVK.

struct OrchardIvkKey {
    ivk: OrchardIvk,
    account_id: AccountId,
}

impl ScanningKeyOps<OrchardDomain, AccountId, OrchardNullifier> for OrchardIvkKey {
    fn prepare(&self) -> PreparedIncomingViewingKey {
        PreparedIncomingViewingKey::new(&self.ivk)
    }

    fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    fn key_scope(&self) -> Option<zip32::Scope> {
        None
    }

    fn nf(&self, _note: &orchard::Note, _position: Position) -> Option<OrchardNullifier> {
        None // IVK-only; nullifiers require the FVK
    }
}

// ── Database ──────────────────────────────────────────────────────────────────

fn open_db() -> rusqlite::Result<Connection> {
    let conn = Connection::open(DB_PATH)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS registrations (
            name    TEXT PRIMARY KEY,
            ua      TEXT NOT NULL,
            txid    BLOB,
            height  INTEGER
        );",
    )?;
    Ok(conn)
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Parse UIVK → extract Orchard IVK
    let uivk = UnifiedIncomingViewingKey::decode(&Network::MainNetwork, UIVK_STR)
        .map_err(|e| format!("Failed to decode UIVK: {e}"))?;
    let orchard_ivk = uivk.orchard().as_ref().ok_or("UIVK has no Orchard key")?;

    // Prepared key is constant — create once, reuse for every memo decryption
    let prepared_ivk = PreparedIncomingViewingKey::new(orchard_ivk);

    // Build ScanningKeys using our own ScanningKeyOps impl (one clone to give ownership)
    let account = AccountId::ZERO;
    let mut orchard_map: HashMap<
        (AccountId, zip32::Scope),
        Box<dyn ScanningKeyOps<OrchardDomain, AccountId, OrchardNullifier>>,
    > = HashMap::new();
    orchard_map.insert(
        (account, zip32::Scope::External),
        Box::new(OrchardIvkKey { ivk: orchard_ivk.clone(), account_id: account }),
    );
    let scanning_keys = ScanningKeys::new(HashMap::new(), orchard_map);

    // Open DB
    let db = open_db()?;

    // Connect to lightwalletd
    println!("Connecting to {LWD_URL}...");
    let mut client = CompactTxStreamerClient::connect(LWD_URL).await?;

    let tip = client
        .get_latest_block(ChainSpec {})
        .await?
        .into_inner()
        .height;
    println!("Chain tip: {tip}. Scanning from birthday {BIRTHDAY}...");

    // ── Scanner loop ──────────────────────────────────────────────────────────
    let mut height = BIRTHDAY;
    while height <= tip {
        let end = (height + CHUNK_SIZE - 1).min(tip);

        let range = BlockRange {
            start: Some(BlockId { height, hash: vec![] }),
            end:   Some(BlockId { height: end, hash: vec![] }),
        };
        let mut stream = client.get_block_range(range).await?.into_inner();

        while let Some(block) = stream.message().await? {
            let block_height = block.height;
            let scanned = scan_block(
                &Network::MainNetwork,
                block,
                &scanning_keys,
                &Nullifiers::empty(),
                None,
            )
            .map_err(|e| format!("scan_block error at {block_height}: {e:?}"))?;

            for tx in scanned.transactions() {
                // Fetch the full transaction to read memos
                let raw = client
                    .get_transaction(TxFilter {
                        block: None,
                        index: 0,
                        hash: tx.txid().as_ref().to_vec(),
                    })
                    .await?
                    .into_inner();

                let branch = BranchId::for_height(
                    &Network::MainNetwork,
                    BlockHeight::from_u32(block_height as u32),
                );
                let full_tx = Transaction::read(&raw.data[..], branch)?;

                // Extract memos from Orchard actions by trial-decrypting the full tx
                if let Some(bundle) = full_tx.orchard_bundle() {
                    for action in bundle.actions() {
                        let domain = OrchardDomain::for_action(action);
                        if let Some((_note, _addr, memo)) =
                            zcash_note_encryption::try_note_decryption(&domain, &prepared_ivk, action)
                        {
                            parse_and_store_memo(
                                &memo,
                                tx.txid().as_ref(),
                                block_height,
                                &db,
                            )?;
                        }
                    }
                }
            }

            if block_height % 1_000 == 0 {
                println!("Scanned height {block_height}");
            }
        }

        height = end + 1;
    }

    println!("Scan complete.");
    Ok(())
}

// ── Memo parsing ──────────────────────────────────────────────────────────────

fn parse_and_store_memo(
    memo: &[u8; 512],
    txid: &[u8],
    height: u64,
    db: &Connection,
) -> rusqlite::Result<()> {
    let Ok(s) = std::str::from_utf8(memo) else { return Ok(()) };
    let s = s.trim_end_matches('\0');
    // Format: zns:register:<name>:<ua>
    let Some(rest) = s.strip_prefix("zns:register:") else { return Ok(()) };
    let mut parts = rest.splitn(2, ':');
    let (Some(name), Some(ua)) = (parts.next(), parts.next()) else { return Ok(()) };
    if name.is_empty() || ua.is_empty() { return Ok(()) }

    db.execute(
        "INSERT OR IGNORE INTO registrations (name, ua, txid, height) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![name, ua, txid, height as i64],
    )?;
    println!("Registered: {name} → {ua} (height {height})");
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;
    use zcash_client_backend::proto::service::{BlockId, BlockRange, ChainSpec, TxFilter};
    use zcash_client_backend::scanning::{Nullifiers, scan_block};
    use zcash_keys::keys::UnifiedSpendingKey;

    fn init_tls() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

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
    async fn test_compact_block_has_orchard_actions() -> Result<(), Box<dyn std::error::Error>> {
        init_tls();
        let mut client = CompactTxStreamerClient::connect(LWD_URL).await?;
        let range = BlockRange {
            start: Some(BlockId { height: 2_500_000, hash: vec![] }),
            end:   Some(BlockId { height: 2_500_000, hash: vec![] }),
        };
        let mut stream = client.get_block_range(range).await?.into_inner();
        let block = stream.message().await?.expect("block");
        let orchard_actions: usize = block.vtx.iter().map(|tx| tx.actions.len()).sum();
        assert!(orchard_actions > 0);
        Ok(())
    }

    #[tokio::test]
    async fn test_scan_block_no_match() -> Result<(), Box<dyn std::error::Error>> {
        use zcash_protocol::consensus::Network;
        init_tls();
        let mut client = CompactTxStreamerClient::connect(LWD_URL).await?;
        let range = BlockRange {
            start: Some(BlockId { height: 2_500_000, hash: vec![] }),
            end:   Some(BlockId { height: 2_500_000, hash: vec![] }),
        };
        let block = client.get_block_range(range).await?.into_inner()
            .message().await?.expect("block");

        let account = AccountId::ZERO;
        let usk = UnifiedSpendingKey::from_seed(&Network::MainNetwork, &[0u8; 32], account)
            .expect("valid usk");
        let scanning_keys = ScanningKeys::from_account_ufvks([(account, usk.to_unified_full_viewing_key())]);

        let scanned = scan_block(&Network::MainNetwork, block, &scanning_keys, &Nullifiers::empty(), None)
            .expect("scan_block");
        assert!(scanned.transactions().is_empty());
        Ok(())
    }

    // Parses the real registry UIVK, builds OrchardIvkKey scanning keys, and scans
    // a 10-block window at the birthday height. Asserts the pipeline completes without
    // error — proving UIVK → ScanningKeyOps → scan_block works end-to-end.
    #[tokio::test]
    async fn test_scan_with_real_uivk() -> Result<(), Box<dyn std::error::Error>> {
        use zcash_protocol::consensus::Network;
        init_tls();

        let uivk = UnifiedIncomingViewingKey::decode(&Network::MainNetwork, UIVK_STR)
            .map_err(|e| format!("decode uivk: {e}"))?;
        let orchard_ivk = uivk.orchard().as_ref().ok_or("no orchard key")?;

        let account = AccountId::ZERO;
        let mut orchard_map: HashMap<
            (AccountId, zip32::Scope),
            Box<dyn ScanningKeyOps<OrchardDomain, AccountId, OrchardNullifier>>,
        > = HashMap::new();
        orchard_map.insert(
            (account, zip32::Scope::External),
            Box::new(OrchardIvkKey { ivk: orchard_ivk.clone(), account_id: account }),
        );
        let scanning_keys = ScanningKeys::new(HashMap::new(), orchard_map);

        let mut client = CompactTxStreamerClient::connect(LWD_URL).await?;
        let range = BlockRange {
            start: Some(BlockId { height: BIRTHDAY, hash: vec![] }),
            end:   Some(BlockId { height: BIRTHDAY + 9, hash: vec![] }),
        };
        let mut stream = client.get_block_range(range).await?.into_inner();
        let mut matched_txs = 0usize;
        while let Some(block) = stream.message().await? {
            let scanned = scan_block(&Network::MainNetwork, block, &scanning_keys, &Nullifiers::empty(), None)
                .expect("scan_block");
            matched_txs += scanned.transactions().len();
        }

        // We scanned successfully — whether or not a registration exists in these 10 blocks
        println!("Matched {matched_txs} transactions in 10 blocks at birthday");
        Ok(())
    }
}

