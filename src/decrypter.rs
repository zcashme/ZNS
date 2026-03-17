// ZNS block decrypter — streams compact blocks, trial-decrypts Orchard notes,
// and dispatches validated ZNS actions to the registry.

use std::collections::HashSet;

use base64::Engine;
use orchard::keys::PreparedIncomingViewingKey;
use orchard::note_encryption::{CompactAction, OrchardDomain};
use rusqlite::Connection;
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;
use zcash_client_backend::proto::service::{BlockId, BlockRange, ChainSpec, TxFilter};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::consensus::BranchId;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, Network};
use zip32::Scope;

use crate::memo::{self, MemoAction};
use crate::registry;

type Client = CompactTxStreamerClient<tonic::transport::Channel>;

/// Scan one block: trial-decrypt to find our notes, fetch full txs, process memos.
async fn scan_block(
    client: &mut Client,
    db: &Connection,
    pivk: &PreparedIncomingViewingKey,
    block: &CompactBlock,
) {
    let height = block.height;

    // Trial-decrypt compact actions to find transactions addressed to us
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
    let matched: HashSet<_> = results.iter().zip(&candidates)
        .filter_map(|(r, (_, txid))| r.as_ref().map(|_| txid.clone()))
        .collect();

    // Fetch full transactions, decrypt memos, and dispatch actions
    let branch = BranchId::for_height(&Network::TestNetwork, BlockHeight::from_u32(height as u32));
    for txid in &matched {
        let Ok(data) = client.get_transaction(TxFilter { block: None, index: 0, hash: txid.clone() })
            .await.map(|r| r.into_inner().data) else { continue };
        let Ok(tx) = Transaction::read(&data[..], branch) else { continue };
        let Some(bundle) = tx.orchard_bundle() else { continue };

        for action in bundle.actions() {
            let domain = OrchardDomain::for_action(action);
            let Some((note, _, memo_bytes)) = zcash_note_encryption::try_note_decryption(&domain, pivk, action) else { continue };
            let Some(memo_action) = memo::parse_memo(&memo_bytes) else { continue };

            handle_action(db, memo_action, note.value().inner(), txid, height);
        }
    }
}

/// Apply a single validated ZNS action to the registry.
fn handle_action(db: &Connection, action: MemoAction, note_value: u64, txid: &[u8], height: u64) {
    match action {
        MemoAction::Register { name, ua } => {
            if registry::is_registered(db, &name, &ua) { return; }
            match registry::create_registration(db, &name, &ua, txid, height) {
                Ok(true) => println!("Registered: {name} → {ua} (height {height})"),
                Ok(false) => eprintln!("Registration ignored (conflict): {name}"),
                Err(e) => eprintln!("DB error (register): {e}"),
            }
        }
        MemoAction::List { name, price, nonce, signature } => {
            let payload = format!("LIST:{name}:{price}:{nonce}");
            if !memo::verify_signed_action(&payload, &signature) {
                eprintln!("Invalid LIST signature for {name}");
                return;
            }
            let Some(current_nonce) = registry::get_nonce(db, &name) else {
                eprintln!("LIST for unregistered name {name}");
                return;
            };
            if nonce <= current_nonce {
                eprintln!("LIST replay rejected for {name}: nonce {nonce} <= {current_nonce}");
                return;
            }
            if let Err(e) = registry::increment_nonce(db, &name, nonce) {
                eprintln!("DB error (nonce): {e}"); return;
            }
            let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&signature);
            match registry::create_listing(db, &name, price, &sig_b64, txid, height) {
                Ok(()) => println!("Listed: {name} for {price} zats (height {height})"),
                Err(e) => eprintln!("DB error (list): {e}"),
            }
        }
        MemoAction::Delist { name, nonce, signature } => {
            let payload = format!("DELIST:{name}:{nonce}");
            if !memo::verify_signed_action(&payload, &signature) {
                eprintln!("Invalid DELIST signature for {name}");
                return;
            }
            let Some(current_nonce) = registry::get_nonce(db, &name) else {
                eprintln!("DELIST for unregistered name {name}");
                return;
            };
            if nonce <= current_nonce {
                eprintln!("DELIST replay rejected for {name}: nonce {nonce} <= {current_nonce}");
                return;
            }
            if registry::get_listing(db, &name).is_none() {
                eprintln!("DELIST for unlisted name {name}");
                return;
            }
            if let Err(e) = registry::increment_nonce(db, &name, nonce) {
                eprintln!("DB error (nonce): {e}"); return;
            }
            let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&signature);
            match registry::delete_listing(db, &name, &sig_b64) {
                Ok(()) => println!("Delisted: {name} (height {height})"),
                Err(e) => eprintln!("DB error (delist): {e}"),
            }
        }
        MemoAction::Update { name, new_ua, nonce, signature } => {
            let payload = format!("UPDATE:{name}:{new_ua}:{nonce}");
            if !memo::verify_signed_action(&payload, &signature) {
                eprintln!("Invalid UPDATE signature for {name}");
                return;
            }
            let Some(current_nonce) = registry::get_nonce(db, &name) else {
                eprintln!("UPDATE for unregistered name {name}");
                return;
            };
            if nonce <= current_nonce {
                eprintln!("UPDATE replay rejected for {name}: nonce {nonce} <= {current_nonce}");
                return;
            }
            if let Err(e) = registry::increment_nonce(db, &name, nonce) {
                eprintln!("DB error (nonce): {e}"); return;
            }
            let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&signature);
            match registry::update_address(db, &name, &new_ua, &sig_b64, txid, height) {
                Ok(()) => println!("Updated: {name} → {new_ua} (height {height})"),
                Err(e) => eprintln!("DB error (update): {e}"),
            }
        }
        MemoAction::Buy { name, buyer_ua } => {
            let Some(listing) = registry::get_listing(db, &name) else {
                eprintln!("BUY for unlisted name {name}");
                return;
            };
            if note_value < listing {
                eprintln!("BUY underpayment for {name}: {note_value} < {listing}");
                return;
            }
            match registry::process_buy(db, &name, &buyer_ua, txid, height) {
                Ok(()) => println!("Sold: {name} → {buyer_ua} for {listing} zats (height {height})"),
                Err(e) => eprintln!("DB error (buy): {e}"),
            }
        }
    }
}

/// Continuously stream and scan new blocks from lightwalletd.
pub async fn run_block_sync(mut client: Client, db: &Connection, ufvk: &UnifiedFullViewingKey) {
    let orchard_fvk = ufvk.orchard().expect("UFVK has no Orchard key");
    let pivk = PreparedIncomingViewingKey::new(&orchard_fvk.to_ivk(Scope::External));
    let mut last_scanned = crate::BIRTHDAY - 100;

    loop {
        let Ok(tip) = client.get_latest_block(ChainSpec {}).await.map(|r| r.into_inner().height) else {
            tokio::time::sleep(crate::POLL_INTERVAL).await; continue;
        };
        if last_scanned >= tip { tokio::time::sleep(crate::POLL_INTERVAL).await; continue; }

        let start = last_scanned + 1;
        println!("Scanning {start}..={tip}");

        let range = BlockRange {
            start: Some(BlockId { height: start, hash: vec![] }),
            end: Some(BlockId { height: tip, hash: vec![] }),
        };
        let Ok(mut stream) = client.get_block_range(range).await.map(|r| r.into_inner()) else {
            tokio::time::sleep(crate::POLL_INTERVAL).await; continue;
        };

        while let Ok(Some(block)) = stream.message().await {
            scan_block(&mut client, db, &pivk, &block).await;
            last_scanned = block.height;
        }
        println!("Synced to {tip}.");
    }
}
