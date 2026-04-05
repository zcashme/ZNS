// ZNS Indexer — Zcash Name System
//
// A long-running service that watches the Zcash blockchain for shielded ZNS
// protocol messages and maintains a local SQLite database of name
// registrations and marketplace listings.
//
// Supported actions:
//   CLAIM     — claim a name (admin-signed, first-come-first-served)
//   LIST      — put a name up for sale at a price (admin-signed)
//   DELIST    — remove a listing (admin-signed)
//   UPDATE    — change the address behind a name (admin-signed)
//   BUY       — purchase a listed name (admin-signed)

mod config; // env-var configuration
mod decrypter; // block streaming and trial decryption
mod memo; // memo protocol: parsing, validation, signature verification
mod registry; // SQLite storage for registrations and listings
mod rpc; // JSON-RPC read-only API

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine;
use orchard::keys::PreparedIncomingViewingKey;
use zcash_keys::keys::UnifiedIncomingViewingKey;

use crate::memo::{ActionKind, MemoAction};
use crate::registry::Registry;

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (uivk_str, admin_pubkey) =
        config::load_secrets().map_err(|e| format!("config error: {e}"))?;

    let uivk = UnifiedIncomingViewingKey::decode(&config::NETWORK, &uivk_str)
        .map_err(|e| format!("Failed to decode UIVK: {e}"))?;
    let orchard_ivk = uivk.orchard().as_ref().expect("UIVK has no Orchard key");
    let pivk = PreparedIncomingViewingKey::new(orchard_ivk);
    let reg = Registry::open(config::DB_PATH)?;

    let synced_height = Arc::new(AtomicU64::new(0));
    let rpc_addr = format!("0.0.0.0:{}", config::RPC_PORT);
    let rpc_state = Arc::new(rpc::RpcState {
        db_path: config::DB_PATH.to_string(),
        synced_height: synced_height.clone(),
        admin_pubkey: base64::engine::general_purpose::STANDARD.encode(admin_pubkey),
        uivk: uivk_str,
    });
    tokio::spawn(rpc::serve(rpc_addr, rpc_state));

    println!("Connecting to {}...", config::LWD_URL);
    let mut client = decrypter::Client::connect(config::LWD_URL.to_string()).await?;

    let mut last_scanned = config::BIRTHDAY - 100;

    loop {
        let Some(tip) = decrypter::get_chain_tip(&mut client).await else {
            tokio::time::sleep(config::POLL_INTERVAL).await;
            continue;
        };
        if last_scanned >= tip {
            tokio::time::sleep(config::POLL_INTERVAL).await;
            continue;
        }

        let start = last_scanned + 1;
        println!("Scanning {start}..={tip}");

        let (notes, scanned_to) =
            decrypter::scan_range(&mut client, &pivk, &config::NETWORK, start, tip).await;
        for note in notes {
            let Some(action) = memo::parse_memo(&note.memo, &admin_pubkey) else {
                continue;
            };
            handle_action(&reg, action, note.value, &note.txid.to_string(), note.height);
        }
        last_scanned = scanned_to;
        synced_height.store(last_scanned, Ordering::Relaxed);

        println!("Synced to {last_scanned}.");
    }
}

// ── Action dispatch ──────────────────────────────────────────────────────────

fn handle_action(reg: &Registry, action: MemoAction, note_value: u64, txid: &str, height: u64) {
    let MemoAction {
        name,
        signature,
        kind,
    } = action;

    match kind {
        ActionKind::SetPrice { prices, nonce } => {
            if let Some(current) = reg.get_pricing_nonce() {
                if nonce <= current {
                    eprintln!("SETPRICE: nonce {nonce} <= current {current}");
                    return;
                }
            }
            let tiers_str: String = prices
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(":");
            match reg.store_pricing(nonce, height, &tiers_str, txid, &signature) {
                Ok(()) => {
                    let _ = reg.insert_event(
                        "",
                        "SETPRICE",
                        txid,
                        height,
                        None,
                        None,
                        Some(nonce),
                        Some(&signature),
                    );
                    println!(
                        "Pricing set: {} tiers, nonce {nonce} (height {height})",
                        prices.len()
                    );
                }
                Err(e) => eprintln!("DB error (setprice): {e}"),
            }
        }
        ActionKind::Claim { ua } => {
            if reg.is_registered(&name) {
                return;
            }
            let Some(cost) = reg.lookup_claim_cost(name.len()) else {
                eprintln!("CLAIM rejected for {name}: no pricing set");
                return;
            };
            if cost > 0 && note_value < cost {
                eprintln!("CLAIM underpayment for {name}: {note_value} < {cost} zats");
                return;
            }
            match reg.create_registration(&name, &ua, &signature, txid, height) {
                Ok(true) => {
                    let _ = reg.insert_event(
                        &name,
                        "CLAIM",
                        txid,
                        height,
                        Some(&ua),
                        None,
                        None,
                        Some(&signature),
                    );
                    println!("Claimed: {name} → {ua} for {note_value} zats (height {height})")
                }
                Ok(false) => eprintln!("Claim ignored (conflict): {name}"),
                Err(e) => eprintln!("DB error (claim): {e}"),
            }
        }
        ActionKind::List { price, nonce } => {
            if let Err(e) = reg.validate_and_increment_nonce(&name, nonce) {
                eprintln!("LIST: {e}");
                return;
            }
            let owner_ua = reg.get_owner_ua(&name);
            match reg.create_listing(&name, price, &signature, txid, height) {
                Ok(()) => {
                    let _ = reg.insert_event(
                        &name,
                        "LIST",
                        txid,
                        height,
                        owner_ua.as_deref(),
                        Some(price),
                        Some(nonce),
                        Some(&signature),
                    );
                    println!("Listed: {name} for {price} zats (height {height})")
                }
                Err(e) => eprintln!("DB error (list): {e}"),
            }
        }
        ActionKind::Delist { nonce } => {
            if reg.get_listing_price(&name).is_none() {
                eprintln!("DELIST for unlisted name {name}");
                return;
            }

            if let Err(e) = reg.validate_and_increment_nonce(&name, nonce) {
                eprintln!("DELIST: {e}");
                return;
            }
            match reg.delete_listing(&name, &signature) {
                Ok(()) => {
                    let _ = reg.insert_event(
                        &name,
                        "DELIST",
                        txid,
                        height,
                        None,
                        None,
                        Some(nonce),
                        Some(&signature),
                    );
                    println!("Delisted: {name} (height {height})")
                }
                Err(e) => eprintln!("DB error (delist): {e}"),
            }
        }
        ActionKind::Release { nonce } => {
            if reg.get_owner_ua(&name).is_none() {
                eprintln!("RELEASE for unregistered name {name}");
                return;
            }
            if let Err(e) = reg.validate_and_increment_nonce(&name, nonce) {
                eprintln!("RELEASE: {e}");
                return;
            }
            match reg.delete_registration(&name) {
                Ok(()) => {
                    let _ = reg.insert_event(
                        &name,
                        "RELEASE",
                        txid,
                        height,
                        None,
                        None,
                        Some(nonce),
                        Some(&signature),
                    );
                    println!("Released: {name} (height {height})")
                }
                Err(e) => eprintln!("DB error (release): {e}"),
            }
        }
        ActionKind::Update { new_ua, nonce } => {
            if let Err(e) = reg.validate_and_increment_nonce(&name, nonce) {
                eprintln!("UPDATE: {e}");
                return;
            }
            match reg.update_address(&name, &new_ua, &signature, txid, height) {
                Ok(()) => {
                    let _ = reg.insert_event(
                        &name,
                        "UPDATE",
                        txid,
                        height,
                        Some(&new_ua),
                        None,
                        Some(nonce),
                        Some(&signature),
                    );
                    println!("Updated: {name} → {new_ua} (height {height})")
                }
                Err(e) => eprintln!("DB error (update): {e}"),
            }
        }
        ActionKind::Buy { buyer_ua } => {
            let Some(price) = reg.get_listing_price(&name) else {
                eprintln!("BUY for unlisted name {name}");
                return;
            };
            if note_value < price {
                eprintln!("BUY underpayment for {name}: {note_value} < {price}");
                return;
            }
            match reg.process_buy(&name, &buyer_ua, &signature, txid, height) {
                Ok(()) => {
                    let _ = reg.insert_event(
                        &name,
                        "BUY",
                        txid,
                        height,
                        Some(&buyer_ua),
                        Some(price),
                        None,
                        Some(&signature),
                    );
                    println!("Sold: {name} → {buyer_ua} for {price} zats (height {height})")
                }
                Err(e) => eprintln!("DB error (buy): {e}"),
            }
        }
    }
}
