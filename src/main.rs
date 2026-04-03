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
use rusqlite::Connection;
use zcash_keys::keys::UnifiedIncomingViewingKey;

use crate::config::Config;
use crate::memo::{ActionKind, MemoAction};

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cfg = Config::from_env().map_err(|e| format!("config error: {e}"))?;

    let uivk = UnifiedIncomingViewingKey::decode(&cfg.network, &cfg.uivk)
        .map_err(|e| format!("Failed to decode UIVK: {e}"))?;
    let orchard_ivk = uivk.orchard().as_ref().expect("UIVK has no Orchard key");
    let pivk = PreparedIncomingViewingKey::new(orchard_ivk);
    let db = registry::open_db(&cfg.db_path)?;

    let synced_height = Arc::new(AtomicU64::new(0));
    let rpc_addr = format!("0.0.0.0:{}", cfg.rpc_port);
    let rpc_state = Arc::new(rpc::RpcState {
        db_path: cfg.db_path.clone(),
        synced_height: synced_height.clone(),
        admin_pubkey: base64::engine::general_purpose::STANDARD.encode(cfg.admin_pubkey),
        uivk: cfg.uivk.clone(),
    });
    tokio::spawn(rpc::serve(rpc_addr, rpc_state));

    println!("Connecting to {}...", cfg.lwd_url);
    let mut client = decrypter::Client::connect(cfg.lwd_url.clone()).await?;

    let mut last_scanned = cfg.birthday - 100;

    loop {
        let Some(tip) = decrypter::get_chain_tip(&mut client).await else {
            tokio::time::sleep(cfg.poll_interval).await;
            continue;
        };
        if last_scanned >= tip {
            tokio::time::sleep(cfg.poll_interval).await;
            continue;
        }

        let start = last_scanned + 1;
        println!("Scanning {start}..={tip}");

        let (notes, scanned_to) =
            decrypter::scan_range(&mut client, &pivk, &cfg.network, start, tip).await;
        for note in notes {
            let Some(action) = memo::parse_memo(&note.memo, &cfg.admin_pubkey) else {
                continue;
            };
            handle_action(&db, action, note.value, &note.txid.to_string(), note.height);
        }
        last_scanned = scanned_to;
        synced_height.store(last_scanned, Ordering::Relaxed);

        println!("Synced to {last_scanned}.");
    }
}

// ── Action dispatch ──────────────────────────────────────────────────────────

fn handle_action(db: &Connection, action: MemoAction, note_value: u64, txid: &str, height: u64) {
    let MemoAction {
        name,
        signature,
        kind,
    } = action;

    match kind {
        ActionKind::SetPrice { prices, nonce } => {
            if let Some(current) = registry::get_pricing_nonce(db) {
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
            match registry::store_pricing(db, nonce, height, &tiers_str, txid, &signature) {
                Ok(()) => {
                    let _ = registry::insert_event(
                        db,
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
            if registry::is_registered(db, &name, &ua) {
                return;
            }
            let Some(cost) = registry::lookup_claim_cost(db, name.len()) else {
                eprintln!("CLAIM rejected for {name}: no pricing set");
                return;
            };
            if cost > 0 && note_value < cost {
                eprintln!("CLAIM underpayment for {name}: {note_value} < {cost} zats");
                return;
            }
            match registry::create_registration(db, &name, &ua, &signature, txid, height) {
                Ok(true) => {
                    let _ = registry::insert_event(
                        db,
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
            if let Err(e) = registry::validate_and_increment_nonce(db, &name, nonce) {
                eprintln!("LIST: {e}");
                return;
            }
            let owner_ua = registry::get_owner_ua(db, &name);
            match registry::create_listing(db, &name, price, &signature, txid, height) {
                Ok(()) => {
                    let _ = registry::insert_event(
                        db,
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
            if registry::get_listing_price(db, &name).is_none() {
                eprintln!("DELIST for unlisted name {name}");
                return;
            }

            if let Err(e) = registry::validate_and_increment_nonce(db, &name, nonce) {
                eprintln!("DELIST: {e}");
                return;
            }
            match registry::delete_listing(db, &name, &signature) {
                Ok(()) => {
                    let _ = registry::insert_event(
                        db,
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
            if registry::get_owner_ua(db, &name).is_none() {
                eprintln!("RELEASE for unregistered name {name}");
                return;
            }
            if let Err(e) = registry::validate_and_increment_nonce(db, &name, nonce) {
                eprintln!("RELEASE: {e}");
                return;
            }
            match registry::delete_registration(db, &name) {
                Ok(()) => {
                    let _ = registry::insert_event(
                        db,
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
            if let Err(e) = registry::validate_and_increment_nonce(db, &name, nonce) {
                eprintln!("UPDATE: {e}");
                return;
            }
            match registry::update_address(db, &name, &new_ua, &signature, txid, height) {
                Ok(()) => {
                    let _ = registry::insert_event(
                        db,
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
            let Some(price) = registry::get_listing_price(db, &name) else {
                eprintln!("BUY for unlisted name {name}");
                return;
            };
            if note_value < price {
                eprintln!("BUY underpayment for {name}: {note_value} < {price}");
                return;
            }
            match registry::process_buy(db, &name, &buyer_ua, &signature, txid, height) {
                Ok(()) => {
                    let _ = registry::insert_event(
                        db,
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
