// ZNS Indexer — Zcash Name System
//
// A long-running service that watches the Zcash blockchain for shielded ZNS
// protocol messages and maintains a local SQLite database of name
// registrations and marketplace listings.
//
// Supported actions:
//   CLAIM     — claim a name (admin-signed; user may append pubkey for sovereignty)
//   LIST      — put a name up for sale at a price
//   DELIST    — remove a listing
//   UPDATE    — change the address behind a name
//   BUY       — purchase a listed name (admin-signed; buyer may append pubkey)
//   RELEASE   — release a name back to the pool

mod config;
mod decrypter;
mod memo;
mod payments;
mod registry;
mod rpc;

use base64::Engine;
use orchard::keys::PreparedIncomingViewingKey;
use tokio::sync::watch;
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedIncomingViewingKey};

use crate::config::Config;
use crate::memo::{ActionKind, MemoAction};
use crate::registry::Registry;

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cfg = Config::from_env().map_err(|e| format!("config error: {e}"))?;

    let uivk = UnifiedIncomingViewingKey::decode(&cfg.network, &cfg.uivk)
        .map_err(|e| format!("Failed to decode UIVK: {e}"))?;
    let orchard_ivk = uivk.orchard().as_ref().expect("UIVK has no Orchard key");
    let pivk = PreparedIncomingViewingKey::new(orchard_ivk);
    let (ua, _) = uivk
        .default_address(UnifiedAddressRequest::AllAvailableKeys)
        .map_err(|e| format!("Failed to derive address from UIVK: {e}"))?;
    let ua_str = ua.encode(&cfg.network);
    let reg = Registry::open(config::DB_PATH)?;

    let (height_tx, height_rx) = watch::channel(0u64);

    let rpc_state = rpc::RpcState {
        db_path: config::DB_PATH.to_string(),
        synced_height: height_rx,
        admin_pubkey: base64::engine::general_purpose::STANDARD.encode(cfg.admin_pubkey),
        uivk: cfg.uivk.clone(),
        address: ua_str,
    };
    tokio::spawn(rpc::serve(format!("0.0.0.0:{}", config::RPC_PORT), rpc_state));

    println!("Connecting to {}...", cfg.lwd_url);
    let mut client = decrypter::Client::connect(cfg.lwd_url.clone()).await?;
    let mut last_scanned = cfg.birthday.saturating_sub(100);

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

        let (notes, scanned_to) = decrypter::scan_range(
            &mut client,
            &pivk,
            &cfg.network,
            start,
            tip,
        )
        .await;

        for note in notes {
            let Some(action) = memo::parse_memo(&note.memo) else {
                continue;
            };
            if !verify_and_authorize(&reg, &action, &cfg.admin_pubkey) {
                continue;
            }
            handle_action(
                &reg,
                action,
                note.value,
                &note.txid.to_string(),
                note.height,
            );
        }

        resolve_pending_buys(&reg, &mut client, cfg.network, scanned_to).await;

        last_scanned = scanned_to;
        height_tx.send(last_scanned).ok();
        println!("Synced to {}.", last_scanned);
    }
}

// ── Signature verification and sovereignty enforcement ───────────────────────

fn verify_and_authorize(reg: &Registry, action: &MemoAction, admin_pubkey: &[u8; 32]) -> bool {
    if let Some(user_pk) = action.user_pubkey {
        // Sovereign path: user signed this action, verify against their pubkey.
        if !memo::verify_action(action, &user_pk) {
            eprintln!("Invalid user sig for '{}'", action.name);
            return false;
        }
        // For non-establishing actions, prove ownership: stored CLAIM/BUY sig
        // must verify against this user key (it was signed by them, not admin).
        if !matches!(action.kind, memo::ActionKind::Claim { .. } | memo::ActionKind::Buy { .. }) {
            let Some((stored_sig, stored_ua, stored_action)) =
                reg.get_claim_sig_for_ownership(&action.name)
            else {
                eprintln!("No claim record for sovereign action on '{}'", action.name);
                return false;
            };
            let Some(payload) = memo::ownership_payload(&stored_action, &action.name, &stored_ua) else {
                eprintln!("Invalid stored action '{}' for ownership proof on '{}'", stored_action, action.name);
                return false;
            };
            if !memo::verify_signature(&payload, &stored_sig, &user_pk) {
                eprintln!("Ownership proof failed for '{}'", action.name);
                return false;
            }
        }
        true
    } else {
        // Admin path: first check sovereignty, then verify sig.
        let is_establishing = matches!(
            action.kind,
            memo::ActionKind::SetPrice { .. }
                | memo::ActionKind::Claim { .. }
                | memo::ActionKind::Buy { .. }
        );
        if !is_establishing {
            if let Some((stored_sig, stored_ua, stored_action)) =
                reg.get_claim_sig_for_ownership(&action.name)
            {
                let Some(payload) =
                    memo::ownership_payload(&stored_action, &action.name, &stored_ua)
                else {
                    eprintln!(
                        "Invalid stored action '{}' for ownership proof on '{}'",
                        stored_action, action.name
                    );
                    return false;
                };
                if !memo::verify_signature(&payload, &stored_sig, admin_pubkey) {
                    eprintln!("Admin rejected: '{}' is sovereign", action.name);
                    return false;
                }
            }
        }
        if !memo::verify_action(action, admin_pubkey) {
            eprintln!("Invalid admin sig for '{}'", action.name);
            return false;
        }
        true
    }
}

// ── Pending buy resolution ───────────────────────────────────────────────────
//
// On each scan tick: drop expired pending buys, then look for transparent
// payments to each active pending buy's pay_taddr. The first matching tx
// finalizes the sale.

async fn resolve_pending_buys(
    reg: &Registry,
    client: &mut decrypter::Client,
    network: zcash_protocol::consensus::Network,
    current_height: u64,
) {
    for name in reg.expire_pending_buys(current_height) {
        println!("Pending buy expired: {name}");
    }

    for pending in reg.list_active_pending_buys(current_height) {
        let Some(payment) = payments::find_payment(
            client,
            network,
            &pending.pay_taddr,
            pending.price,
            pending.claim_height,
            current_height,
        )
        .await
        else {
            continue;
        };

        let pubkey = pending.pubkey.as_deref();
        if let Err(e) = reg.finalize_buy(
            &pending.name,
            &pending.buyer_ua,
            &pending.signature,
            &payment.txid,
            payment.height,
            pending.price,
            pubkey,
        ) {
            eprintln!("DB error (finalize buy {}): {e}", pending.name);
            continue;
        }
        println!(
            "Sold: {} → {} for {} zats (payment txid {}, height {})",
            pending.name, pending.buyer_ua, pending.price, payment.txid, payment.height
        );
    }
}

// ── Action dispatch ──────────────────────────────────────────────────────────

fn handle_action(reg: &Registry, action: MemoAction, note_value: u64, txid: &str, height: u64) {
    let pubkey_b64 = action
        .user_pubkey
        .as_ref()
        .map(|k| base64::engine::general_purpose::STANDARD.encode(k));
    let pubkey = pubkey_b64.as_deref();
    match &action.kind {
        ActionKind::SetPrice { prices, nonce } => {
            if let Some(current) = reg.get_pricing_nonce() {
                if nonce <= &current {
                    eprintln!("SETPRICE: nonce {nonce} <= current {current}");
                    return;
                }
            }
            let tiers_str: String = prices
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(":");
            match reg.store_pricing(*nonce, height, &tiers_str, txid, &action.signature) {
                Ok(()) => {
                    let _ = reg.insert_event(&action, action.kind.label(), txid, height, None, None, Some(*nonce), None);
                    println!(
                        "Pricing set: {} tiers, nonce {nonce} (height {height})",
                        prices.len()
                    );
                }
                Err(e) => eprintln!("DB error (setprice): {e}"),
            }
        }
        ActionKind::Claim { ua } => {
            if reg.is_registered(&action.name) {
                return;
            }
            let Some(cost) = reg.lookup_claim_cost(action.name.len()) else {
                eprintln!("CLAIM rejected for {}: no pricing set", action.name);
                return;
            };
            if cost > 0 && note_value < cost {
                eprintln!(
                    "CLAIM underpayment for {}: {note_value} < {cost} zats",
                    action.name
                );
                return;
            }
            match reg.create_registration(&action.name, ua, &action.signature, txid, height, pubkey) {
                Ok(true) => {
                    let _ = reg.insert_event(&action, action.kind.label(), txid, height, Some(ua), None, None, pubkey);
                    println!(
                        "Claimed: {} → {ua} for {note_value} zats (height {height})",
                        action.name
                    )
                }
                Ok(false) => eprintln!("Claim ignored (conflict): {}", action.name),
                Err(e) => eprintln!("DB error (claim): {e}"),
            }
        }
        ActionKind::List { price, pay_taddr, nonce } => {
            // Flat 0.01 ZEC listing commission, prepaid as the indexer's note
            // value. Forfeited if the listing never completes.
            const LIST_COMMISSION: u64 = 1_000_000;
            if note_value < LIST_COMMISSION {
                eprintln!(
                    "LIST: commission underpayment for {}: {note_value} < {LIST_COMMISSION}",
                    action.name
                );
                return;
            }
            if let Err(e) = reg.validate_and_increment_nonce(&action.name, *nonce) {
                eprintln!("LIST: {e}");
                return;
            }
            let owner_ua = reg.get_owner_ua(&action.name);
            let listing_pubkey_b64 = action
                .user_pubkey
                .as_ref()
                .map(|k| base64::engine::general_purpose::STANDARD.encode(k));
            match reg.create_listing(&action.name, *price, pay_taddr, *nonce, &action.signature, txid, height, listing_pubkey_b64.as_deref()) {
                Ok(()) => {
                    let _ = reg.insert_event(
                        &action,
                        action.kind.label(),
                        txid,
                        height,
                        owner_ua.as_deref(),
                        Some(*price),
                        Some(*nonce),
                        pubkey,
                    );
                    println!("Listed: {} for {price} zats → {pay_taddr} (height {height})", action.name)
                }
                Err(e) => eprintln!("DB error (list): {e}"),
            }
        }
        ActionKind::Delist { nonce } => {
            if reg.get_listing_price(&action.name).is_none() {
                eprintln!("DELIST for unlisted name {}", action.name);
                return;
            }
            if let Some(pending) = reg.get_pending_buy(&action.name) {
                if pending.expires_at >= height {
                    eprintln!(
                        "DELIST rejected for {}: pending buy active until height {}",
                        action.name, pending.expires_at
                    );
                    return;
                }
            }
            if let Err(e) = reg.validate_and_increment_nonce(&action.name, *nonce) {
                eprintln!("DELIST: {e}");
                return;
            }
            match reg.delete_listing(&action.name, &action.signature) {
                Ok(()) => {
                    let _ = reg.insert_event(&action, action.kind.label(), txid, height, None, None, Some(*nonce), pubkey);
                    println!("Delisted: {} (height {height})", action.name)
                }
                Err(e) => eprintln!("DB error (delist): {e}"),
            }
        }
        ActionKind::Release { nonce } => {
            if reg.get_owner_ua(&action.name).is_none() {
                eprintln!("RELEASE for unregistered name {}", action.name);
                return;
            }
            if let Err(e) = reg.validate_and_increment_nonce(&action.name, *nonce) {
                eprintln!("RELEASE: {e}");
                return;
            }
            match reg.delete_registration(&action.name) {
                Ok(()) => {
                    let _ = reg.insert_event(&action, action.kind.label(), txid, height, None, None, Some(*nonce), pubkey);
                    println!("Released: {} (height {height})", action.name)
                }
                Err(e) => eprintln!("DB error (release): {e}"),
            }
        }
        ActionKind::Update { new_ua, nonce } => {
            if let Err(e) = reg.validate_and_increment_nonce(&action.name, *nonce) {
                eprintln!("UPDATE: {e}");
                return;
            }
            match reg.update_address(&action.name, new_ua, &action.signature, txid, height) {
                Ok(()) => {
                    let _ = reg.insert_event(&action, action.kind.label(), txid, height, Some(new_ua), None, Some(*nonce), pubkey);
                    println!("Updated: {} → {new_ua} (height {height})", action.name)
                }
                Err(e) => eprintln!("DB error (update): {e}"),
            }
        }
        ActionKind::Buy { buyer_ua, price } => {
            const BUY_COMMISSION: u64 = 10_000; // 0.0001 ZEC dust to indexer
            if note_value < BUY_COMMISSION {
                eprintln!(
                    "BUY: commission underpayment for {}: {note_value} < {BUY_COMMISSION}",
                    action.name
                );
                return;
            }
            let Some(listing) = reg.get_listing(&action.name) else {
                eprintln!("BUY for unlisted name {}", action.name);
                return;
            };
            if *price != listing.price {
                eprintln!(
                    "BUY: price mismatch for {}: memo {price} != listing {}",
                    action.name, listing.price
                );
                return;
            }
            if let Some(existing) = reg.get_pending_buy(&action.name) {
                if existing.expires_at >= height {
                    eprintln!(
                        "BUY: {} already has an active pending buy until height {}",
                        action.name, existing.expires_at
                    );
                    return;
                }
            }
            let expires_at = height + config::BUY_WINDOW_BLOCKS;
            match reg.create_pending_buy(
                &action.name,
                buyer_ua,
                *price,
                &listing.pay_taddr,
                height,
                expires_at,
                txid,
                &action.signature,
                pubkey,
            ) {
                Ok(true) => {
                    println!(
                        "Pending buy: {} → {buyer_ua} for {price} zats, awaiting payment to {} (expires {expires_at})",
                        action.name, listing.pay_taddr
                    );
                }
                Ok(false) => eprintln!("BUY ignored (conflict): {}", action.name),
                Err(e) => eprintln!("DB error (pending buy): {e}"),
            }
        }
    }
}
