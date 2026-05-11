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
mod registry;
mod rpc;

use base64::Engine;
use tokio::sync::watch;
use tracing::{error, info, warn};
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedIncomingViewingKey};

use crate::config::Config;
use crate::memo::{ActionKind, MemoAction};
use crate::registry::Registry;

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(config::LOG_LEVEL)
        .init();
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cfg = Config::from_env().map_err(|e| format!("config error: {e}"))?;

    let uivk = UnifiedIncomingViewingKey::decode(&config::NETWORK, &cfg.uivk)
        .map_err(|e| format!("Failed to decode UIVK: {e}"))?;
    let (ua, _) = uivk
        .default_address(UnifiedAddressRequest::AllAvailableKeys)
        .map_err(|e| format!("Failed to derive address from UIVK: {e}"))?;
    let ua_str = ua.encode(&config::NETWORK);
    let reg = Registry::open(config::DB_PATH)?;

    let (height_tx, height_rx) = watch::channel(0u64);

    let rpc_ctx = rpc::RpcContext {
        db_path: config::DB_PATH.to_string(),
        synced_height: height_rx,
        admin_pubkey: base64::engine::general_purpose::STANDARD.encode(cfg.admin_pubkey),
        uivk: cfg.uivk.clone(),
        address: ua_str,
    };
    tokio::spawn(rpc::serve(format!("0.0.0.0:{}", config::RPC_PORT), rpc_ctx));

    info!(network = ?config::NETWORK, lwd_url = %config::LWD_URL, "connecting to lightwalletd");
    let mut indexer = decrypter::IndexerState::connect(
        config::LWD_URL,
        &uivk,
        config::NETWORK,
        config::BIRTHDAY,
    )
    .await?;

    loop {
        let Some(tip) = indexer.chain_tip().await else {
            tokio::time::sleep(config::POLL_INTERVAL).await;
            continue;
        };
        if indexer.height() >= tip {
            tokio::time::sleep(config::POLL_INTERVAL).await;
            continue;
        }

        info!("Scanning {}..={tip}", indexer.height() + 1);
        let notes = indexer.scan_to(tip).await;

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

        resolve_pending_buys(&reg, &mut indexer).await;

        height_tx.send(indexer.height()).ok();
        info!("Synced to {}.", indexer.height());
    }
}

// ── Signature verification and sovereignty enforcement ───────────────────────

fn verify_and_authorize(reg: &Registry, action: &MemoAction, admin_pubkey: &[u8; 32]) -> bool {
    if let Some(user_pk) = action.user_pubkey {
        // Sovereign path: user signed this action, verify against their pubkey.
        if !memo::verify_action(action, &user_pk) {
            warn!("Invalid user sig for '{}'", action.name);
            return false;
        }
        // For non-establishing actions, prove ownership: stored CLAIM/BUY sig
        // must verify against this user key (it was signed by them, not admin).
        if !matches!(action.kind, memo::ActionKind::Claim { .. } | memo::ActionKind::Buy { .. }) {
            let Some((stored_sig, stored_ua, stored_action)) =
                reg.get_claim_sig_for_ownership(&action.name)
            else {
                warn!("No claim record for sovereign action on '{}'", action.name);
                return false;
            };
            let Some(payload) = memo::ownership_payload(&stored_action, &action.name, &stored_ua) else {
                warn!("Invalid stored action '{}' for ownership proof on '{}'", stored_action, action.name);
                return false;
            };
            if !memo::verify_signature(&payload, &stored_sig, &user_pk) {
                warn!("Ownership proof failed for '{}'", action.name);
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
                    warn!(
                        "Invalid stored action '{}' for ownership proof on '{}'",
                        stored_action, action.name
                    );
                    return false;
                };
                if !memo::verify_signature(&payload, &stored_sig, admin_pubkey) {
                    warn!("Admin rejected: '{}' is sovereign", action.name);
                    return false;
                }
            }
        }
        if !memo::verify_action(action, admin_pubkey) {
            warn!("Invalid admin sig for '{}'", action.name);
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

async fn resolve_pending_buys(reg: &Registry, indexer: &mut decrypter::IndexerState) {
    let current_height = indexer.height();
    for name in reg.expire_pending_buys(current_height) {
        info!("Pending buy expired: {name}");
    }

    for pending in reg.list_active_pending_buys(current_height) {
        let Some(payment) = indexer
            .find_payment(
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
            &pending.buyer,
            &pending.signature,
            &payment.txid,
            payment.height,
            pending.price,
            pubkey,
        ) {
            error!("DB error (finalize buy {}): {e}", pending.name);
            continue;
        }
        info!(
            "Sold: {} → {} for {} zats (payment txid {}, height {})",
            pending.name, pending.buyer, pending.price, payment.txid, payment.height
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
                    warn!("SETPRICE: nonce {nonce} <= current {current}");
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
                    info!(
                        "Pricing set: {} tiers, nonce {nonce} (height {height})",
                        prices.len()
                    );
                }
                Err(e) => error!("DB error (setprice): {e}"),
            }
        }
        ActionKind::Claim { ua } => {
            if reg.is_registered(&action.name) {
                return;
            }
            let Some(cost) = reg.lookup_claim_cost(action.name.len()) else {
                warn!("CLAIM rejected for {}: no pricing set", action.name);
                return;
            };
            if cost > 0 && note_value < cost {
                warn!(
                    "CLAIM underpayment for {}: {note_value} < {cost} zats",
                    action.name
                );
                return;
            }
            match reg.create_registration(&action.name, ua, &action.signature, txid, height, pubkey) {
                Ok(true) => {
                    info!(
                        "Claimed: {} → {ua} for {note_value} zats (height {height})",
                        action.name
                    )
                }
                Ok(false) => warn!("Claim ignored (conflict): {}", action.name),
                Err(e) => error!("DB error (claim): {e}"),
            }
        }
        ActionKind::List { price, pay_taddr, nonce } => {
            // 10% of the minimum pricing tier as listing commission, prepaid as the
            // indexer's note value. Forfeited if the listing never completes.
            let Some(commission) = reg.min_tier().map(|t| t * 1_000) else {
                warn!("LIST rejected for {}: no pricing set", action.name);
                return;
            };
            if note_value < commission {
                warn!(
                    "LIST: commission underpayment for {}: {note_value} < {commission}",
                    action.name
                );
                return;
            }
            if let Err(e) = reg.validate_and_increment_nonce(&action.name, *nonce) {
                warn!("LIST: {e}");
                return;
            }
            let listing_pubkey_b64 = action
                .user_pubkey
                .as_ref()
                .map(|k| base64::engine::general_purpose::STANDARD.encode(k));
            match reg.create_listing(&action.name, *price, pay_taddr, *nonce, &action.signature, txid, height, listing_pubkey_b64.as_deref()) {
                Ok(()) => {
                    info!("Listed: {} for {price} zats → {pay_taddr} (height {height})", action.name)
                }
                Err(e) => error!("DB error (list): {e}"),
            }
        }
        ActionKind::Delist { nonce } => {
            if reg.get_listing_price(&action.name).is_none() {
                warn!("DELIST for unlisted name {}", action.name);
                return;
            }
            if let Some(pending) = reg.get_pending_buy(&action.name) {
                if pending.expires_at >= height {
                    warn!(
                        "DELIST rejected for {}: pending buy active until height {}",
                        action.name, pending.expires_at
                    );
                    return;
                }
            }
            if let Err(e) = reg.validate_and_increment_nonce(&action.name, *nonce) {
                warn!("DELIST: {e}");
                return;
            }
            match reg.delete_listing(&action.name, &action.signature, txid, height, *nonce, pubkey) {
                Ok(()) => {
                    info!("Delisted: {} (height {height})", action.name)
                }
                Err(e) => error!("DB error (delist): {e}"),
            }
        }
        ActionKind::Release { nonce } => {
            if reg.get_owner_ua(&action.name).is_none() {
                warn!("RELEASE for unregistered name {}", action.name);
                return;
            }
            if let Err(e) = reg.validate_and_increment_nonce(&action.name, *nonce) {
                warn!("RELEASE: {e}");
                return;
            }
            match reg.delete_registration(&action.name, txid, height, *nonce, &action.signature, pubkey) {
                Ok(()) => {
                    info!("Released: {} (height {height})", action.name)
                }
                Err(e) => error!("DB error (release): {e}"),
            }
        }
        ActionKind::Update { new_ua, nonce } => {
            if let Err(e) = reg.validate_and_increment_nonce(&action.name, *nonce) {
                warn!("UPDATE: {e}");
                return;
            }
            match reg.update_address(&action.name, new_ua, &action.signature, txid, height, pubkey) {
                Ok(()) => {
                    info!("Updated: {} → {new_ua} (height {height})", action.name)
                }
                Err(e) => error!("DB error (update): {e}"),
            }
        }
        ActionKind::Buy { buyer_ua, price } => {
            const BUY_COMMISSION: u64 = 10_000; // 0.0001 ZEC dust to indexer
            if note_value < BUY_COMMISSION {
                warn!(
                    "BUY: commission underpayment for {}: {note_value} < {BUY_COMMISSION}",
                    action.name
                );
                return;
            }
            let Some(listing) = reg.get_listing(&action.name) else {
                warn!("BUY for unlisted name {}", action.name);
                return;
            };
            if *price != listing.price {
                warn!(
                    "BUY: price mismatch for {}: memo {price} != listing {}",
                    action.name, listing.price
                );
                return;
            }
            if let Some(existing) = reg.get_pending_buy(&action.name) {
                if existing.expires_at >= height {
                    warn!(
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
                    info!(
                        "Pending buy: {} → {buyer_ua} for {price} zats, awaiting payment to {} (expires {expires_at})",
                        action.name, listing.pay_taddr
                    );
                }
                Ok(false) => warn!("BUY ignored (conflict): {}", action.name),
                Err(e) => error!("DB error (pending buy): {e}"),
            }
        }
    }
}
