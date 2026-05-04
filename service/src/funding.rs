//! Background worker that drives every active buyer registration through to
//! a settled payout.
//!
//! For each registration in the local DB:
//!
//!   * **AwaitingPayment** — poll the listing's burner t-addr; when an
//!     exact-amount UTXO with enough confirmations lands, build the payout
//!     tx, call `submit_funding` on chain, then `request_payout_signature`.
//!   * **Submitted**       — poll `get_payout_signature`; once available,
//!     finalize the tx and broadcast via lightwalletd.
//!   * **Completed**       — terminal.
//!
//! Refunds for wrong-amount or losing-race UTXOs are out of scope here and
//! sit at the burner address until a future flow handles them.

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use near_primitives::views::FinalExecutionStatus;
use serde::Deserialize;
use serde_json::json;
use zcash_transparent as transparent;

use crate::{
    db::{BuyerRegistration, Listing, RegistrationStatus},
    http::{AppState, ContractListingView},
    payout::{self, PayoutInputs},
    zcash::EscrowUtxo,
};

const SUBMIT_FUNDING_GAS: u64 = 150_000_000_000_000;
const SIGN_REQUEST_GAS: u64 = 300_000_000_000_000;

#[derive(Debug, Deserialize)]
struct MpcSignature {
    pub big_r: AffinePoint,
    pub s: ScalarHex,
}

#[derive(Debug, Deserialize)]
struct AffinePoint {
    pub affine_point: String,
}

#[derive(Debug, Deserialize)]
struct ScalarHex {
    pub scalar: String,
}

pub async fn run_worker(state: Arc<AppState>) {
    let interval = Duration::from_secs(state.cfg.poll_interval_secs.max(1));
    loop {
        match state.store.list_active_registrations() {
            Ok(registrations) => {
                for reg in registrations {
                    if let Err(e) = process_registration(&state, reg).await {
                        tracing::error!(error = %e, "funding worker failed for registration");
                    }
                }
            }
            Err(e) => tracing::error!(error = %e, "load active registrations failed"),
        }
        tokio::time::sleep(interval).await;
    }
}

async fn process_registration(state: &Arc<AppState>, reg: BuyerRegistration) -> Result<()> {
    let listing = state
        .store
        .get_listing_by_id(reg.listing_id)?
        .context("listing not found for registration")?;
    let contract_listing = fetch_contract_listing(state, listing.contract_listing_id)
        .await?
        .context("contract listing not found")?;

    if contract_listing.funded != listing.funded {
        state
            .store
            .set_listing_funded(listing.contract_listing_id, contract_listing.funded)?;
    }

    match reg.status {
        RegistrationStatus::AwaitingPayment => {
            handle_awaiting_payment(state, &reg, &listing, &contract_listing).await
        }
        RegistrationStatus::Submitted => {
            drive_payout(state, &reg, &listing, &contract_listing).await
        }
        RegistrationStatus::Completed => Ok(()),
    }
}

async fn handle_awaiting_payment(
    state: &Arc<AppState>,
    reg: &BuyerRegistration,
    listing: &Listing,
    contract_listing: &ContractListingView,
) -> Result<()> {
    if contract_listing.funded {
        // Listing was funded by someone else — our registration is moot.
        return Ok(());
    }

    let Some(utxo) = find_exact_funding_utxo(state, listing, contract_listing).await? else {
        return Ok(());
    };

    submit_funding(state, reg, listing, contract_listing, &utxo).await?;
    request_payout_signature(state, listing.contract_listing_id).await?;
    Ok(())
}

async fn submit_funding(
    state: &Arc<AppState>,
    reg: &BuyerRegistration,
    listing: &Listing,
    contract_listing: &ContractListingView,
    utxo: &EscrowUtxo,
) -> Result<()> {
    let build_height = state.watcher.latest_height().await? as u32;
    let burner_pubkey = decode_pubkey(&listing.burner_pubkey_hex)?;
    let outpoint = transparent::bundle::OutPoint::new(txid_le(&utxo.txid)?, utxo.vout);

    let payout_tx = payout::build_tx_bytes(PayoutInputs {
        network: &state.cfg.zcash_network,
        target_height: build_height,
        utxo_outpoint: outpoint,
        utxo_value_zats: utxo.value_zats,
        utxo_script_pubkey: utxo.script.clone(),
        burner_pubkey,
        seller_ua: &listing.seller_ua,
        treasury_ua: &listing.treasury_ua,
        buyer_ua: None,
        seller_amount: contract_listing.seller_receives_zat(crate::payout::payout_fee()),
        treasury_amount: contract_listing.commission_zat(),
        memo: build_buy_memo(
            &listing.name,
            &reg.buyer_ua,
            &reg.buyer_signature_b64,
            reg.is_sovereign.then_some(&reg.buyer_pubkey_b64),
        ),
        fee: Some(crate::payout::payout_fee()),
    })?;

    // Sovereign signatures are flagged in the DB so the contract can verify
    // them on chain. Admin-signed credentials are kept off-chain (the memo
    // still carries them so indexers can re-verify).
    let (sovereign_sig, sovereign_pk) = if reg.is_sovereign {
        (Some(reg.buyer_signature_b64.as_str()), Some(reg.buyer_pubkey_b64.as_str()))
    } else {
        (None, None)
    };

    call_contract_method(
        state,
        "submit_funding",
        json!({
            "listing_id": contract_listing.id,
            "utxo_value_zats": utxo.value_zats,
            "utxo_script_pubkey": utxo.script,
            "payout_tx": payout_tx,
            "buyer_ua": reg.buyer_ua,
            "admin_signature_b64": reg.admin_signature_b64,
            "buyer_signature_b64": sovereign_sig,
            "buyer_pubkey_b64": sovereign_pk,
        }),
        SUBMIT_FUNDING_GAS,
        0,
    )
    .await?;

    state.store.mark_registration_submitted(
        reg.id,
        &utxo.txid,
        utxo.vout,
        build_height,
    )?;
    state
        .store
        .set_listing_funded(listing.contract_listing_id, true)?;

    Ok(())
}

async fn drive_payout(
    state: &Arc<AppState>,
    reg: &BuyerRegistration,
    listing: &Listing,
    contract_listing: &ContractListingView,
) -> Result<()> {
    if reg.payout_txid.is_some() {
        return Ok(());
    }

    let sig = fetch_payout_signature(state, listing.contract_listing_id).await?;
    let Some(sig) = sig else {
        // Signature not yet available — re-request to nudge the MPC.
        request_payout_signature(state, listing.contract_listing_id).await?;
        return Ok(());
    };

    let utxo = find_stored_utxo(state, reg, listing, contract_listing.price_zat)
        .await?
        .context("stored funding utxo not found")?;
    let build_height = reg
        .build_height
        .context("registration missing build_height")? as u32;
    let burner_pubkey = decode_pubkey(&listing.burner_pubkey_hex)?;
    let outpoint = transparent::bundle::OutPoint::new(txid_le(&utxo.txid)?, utxo.vout);

    let plan = payout::build_unsigned(PayoutInputs {
        network: &state.cfg.zcash_network,
        target_height: build_height,
        utxo_outpoint: outpoint,
        utxo_value_zats: utxo.value_zats,
        utxo_script_pubkey: utxo.script,
        burner_pubkey,
        seller_ua: &listing.seller_ua,
        treasury_ua: &listing.treasury_ua,
        buyer_ua: None,
        seller_amount: contract_listing.seller_receives_zat(crate::payout::payout_fee()),
        treasury_amount: contract_listing.commission_zat(),
        memo: build_buy_memo(
            &listing.name,
            &reg.buyer_ua,
            &reg.buyer_signature_b64,
            reg.is_sovereign.then_some(&reg.buyer_pubkey_b64),
        ),
        fee: Some(crate::payout::payout_fee()),
    })?;

    let final_tx = payout::finalize_with_mpc(plan, &signature_to_compact(&sig)?)?;
    let txid = state.watcher.send_tx(&final_tx).await?;
    state.store.mark_registration_completed(reg.id, &txid)?;
    Ok(())
}

async fn find_exact_funding_utxo(
    state: &Arc<AppState>,
    listing: &Listing,
    contract_listing: &ContractListingView,
) -> Result<Option<EscrowUtxo>> {
    let mut utxos = state.watcher.get_utxos(&listing.burner_taddr).await?;
    utxos.retain(|u| {
        u.value_zats == contract_listing.price_zat
            && u.confirmations >= state.cfg.min_confirmations
    });
    utxos.sort_by_key(|u| std::cmp::Reverse(u.confirmations));
    Ok(utxos.into_iter().next())
}

async fn find_stored_utxo(
    state: &Arc<AppState>,
    reg: &BuyerRegistration,
    listing: &Listing,
    wanted_value: u64,
) -> Result<Option<EscrowUtxo>> {
    let Some(funding_txid) = reg.funding_txid.as_ref() else {
        return Ok(None);
    };
    let Some(funding_vout) = reg.funding_vout else {
        return Ok(None);
    };

    let utxos = state.watcher.get_utxos(&listing.burner_taddr).await?;
    Ok(utxos.into_iter().find(|u| {
        u.txid == *funding_txid && u.vout == funding_vout as u32 && u.value_zats == wanted_value
    }))
}

async fn fetch_contract_listing(
    state: &Arc<AppState>,
    contract_listing_id: i64,
) -> Result<Option<ContractListingView>> {
    state
        .near
        .view_zns("get_listing", json!({ "id": contract_listing_id }))
        .await
        .context("view get_listing")
}

async fn fetch_payout_signature(
    state: &Arc<AppState>,
    contract_listing_id: i64,
) -> Result<Option<MpcSignature>> {
    state
        .near
        .view_zns(
            "get_payout_signature",
            json!({ "listing_id": contract_listing_id }),
        )
        .await
        .context("view payout signature")
}

async fn request_payout_signature(state: &Arc<AppState>, contract_listing_id: i64) -> Result<()> {
    call_contract_method(
        state,
        "request_payout_signature",
        json!({ "listing_id": contract_listing_id }),
        SIGN_REQUEST_GAS,
        0,
    )
    .await
}

async fn call_contract_method(
    state: &Arc<AppState>,
    method: &str,
    args: serde_json::Value,
    gas: u64,
    deposit: u128,
) -> Result<()> {
    let outcome = state.near.call_zns_mut(method, args, gas, deposit).await?;
    match outcome.status {
        FinalExecutionStatus::SuccessValue(_) => Ok(()),
        FinalExecutionStatus::Failure(err) => bail!("{method} failed: {err:?}"),
        other => bail!("{method} unexpected status: {other:?}"),
    }
}

/// Build the BUY memo placed on the treasury Orchard output.
///
/// Sovereign format: `ZNS:BUY:<name>:<buyer_ua>:<buyer_sig_b64>:<buyer_pubkey_b64>`.
/// Admin format:    `ZNS:BUY:<name>:<buyer_ua>:<admin_sig_b64>` (no pubkey).
///
/// The signature was already verified by both the relayer's POST handler
/// and the contract's submit_funding — this just embeds it on chain so
/// any indexer can re-verify the sale.
fn build_buy_memo(
    listing_name: &str,
    buyer_ua: &str,
    buyer_signature_b64: &str,
    buyer_pubkey_b64: Option<&str>,
) -> [u8; 512] {
    let memo = match buyer_pubkey_b64 {
        Some(pk) => format!(
            "ZNS:BUY:{listing_name}:{buyer_ua}:{buyer_signature_b64}:{pk}"
        ),
        None => format!(
            "ZNS:BUY:{listing_name}:{buyer_ua}:{buyer_signature_b64}"
        ),
    };
    let mut bytes = [0u8; 512];
    let raw = memo.as_bytes();
    let len = raw.len().min(512);
    bytes[..len].copy_from_slice(&raw[..len]);
    bytes
}

fn decode_pubkey(hex_key: &str) -> Result<[u8; 33]> {
    let bytes = hex::decode(hex_key).context("decode burner_pubkey_hex")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("burner pubkey must be 33 bytes"))
}

fn txid_le(txid_be_hex: &str) -> Result<[u8; 32]> {
    let mut bytes = hex::decode(txid_be_hex).context("decode funding txid")?;
    if bytes.len() != 32 {
        bail!("funding txid must be 32 bytes");
    }
    bytes.reverse();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn signature_to_compact(sig: &MpcSignature) -> Result<[u8; 64]> {
    let point_hex = sig.big_r.affine_point.trim_start_matches("0x");
    let point_bytes = hex::decode(point_hex).context("decode big_r affine point")?;
    // MPC returns big_r as either a 33-byte compressed point (03||x) or a 65-byte
    // uncompressed point (04||x||y).  Either way, r is the x-coordinate.
    let r_bytes: &[u8] = match point_bytes.len() {
        33 => &point_bytes[1..], // compressed: skip 02/03 prefix
        65 => &point_bytes[1..33], // uncompressed: skip 04 prefix, take x
        64 => &point_bytes[..32], // raw affine coordinate pair
        other => bail!("big_r unexpected length: {other}"),
    };

    let scalar_hex = sig.s.scalar.trim_start_matches("0x");
    let scalar_bytes = hex::decode(scalar_hex).context("decode signature scalar")?;
    if scalar_bytes.len() != 32 {
        bail!("signature scalar must be 32 bytes");
    }

    let mut compact = [0u8; 64];
    compact[..32].copy_from_slice(r_bytes);
    compact[32..].copy_from_slice(&scalar_bytes);
    Ok(compact)
}
