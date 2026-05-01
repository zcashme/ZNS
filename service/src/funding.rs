use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use near_primitives::views::FinalExecutionStatus;
use serde::Deserialize;
use serde_json::json;
use zcash_transparent as transparent;

use crate::{
    db::{Purchase, PurchaseStatus},
    http::AppState,
    payout::{self, PayoutInputs},
    zcash::EscrowUtxo,
};

const SUBMIT_FUNDING_GAS: u64 = 150_000_000_000_000;
const SIGN_REQUEST_GAS: u64 = 300_000_000_000_000;
const SIMPLE_CALL_GAS: u64 = 50_000_000_000_000;

#[derive(Debug, Clone, Deserialize)]
struct ContractPurchaseView {
    pub id: u64,
    pub required_memo: String,
    pub buyer_signature_b64: Option<String>,
    pub buyer_pubkey_b64: Option<String>,
    pub price_zat: u64,
    pub commission_zat: u64,
    pub payout_fee_zat: u64,
    pub seller_receives_zat: u64,
    pub refund_receives_zat: u64,
    pub status: String,
    pub expires_at_ns: u64,
}

#[derive(Debug, Deserialize)]
struct SubmittedFundingView {
    pub status: String,
}

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
        match state.store.list_work_queue() {
            Ok(purchases) => {
                for purchase in purchases {
                    if let Err(e) = process_purchase(&state, purchase).await {
                        tracing::error!(error = %e, "funding worker failed for purchase");
                    }
                }
            }
            Err(e) => tracing::error!(error = %e, "load work queue failed"),
        }
        tokio::time::sleep(interval).await;
    }
}

async fn process_purchase(state: &Arc<AppState>, purchase: Purchase) -> Result<()> {
    let contract_purchase_id = purchase
        .contract_purchase_id
        .context("purchase missing contract_purchase_id")? as u64;
    let contract_purchase = fetch_contract_purchase(state, contract_purchase_id)
        .await?
        .context("contract purchase not found")?;

    let contract_status = parse_contract_status(&contract_purchase.status)?;
    if purchase.status != contract_status {
        state
            .store
            .update_purchase_status(purchase.id, contract_status.clone())?;
    }

    match contract_status {
        PurchaseStatus::AwaitingPayment => {
            handle_awaiting_payment(state, &purchase, &contract_purchase).await?
        }
        PurchaseStatus::PayoutAuthorized => {
            request_signature(state, contract_purchase_id, true).await?;
            maybe_broadcast_signed(state, &purchase, &contract_purchase, true).await?;
        }
        PurchaseStatus::Completed => {
            maybe_broadcast_signed(state, &purchase, &contract_purchase, true).await?;
        }
        PurchaseStatus::Refundable => {
            request_signature(state, contract_purchase_id, false).await?;
            maybe_broadcast_signed(state, &purchase, &contract_purchase, false).await?;
        }
        PurchaseStatus::Refunded => {
            maybe_broadcast_signed(state, &purchase, &contract_purchase, false).await?;
        }
        PurchaseStatus::Expired => {
            state
                .store
                .update_purchase_status(purchase.id, PurchaseStatus::Expired)?;
        }
    }

    Ok(())
}

async fn handle_awaiting_payment(
    state: &Arc<AppState>,
    purchase: &Purchase,
    contract_purchase: &ContractPurchaseView,
) -> Result<()> {
    if let Some(utxo) = find_matching_funding_utxo(state, purchase, contract_purchase).await? {
        build_and_submit_funding(state, purchase, contract_purchase, &utxo).await?;
        return Ok(());
    }

    if is_expired(contract_purchase.expires_at_ns) {
        call_contract_method(
            state,
            "authorize_refund",
            json!({ "purchase_id": contract_purchase.id }),
            SIMPLE_CALL_GAS,
            0,
        )
        .await?;
        state
            .store
            .update_purchase_status(purchase.id, PurchaseStatus::Expired)?;
    }

    Ok(())
}

async fn build_and_submit_funding(
    state: &Arc<AppState>,
    purchase: &Purchase,
    contract_purchase: &ContractPurchaseView,
    utxo: &EscrowUtxo,
) -> Result<()> {
    let listing = state
        .store
        .get_listing_by_id(purchase.listing_id)?
        .context("listing not found for purchase")?;
    let build_height = state.watcher.latest_height().await? as u32;
    let burner_pubkey = decode_pubkey(&purchase.burner_pubkey_hex)?;
    let outpoint = transparent::bundle::OutPoint::new(txid_le(&utxo.txid)?, utxo.vout);

    let payout_tx = payout::build_tx_bytes(PayoutInputs {
        network: &state.cfg.zcash_network,
        target_height: build_height,
        utxo_outpoint: outpoint.clone(),
        utxo_value_zats: utxo.value_zats,
        utxo_script_pubkey: utxo.script.clone(),
        burner_pubkey,
        seller_ua: &listing.seller_ua,
        treasury_ua: &listing.treasury_ua,
        buyer_ua: None,
        seller_amount: contract_purchase.seller_receives_zat,
        treasury_amount: contract_purchase.commission_zat,
        memo: build_buy_memo(
            &state,
            &listing.name,
            &purchase.buyer_ua,
            &purchase.buyer_signature_b64,
            &purchase.buyer_pubkey_b64,
            &contract_purchase.required_memo,
        ),
        fee: Some(contract_purchase.payout_fee_zat),
    })?;

    let refund_tx = payout::build_tx_bytes(PayoutInputs {
        network: &state.cfg.zcash_network,
        target_height: build_height,
        utxo_outpoint: outpoint,
        utxo_value_zats: utxo.value_zats,
        utxo_script_pubkey: utxo.script.clone(),
        burner_pubkey,
        seller_ua: &listing.seller_ua,
        treasury_ua: &listing.treasury_ua,
        buyer_ua: Some(&purchase.buyer_ua),
        seller_amount: contract_purchase.refund_receives_zat,
        treasury_amount: 0,
        memo: [0u8; 512],
        fee: Some(contract_purchase.payout_fee_zat),
    })?;

    let submitted: SubmittedFundingView = call_contract_method_with_result(
        state,
        "submit_funding",
        json!({
            "purchase_id": contract_purchase.id,
            "utxo_value_zats": utxo.value_zats,
            "utxo_script_pubkey": utxo.script,
            "payout_tx": payout_tx,
            "refund_tx": refund_tx,
        }),
        SUBMIT_FUNDING_GAS,
        0,
    )
    .await?;

    let new_status = parse_contract_status(&submitted.status)?;
    state.store.store_funding(
        purchase.id,
        &utxo.txid,
        utxo.vout,
        build_height,
        &payout_tx,
        &refund_tx,
        new_status,
    )?;

    Ok(())
}

async fn maybe_broadcast_signed(
    state: &Arc<AppState>,
    purchase: &Purchase,
    contract_purchase: &ContractPurchaseView,
    payout_path: bool,
) -> Result<()> {
    if purchase.settlement_txid.is_some() {
        return Ok(());
    }

    let sig = fetch_signature(state, contract_purchase.id, payout_path).await?;
    let Some(sig) = sig else {
        return Ok(());
    };

    let listing = state
        .store
        .get_listing_by_id(purchase.listing_id)?
        .context("listing not found for purchase")?;
    let utxo = find_stored_utxo(state, purchase, contract_purchase.price_zat)
        .await?
        .context("stored funding utxo not found")?;
    let build_height = purchase
        .build_height
        .context("purchase missing build_height")? as u32;
    let burner_pubkey = decode_pubkey(&purchase.burner_pubkey_hex)?;
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
        buyer_ua: if payout_path {
            None
        } else {
            Some(&purchase.buyer_ua)
        },
        seller_amount: if payout_path {
            contract_purchase.seller_receives_zat
        } else {
            contract_purchase.refund_receives_zat
        },
        treasury_amount: if payout_path {
            contract_purchase.commission_zat
        } else {
            0
        },
        memo: if payout_path {
            build_buy_memo(
                &state,
                &listing.name,
                &purchase.buyer_ua,
                &purchase.buyer_signature_b64,
                &purchase.buyer_pubkey_b64,
                &contract_purchase.required_memo,
            )
        } else {
            [0u8; 512]
        },
        fee: Some(contract_purchase.payout_fee_zat),
    })?;

    let final_tx = payout::finalize_with_mpc(plan, &signature_to_compact(&sig)?)?;
    let txid = state.watcher.send_tx(&final_tx).await?;
    state.store.set_settlement_txid(
        purchase.id,
        &txid,
        if payout_path {
            PurchaseStatus::Completed
        } else {
            PurchaseStatus::Refunded
        },
    )?;
    Ok(())
}

async fn find_matching_funding_utxo(
    state: &Arc<AppState>,
    purchase: &Purchase,
    contract_purchase: &ContractPurchaseView,
) -> Result<Option<EscrowUtxo>> {
    let mut utxos = state.watcher.get_utxos(&purchase.burner_taddr).await?;
    utxos.retain(|u| {
        u.value_zats == contract_purchase.price_zat
            && u.confirmations >= state.cfg.min_confirmations
    });
    utxos.sort_by_key(|u| std::cmp::Reverse(u.confirmations));
    Ok(utxos.into_iter().next())
}

async fn find_stored_utxo(
    state: &Arc<AppState>,
    purchase: &Purchase,
    wanted_value: u64,
) -> Result<Option<EscrowUtxo>> {
    let Some(funding_txid) = purchase.funding_txid.as_ref() else {
        return Ok(None);
    };
    let Some(funding_vout) = purchase.funding_vout else {
        return Ok(None);
    };

    let utxos = state.watcher.get_utxos(&purchase.burner_taddr).await?;
    Ok(utxos.into_iter().find(|u| {
        u.txid == *funding_txid && u.vout == funding_vout as u32 && u.value_zats == wanted_value
    }))
}

async fn fetch_contract_purchase(
    state: &Arc<AppState>,
    purchase_id: u64,
) -> Result<Option<ContractPurchaseView>> {
    state
        .near
        .view_zns("get_purchase", json!({ "id": purchase_id }))
        .await
        .context("view get_purchase")
}

async fn fetch_signature(
    state: &Arc<AppState>,
    purchase_id: u64,
    payout_path: bool,
) -> Result<Option<MpcSignature>> {
    state
        .near
        .view_zns(
            if payout_path {
                "get_payout_signature"
            } else {
                "get_refund_signature"
            },
            json!({ "purchase_id": purchase_id }),
        )
        .await
        .context("view signature")
}

async fn request_signature(
    state: &Arc<AppState>,
    purchase_id: u64,
    payout_path: bool,
) -> Result<()> {
    call_contract_method(
        state,
        if payout_path {
            "request_payout_signature"
        } else {
            "request_refund_signature"
        },
        json!({ "purchase_id": purchase_id }),
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

async fn call_contract_method_with_result<T: for<'de> Deserialize<'de>>(
    state: &Arc<AppState>,
    method: &str,
    args: serde_json::Value,
    gas: u64,
    deposit: u128,
) -> Result<T> {
    let outcome = state.near.call_zns_mut(method, args, gas, deposit).await?;
    match outcome.status {
        FinalExecutionStatus::SuccessValue(v) => {
            serde_json::from_slice(&v).context("decode contract method result")
        }
        FinalExecutionStatus::Failure(err) => bail!("{method} failed: {err:?}"),
        other => bail!("{method} unexpected status: {other:?}"),
    }
}

fn parse_contract_status(status: &str) -> Result<PurchaseStatus> {
    match status {
        "AwaitingPayment" => Ok(PurchaseStatus::AwaitingPayment),
        "PayoutAuthorized" => Ok(PurchaseStatus::PayoutAuthorized),
        "Completed" => Ok(PurchaseStatus::Completed),
        "Refundable" => Ok(PurchaseStatus::Refundable),
        "Refunded" => Ok(PurchaseStatus::Refunded),
        "Expired" => Ok(PurchaseStatus::Expired),
        other => bail!("unknown contract purchase status: {other}"),
    }
}

fn fixed_memo(memo: &str) -> [u8; 512] {
    let mut bytes = [0u8; 512];
    let raw = memo.as_bytes();
    let len = raw.len().min(512);
    bytes[..len].copy_from_slice(&raw[..len]);
    bytes
}

/// Build the BUY memo for the treasury Orchard output.
///
/// Priority:
/// 1. Buyer-signed memo if buyer_signature_b64 & buyer_pubkey_b64 are present.
/// 2. Admin-signed memo if the service has a memo_signer configured.
/// 3. Contract required_memo fallback (indexer won't parse as BUY action).
fn build_buy_memo(
    state: &AppState,
    listing_name: &str,
    buyer_ua: &str,
    buyer_signature_b64: &Option<String>,
    buyer_pubkey_b64: &Option<String>,
    required_memo: &str,
) -> [u8; 512] {
    if let (Some(sig), Some(pk)) = (buyer_signature_b64, buyer_pubkey_b64) {
        let memo = format!("ZNS:BUY:{listing_name}:{buyer_ua}:{sig}:{pk}");
        return fixed_memo(&memo);
    }
    if let Some(ref signer) = state.memo_signer {
        let memo = signer.sign_buy(listing_name, buyer_ua);
        return fixed_memo(&memo);
    }
    fixed_memo(required_memo)
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
    let point = sig
        .big_r
        .affine_point
        .strip_prefix("secp256k1:")
        .context("unexpected big_r format")?;
    let point_bytes = bs58::decode(point)
        .into_vec()
        .context("decode big_r affine point")?;
    if point_bytes.len() != 64 {
        bail!("big_r affine point must decode to 64 bytes");
    }

    let scalar_hex = sig.s.scalar.trim_start_matches("0x");
    let scalar_bytes = hex::decode(scalar_hex).context("decode signature scalar")?;
    if scalar_bytes.len() != 32 {
        bail!("signature scalar must be 32 bytes");
    }

    let mut compact = [0u8; 64];
    compact[..32].copy_from_slice(&point_bytes[..32]);
    compact[32..].copy_from_slice(&scalar_bytes);
    Ok(compact)
}

fn is_expired(expires_at_ns: u64) -> bool {
    chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default() as u64 >= expires_at_ns
}
