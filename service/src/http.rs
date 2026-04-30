use anyhow::Result;
use axum::{Router, extract::State, response::Json, routing::post};
use near_primitives::views::FinalExecutionStatus;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::Config;
use crate::db::{Listing, ListingStatus, Store};
use crate::escrow;
use crate::memo::MemoSigner;
use crate::near::NearClient;
use crate::payout;
use crate::zcash::Watcher;

pub struct AppState {
    pub cfg: Arc<Config>,
    pub store: Arc<Store>,
    pub near: NearClient,
    pub watcher: Watcher,
    pub memo_signer: MemoSigner,
}

// ─── POST /purchase ─────────────────────────────────────────────────────
/// Buyer calls this with the name they want and their UA.
/// The service resolves the listing from the ZNS indexer, auto-creates the
/// NEAR contract entry if needed, and returns a burner address to pay.

#[derive(Deserialize)]
pub struct CreatePurchaseRequest {
    pub name: String,
    pub buyer_ua: String,
}

#[derive(Serialize)]
pub struct CreatePurchaseResponse {
    pub local_purchase_id: i64,
    pub contract_purchase_id: u64,
    pub burner_taddr: String,
    pub price_zat: u64,
    pub commission_zat: u64,
    pub fee_zat: u64,
    pub seller_receives_zat: u64,
    pub expires_at: String,
}

/// Resolve a name from the ZNS indexer.
async fn resolve_name(indexer_url: &str, name: &str) -> Result<( String, u64 ), reqwest::Error> {
    let resp: serde_json::Value = reqwest::Client::new()
        .post(indexer_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "resolve", "params": [name],
        }))
        .send()
        .await?
        .json()
        .await?;

    let seller_ua = resp["result"]["address"].as_str().unwrap_or("").to_string();
    let price = resp["result"]["listing"]["price"].as_u64().unwrap_or(0);
    Ok((seller_ua, price))
}

/// Get or create the NEAR contract listing for a name.
/// First checks local DB, then falls back to creating on-chain.
async fn ensure_listing(
    state: &AppState,
    name: &str,
) -> Result<Listing, axum::http::StatusCode> {
    // 1. Check local DB first
    if let Ok(Some(listing)) = state.store.get_listing_by_name(name) {
        if listing.status == ListingStatus::Open {
            return Ok(listing);
        }
        // If Sold/Cancelled, return conflict
        return Err(axum::http::StatusCode::CONFLICT);
    }

    // 2. Not in DB — resolve from indexer
    let (seller_ua, price_zat) = resolve_name(&state.cfg.indexer_rpc, name)
        .await
        .map_err(|e| {
            tracing::error!("indexer resolve: {e}");
            axum::http::StatusCode::BAD_GATEWAY
        })?;

    if seller_ua.is_empty() || price_zat == 0 {
        tracing::warn!("name not listed: {}", name);
        return Err(axum::http::StatusCode::NOT_FOUND);
    }

    // 3. Create on-chain via NEAR contract
    let args = serde_json::json!({
        "name": name,
        "seller_ua": seller_ua,
        "price_zat": price_zat,
    });
    let deposit_yocto = 50_000_000_000_000_000_000_000u128; // 0.05 NEAR
    let gas = 50_000_000_000_000u64; // 50 Tgas

    let outcome = state
        .near
        .call_zns_mut("create_listing", args, gas, deposit_yocto)
        .await
        .map_err(|e| {
            tracing::error!("NEAR create_listing: {e}");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let value = match outcome.status {
        FinalExecutionStatus::SuccessValue(v) => v,
        FinalExecutionStatus::Failure(err) => {
            tracing::error!("NEAR create_listing failure: {:?}", err);
            return Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        }
        other => {
            tracing::error!("NEAR create_listing unexpected status: {:?}", other);
            return Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    if value.len() < 8 {
        tracing::error!("NEAR create_listing return value too short");
        return Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    }
    let contract_listing_id = u64::from_le_bytes(value[..8].try_into().map_err(|_| {
        tracing::error!("NEAR create_listing return value not a valid u64");
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    })?);

    // 4. Store locally
    let local_id = state
        .store
        .insert_listing(name, &seller_ua, price_zat, state.cfg.commission_bps as u64, &state.cfg.treasury_ua)
        .map_err(|e| {
            tracing::error!("insert listing: {e}");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })?;

    state
        .store
        .set_contract_listing_id(local_id, contract_listing_id as i64)
        .map_err(|e| {
            tracing::error!("update contract_listing_id: {e}");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Return the newly created listing
    state
        .store
        .get_listing_by_id(local_id)
        .map_err(|e| {
            tracing::error!("get listing after insert: {e}");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
}

async fn create_purchase_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreatePurchaseRequest>,
) -> Result<Json<CreatePurchaseResponse>, axum::http::StatusCode> {
    // 1. Resolve or create the NEAR listing for this name
    let listing = ensure_listing(&state, &body.name)
        .await?;

    if listing.status != ListingStatus::Open {
        return Err(axum::http::StatusCode::CONFLICT);
    }

    // 2. Derive unique MPC path and burner
    let path = format!(
        "zns-purchase-{}-{}",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default(),
        listing.id
    );
    let burner = escrow::derive_burner(
        &state.cfg.mpc_master_pubkey,
        &state.cfg.near_account,
        &path,
        &state.cfg.zcash_network,
    )
    .map_err(|e| {
        tracing::error!("derive burner: {e}");
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let script_pubkey = escrow::p2pkh_script(&burner.public_key);

    // 3. Compute amounts from the snapshotted listing terms
    let price = listing.price_zat;
    let commission = price * listing.commission_bps / 10_000;
    let fee = payout::payout_fee();
    let seller_amount = price
        .checked_sub(commission)
        .and_then(|v| v.checked_sub(fee))
        .ok_or_else(|| {
            tracing::error!("price too small to cover commission + fee");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // 4. Current chain height for bundle construction
    let target_height = state
        .watcher
        .latest_height()
        .await
        .map_err(|e| {
            tracing::error!("lightwalletd height: {e}");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })? as u32;

    // 5. Build BUY memo
    let memo_str = state.memo_signer.sign_buy(&body.name, &body.buyer_ua);
    let mut memo_bytes = [0u8; 512];
    let raw = memo_str.as_bytes();
    let len = raw.len().min(512);
    memo_bytes[..len].copy_from_slice(&raw[..len]);

    // 6. Build payout bundle (placeholder outpoint)
    let payout_bundle = payout::build_bundle_bytes(
        &state.cfg.zcash_network,
        target_height,
        &listing.seller_ua,
        &listing.treasury_ua,
        &body.buyer_ua,
        seller_amount,
        commission,
        fee,
        memo_bytes,
        burner.public_key,
        script_pubkey.clone(),
        false,
    )
    .map_err(|e| {
        tracing::error!("build payout bundle: {e}");
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // 7. Build refund bundle (placeholder outpoint)
    let refund_bundle = payout::build_bundle_bytes(
        &state.cfg.zcash_network,
        target_height,
        &listing.seller_ua,
        &listing.treasury_ua,
        &body.buyer_ua,
        price - fee, // refund amount
        0,           // treasury gets 0 on refund
        fee,
        [0u8; 512],  // no memo on refund
        burner.public_key,
        script_pubkey,
        true,
    )
    .map_err(|e| {
        tracing::error!("build refund bundle: {e}");
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // 8. Call contract.accept_listing
    let args = serde_json::json!({
        "listing_id": listing.contract_listing_id.map(|v| v as u64).unwrap_or(listing.id as u64),
        "buyer_ua": body.buyer_ua,
        "burner_taddr": burner.taddr,
        "burner_pubkey": burner.public_key.to_vec(),
        "mpc_path": path,
        "payout_bundle": payout_bundle,
        "refund_bundle": refund_bundle,
    });

    let deposit_yocto = 100_000_000_000_000_000_000_000u128; // 0.1 NEAR
    let gas = 100_000_000_000_000u64; // 100 Tgas

    let outcome = state
        .near
        .call_zns_mut("accept_listing", args, gas, deposit_yocto)
        .await
        .map_err(|e| {
            tracing::error!("NEAR accept_listing: {e}");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let value = match outcome.status {
        FinalExecutionStatus::SuccessValue(v) => v,
        FinalExecutionStatus::Failure(err) => {
            tracing::error!("NEAR accept_listing failure: {:?}", err);
            return Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        }
        other => {
            tracing::error!("NEAR accept_listing unexpected status: {:?}", other);
            return Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    if value.len() < 8 {
        tracing::error!("NEAR accept_listing return value too short: {} bytes", value.len());
        return Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    }
    let contract_purchase_id =
        u64::from_le_bytes(value[..8].try_into().map_err(|_| {
            tracing::error!("NEAR accept_listing return value not a valid u64");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })?);

    // 9. Store locally
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(15);
    let local_purchase_id = state
        .store
        .insert_purchase(
            listing.id,
            &body.buyer_ua,
            &burner.taddr,
            &hex::encode(burner.public_key),
            &path,
            &payout_bundle,
            &refund_bundle,
            expires_at,
        )
        .map_err(|e| {
            tracing::error!("insert purchase: {e}");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(CreatePurchaseResponse {
        local_purchase_id,
        contract_purchase_id,
        burner_taddr: burner.taddr,
        price_zat: price,
        commission_zat: commission,
        fee_zat: fee,
        seller_receives_zat: seller_amount,
        expires_at: expires_at.to_rfc3339(),
    }))
}

// ─── Server ─────────────────────────────────────────────────────────────

pub async fn serve(bind: SocketAddr, state: Arc<AppState>) -> Result<()> {
    let app = Router::new()
        .route("/purchase", post(create_purchase_handler))
        .with_state(state);

    tracing::info!(%bind, "HTTP API starting");
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
