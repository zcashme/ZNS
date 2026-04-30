use anyhow::Result;
use axum::{Router, extract::State, response::Json, routing::post};
use near_primitives::views::FinalExecutionStatus;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::Config;
use crate::db::Store;
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

// ─── POST /listing ──────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateListingRequest {
    pub name: String,
    pub seller_ua: String,
    pub price_zat: u64,
}

#[derive(Serialize)]
pub struct CreateListingResponse {
    pub local_listing_id: i64,
    pub name: String,
    pub seller_ua: String,
    pub price_zat: u64,
}

async fn create_listing_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateListingRequest>,
) -> Result<Json<CreateListingResponse>, axum::http::StatusCode> {
    // 1. Insert locally first (gives us a local ID for reference)
    let local_id = state
        .store
        .insert_listing(
            &body.name,
            &body.seller_ua,
            body.price_zat,
            state.cfg.commission_bps as u64,
            &state.cfg.treasury_ua,
        )
        .map_err(|e| {
            tracing::error!("insert listing: {e}");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // 2. Create on-chain via NEAR contract
    let args = serde_json::json!({
        "name": body.name,
        "seller_ua": body.seller_ua,
        "price_zat": body.price_zat,
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

    // 3. Record the on-chain ID locally
    state
        .store
        .set_contract_listing_id(local_id, contract_listing_id as i64)
        .map_err(|e| {
            tracing::error!("update contract_listing_id: {e}");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(CreateListingResponse {
        local_listing_id: local_id,
        name: body.name,
        seller_ua: body.seller_ua,
        price_zat: body.price_zat,
    }))
}

// ─── POST /purchase ─────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreatePurchaseRequest {
    pub local_listing_id: i64,
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

async fn create_purchase_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreatePurchaseRequest>,
) -> Result<Json<CreatePurchaseResponse>, axum::http::StatusCode> {
    // 1. Resolve listing
    let listing = state
        .store
        .get_listing_by_id(body.local_listing_id)
        .map_err(|e| {
            tracing::error!("get listing: {e}");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(axum::http::StatusCode::NOT_FOUND)?;

    if listing.status != crate::db::ListingStatus::Open {
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
    let memo_str = state.memo_signer.sign_buy(&listing.name, &body.buyer_ua);
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

    // Attach 0.1 NEAR for storage staking; contract refunds excess.
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

    // 10. Update listing status locally to Sold so no one else can purchase
    // (the contract already did this atomically, but our local cache needs to reflect it)
    // Note: Store currently doesn't have an update_listing_status method.
    // We'll add one if needed, but for now the contract is the source of truth.

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
        .route("/listing", post(create_listing_handler))
        .route("/purchase", post(create_purchase_handler))
        .with_state(state);

    tracing::info!(%bind, "HTTP API starting");
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
