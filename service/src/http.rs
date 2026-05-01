use anyhow::Result;
use axum::{Router, extract::State, response::Json, routing::post};
use near_primitives::views::FinalExecutionStatus;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::Config;
use crate::db::{ListingStatus, Store};
use crate::near::NearClient;
use crate::zcash::Watcher;

pub struct AppState {
    pub cfg: Arc<Config>,
    pub store: Arc<Store>,
    pub near: NearClient,
    pub watcher: Watcher,
}

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
    pub required_memo: String,
    pub price_zat: u64,
    pub commission_zat: u64,
    pub fee_zat: u64,
    pub seller_receives_zat: u64,
    pub refund_receives_zat: u64,
    pub expires_at: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ContractListingView {
    pub id: u64,
    pub name: String,
    pub seller_ua: String,
    pub price_zat: u64,
    pub commission_bps: u64,
    pub treasury_ua: String,
    pub status: String,
    pub created_at_ns: u64,
    pub listing_nonce: u64,
}

#[derive(Debug, Deserialize)]
struct PurchaseAcceptedView {
    pub purchase_id: u64,
    pub burner_taddr: String,
    pub burner_pubkey_hex: String,
    pub mpc_path: String,
    pub required_memo: String,
    pub price_zat: u64,
    pub commission_zat: u64,
    pub payout_fee_zat: u64,
    pub seller_receives_zat: u64,
    pub refund_receives_zat: u64,
    pub expires_at_ns: u64,
}

struct ResolvedListing {
    local_id: i64,
    contract: ContractListingView,
}

async fn resolve_name(indexer_url: &str, name: &str) -> Result<(String, u64, u64, String), reqwest::Error> {
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
    let nonce = resp["result"]["listing"]["nonce"].as_u64().unwrap_or(0);
    let signature = resp["result"]["listing"]["signature"].as_str().unwrap_or("").to_string();
    Ok((seller_ua, price, nonce, signature))
}

fn listing_status_from_contract(status: &str) -> ListingStatus {
    match status {
        "Open" => ListingStatus::Open,
        "Sold" => ListingStatus::Sold,
        "Cancelled" => ListingStatus::Cancelled,
        _ => ListingStatus::Cancelled,
    }
}

fn cache_listing(
    state: &AppState,
    listing: &ContractListingView,
) -> Result<i64, axum::http::StatusCode> {
    state
        .store
        .upsert_listing(
            listing.id as i64,
            &listing.name,
            &listing.seller_ua,
            listing.price_zat,
            listing.commission_bps,
            &listing.treasury_ua,
            listing_status_from_contract(&listing.status),
        )
        .map_err(|e| {
            tracing::error!("upsert listing: {e}");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })
}

async fn ensure_listing(
    state: &AppState,
    name: &str,
) -> Result<ResolvedListing, axum::http::StatusCode> {
    let on_chain = state
        .near
        .view_zns::<Option<ContractListingView>>(
            "get_listing_by_name",
            serde_json::json!({ "name": name }),
        )
        .await
        .map_err(|e| {
            tracing::error!("NEAR get_listing_by_name: {e}");
            axum::http::StatusCode::BAD_GATEWAY
        })?;

    if let Some(listing) = on_chain {
        let local_id = cache_listing(state, &listing)?;
        if listing.status == "Open" {
            return Ok(ResolvedListing {
                local_id,
                contract: listing,
            });
        }
        return Err(axum::http::StatusCode::CONFLICT);
    }

    let (seller_ua, price_zat, nonce, signature) = resolve_name(&state.cfg.indexer_rpc, name)
        .await
        .map_err(|e| {
            tracing::error!("indexer resolve: {e}");
            axum::http::StatusCode::BAD_GATEWAY
        })?;

    if seller_ua.is_empty() || price_zat == 0 || signature.is_empty() {
        tracing::warn!("name not listed: {}", name);
        return Err(axum::http::StatusCode::NOT_FOUND);
    }

    let args = serde_json::json!({
        "name": name,
        "seller_ua": seller_ua,
        "price_zat": price_zat,
        "nonce": nonce,
        "signature_hex": signature,
        "user_pubkey_hex": null,
    });
    let deposit_yocto = 50_000_000_000_000_000_000_000u128;
    let gas = 50_000_000_000_000u64;

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

    let listing: ContractListingView = serde_json::from_slice(&value).map_err(|e| {
        tracing::error!("decode create_listing result: {e}");
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let local_id = cache_listing(state, &listing)?;
    Ok(ResolvedListing {
        local_id,
        contract: listing,
    })
}

fn ns_to_rfc3339(ts_ns: u64) -> Result<String, axum::http::StatusCode> {
    let ts = chrono::DateTime::<chrono::Utc>::from_timestamp_nanos(ts_ns as i64);
    Ok(ts.to_rfc3339())
}

async fn create_purchase_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreatePurchaseRequest>,
) -> Result<Json<CreatePurchaseResponse>, axum::http::StatusCode> {
    let listing = ensure_listing(&state, &body.name).await?;

    if listing.contract.status != "Open" {
        return Err(axum::http::StatusCode::CONFLICT);
    }

    let path = format!(
        "zns-purchase-{}-{}",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default(),
        listing.contract.id
    );

    let args = serde_json::json!({
        "listing_id": listing.contract.id,
        "buyer_ua": body.buyer_ua,
        "mpc_path": path,
    });
    let deposit_yocto = 100_000_000_000_000_000_000_000u128;
    let gas = 100_000_000_000_000u64;

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

    let accepted: PurchaseAcceptedView = serde_json::from_slice(&value).map_err(|e| {
        tracing::error!("decode accept_listing result: {e}");
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let expires_at = ns_to_rfc3339(accepted.expires_at_ns)?;
    let local_purchase_id = state
        .store
        .insert_purchase(
            listing.local_id,
            &body.buyer_ua,
            &accepted.burner_taddr,
            &accepted.burner_pubkey_hex,
            &accepted.mpc_path,
            chrono::DateTime::parse_from_rfc3339(&expires_at)
                .map_err(|e| {
                    tracing::error!("parse expires_at: {e}");
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR
                })?
                .with_timezone(&chrono::Utc),
        )
        .map_err(|e| {
            tracing::error!("insert purchase: {e}");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })?;

    state
        .store
        .set_contract_purchase_id(local_purchase_id, accepted.purchase_id as i64)
        .map_err(|e| {
            tracing::error!("set contract_purchase_id: {e}");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(CreatePurchaseResponse {
        local_purchase_id,
        contract_purchase_id: accepted.purchase_id,
        burner_taddr: accepted.burner_taddr,
        required_memo: accepted.required_memo,
        price_zat: accepted.price_zat,
        commission_zat: accepted.commission_zat,
        fee_zat: accepted.payout_fee_zat,
        seller_receives_zat: accepted.seller_receives_zat,
        refund_receives_zat: accepted.refund_receives_zat,
        expires_at,
    }))
}

pub async fn serve(bind: SocketAddr, state: Arc<AppState>) -> Result<()> {
    let app = Router::new()
        .route("/purchase", post(create_purchase_handler))
        .with_state(state);

    tracing::info!(%bind, "HTTP API starting");
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
