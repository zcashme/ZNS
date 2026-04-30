use anyhow::Result;
use axum::{Router, extract::State, response::Json, routing::post};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::Config;
use crate::db::Store;

pub struct AppState {
    pub cfg: Arc<Config>,
    pub store: Arc<Store>,
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
    let id = state
        .store
        .insert_listing(&body.name,
            &body.seller_ua,
            body.price_zat,
            state.cfg.commission_bps as u64,
            &state.cfg.treasury_ua,
        )
        .map_err(|e| {
            tracing::error!("insert listing: {e}");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(CreateListingResponse {
        local_listing_id: id,
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
    pub burner_taddr: String,
    pub price_zat: u64,
    pub expires_at: String,
}

async fn create_purchase_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreatePurchaseRequest>,
) -> Result<Json<CreatePurchaseResponse>, axum::http::StatusCode> {
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

    // TODO: derive burner via MPC path, build payout/refund bundles,
    // call contract.accept_listing, insert into DB.
    return Err(axum::http::StatusCode::NOT_IMPLEMENTED);
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
