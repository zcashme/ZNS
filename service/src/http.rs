use anyhow::Result;
use axum::{Router, extract::State, response::Json, routing::post};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::Config;
use crate::db::IntentStore;
use crate::escrow;

/// Shared application state passed to every HTTP handler.
pub struct AppState {
    pub cfg: Arc<Config>,
    pub store: Arc<IntentStore>,
}

#[derive(Deserialize)]
pub struct PurchaseRequest {
    pub name: String,
    /// Bob's Orchard unified address (where he wants the name transferred).
    pub buyer_ua: String,
    /// Optional transparent refund address.
    pub buyer_taddr: Option<String>,
}

#[derive(Serialize)]
pub struct PurchaseResponse {
    pub intent_id: i64,
    pub burner_taddr: String,
    pub price_zat: u64,
    pub commission_zat: u64,
    pub expires_at: String,
    pub instruction: String,
}

async fn purchase_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PurchaseRequest>,
) -> Result<Json<PurchaseResponse>, axum::http::StatusCode> {
    // Resolve listing price from indexer.
    let price_zat = resolve_price(&state.cfg.indexer_rpc, &body.name)
        .await
        .map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;

    if price_zat == 0 {
        return Err(axum::http::StatusCode::BAD_REQUEST);
    }

    // The MPC path must be stable across derive + sign, so generate it up front.
    // We use a high-resolution timestamp; the predecessor + path uniquely scopes the
    // burner key to this service's NEAR account.
    let path = format!(
        "zns-{}-{}",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default(),
        body.name.replace('/', "_")
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

    let commission = price_zat * state.cfg.commission_bps as u64 / 10_000;
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(15);

    let intent_id = state
        .store
        .insert_intent(
            &body.name,
            &body.buyer_ua,
            body.buyer_taddr.as_deref(),
            price_zat,
            &burner.taddr,
            &burner.path,
            expires_at,
        )
        .map_err(|e| {
            tracing::error!("insert intent: {e}");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let resp = PurchaseResponse {
        intent_id,
        burner_taddr: burner.taddr.clone(),
        price_zat,
        commission_zat: commission,
        expires_at: expires_at.to_rfc3339(),
        instruction: format!(
            "Send exactly {} ZEC to {}. The sale completes automatically once confirmed on-chain.",
            price_zat as f64 / 100_000_000.0,
            burner.taddr
        ),
    };

    Ok(Json(resp))
}

async fn resolve_price(indexer_url: &str, name: &str) -> Result<u64> {
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

    let price = resp["result"]["listing"]["price"].as_u64().unwrap_or(0);
    Ok(price)
}

pub async fn serve(bind: SocketAddr, state: Arc<AppState>) -> Result<()> {
    let app = Router::new()
        .route("/purchase", post(purchase_handler))
        .with_state(state);

    tracing::info!(%bind, "HTTP API starting");
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
