use anyhow::Result;
use axum::{Router, extract::State, response::Json, routing::post};
use near_primitives::views::FinalExecutionStatus;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::Config;
use crate::db::Store;
use crate::near::NearClient;
use crate::zcash::Watcher;

pub struct AppState {
    pub cfg: Arc<Config>,
    pub store: Arc<Store>,
    pub near: NearClient,
    pub watcher: Watcher,
    pub memo_signer: Option<crate::memo::MemoSigner>,
}

#[derive(Deserialize)]
pub struct CreatePurchaseRequest {
    pub name: String,
    pub buyer_ua: String,
    /// Optional sovereign buyer signature over `BUY:<name>:<buyer_ua>`.
    /// If omitted, the relayer falls back to its admin ed25519 key.
    pub buyer_signature_b64: Option<String>,
    pub buyer_pubkey_b64: Option<String>,
}

#[derive(Serialize)]
pub struct CreatePurchaseResponse {
    pub registration_id: i64,
    pub listing_id: u64,
    pub burner_taddr: String,
    pub price_zat: u64,
    pub commission_zat: u64,
    pub fee_zat: u64,
    pub seller_receives_zat: u64,
    pub buy_memo: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ContractListingView {
    pub id: u64,
    pub name: String,
    pub seller_ua: String,
    pub price_zat: u64,
    pub commission_bps: u64,
    pub treasury_ua: String,
    pub created_at_ns: u64,
    pub listing_nonce: u64,
    pub burner_taddr: String,
    pub burner_pubkey_hex: String,
    pub mpc_path: String,
    pub funded: bool,
    pub buyer_ua: Option<String>,
    pub buyer_signature_b64: Option<String>,
    pub buyer_pubkey_b64: Option<String>,
    pub funding_outpoint_txid_hex: Option<String>,
    pub funding_vout: Option<u32>,
    pub utxo_value_zats: Option<u64>,
    pub payout_tx_hash_hex: Option<String>,
    pub payout_sighash_hex: Option<String>,
    pub payout_fee_zat: u64,
    pub commission_zat: u64,
    pub seller_receives_zat: u64,
}

struct ResolvedListing {
    local_id: i64,
    contract: ContractListingView,
}

async fn resolve_name(
    indexer_url: &str,
    name: &str,
) -> Result<(String, u64, u64, String), reqwest::Error> {
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
    let signature = resp["result"]["listing"]["signature"]
        .as_str()
        .unwrap_or("")
        .to_string();
    Ok((seller_ua, price, nonce, signature))
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
            &listing.burner_taddr,
            &listing.burner_pubkey_hex,
            &listing.mpc_path,
            listing.funded,
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
        return Ok(ResolvedListing {
            local_id,
            contract: listing,
        });
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
        "signature_b64": signature,
        "user_pubkey_b64": null,
    });
    let deposit_yocto = 100_000_000_000_000_000_000_000u128;
    let gas = 100_000_000_000_000u64;

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

async fn create_purchase_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreatePurchaseRequest>,
) -> Result<Json<CreatePurchaseResponse>, axum::http::StatusCode> {
    let listing = ensure_listing(&state, &body.name).await?;

    if listing.contract.funded {
        tracing::warn!("listing {} already funded", listing.contract.name);
        return Err(axum::http::StatusCode::CONFLICT);
    }

    // Default path: relayer's admin key signs the BUY memo.
    // Sovereign override: if the buyer supplies their own ed25519 sig+pk,
    // we verify and use those instead. Either way the DB stores final
    // credentials and the on-chain memo embeds them.
    let (sig_b64, pk_b64, is_sovereign) =
        match (body.buyer_signature_b64, body.buyer_pubkey_b64) {
            (Some(sig), Some(pk)) => {
                if !crate::memo::verify_buy_signature(
                    &listing.contract.name,
                    &body.buyer_ua,
                    &sig,
                    &pk,
                ) {
                    tracing::warn!(
                        "buyer signature verification failed for {}",
                        listing.contract.name
                    );
                    return Err(axum::http::StatusCode::UNAUTHORIZED);
                }
                (sig, pk, true)
            }
            _ => {
                let Some(signer) = state.memo_signer.as_ref() else {
                    tracing::warn!(
                        "no admin key configured and buyer didn't sign for {}",
                        listing.contract.name
                    );
                    return Err(axum::http::StatusCode::SERVICE_UNAVAILABLE);
                };
                let (sig, pk) =
                    signer.sign_buy_credentials(&listing.contract.name, &body.buyer_ua);
                (sig, pk, false)
            }
        };

    if let Some(existing) = state
        .store
        .get_active_registration_for_listing(listing.local_id)
        .map_err(|e| {
            tracing::error!("check active registration: {e}");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })?
    {
        tracing::info!(
            "listing {} already has an active registration {}",
            listing.contract.name,
            existing.id
        );
        return Err(axum::http::StatusCode::CONFLICT);
    }

    let registration_id = state
        .store
        .insert_registration(
            listing.local_id,
            &body.buyer_ua,
            &sig_b64,
            &pk_b64,
            is_sovereign,
        )
        .map_err(|e| {
            tracing::error!("insert registration: {e}");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let buy_memo = format!(
        "ZNS:BUY:{}:{}:{}:{}",
        listing.contract.name,
        body.buyer_ua,
        sig_b64,
        pk_b64,
    );

    Ok(Json(CreatePurchaseResponse {
        registration_id,
        listing_id: listing.contract.id,
        burner_taddr: listing.contract.burner_taddr,
        price_zat: listing.contract.price_zat,
        commission_zat: listing.contract.commission_zat,
        fee_zat: listing.contract.payout_fee_zat,
        seller_receives_zat: listing.contract.seller_receives_zat,
        buy_memo,
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
