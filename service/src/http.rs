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
    pub treasury_ua: String,
    pub commission_bps: u64,
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
    pub created_at_ns: u64,
    pub listing_nonce: u64,
    pub burner_taddr: String,
    pub burner_pubkey: Vec<u8>,
    pub mpc_path: String,
    pub funded: bool,
    pub buyer_ua: Option<String>,
    pub buyer_pubkey_b64: Option<String>,
    pub funding_outpoint: Option<([u8; 32], u32)>,
    pub utxo_value_zats: Option<u64>,
    pub payout_tx_hash: Option<[u8; 32]>,
    pub payout_sighash: Option<[u8; 32]>,
}

impl ContractListingView {
    pub fn burner_pubkey_hex(&self) -> String {
        hex::encode(&self.burner_pubkey)
    }
    pub fn funding_outpoint_txid_hex(&self) -> Option<String> {
        self.funding_outpoint.as_ref().map(|(txid, _)| hex::encode(txid))
    }
    pub fn funding_vout(&self) -> Option<u32> {
        self.funding_outpoint.map(|(_, vout)| vout)
    }
    pub fn payout_tx_hash_hex(&self) -> Option<String> {
        self.payout_tx_hash.map(|h| hex::encode(h))
    }
    pub fn payout_sighash_hex(&self) -> Option<String> {
        self.payout_sighash.map(|h| hex::encode(h))
    }
    pub fn commission_zat(&self, commission_bps: u64) -> u64 {
        self.price_zat * commission_bps / 10_000
    }
    pub fn seller_receives_zat(&self, commission_bps: u64, payout_fee_zat: u64) -> u64 {
        self.price_zat
            .saturating_sub(self.commission_zat(commission_bps))
            .saturating_sub(payout_fee_zat)
    }
}

struct ResolvedListing {
    local_id: i64,
    contract: ContractListingView,
}

async fn resolve_name(
    indexer_url: &str,
    name: &str,
) -> Result<(String, u64, u64, String, Option<String>), reqwest::Error> {
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
    let pubkey = resp["result"]["listing"]["pubkey"]
        .as_str()
        .map(|s| s.to_string());
    Ok((seller_ua, price, nonce, signature, pubkey))
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
            &listing.burner_taddr,
            &listing.burner_pubkey_hex(),
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
    let (seller_ua, price_zat, nonce, signature, pubkey) = resolve_name(&state.cfg.indexer_rpc, name)
        .await
        .map_err(|e| {
            tracing::error!("indexer resolve: {e}");
            axum::http::StatusCode::BAD_GATEWAY
        })?;

    if seller_ua.is_empty() || price_zat == 0 || signature.is_empty() {
        tracing::warn!("name not listed: {}", name);
        return Err(axum::http::StatusCode::NOT_FOUND);
    }

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

    if let Some(existing) = on_chain {
        if !existing.funded && nonce > existing.listing_nonce {
            let args = serde_json::json!({
                "name": name,
                "seller_ua": seller_ua,
                "price_zat": price_zat,
                "nonce": nonce,
                "signature_b64": signature,
                "user_pubkey_b64": pubkey,
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
            return Ok(ResolvedListing {
                local_id,
                contract: listing,
            });
        }

        let local_id = cache_listing(state, &existing)?;
        return Ok(ResolvedListing {
            local_id,
            contract: existing,
        });
    }

    let args = serde_json::json!({
        "name": name,
        "seller_ua": seller_ua,
        "price_zat": price_zat,
        "nonce": nonce,
        "signature_b64": signature,
        "user_pubkey_b64": pubkey,
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

    // Always sign with the admin key — the admin signature proves the relayer
    // confirmed a valid UTXO and is the anti-forgery anchor for indexers.
    // Sovereign path: the buyer also signs (verified on-chain) and their pubkey
    // is appended to the memo as a mode flag.
    let Some(signer) = state.memo_signer.as_ref() else {
        tracing::warn!(
            "no admin memo signer configured for {}",
            listing.contract.name
        );
        return Err(axum::http::StatusCode::SERVICE_UNAVAILABLE);
    };

    let (admin_sig_b64, buyer_sig_b64, buyer_pk_b64, is_sovereign) =
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
                let (admin_sig, _) =
                    signer.sign_buy_credentials(&listing.contract.name, &body.buyer_ua);
                (admin_sig, sig, pk, true)
            }
            _ => {
                let (admin_sig, _admin_pk) =
                    signer.sign_buy_credentials(&listing.contract.name, &body.buyer_ua);
                (admin_sig, String::new(), String::new(), false)
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
            &buyer_sig_b64,
            &buyer_pk_b64,
            &admin_sig_b64,
            is_sovereign,
        )
        .map_err(|e| {
            tracing::error!("insert registration: {e}");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let buy_memo = if is_sovereign {
        format!(
            "ZNS:BUY:{}:{}:{}:{}",
            listing.contract.name,
            body.buyer_ua,
            admin_sig_b64,
            buyer_pk_b64,
        )
    } else {
        format!(
            "ZNS:BUY:{}:{}:{}",
            listing.contract.name,
            body.buyer_ua,
            admin_sig_b64,
        )
    };

    let fee_zat = crate::payout::payout_fee();
    Ok(Json(CreatePurchaseResponse {
        registration_id,
        listing_id: listing.contract.id,
        burner_taddr: listing.contract.burner_taddr.clone(),
        price_zat: listing.contract.price_zat,
        commission_zat: listing.contract.commission_zat(state.commission_bps),
        fee_zat,
        seller_receives_zat: listing.contract.seller_receives_zat(state.commission_bps, fee_zat),
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
