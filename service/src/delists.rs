use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::json;

use crate::contract_view::ContractListingMeta;
use crate::http::AppState;

const DELIST_SYNC_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Deserialize)]
struct RpcResponse<T> {
    result: T,
}

#[derive(Debug, Deserialize)]
struct EventEntry {
    name: String,
    #[allow(dead_code)]
    action: String,
    #[allow(dead_code)]
    txid: String,
    #[allow(dead_code)]
    height: u64,
    signature: Option<String>,
    nonce: Option<u64>,
    pubkey: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EventsResult {
    events: Vec<EventEntry>,
    #[allow(dead_code)]
    total: u64,
}

pub async fn run_worker(state: Arc<AppState>) {
    let client = reqwest::Client::new();
    loop {
        if let Err(e) = sync_once(&state, &client).await {
            tracing::error!("delist mirror worker error: {e}");
        }
        tokio::time::sleep(DELIST_SYNC_INTERVAL).await;
    }
}

async fn sync_once(state: &Arc<AppState>, client: &reqwest::Client) -> Result<()> {
    let limit = 500u64;
    let mut offset = 0u64;

    loop {
        let resp: RpcResponse<EventsResult> = client
            .post(&state.cfg.indexer_rpc)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "events",
                "params": [null, "DELIST", null, limit, offset],
            }))
            .send()
            .await?
            .json()
            .await
            .context("parse indexer events response")?;

        if resp.result.events.is_empty() {
            break;
        }

        for event in &resp.result.events {
            let Some(signature) = &event.signature else {
                continue;
            };
            let Some(nonce) = event.nonce else {
                continue;
            };

            let listing = state
                .near
                .view_zns::<Option<ContractListingMeta>>(
                    "get_listing_by_name",
                    json!({ "name": event.name }),
                )
                .await;

            let Some(listing) = listing.ok().flatten() else {
                continue;
            };

            if listing.funded {
                // Cannot cancel a funded listing — payout is in flight.
                continue;
            }

            let deposit_yocto = 50_000_000_000_000_000_000_000u128;
            let gas = 50_000_000_000_000u64;

            tracing::info!(
                "mirroring DELIST for {} to NEAR contract (listing id {})",
                event.name,
                listing.id
            );

            if let Err(e) = state
                .near
                .call_zns_mut(
                    "cancel_listing",
                    json!({
                        "id": listing.id,
                        "nonce": nonce,
                        "signature_b64": signature,
                        "user_pubkey_b64": event.pubkey,
                    }),
                    gas,
                    deposit_yocto,
                )
                .await
            {
                tracing::error!("failed to mirror DELIST for {}: {e}", event.name);
            }
        }

        if resp.result.events.len() < limit as usize {
            break;
        }
        offset += limit;
    }

    Ok(())
}
