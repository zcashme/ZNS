use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::json;

use crate::http::AppState;

const LISTING_SYNC_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Deserialize)]
struct RpcResponse<T> {
    result: T,
}

#[derive(Debug, Deserialize)]
struct RegistrationItem {
    name: String,
    address: String,
    listing: Option<ListingItem>,
}

#[derive(Debug, Deserialize)]
struct ListingItem {
    price: u64,
}

pub async fn run_worker(state: Arc<AppState>) {
    let client = reqwest::Client::new();
    loop {
        if let Err(e) = sync_once(&state, &client).await {
            tracing::error!("listing mirror worker error: {e}");
        }
        tokio::time::sleep(LISTING_SYNC_INTERVAL).await;
    }
}

async fn sync_once(state: &Arc<AppState>, client: &reqwest::Client) -> Result<()> {
    let limit = 500u64;
    let mut offset = 0u64;

    loop {
        let resp: RpcResponse<Vec<RegistrationItem>> = client
            .post(&state.cfg.indexer_rpc)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "resolve",
                "params": ["", limit, offset],
            }))
            .send()
            .await?
            .json()
            .await
            .context("parse indexer resolve response")?;

        if resp.result.is_empty() {
            break;
        }

        for item in &resp.result {
            let Some(listing) = &item.listing else {
                continue;
            };

            let on_chain = state
                .near
                .view_zns::<Option<crate::http::ContractListingView>>(
                    "get_listing_by_name",
                    json!({ "name": item.name }),
                )
                .await;

            match on_chain {
                Ok(Some(_)) => continue,
                Ok(None) => {
                    let deposit_yocto = 50_000_000_000_000_000_000_000u128;
                    let gas = 50_000_000_000_000u64;
                    tracing::info!("mirroring listing {} to NEAR contract", item.name);
                    if let Err(e) = state
                        .near
                        .call_zns_mut(
                            "create_listing",
                            json!({
                                "name": item.name,
                                "seller_ua": item.address,
                                "price_zat": listing.price,
                            }),
                            gas,
                            deposit_yocto,
                        )
                        .await
                    {
                        tracing::error!("failed to mirror listing {}: {e}", item.name);
                    }
                }
                Err(e) => {
                    tracing::error!("NEAR get_listing_by_name for {}: {e}", item.name);
                }
            }
        }

        if resp.result.len() < limit as usize {
            break;
        }
        offset += limit;
    }

    Ok(())
}
