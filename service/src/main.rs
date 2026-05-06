use anyhow::{Context, Result};
use clap::Parser;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

mod burner;
mod config;
mod contract_view;
mod db;
mod delists;
mod funding;
mod http;
mod listings;
mod memo;
mod near;
mod payout;
mod sp1_prover;
mod zcash;

use config::Config;
use db::Store;
use near::NearClient;
use zcash::Watcher;

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    if let Err(e) = dotenvy::dotenv() {
        tracing::debug!("no .env file loaded: {e}");
    }

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cfg = Arc::new(Config::parse());
    tracing::info!("zns-service starting");

    let store = Arc::new(Store::open(&cfg.sqlite_path).context("open store")?);

    let near = NearClient::new(
        &cfg.near_rpc,
        &cfg.near_account,
        &cfg.near_secret_key,
        &cfg.zns_contract,
    )
    .context("NEAR client init")?;

    let watcher = Watcher::new(&cfg.lwd_url);

    let memo_signer = cfg
        .admin_ed25519_key
        .as_ref()
        .and_then(|k| memo::MemoSigner::from_hex(k).ok());

    let indexer_status: serde_json::Value = reqwest::Client::new()
        .post(&cfg.indexer_rpc)
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "status", "params": [],
        }))
        .send()
        .await
        .context("fetch indexer status")?
        .json()
        .await
        .context("parse indexer status")?;
    let treasury_ua = indexer_status["result"]["address"]
        .as_str()
        .context("indexer status missing address field")?
        .to_string();

    let config_view: serde_json::Value = near
        .view_zns("get_config", serde_json::json!({}))
        .await
        .context("fetch ZNS contract config")?;
    let commission_bps = config_view["commission_bps"]
        .as_u64()
        .context("commission_bps missing from contract config")?;
    let mpc_root_pubkey = config_view["mpc_root_pubkey"]
        .as_str()
        .context("mpc_root_pubkey missing from contract config")?
        .to_string();
    let mainnet = config_view["mainnet"]
        .as_bool()
        .context("mainnet missing from contract config")?;
    let contract_account = cfg.zns_contract.clone();

    let http_state = Arc::new(http::AppState {
        cfg: cfg.clone(),
        store: store.clone(),
        near,
        watcher,
        memo_signer,
        treasury_ua,
        commission_bps,
        mpc_root_pubkey,
        contract_account,
        mainnet,
    });

    tokio::spawn(funding::run_worker(http_state.clone()));
    tokio::spawn(listings::run_worker(http_state.clone()));
    tokio::spawn(delists::run_worker(http_state.clone()));

    let bind = cfg.bind_addr;
    http::serve(bind, http_state).await.context("http server")?;
    Ok(())
}
