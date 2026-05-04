use anyhow::{Context, Result};
use clap::Parser;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

mod config;
mod db;
mod memo;
mod delists;
mod funding;
mod http;
mod listings;
mod near;
mod payout;
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

    let config_view: serde_json::Value = near
        .view_zns("get_config", serde_json::json!({}))
        .await
        .context("fetch ZNS contract config")?;
    let treasury_ua = config_view["treasury_ua"]
        .as_str()
        .context("treasury_ua missing from contract config")?
        .to_string();
    let commission_bps = config_view["commission_bps"]
        .as_u64()
        .context("commission_bps missing from contract config")?;

    let http_state = Arc::new(http::AppState {
        cfg: cfg.clone(),
        store: store.clone(),
        near,
        watcher,
        memo_signer,
        treasury_ua,
        commission_bps,
    });

    tokio::spawn(funding::run_worker(http_state.clone()));
    tokio::spawn(listings::run_worker(http_state.clone()));
    tokio::spawn(delists::run_worker(http_state.clone()));

    let bind = cfg.bind_addr;
    http::serve(bind, http_state).await.context("http server")?;
    Ok(())
}
