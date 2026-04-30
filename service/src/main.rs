use anyhow::{Context, Result};
use clap::Parser;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

mod config;
mod db;
mod escrow;
mod http;
mod memo;
mod near;
mod payout;
mod zcash;

use config::Config;
use db::Store;
use memo::MemoSigner;
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
        &cfg.mpc_contract,
        &cfg.zns_contract,
    )
    .context("NEAR client init")?;

    let watcher = Watcher::new(&cfg.lwd_url);

    let memo_signer =
        MemoSigner::from_hex(&cfg.admin_ed25519_key).context("admin ed25519 key")?;

    let http_state = Arc::new(http::AppState {
        cfg: cfg.clone(),
        store: store.clone(),
        near,
        watcher,
        memo_signer,
    });

    let bind = cfg.bind_addr;
    http::serve(bind, http_state).await.context("http server")?;
    Ok(())
}
