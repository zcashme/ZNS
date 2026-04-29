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
mod state_machine;
mod zcash;

use config::Config;
use db::IntentStore;
use memo::MemoSigner;
use near::NearMpcClient;
use state_machine::StateMachine;
use zcash::Watcher;

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env file before CLI parsing.
    if let Err(e) = dotenvy::dotenv() {
        tracing::debug!("no .env file loaded: {e}");
    }

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cfg = Arc::new(Config::parse());
    tracing::info!("zns-custody-service starting");
    tracing::info!(
        near_account = %cfg.near_account,
        mpc_contract = %cfg.mpc_contract,
        "NEAR/MPC config"
    );

    // SQLite — single source of truth.
    let store = Arc::new(IntentStore::open(&cfg.sqlite_path).context("open intent store")?);

    // MPC client (talks directly to v1.signer).
    let mpc = NearMpcClient::new(
        &cfg.near_rpc,
        &cfg.near_account,
        &cfg.near_secret_key,
        &cfg.mpc_contract,
    )
    .context("MPC client init")?;

    // Zcash lightwalletd watcher.
    let watcher = Watcher::new(&cfg.lwd_url);

    // Admin Ed25519 memo signer.
    let memo_signer = MemoSigner::from_hex(&cfg.admin_ed25519_key).context("admin ed25519 key")?;

    // Shared HTTP state.
    let http_state = Arc::new(http::AppState {
        cfg: cfg.clone(),
        store: store.clone(),
    });

    // Spawn HTTP API.
    let http_handle = tokio::spawn({
        let bind = cfg.bind_addr;
        let state = http_state.clone();
        async move {
            if let Err(e) = http::serve(bind, state).await {
                tracing::error!("http server died: {e}");
            }
        }
    });

    // Spawn state machine (background watcher + MPC coordinator).
    let sm_handle = tokio::spawn({
        let cfg = cfg.clone();
        let store = store.clone();
        let watcher = watcher;
        let mpc = mpc;
        let memo_signer = memo_signer;
        async move {
            let sm = StateMachine::new(cfg, store, watcher, mpc, memo_signer);
            if let Err(e) = sm.run().await {
                tracing::error!("state machine died: {e}");
            }
        }
    });

    tokio::select! {
        _ = http_handle => tracing::info!("http task ended"),
        _ = sm_handle => tracing::info!("state machine task ended"),
    }

    Ok(())
}
