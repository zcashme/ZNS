//! End-to-end state machine for ZNS non-custodial sales.
//!
//! Fully stateless relative to the service process.  All durable intent
//! state lives in SQLite (`db::IntentStore`).  On restart the service
//! replays from the database and lightwalletd.
//!
//! 1. Bob calls HTTP API → intent created in SQLite (PendingPayment)
//! 2. Background loop polls lightwalletd → on UTXO detected → PaymentConfirmed
//! 3. Service builds unsigned payout tx, computes sighash → PayoutPending
//! 4. Service calls NEAR v1.signer → on signature → assembles, broadcasts → Completed
//! 5. Service signs BUY memo, broadcasts to Registry UA → Completed

use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::time::{Duration, interval};
use zcash_transparent as transparent;

fn hex_to_le_array(display_hex: &str) -> Result<[u8; 32]> {
    let mut bytes = hex::decode(display_hex.trim()).context("decode txid hex")?;
    if bytes.len() != 32 {
        anyhow::bail!("txid must be 32 bytes, got {}", bytes.len());
    }
    bytes.reverse();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

use crate::config::Config;
use crate::db::{IntentStatus, IntentStore};
use crate::escrow;
use crate::memo::MemoSigner;
use crate::near::NearMpcClient;
use crate::payout::{self, PayoutInputs};
use crate::zcash::Watcher;

pub struct StateMachine {
    cfg: Arc<Config>,
    store: Arc<IntentStore>,
    watcher: Watcher,
    mpc: NearMpcClient,
    memo_signer: MemoSigner,
}

impl StateMachine {
    pub fn new(
        cfg: Arc<Config>,
        store: Arc<IntentStore>,
        watcher: Watcher,
        mpc: NearMpcClient,
        memo_signer: MemoSigner,
    ) -> Self {
        Self {
            cfg,
            store,
            watcher,
            mpc,
            memo_signer,
        }
    }

    /// Background tick loop.
    pub async fn run(&self) -> Result<()> {
        let mut tick = interval(Duration::from_secs(self.cfg.poll_interval_secs));
        loop {
            tick.tick().await;
            if let Err(e) = self.process_tick().await {
                tracing::error!("tick error: {e:?}");
            }
        }
    }

    async fn process_tick(&self) -> Result<()> {
        let intents = self.store.list_active_intents().context("list intents")?;
        if !intents.is_empty() {
            tracing::debug!(count = intents.len(), "processing active intents");
        }
        for intent in intents {
            match intent.status {
                IntentStatus::PendingPayment => {
                    if let Err(e) = self.handle_pending(&intent).await {
                        tracing::warn!(intent.id, "pending handler: {e}");
                    }
                }
                IntentStatus::PaymentConfirmed => {
                    if let Err(e) = self.handle_confirmed(&intent).await {
                        tracing::warn!(intent.id, "confirmed handler: {e:?}");
                    }
                }
                IntentStatus::PayoutPending => {
                    if let Err(e) = self.handle_poll_mpc(&intent).await {
                        tracing::warn!(intent.id, "poll mpc handler: {e:?}");
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    // ─── PendingPayment ────────────────────────────────────────────────────

    async fn handle_pending(&self, intent: &crate::db::Intent) -> Result<()> {
        let utxos = self.watcher.get_utxos(&intent.burner_taddr).await?;

        let fee = payout::payout_fee();
        let fee_reserve = fee;
        let found = utxos.into_iter().find(|u| {
            escrow::verify_sufficient_payment(
                u.value_zats,
                intent.price_zat,
                fee_reserve,
                self.cfg.min_confirmations,
                u.confirmations,
            )
        });

        let Some(utxo) = found else {
            // Check expiry.
            if chrono::Utc::now() > intent.expires_at {
                self.store.set_expired(intent.id)?;
                tracing::info!(intent.id, "intent expired");
            }
            return Ok(());
        };

        tracing::info!(
            intent.id, txid = %utxo.txid, value = utxo.value_zats,
            "payment detected"
        );

        self.store
            .set_zcash_txid(intent.id, &utxo.txid)
            .context("db set zcash txid")?;
        Ok(())
    }

    // ─── PaymentConfirmed ────────────────────────────────────────────────

    async fn handle_confirmed(&self, intent: &crate::db::Intent) -> Result<()> {
        let zcash_txid = intent
            .zcash_txid
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing zcash txid for confirmed intent"))?;

        // Resolve Alice's current UA from our indexer.
        let seller_ua = self
            .resolve_seller_ua(&intent.name)
            .await
            .with_context(|| format!("resolve seller ua for {}", intent.name))?;

        // Re-derive the burner pubkey for this intent.
        let burner = escrow::derive_burner(
            &self.cfg.mpc_master_pubkey,
            &self.cfg.near_account,
            &intent.mpc_path,
            &self.cfg.zcash_network,
        )?;

        // Find the UTXO again so we have its outpoint, value and script_pubkey.
        let utxos = self.watcher.get_utxos(&intent.burner_taddr).await?;
        let utxo = utxos
            .into_iter()
            .find(|u| u.txid == zcash_txid)
            .with_context(|| format!("burner UTXO not found for txid {zcash_txid}"))?;

        // Commission is computed from the listed price (the figure the seller
        // agreed to), not the UTXO value, so a buyer overpayment doesn't
        // inflate the platform cut. The seller absorbs any surplus until we
        // implement refunds. Underpayment is already rejected upstream by
        // `verify_sufficient_payment`, so utxo.value_zats >= price + fee here.
        let commission = intent.price_zat * self.cfg.commission_bps as u64 / 10_000;
        let fee = payout::payout_fee();
        let seller_amount = utxo
            .value_zats
            .checked_sub(commission)
            .and_then(|v| v.checked_sub(fee))
            .with_context(|| "utxo value too small to cover commission + fee")?;

        let target_height = self.watcher.latest_height().await? as u32;
        let outpoint = transparent::bundle::OutPoint::new(hex_to_le_array(zcash_txid)?, utxo.vout);

        // Build BUY memo up front so we can embed it in the treasury output.
        let memo_str = self.memo_signer.sign_buy(&intent.name, &intent.buyer_ua);
        let mut memo_bytes = [0u8; 512];
        let raw = memo_str.as_bytes();
        let len = raw.len().min(512);
        memo_bytes[..len].copy_from_slice(&raw[..len]);

        let plan = payout::build_unsigned(PayoutInputs {
            network: &self.cfg.zcash_network,
            target_height,
            utxo_outpoint: outpoint,
            utxo_value_zats: utxo.value_zats,
            utxo_script_pubkey: utxo.script,
            burner_pubkey: burner.public_key,
            seller_ua: &seller_ua,
            treasury_ua: &self.cfg.treasury_ua,
            seller_amount,
            treasury_amount: commission,
            memo: memo_bytes,
            fee: Some(fee),
        })
        .context("build unsigned payout")?;

        let tx_hash = hex::encode(plan.sighash);
        self.store
            .set_payout_pending(intent.id, &tx_hash)
            .context("db set payout pending")?;

        let mpc_sig = self
            .mpc
            .request_sign(&intent.mpc_path, &plan.sighash)
            .await
            .with_context(|| format!("MPC sign for intent {}", intent.id))?;

        tracing::info!(intent.id, "MPC signature received");

        // Convert v1.signer response {big_r: {affine_point}, s: {scalar}} into
        // secp256k1 compact format (64 bytes).
        let r_bytes = hex::decode(&mpc_sig.big_r.affine_point)
            .context("decode MPC big_r affine_point")?;
        let s_bytes = hex::decode(&mpc_sig.s.scalar)
            .context("decode MPC s scalar")?;
        let mut compact = [0u8; 64];
        // big_r is a compressed point (33 bytes); the r scalar is the last 32 bytes.
        let r_start = r_bytes.len().saturating_sub(32);
        compact[..32].copy_from_slice(&r_bytes[r_start..]);
        compact[32..].copy_from_slice(&s_bytes);

        let signed_bytes = payout::finalize_with_mpc(plan, &compact)
            .context("finalize payout tx")?;

        let payout_txid = self
            .watcher
            .send_tx(&signed_bytes)
            .await
            .context("broadcast payout tx")?;
        tracing::info!(intent.id, %payout_txid, "broadcasted payout tx with embedded BUY memo");

        self.store
            .set_completed(intent.id, &payout_txid)
            .context("db set completed")?;

        Ok(())
    }

    // ─── PayoutPending ───────────────────────────────────────────────────

    async fn handle_poll_mpc(&self, _intent: &crate::db::Intent) -> Result<()> {
        // In the v1.signer model the signature is returned synchronously (async/blocking
        // inside broadcast_tx_commit), so we should never land here.  Keeping the handler
        // for future retry / timeout logic.
        Ok(())
    }

    // ─── Helpers ─────────────────────────────────────────────────────────

    async fn resolve_seller_ua(&self, name: &str) -> Result<String> {
        let resp: serde_json::Value = reqwest::Client::new()
            .post(&self.cfg.indexer_rpc)
            .json(&serde_json::json!({
                "jsonrpc": "2.0", "id": 1,
                "method": "resolve", "params": [name],
            }))
            .send()
            .await?
            .json()
            .await?;
        Ok(resp["result"]["address"].as_str().unwrap_or("").to_string())
    }
}
