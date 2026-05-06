//! SP1 Groth16 prover for ZNS payout note-commitment proofs.
//!
//! Delegates proof generation to the `prove` binary from the sp1-guest
//! workspace by spawning it as a subprocess and communicating via JSON on
//! stdin/stdout.  This keeps the heavy sp1-sdk out of the service's own Cargo
//! dependency graph.
//!
//! The binary path is configured via `ZNS_PROVER_BIN` (required in
//! production).  If unset, defaults to the debug build path next to the
//! sp1-guest workspace for local development.

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::payout::PayoutPlan;

/// Default path to the `prove` binary when `ZNS_PROVER_BIN` is not set.
const DEFAULT_PROVER_BIN: &str =
    "../sp1-guest/target/release/prove";

/// Groth16 proof data returned by the subprocess.
pub struct Sp1PayoutProof {
    /// ABI-encoded Groth16 proof bytes (from gnark / Solidity encoding).
    /// Phase 4 will pass these to the NEAR contract.
    pub encoded_proof_bytes: Vec<u8>,
    /// Raw SP1 public values as committed by the guest (160 bytes for the
    /// 5 × 32-byte fields: seller_cmx, treasury_cmx, seller_pk_d,
    /// treasury_pk_d, tx_hash).
    pub public_values: Vec<u8>,
    /// SP1 verifying-key hash (bytes32) — used by the NEAR contract to
    /// identify the correct guest program.
    pub vkey_hash: [u8; 32],
}

/// JSON wire format sent to the `prove` subprocess on stdin.
#[derive(Serialize)]
struct ProveInput {
    seller_addr_hex: String,
    seller_value: u64,
    seller_rho_hex: String,
    seller_rseed_hex: String,
    treasury_addr_hex: String,
    treasury_value: u64,
    treasury_rho_hex: String,
    treasury_rseed_hex: String,
    tx_hash_hex: String,
}

/// JSON wire format received from the `prove` subprocess on stdout.
#[derive(Deserialize)]
struct ProveOutput {
    encoded_proof_hex: String,
    public_values_hex: String,
    vkey_hash_hex: String,
}

/// JSON wire format on subprocess failure.
#[derive(Deserialize)]
struct ProveError {
    error: String,
}

/// Generate an SP1 Groth16 proof for a payout [`PayoutPlan`].
///
/// Errors if `plan` was built for a refund (no seller/treasury notes) or if
/// the `prove` subprocess fails.
pub async fn prove(plan: &PayoutPlan) -> Result<Sp1PayoutProof> {
    let seller_note = plan
        .seller_note
        .as_ref()
        .context("no seller note in plan — SP1 proof only supported for payout bundles")?;
    let treasury_note = plan
        .treasury_note
        .as_ref()
        .context("no treasury note in plan — SP1 proof only supported for payout bundles")?;

    let seller_addr = seller_note.recipient().to_raw_address_bytes();
    let treasury_addr = treasury_note.recipient().to_raw_address_bytes();

    let input = ProveInput {
        seller_addr_hex: hex::encode(seller_addr),
        seller_value: seller_note.value().inner(),
        seller_rho_hex: hex::encode(seller_note.rho().to_bytes()),
        seller_rseed_hex: hex::encode(seller_note.rseed().as_bytes()),
        treasury_addr_hex: hex::encode(treasury_addr),
        treasury_value: treasury_note.value().inner(),
        treasury_rho_hex: hex::encode(treasury_note.rho().to_bytes()),
        treasury_rseed_hex: hex::encode(treasury_note.rseed().as_bytes()),
        tx_hash_hex: hex::encode(plan.sighash),
    };

    let bin = std::env::var("ZNS_PROVER_BIN")
        .unwrap_or_else(|_| DEFAULT_PROVER_BIN.to_string());

    tracing::info!(%bin, "spawning SP1 prover subprocess");

    let output = tokio::process::Command::new(&bin)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .with_context(|| format!("failed to spawn prove binary at {bin}"))?
        .wait_with_output_and_input(serde_json::to_vec(&input)?)
        .await
        .context("prove subprocess I/O failed")?;

    if !output.status.success() {
        // Try to parse an error message from stdout before bailing.
        if let Ok(err) = serde_json::from_slice::<ProveError>(&output.stdout) {
            return Err(anyhow!("prove subprocess failed: {}", err.error));
        }
        return Err(anyhow!(
            "prove subprocess exited with status {}",
            output.status
        ));
    }

    let result: ProveOutput = serde_json::from_slice(&output.stdout)
        .context("failed to parse prove subprocess output")?;

    let encoded_proof_bytes =
        hex::decode(&result.encoded_proof_hex).context("decode encoded_proof_hex")?;
    let public_values =
        hex::decode(&result.public_values_hex).context("decode public_values_hex")?;
    let vkey_hash_bytes =
        hex::decode(&result.vkey_hash_hex).context("decode vkey_hash_hex")?;
    let vkey_hash: [u8; 32] = vkey_hash_bytes
        .try_into()
        .map_err(|_| anyhow!("vkey_hash must be 32 bytes"))?;

    tracing::info!(
        tx_hash = hex::encode(plan.sighash),
        vkey_hash = hex::encode(vkey_hash),
        "SP1 Groth16 proof received from subprocess"
    );

    Ok(Sp1PayoutProof {
        encoded_proof_bytes,
        public_values,
        vkey_hash,
    })
}

/// Extension trait to write stdin + collect stdout for a spawned child.
trait ChildExt {
    async fn wait_with_output_and_input(
        self,
        input: Vec<u8>,
    ) -> std::io::Result<std::process::Output>;
}

impl ChildExt for tokio::process::Child {
    async fn wait_with_output_and_input(
        mut self,
        input: Vec<u8>,
    ) -> std::io::Result<std::process::Output> {
        use tokio::io::AsyncWriteExt;
        if let Some(mut stdin) = self.stdin.take() {
            stdin.write_all(&input).await?;
            // Drop stdin to signal EOF to the subprocess.
        }
        self.wait_with_output().await
    }
}
