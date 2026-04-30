use anyhow::{Context, Result, bail};
use near_crypto::Signer;
use near_jsonrpc_client::{JsonRpcClient, methods};
use near_primitives::{
    transaction::{Action, Transaction, TransactionV0},
    types::{AccountId, FunctionArgs},
    views::{FinalExecutionStatus, QueryRequest},
};
use serde::Deserialize;
use std::str::FromStr;

/// Generic NEAR client for calling both the ZNS contract and the MPC signer.
pub struct NearClient {
    pub account: AccountId,
    client: JsonRpcClient,
    signer: Signer,
    pub mpc_contract: AccountId,
    pub zns_contract: AccountId,
}

/// Response from v1.signer after a successful `sign` call.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct MpcSignature {
    pub big_r: AffinePoint,
    pub s: ScalarHex,
    pub recovery_id: u8,
    #[allow(dead_code)]
    pub scheme: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AffinePoint {
    pub affine_point: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScalarHex {
    pub scalar: String,
}

impl NearClient {
    pub fn new(
        rpc_url: &str,
        account: &str,
        secret_key: &str,
        mpc_contract: &str,
        zns_contract: &str,
    ) -> Result<Self> {
        let signer = near_crypto::InMemorySigner::from_secret_key(
            AccountId::from_str(account)?,
            near_crypto::SecretKey::from_str(secret_key)?,
        );
        let client = JsonRpcClient::connect(rpc_url);
        Ok(Self {
            account: account.parse()?,
            client,
            signer,
            mpc_contract: mpc_contract.parse()?,
            zns_contract: zns_contract.parse()?,
        })
    }

    /// Call a mutable method on any NEAR contract and return the execution outcome.
    pub async fn call_mut(
        &self,
        contract: &AccountId,
        method: &str,
        args: serde_json::Value,
        gas: u64,
        deposit: u128,
    ) -> Result<near_primitives::views::FinalExecutionOutcomeView> {
        let block = self
            .client
            .call(methods::block::RpcBlockRequest {
                block_reference: near_primitives::types::Finality::Final.into(),
            })
            .await?;
        let block_hash = block.header.hash;

        let nonce = self.next_nonce().await?;

        let tx_v0 = TransactionV0 {
            signer_id: self.account.clone(),
            public_key: self.signer.public_key(),
            nonce,
            receiver_id: contract.clone(),
            block_hash,
            actions: vec![Action::FunctionCall(Box::new(
                near_primitives::transaction::FunctionCallAction {
                    method_name: method.to_string(),
                    args: args.to_string().into_bytes(),
                    gas,
                    deposit,
                },
            ))],
        };
        let tx = Transaction::V0(tx_v0);
        let signed = tx.sign(&self.signer);
        let resp = self
            .client
            .call(methods::broadcast_tx_commit::RpcBroadcastTxCommitRequest {
                signed_transaction: signed,
            })
            .await?;
        Ok(resp)
    }

    async fn next_nonce(&self) -> Result<u64> {
        let resp = self
            .client
            .call(methods::query::RpcQueryRequest {
                block_reference: near_primitives::types::Finality::Final.into(),
                request: QueryRequest::ViewAccessKey {
                    account_id: self.account.clone(),
                    public_key: self.signer.public_key(),
                },
            })
            .await?;

        if let near_jsonrpc_primitives::types::query::QueryResponseKind::AccessKey(k) = resp.kind {
            Ok(k.nonce + 1)
        } else {
            bail!("unexpected access key response")
        }
    }

    // ── ZNS contract helpers ──────────────────────────────────────────

    /// Call a mutable method on the ZNS marketplace contract.
    pub async fn call_zns_mut(
        &self,
        method: &str,
        args: serde_json::Value,
        gas: u64,
        deposit: u128,
    ) -> Result<near_primitives::views::FinalExecutionOutcomeView> {
        self.call_mut(&self.zns_contract.clone(), method, args, gas, deposit)
            .await
    }

    // ── MPC helpers ───────────────────────────────────────────────────

    /// Request the MPC network to sign a 32-byte sighash for the given derivation path.
    pub async fn request_sign(&self, path: &str, sighash: &[u8; 32]) -> Result<MpcSignature> {
        tracing::info!(path, "requesting MPC signature");
        let payload: Vec<u8> = sighash.to_vec();
        let outcome = self
            .call_mut(
                &self.mpc_contract.clone(),
                "sign",
                serde_json::json!({
                    "request": {
                        "payload": payload,
                        "path": path,
                        "key_version": 0,
                    }
                }),
                300_000_000_000_000, // 300 Tgas
                100,
            )
            .await?;

        let value = match outcome.status {
            FinalExecutionStatus::SuccessValue(v) => v,
            FinalExecutionStatus::Failure(tx_execution_error) => {
                bail!("MPC sign tx failed: {:?}", tx_execution_error)
            }
            other => {
                tracing::warn!("MPC sign unexpected status: {:?}", other);
                bail!("MPC sign tx failed: unexpected status {:?}", other)
            }
        };

        let sig: MpcSignature =
            serde_json::from_slice(&value).context("parse MPC signature from tx outcome")?;

        tracing::info!("MPC signature received");
        Ok(sig)
    }

    /// Query the MPC contract for the master public key.
    #[allow(dead_code)]
    pub async fn query_mpc_public_key(&self) -> Result<Option<String>> {
        let req = QueryRequest::CallFunction {
            account_id: self.mpc_contract.clone(),
            method_name: "public_key".to_string(),
            args: FunctionArgs::from(b"{}".to_vec()),
        };
        let resp = self
            .client
            .call(methods::query::RpcQueryRequest {
                block_reference: near_primitives::types::Finality::Final.into(),
                request: req,
            })
            .await?;

        if let near_jsonrpc_primitives::types::query::QueryResponseKind::CallResult(r) = resp.kind {
            let key: String = serde_json::from_slice(&r.result).unwrap_or_default();
            Ok(Some(key))
        } else {
            Ok(None)
        }
    }
}
