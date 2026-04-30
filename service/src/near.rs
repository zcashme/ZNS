use anyhow::{Context, Result, bail};
use near_crypto::Signer;
use near_jsonrpc_client::{JsonRpcClient, methods};
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_primitives::{
    transaction::{Action, Transaction, TransactionV0},
    types::{AccountId, FunctionArgs},
    views::QueryRequest,
};
use serde::de::DeserializeOwned;
use std::str::FromStr;

/// Generic NEAR client for calling the ZNS contract.
pub struct NearClient {
    pub account: AccountId,
    client: JsonRpcClient,
    signer: Signer,
    pub zns_contract: AccountId,
}

impl NearClient {
    pub fn new(rpc_url: &str, account: &str, secret_key: &str, zns_contract: &str) -> Result<Self> {
        let signer = near_crypto::InMemorySigner::from_secret_key(
            AccountId::from_str(account)?,
            near_crypto::SecretKey::from_str(secret_key)?,
        );
        let client = JsonRpcClient::connect(rpc_url);
        Ok(Self {
            account: account.parse()?,
            client,
            signer,
            zns_contract: zns_contract.parse()?,
        })
    }

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

    pub async fn view<T: DeserializeOwned>(
        &self,
        contract: &AccountId,
        method: &str,
        args: serde_json::Value,
    ) -> Result<T> {
        let req = QueryRequest::CallFunction {
            account_id: contract.clone(),
            method_name: method.to_string(),
            args: FunctionArgs::from(args.to_string().into_bytes()),
        };
        let resp = self
            .client
            .call(methods::query::RpcQueryRequest {
                block_reference: near_primitives::types::Finality::Final.into(),
                request: req,
            })
            .await?;

        match resp.kind {
            QueryResponseKind::CallResult(r) => {
                serde_json::from_slice(&r.result).context("parse view result")
            }
            _ => bail!("unexpected query response"),
        }
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

    pub async fn view_zns<T: DeserializeOwned>(
        &self,
        method: &str,
        args: serde_json::Value,
    ) -> Result<T> {
        self.view(&self.zns_contract.clone(), method, args).await
    }
}
