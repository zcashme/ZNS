//! Zcash lightwalletd watcher and payout-transaction builder.
//!
//! Uses the `CompactTxStreamer` gRPC service exposed by lightwalletd:
//!   * `GetAddressUtxos` to find payments to a burner transparent address
//!   * `GetTransaction`  to fetch the full payment tx (for input proof of value)
//!   * `SendTransaction` to broadcast the signed payout

use anyhow::{Context, Result, anyhow};
use tokio::sync::Mutex;
use tonic::transport::{Channel, ClientTlsConfig};
use zcash_client_backend::proto::service::{
    BlockId, ChainSpec, GetAddressUtxosArg, RawTransaction, TxFilter,
    compact_tx_streamer_client::CompactTxStreamerClient,
};

pub struct Watcher {
    /// Lazily-initialised tonic client; sharing a Channel is cheap & multiplexed.
    inner: Mutex<Option<CompactTxStreamerClient<Channel>>>,
    lwd_url: String,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct EscrowUtxo {
    pub txid: String,
    pub vout: u32,
    pub value_zats: u64,
    pub confirmations: u32,
    pub address: String,
    /// Output script of the UTXO — needed by the tx builder when we sign the spend.
    pub script: Vec<u8>,
    pub height: u64,
}

impl Watcher {
    pub fn new(lwd_url: &str) -> Self {
        Self {
            inner: Mutex::new(None),
            lwd_url: lwd_url.to_string(),
        }
    }

    async fn client(&self) -> Result<CompactTxStreamerClient<Channel>> {
        let mut guard = self.inner.lock().await;
        if let Some(c) = guard.as_ref() {
            return Ok(c.clone());
        }
        let endpoint = Channel::from_shared(self.lwd_url.clone())
            .context("invalid lwd url")?
            .tls_config(ClientTlsConfig::new().with_webpki_roots())
            .context("tls config")?;
        let channel = endpoint.connect().await.context("connect lightwalletd")?;
        let c = CompactTxStreamerClient::new(channel);
        *guard = Some(c.clone());
        Ok(c)
    }

    /// Fetch the current chain tip height. Used to compute confirmation counts.
    pub async fn latest_height(&self) -> Result<u64> {
        let mut c = self.client().await?;
        let resp = c
            .get_latest_block(ChainSpec {})
            .await
            .context("get_latest_block")?;
        let id: BlockId = resp.into_inner();
        Ok(id.height)
    }

    /// Look up all UTXOs paid to a given transparent address.
    pub async fn get_utxos(&self, taddr: &str) -> Result<Vec<EscrowUtxo>> {
        let mut c = self.client().await?;
        let tip = self.latest_height().await.unwrap_or(0);

        let req = GetAddressUtxosArg {
            addresses: vec![taddr.to_string()],
            start_height: 0,
            max_entries: 0,
        };
        let resp = c
            .get_address_utxos(req)
            .await
            .context("get_address_utxos")?;
        let list = resp.into_inner();

        Ok(list
            .address_utxos
            .into_iter()
            .map(|u| {
                let confs = if tip >= u.height && u.height > 0 {
                    (tip - u.height + 1) as u32
                } else {
                    0
                };
                EscrowUtxo {
                    txid: hex_le(&u.txid),
                    vout: u.index as u32,
                    value_zats: u.value_zat as u64,
                    confirmations: confs,
                    address: u.address,
                    script: u.script,
                    height: u.height,
                }
            })
            .collect())
    }

    /// Fetch the raw bytes of a transaction by txid (hex, big-endian display form).
    #[allow(dead_code)]
    pub async fn get_raw_tx(&self, txid: &str) -> Result<Option<Vec<u8>>> {
        let mut c = self.client().await?;
        let hash_le = hex_to_le_bytes(txid).context("decode txid")?;
        let req = TxFilter {
            block: None,
            index: 0,
            hash: hash_le,
        };
        match c.get_transaction(req).await {
            Ok(resp) => {
                let raw: RawTransaction = resp.into_inner();
                if raw.data.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(raw.data))
                }
            }
            Err(status) if status.code() == tonic::Code::NotFound => Ok(None),
            Err(e) => Err(anyhow!("get_transaction: {e}")),
        }
    }

    /// Broadcast a fully-signed transaction.
    pub async fn send_tx(&self, raw: &[u8]) -> Result<String> {
        let mut c = self.client().await?;
        let req = RawTransaction {
            data: raw.to_vec(),
            height: 0,
        };
        let resp = c.send_transaction(req).await.context("send_transaction")?;
        let r = resp.into_inner();
        if r.error_code != 0 {
            return Err(anyhow!(
                "lwd send_transaction error {}: {}",
                r.error_code,
                r.error_message
            ));
        }
        // Compute the ZIP-244 transaction identifier (Zcash v5 txid) by
        // deserializing the signed bytes and calling .txid(), which uses
        // TxIdDigester internally.  Double-SHA256 of the raw bytes is the
        // Bitcoin convention and produces the wrong txid for Zcash v5.
        use zcash_primitives::transaction::Transaction;
        let tx = Transaction::read(raw, zcash_primitives::consensus::BranchId::Nu6)
            .context("deserialize tx to compute txid")?;
        Ok(tx.txid().to_string())
    }
}

/// Display form of a 32-byte txid: lightwalletd returns internal (little-endian)
/// byte order; users see the reversed (big-endian) hex.
fn hex_le(bytes: &[u8]) -> String {
    let mut be = bytes.to_vec();
    be.reverse();
    hex::encode(be)
}

#[allow(dead_code)]
fn hex_to_le_bytes(display_hex: &str) -> Result<Vec<u8>> {
    let mut be = hex::decode(display_hex.trim()).context("hex decode txid")?;
    be.reverse();
    Ok(be)
}
