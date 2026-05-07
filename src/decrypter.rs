// ZNS block decrypter — owns the lightwalletd connection and trial-decrypts
// Orchard notes against the indexer's incoming viewing key.

use orchard::keys::PreparedIncomingViewingKey;
use orchard::note_encryption::{CompactAction, OrchardDomain};
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;
use zcash_client_backend::proto::service::{BlockId, BlockRange, ChainSpec, TxFilter, TransparentAddressBlockFilter};
use zcash_keys::keys::UnifiedIncomingViewingKey;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::TxId;
use zcash_protocol::consensus::{BlockHeight, BranchId, Network};
use zcash_transparent::address::TransparentAddress;

pub type Client = CompactTxStreamerClient<tonic::transport::Channel>;

/// A transparent payment that satisfied a pending buy.
#[derive(Debug, Clone)]
pub struct PaymentMatch {
    pub txid: String,
    pub height: u64,
}

/// A single decrypted Orchard note with its chain context.
#[derive(Debug, Clone)]
pub struct DecryptedNote {
    pub memo: [u8; 512],
    pub value: u64,
    pub txid: TxId,
    pub height: u64,
}

/// The indexer's view of the Zcash chain — owns the lightwalletd connection,
/// the viewing key, and the synced position.
pub struct IndexerState {
    client: Client,
    pivk: PreparedIncomingViewingKey,
    network: Network,
    height: u64,
    hash: [u8; 32],
}

impl IndexerState {
    /// Connect to lightwalletd and prepare the indexer at `birthday`.
    pub async fn connect(
        lwd_url: &'static str,
        uivk: &UnifiedIncomingViewingKey,
        network: Network,
        birthday: u64,
    ) -> Result<Self, tonic::transport::Error> {
        let client = Client::connect(lwd_url).await?;
        let orchard_ivk = uivk.orchard().as_ref().expect("UIVK has no Orchard key");
        let pivk = PreparedIncomingViewingKey::new(orchard_ivk);
        Ok(Self {
            client,
            pivk,
            network,
            height: birthday,
            hash: [0u8; 32],
        })
    }

    pub fn height(&self) -> u64 {
        self.height
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn client_mut(&mut self) -> &mut Client {
        &mut self.client
    }

    /// Ask lightwalletd for the current chain tip height.
    pub async fn chain_tip(&mut self) -> Option<u64> {
        self.client
            .get_latest_block(ChainSpec {})
            .await
            .ok()
            .map(|r| r.into_inner().height)
    }

    /// Scan blocks `(self.height, tip]`, advancing the indexer's position
    /// and returning all decrypted notes addressed to our viewing key.
    pub async fn scan_to(&mut self, tip: u64) -> Vec<DecryptedNote> {
        let start = self.height + 1;
        let mut notes = Vec::new();

        let range = BlockRange {
            start: Some(BlockId { height: start, hash: vec![] }),
            end: Some(BlockId { height: tip, hash: vec![] }),
            pool_types: vec![],
        };
        let Ok(mut stream) = self
            .client
            .get_block_range(range)
            .await
            .map(|r| r.into_inner())
        else {
            return notes;
        };

        while let Ok(Some(block)) = stream.message().await {
            self.scan_block(&block, &mut notes).await;
            self.height = block.height;
            self.hash.copy_from_slice(&block.hash);
        }

        notes
    }

    /// Scan one block: trial-decrypt compact actions, fetch full txs, collect notes.
    async fn scan_block(&mut self, block: &CompactBlock, notes: &mut Vec<DecryptedNote>) {
        let height = block.height;

        let candidates: Vec<_> = block
            .vtx
            .iter()
            .flat_map(|tx| {
                let idx = tx.index as u32;
                tx.actions.iter().filter_map(move |a| {
                    CompactAction::try_from(a)
                        .ok()
                        .map(|ca| (ca, tx.txid.clone(), idx))
                })
            })
            .collect();
        if candidates.is_empty() {
            return;
        }

        let pairs: Vec<_> = candidates
            .iter()
            .map(|(ca, _, _)| (OrchardDomain::for_compact_action(ca), ca.clone()))
            .collect();
        let results = zcash_note_encryption::batch::try_compact_note_decryption(
            std::slice::from_ref(&self.pivk),
            &pairs,
        );
        let matched: std::collections::BTreeMap<u32, Vec<u8>> = results
            .iter()
            .zip(&candidates)
            .filter_map(|(r, (_, txid, idx))| r.as_ref().map(|_| (*idx, txid.clone())))
            .collect();

        let branch = BranchId::for_height(&self.network, BlockHeight::from_u32(height as u32));
        for (_, txid) in &matched {
            let Ok(data) = self
                .client
                .get_transaction(TxFilter {
                    block: None,
                    index: 0,
                    hash: txid.clone(),
                })
                .await
                .map(|r| r.into_inner().data)
            else {
                continue;
            };
            let Ok(tx) = Transaction::read(&data[..], branch) else {
                continue;
            };
            let tx_id = tx.txid();
            let Some(bundle) = tx.orchard_bundle() else {
                continue;
            };

            for action in bundle.actions() {
                let domain = OrchardDomain::for_action(action);
                let Some((note, _, memo_bytes)) =
                    zcash_note_encryption::try_note_decryption(&domain, &self.pivk, action)
                else {
                    continue;
                };
                notes.push(DecryptedNote {
                    memo: memo_bytes,
                    value: note.value().inner(),
                    txid: tx_id,
                    height,
                });
            }
        }
    }

    /// Scan for the first transparent transaction in `[start_height, end_height]`
    /// that pays at least `min_amount` zatoshis to `pay_taddr`.
    pub async fn find_payment(
        &mut self,
        pay_taddr: &str,
        min_amount: u64,
        start_height: u64,
        end_height: u64,
    ) -> Option<PaymentMatch> {
        let filter = TransparentAddressBlockFilter {
            address: pay_taddr.to_string(),
            range: Some(BlockRange {
                start: Some(BlockId { height: start_height, hash: vec![] }),
                end: Some(BlockId { height: end_height, hash: vec![] }),
                pool_types: vec![],
            }),
        };
        let mut stream = self
            .client
            .get_taddress_transactions(filter)
            .await
            .ok()?
            .into_inner();

        while let Ok(Some(raw)) = stream.message().await {
            let tx_height = raw.height;
            let branch = BranchId::for_height(&self.network, BlockHeight::from_u32(tx_height as u32));
            let Ok(tx) = Transaction::read(&raw.data[..], branch) else {
                continue;
            };
            let total: u64 = tx
                .transparent_bundle()
                .iter()
                .flat_map(|b| b.vout.iter())
                .filter(|out| {
                    out.recipient_address()
                        .map(|a| self.encode_taddr(&a) == pay_taddr)
                        .unwrap_or(false)
                })
                .map(|out| u64::from(out.value()))
                .sum();
            if total >= min_amount {
                return Some(PaymentMatch {
                    txid: tx.txid().to_string(),
                    height: tx_height,
                });
            }
        }
        None
    }

    fn encode_taddr(&self, addr: &TransparentAddress) -> String {
        let testnet = matches!(self.network, Network::TestNetwork);
        let (prefix, data) = match addr {
            TransparentAddress::PublicKeyHash(hash) => (
                if testnet { [0x1D, 0x25] } else { [0x1C, 0xB8] },
                hash,
            ),
            TransparentAddress::ScriptHash(hash) => (
                if testnet { [0x1C, 0xBA] } else { [0x1C, 0xBD] },
                hash,
            ),
        };
        let mut payload = Vec::with_capacity(2 + 20);
        payload.extend_from_slice(&prefix);
        payload.extend_from_slice(data);
        bs58::encode(&payload).with_check().into_string()
    }
}
