// ZNS block decrypter — streams compact blocks and trial-decrypts Orchard notes.
//
//
use std::collections::HashSet;

use orchard::keys::PreparedIncomingViewingKey;
use orchard::note_encryption::{CompactAction, OrchardDomain};
use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;
use zcash_client_backend::proto::service::{BlockId, BlockRange, ChainSpec, TxFilter};
use zcash_primitives::consensus::BranchId;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::TxId;
use zcash_protocol::consensus::{BlockHeight, Network};

pub type Client = CompactTxStreamerClient<tonic::transport::Channel>;

/// A single decrypted Orchard note with its chain context.
pub struct DecryptedNote {
    pub memo: [u8; 512],
    pub value: u64,
    pub txid: TxId,
    pub height: u64,
}

/// Ask lightwalletd for the current chain tip height.
pub async fn get_chain_tip(client: &mut Client) -> Option<u64> {
    client
        .get_latest_block(ChainSpec {})
        .await
        .ok()
        .map(|r| r.into_inner().height)
}

/// Stream and decrypt a range of blocks, returning all decrypted notes
/// and the height of the last block that was fully scanned.
pub async fn scan_range(
    client: &mut Client,
    pivk: &PreparedIncomingViewingKey,
    network: &Network,
    start: u64,
    end: u64,
) -> (Vec<DecryptedNote>, u64) {
    let mut notes = Vec::new();
    let mut last_scanned = start.saturating_sub(1);

    let range = BlockRange {
        start: Some(BlockId {
            height: start,
            hash: vec![],
        }),
        end: Some(BlockId {
            height: end,
            hash: vec![],
        }),
    };
    let Ok(mut stream) = client.get_block_range(range).await.map(|r| r.into_inner()) else {
        return (notes, last_scanned);
    };

    while let Ok(Some(block)) = stream.message().await {
        scan_block(client, pivk, network, &block, &mut notes).await;
        last_scanned = block.height;
    }

    (notes, last_scanned)
}

/// Scan one block: trial-decrypt compact actions, fetch full txs, collect notes.
async fn scan_block(
    client: &mut Client,
    pivk: &PreparedIncomingViewingKey,
    network: &Network,
    block: &CompactBlock,
    notes: &mut Vec<DecryptedNote>,
) {
    let height = block.height;

    // Trial-decrypt compact actions to find transactions addressed to us
    let candidates: Vec<_> = block
        .vtx
        .iter()
        .flat_map(|tx| {
            tx.actions.iter().filter_map(|a| {
                CompactAction::try_from(a)
                    .ok()
                    .map(|ca| (ca, tx.hash.clone()))
            })
        })
        .collect();
    if candidates.is_empty() {
        return;
    }

    let pairs: Vec<_> = candidates
        .iter()
        .map(|(ca, _)| (OrchardDomain::for_compact_action(ca), ca.clone()))
        .collect();
    let results = zcash_note_encryption::batch::try_compact_note_decryption(
        std::slice::from_ref(pivk),
        &pairs,
    );
    let matched: HashSet<_> = results
        .iter()
        .zip(&candidates)
        .filter_map(|(r, (_, txid))| r.as_ref().map(|_| txid.clone()))
        .collect();

    // Fetch full transactions and decrypt memos
    let branch = BranchId::for_height(network, BlockHeight::from_u32(height as u32));
    for txid in &matched {
        let Ok(data) = client
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
                zcash_note_encryption::try_note_decryption(&domain, pivk, action)
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
