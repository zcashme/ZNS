// Transparent payment scanner — finds payments to a t-addr in a block range.
//
// Used by the BUY pending-buy lifecycle: when a buyer claims a listing, the
// indexer watches the seller's `pay_taddr` for a transparent transaction whose
// outputs sum to at least the listing price. The first such transaction found
// in the (claim_height, current_tip] window finalizes the sale.

use zcash_client_backend::proto::service::{BlockId, BlockRange, TransparentAddressBlockFilter};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, Network};
use zcash_transparent::address::TransparentAddress;

use crate::decrypter::Client;

/// Encode a parsed `TransparentAddress` to its bs58check string for the given network.
pub fn encode_taddr(addr: &TransparentAddress, network: Network) -> String {
    let testnet = matches!(network, Network::TestNetwork);
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

/// A transparent payment that satisfied a pending buy.
#[derive(Debug, Clone)]
pub struct PaymentMatch {
    pub txid: String,
    pub height: u64,
}

/// Scan for the first transparent transaction in `[start_height, end_height]`
/// that pays at least `min_amount` zatoshis to `pay_taddr`.
///
/// Returns the matching payment's txid + height, or `None` if no match.
pub async fn find_payment(
    client: &mut Client,
    network: Network,
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
    let mut stream = client
        .get_taddress_transactions(filter)
        .await
        .ok()?
        .into_inner();

    while let Ok(Some(raw)) = stream.message().await {
        let tx_height = raw.height;
        let branch = BranchId::for_height(&network, BlockHeight::from_u32(tx_height as u32));
        let Ok(tx) = Transaction::read(&raw.data[..], branch) else {
            continue;
        };
        let total: u64 = tx
            .transparent_bundle()
            .iter()
            .flat_map(|b| b.vout.iter())
            .filter(|out| {
                out.recipient_address()
                    .map(|a| encode_taddr(&a, network) == pay_taddr)
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
