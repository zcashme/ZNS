// ZNS Indexer


const LWD_URL: &str = "https://light.zcash.me:443";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    println!("Connecting to lightwalletd at {LWD_URL}...");
    let mut client = zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient::connect(LWD_URL).await?;

    let tip = client
        .get_latest_block(zcash_client_backend::proto::service::ChainSpec {})
        .await?
        .into_inner();

    println!("Connected. Chain tip: height={} hash={}", tip.height, hex::encode(&tip.hash));

    Ok(())
}

#[cfg(test)]
mod tests {
    use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;
    use zcash_client_backend::proto::service::{BlockId, BlockRange, ChainSpec, TxFilter};

    const LWD_URL: &str = "https://light.zcash.me:443";

    fn init_tls() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    // Verifies we can open a gRPC channel to light.zcash.me without error.
    // Fails if the endpoint is unreachable or TLS handshake fails.
    #[tokio::test]
    async fn test_connect() -> Result<(), Box<dyn std::error::Error>> {
        init_tls();
        CompactTxStreamerClient::connect(LWD_URL).await?;
        Ok(())
    }

    // Calls get_latest_block and checks the returned height is above mainnet
    // Orchard activation (~1,687,104). Fails if the node returns 0 or errors.
    #[tokio::test]
    async fn test_get_latest_height() -> Result<(), Box<dyn std::error::Error>> {
        init_tls();
        let mut client = CompactTxStreamerClient::connect(LWD_URL).await?;
        let block_id = client.get_latest_block(ChainSpec {}).await?.into_inner();
        assert!(block_id.height > 1_687_104, "height should be above Orchard activation");
        Ok(())
    }

    // Streams blocks 2_500_000..=2_500_001 and asserts we get back exactly
    // 2 CompactBlocks with heights 2_500_000 and 2_500_001 in order.
    #[tokio::test]
    async fn test_get_block_range() -> Result<(), Box<dyn std::error::Error>> {
        init_tls();
        let mut client = CompactTxStreamerClient::connect(LWD_URL).await?;
        let range = BlockRange {
            start: Some(BlockId { height: 2_500_000, hash: vec![] }),
            end:   Some(BlockId { height: 2_500_001, hash: vec![] }),
        };
        let mut stream = client.get_block_range(range).await?.into_inner();
        let mut blocks = vec![];
        while let Some(block) = stream.message().await? {
            blocks.push(block);
        }
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].height, 2_500_000);
        assert_eq!(blocks[1].height, 2_500_001);
        Ok(())
    }

    // Fetches a known mainnet txid and asserts the returned RawTransaction
    // is non-empty (data.len() > 0). Fails if the tx is not found or errors.
    #[tokio::test]
    async fn test_get_transaction() -> Result<(), Box<dyn std::error::Error>> {
        init_tls();
        let mut client = CompactTxStreamerClient::connect(LWD_URL).await?;
        // A known Orchard mainnet tx from block 2_500_000 (raw bytes as returned by GetBlockRange)
        let hash = hex::decode("3e12cd4942dd15205ebe4d5c4a624e2b4edce42e2346ff1ebe74f3afe107443c")?;
        let raw_tx = client
            .get_transaction(TxFilter { block: None, index: 0, hash })
            .await?
            .into_inner();
        assert!(!raw_tx.data.is_empty());
        Ok(())
    }

    // Fetches block 2_500_000 and asserts it contains at least one Orchard action,
    // confirming the compact block parser surfaces Orchard data we can trial-decrypt.
    #[tokio::test]
    async fn test_compact_block_has_orchard_actions() -> Result<(), Box<dyn std::error::Error>> {
        init_tls();
        let mut client = CompactTxStreamerClient::connect(LWD_URL).await?;
        let range = BlockRange {
            start: Some(BlockId { height: 2_500_000, hash: vec![] }),
            end:   Some(BlockId { height: 2_500_000, hash: vec![] }),
        };
        let mut stream = client.get_block_range(range).await?.into_inner();
        let block = stream.message().await?.expect("block");
        let orchard_actions: usize = block.vtx.iter().map(|tx| tx.actions.len()).sum();
        assert!(orchard_actions > 0, "expected Orchard actions in block 2_500_000");
        Ok(())
    }

    // Scans block 2_500_000 with a UFVK derived from a dummy seed. No notes should
    // match, but scan_block must complete without error, proving the trial-decryption
    // pipeline works end-to-end against real mainnet compact blocks.
    #[tokio::test]
    async fn test_scan_block_no_match() -> Result<(), Box<dyn std::error::Error>> {
        use zip32::AccountId;
        use zcash_protocol::consensus::Network;
        use zcash_client_backend::scanning::{Nullifiers, ScanningKeys, scan_block};
        use zcash_client_backend::keys::UnifiedSpendingKey;

        init_tls();
        let mut client = CompactTxStreamerClient::connect(LWD_URL).await?;
        let range = BlockRange {
            start: Some(BlockId { height: 2_500_000, hash: vec![] }),
            end:   Some(BlockId { height: 2_500_000, hash: vec![] }),
        };
        let block = client.get_block_range(range).await?.into_inner()
            .message().await?.expect("block");

        let account = AccountId::ZERO;
        let usk = UnifiedSpendingKey::from_seed(&Network::MainNetwork, &[0u8; 32], account)
            .expect("valid usk");
        let ufvk = usk.to_unified_full_viewing_key();
        let scanning_keys = ScanningKeys::from_account_ufvks([(account, ufvk)]);

        let scanned = scan_block(
            &Network::MainNetwork,
            block,
            &scanning_keys,
            &Nullifiers::empty(),
            None,
        ).expect("scan_block failed");

        // No transactions should match a random dummy UFVK
        assert!(scanned.transactions().is_empty());
        Ok(())
    }
}
