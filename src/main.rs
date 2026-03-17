// ZNS Indexer — Zcash Name System
//
// A long-running service that watches the Zcash testnet blockchain for
// shielded ZNS protocol messages and maintains a local SQLite database
// of name registrations and marketplace listings.
//
// Supported actions:
//   REGISTER  — claim a name (first-come-first-served)
//   LIST      — put a name up for sale at a price (admin-signed)
//   DELIST    — remove a listing (admin-signed)
//   UPDATE    — change the address behind a name (admin-signed)
//   BUY       — purchase a listed name by sending sufficient ZEC

mod decrypter;  // block streaming, trial decryption, action dispatch
mod memo;       // memo protocol: parsing, validation, signature verification
mod registry;   // SQLite storage for registrations and listings

use std::time::Duration;

use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus::Network;

// ── Config ───────────────────────────────────────────────────────────────────

const LWD_URL: &str = "https://testnet.zec.rocks:443";
const DB_PATH: &str = "zns.db";
const BIRTHDAY: u64 = 3_901_175;
const UFVK_STR: &str = "uviewtest1h075nwxk0s66hyw0gmy5l2gmr37eahe9ewzgu2lff90rc85mazdhc66udklmd2p7cqm3mg2up8487pusvh78dh89y7mzlfgdl57tncqxrwshhc2kf26js0ymdwd476r0v7qn6es0etgjeg3g0y3pngvvf8zdawg6nlwca7jqy2fv82rc5skauw05ptfuf5twj67u0gzzvhakvkxpvx8rvf2rlh5yh560fdr6p28368kjxez5gu9azam5cm08ygre0uqwhvrkz7sr7ld0nyv05a0xrqeffdvhujafq3ke860skmxzshtjlrlew72vycu54pkgjtyp2phr6fmmkqlxvsan54jh7mc59r7kazgwwrcfnmqjm5pt40kjeafp6lwtx2lp4gm5pzg9c9ugphrsclfnz50spnsrersk34ht5mrevw9yvspkfjg9mjhusc588d855hdch0z82pr5fhkvaz3p4cmjlxujxqw2w20tpgyt3rzkwuuwl4r7";
const POLL_INTERVAL: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ufvk = UnifiedFullViewingKey::decode(&Network::TestNetwork, UFVK_STR)
        .map_err(|e| format!("Failed to decode UFVK: {e}"))?;

    let db = registry::open_db(DB_PATH)?;

    println!("Connecting to {LWD_URL}...");
    let client = CompactTxStreamerClient::connect(LWD_URL).await?;
    decrypter::run_block_sync(client, &db, &ufvk).await;

    Ok(())
}
