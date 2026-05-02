use clap::Parser;
use std::net::SocketAddr;

/// zns-custody-service
///
/// Builds Zcash escrow transactions and submits them to the contract.
#[derive(Parser, Clone, Debug)]
#[command(name = "zns-custody-service")]
#[command(about = "ZNS non-custodial sale orchestrator")]
pub struct Config {
    /// NEAR account ID used to pay gas for v1.signer calls.
    #[arg(long, env = "ZNS_NEAR_ACCOUNT")]
    pub near_account: String,

    /// NEAR secret key for the account above.
    #[arg(long, env = "ZNS_NEAR_SECRET_KEY")]
    pub near_secret_key: String,

    /// NEAR RPC endpoint.
    #[arg(
        long,
        env = "ZNS_NEAR_RPC",
        default_value = "https://rpc.testnet.near.org"
    )]
    pub near_rpc: String,

    /// ZNS marketplace contract on NEAR.
    #[arg(long, env = "ZNS_CONTRACT")]
    pub zns_contract: String,

    /// Zcash network: mainnet or testnet.
    #[arg(long, env = "ZNS_ZCASH_NETWORK", default_value = "testnet")]
    pub zcash_network: String,

    /// lightwalletd gRPC URL.
    #[arg(
        long,
        env = "ZNS_LWD_URL",
        default_value = "https://testnet.zec.rocks:443"
    )]
    pub lwd_url: String,

    /// ZNS indexer JSON-RPC URL (for resolving names).
    #[arg(long, env = "ZNS_INDEXER_RPC", default_value = "http://127.0.0.1:3000")]
    pub indexer_rpc: String,

    /// How often to poll lightwalletd for new blocks (seconds).
    #[arg(long, env = "ZNS_POLL_INTERVAL_SECS", default_value = "10")]
    pub poll_interval_secs: u64,

    /// Number of Zcash confirmations required before confirming payment.
    #[arg(long, env = "ZNS_MIN_CONFIRMATIONS", default_value = "6")]
    pub min_confirmations: u32,

    /// Bind address for the public HTTP API.
    #[arg(long, env = "ZNS_BIND_ADDR", default_value = "127.0.0.1:8080")]
    pub bind_addr: SocketAddr,

    /// Admin Ed25519 secret key (hex) used to sign BUY memos on behalf of
    /// buyers who do not provide their own sovereign signature.
    #[arg(long, env = "ZNS_ADMIN_ED25519_KEY")]
    pub admin_ed25519_key: Option<String>,

    /// Path to the local SQLite database.
    #[arg(long, env = "ZNS_SQLITE_PATH", default_value = "zns_intents.db")]
    pub sqlite_path: String,
}
