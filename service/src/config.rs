use clap::Parser;
use std::net::SocketAddr;

/// zns-custody-service
///
/// Watches Zcash transparent escrows, coordinates MPC signing, and broadcasts
/// BUY memos.  Holds no escrow keys.
#[derive(Parser, Clone, Debug)]
#[command(name = "zns-custody-service")]
#[command(about = "ZNS non-custodial sale orchestrator")]
pub struct Config {
    /// Admin Ed25519 private key (hex, 64 chars) used for BUY memo signing.
    #[arg(long, env = "ZNS_ADMIN_ED25519_KEY")]
    pub admin_ed25519_key: String,

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

    /// MPC signer contract on NEAR (v1.signer).
    #[arg(
        long,
        env = "ZNS_MPC_CONTRACT",
        default_value = "v1.signer-prod.testnet"
    )]
    pub mpc_contract: String,

    /// MPC master public key (hex, 66 bytes compressed secp256k1) used to derive
    /// transparent escrow addresses.  This MUST match the key managed by the
    /// MPC network for the NEAR account above.
    #[arg(long, env = "ZNS_MPC_MASTER_PUBKEY")]
    pub mpc_master_pubkey: String,

    /// Zcash unified address receiving commission / treasury funds.
    #[arg(long, env = "ZNS_TREASURY_UA")]
    pub treasury_ua: String,

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

    /// Zcash block height after which a pending intent is treated as expired.
    #[arg(long, env = "ZNS_INTENT_EXPIRY_ZEC_BLOCKS", default_value = "100")]
    pub intent_expiry_zec_blocks: u64,

    /// Commission basis points taken from each sale (e.g. 250 = 2.5%).
    #[arg(long, env = "ZNS_COMMISSION_BPS", default_value = "250")]
    pub commission_bps: u16,

    /// Bind address for the public HTTP API.
    #[arg(long, env = "ZNS_BIND_ADDR", default_value = "127.0.0.1:8080")]
    pub bind_addr: SocketAddr,

    /// Path to the local SQLite database.
    #[arg(long, env = "ZNS_SQLITE_PATH", default_value = "zns_intents.db")]
    pub sqlite_path: String,
}
