// ZNS configuration — populated from environment variables.

use std::time::Duration;

#[cfg(all(feature = "testnet", feature = "mainnet"))]
compile_error!("features 'testnet' and 'mainnet' are mutually exclusive");

#[cfg(not(any(feature = "testnet", feature = "mainnet")))]
compile_error!("exactly one of 'testnet' or 'mainnet' must be enabled");

use zcash_protocol::consensus::Network;

#[cfg(feature = "testnet")]
pub const NETWORK: Network = Network::TestNetwork;
#[cfg(feature = "mainnet")]
pub const NETWORK: Network = Network::MainNetwork;

#[cfg(feature = "testnet")]
const DEFAULT_LWD_URL: &str = "https://testnet.zec.rocks:443";
#[cfg(feature = "mainnet")]
const DEFAULT_LWD_URL: &str = "https://zec.rocks:443";

#[cfg(feature = "testnet")]
const DEFAULT_BIRTHDAY: u64 = 1_842_420; // NU5 activation
#[cfg(feature = "mainnet")]
const DEFAULT_BIRTHDAY: u64 = 1_687_104; // NU5 activation

pub struct Config {
    pub network: Network,
    pub lwd_url: String,
    pub uivk: String,
    pub birthday: u64,
    pub db_path: String,
    pub rpc_port: u16,
    pub poll_interval: Duration,
    pub admin_pubkey: [u8; 32],
}

impl Config {
    /// Build configuration from environment variables.
    ///
    /// Required:
    ///   ZNS_UIVK         — Unified Incoming Viewing Key for the indexer wallet
    ///   ZNS_ADMIN_PUBKEY — hex-encoded 32-byte Ed25519 admin public key
    ///
    /// Optional (with defaults):
    ///   ZNS_NETWORK      — "testnet" (default) or "mainnet"
    ///   ZNS_LWD_URL      — lightwalletd endpoint
    ///   ZNS_BIRTHDAY     — block height to start scanning from
    ///   ZNS_DB_PATH      — path to SQLite database (default: "zns.db")
    ///   ZNS_RPC_PORT     — RPC server port (default: 3000)
    ///   ZNS_POLL_INTERVAL — seconds between chain tip polls (default: 10)
    pub fn from_env() -> Result<Self, String> {
        let lwd_url = env_or("ZNS_LWD_URL", DEFAULT_LWD_URL);
        let uivk = std::env::var("ZNS_UIVK").map_err(|_| "ZNS_UIVK is required")?;
        let birthday = env_parse::<u64>("ZNS_BIRTHDAY", DEFAULT_BIRTHDAY)?;

        let db_path = env_or("ZNS_DB_PATH", "zns.db");
        let rpc_port = env_parse::<u16>("ZNS_RPC_PORT", 3000)?;
        let poll_interval = Duration::from_secs(env_parse::<u64>("ZNS_POLL_INTERVAL", 10)?);

        let admin_pubkey = parse_hex_32(
            &std::env::var("ZNS_ADMIN_PUBKEY").map_err(|_| "ZNS_ADMIN_PUBKEY is required")?,
        )
        .map_err(|e| format!("ZNS_ADMIN_PUBKEY: {e}"))?;

        Ok(Config {
            network: NETWORK,
            lwd_url,
            uivk,
            birthday,
            db_path,
            rpc_port,
            poll_interval,
            admin_pubkey,
        })
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_parse<T: std::str::FromStr>(key: &str, default: T) -> Result<T, String>
where
    T::Err: std::fmt::Display,
{
    match std::env::var(key) {
        Ok(val) => val.parse::<T>().map_err(|e| format!("{key}: {e}")),
        Err(_) => Ok(default),
    }
}

fn parse_hex_32(hex: &str) -> Result<[u8; 32], String> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", hex.len()));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("invalid hex at position {}: {e}", i * 2))?;
    }
    Ok(out)
}
