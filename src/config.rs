// ZNS configuration — compile-time network selection via feature flags.
//
// Exactly one of `testnet` or `mainnet` must be enabled. Default is `mainnet`.
// Build:
//   cargo build             → mainnet
//   cargo build --features testnet → testnet
//   cargo build --features testnet,mainnet → compile error

use std::time::Duration;

use zcash_protocol::consensus::Network;

pub const DB_PATH: &str = "zns.db";
pub const RPC_PORT: u16 = 3000;
pub const POLL_INTERVAL: Duration = Duration::from_secs(10);

/// Block window during which a pending buy must be funded before expiring.
/// 144 blocks ≈ 2 hours on Zcash (75s target).
pub const BUY_WINDOW_BLOCKS: u64 = 144;

// Compile-time network constants — exactly one is active.

#[cfg(feature = "testnet")]
pub const LWD_URL: &str = "https://testnet.zec.rocks:443";
#[cfg(feature = "testnet")]
pub const NETWORK: Network = Network::TestNetwork;
#[cfg(feature = "testnet")]
pub const BIRTHDAY: u64 = 2_726_400; // NU6 activation (same height on testnet)

#[cfg(feature = "mainnet")]
pub const LWD_URL: &str = "https://zec.rocks:443";
#[cfg(feature = "mainnet")]
pub const NETWORK: Network = Network::MainNetwork;
#[cfg(feature = "mainnet")]
pub const BIRTHDAY: u64 = 2_726_400; // NU6 activation (2024-11-23)

#[cfg(all(feature = "testnet", feature = "mainnet"))]
compile_error!("testnet and mainnet are mutually exclusive");

// Compile-time log level — one knob, controlled by feature flags.
//
//   default                       → info
//   --features verbose-logs       → debug
//   --features quiet-logs         → warn
#[cfg(all(feature = "verbose-logs", feature = "quiet-logs"))]
compile_error!("verbose-logs and quiet-logs are mutually exclusive");

#[cfg(feature = "verbose-logs")]
pub const LOG_LEVEL: tracing::Level = tracing::Level::DEBUG;
#[cfg(feature = "quiet-logs")]
pub const LOG_LEVEL: tracing::Level = tracing::Level::WARN;
#[cfg(not(any(feature = "verbose-logs", feature = "quiet-logs")))]
pub const LOG_LEVEL: tracing::Level = tracing::Level::INFO;

#[derive(Debug, Clone)]
pub struct Config {
    pub uivk: String,
    pub admin_pubkey: [u8; 32],
}

impl Config {
    /// Build configuration from environment.
    ///
    /// Required:
    ///   ZNS_UIVK         — Unified Incoming Viewing Key for the indexer wallet
    ///   ZNS_ADMIN_PUBKEY — hex-encoded 32-byte Ed25519 admin public key
    pub fn from_env() -> Result<Self, String> {
        let uivk = std::env::var("ZNS_UIVK").map_err(|_| "ZNS_UIVK is required")?;
        let admin_pubkey = parse_hex_32(
            &std::env::var("ZNS_ADMIN_PUBKEY").map_err(|_| "ZNS_ADMIN_PUBKEY is required")?,
        )
        .map_err(|e| format!("ZNS_ADMIN_PUBKEY: {e}"))?;

        Ok(Self { uivk, admin_pubkey })
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
