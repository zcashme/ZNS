// ZNS configuration — compile-time constants with env-var overrides for secrets.

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
pub const LWD_URL: &str = "https://testnet.zec.rocks:443";
#[cfg(feature = "mainnet")]
pub const LWD_URL: &str = "https://zec.rocks:443";

#[cfg(feature = "testnet")]
pub const BIRTHDAY: u64 = 1_842_420; // NU5 activation
#[cfg(feature = "mainnet")]
pub const BIRTHDAY: u64 = 1_687_104; // NU5 activation

pub const DB_PATH: &str = "zns.db";
pub const RPC_PORT: u16 = 3000;
pub const POLL_INTERVAL: Duration = Duration::from_secs(10);

/// Load the two deployment-specific secrets from environment variables.
///
/// Required:
///   ZNS_UIVK         — Unified Incoming Viewing Key for the indexer wallet
///   ZNS_ADMIN_PUBKEY  — hex-encoded 32-byte Ed25519 admin public key
pub fn load_secrets() -> Result<(String, [u8; 32]), String> {
    let uivk = std::env::var("ZNS_UIVK").map_err(|_| "ZNS_UIVK is required")?;
    let admin_pubkey = parse_hex_32(
        &std::env::var("ZNS_ADMIN_PUBKEY").map_err(|_| "ZNS_ADMIN_PUBKEY is required")?,
    )
    .map_err(|e| format!("ZNS_ADMIN_PUBKEY: {e}"))?;
    Ok((uivk, admin_pubkey))
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
