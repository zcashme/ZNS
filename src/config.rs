// ZNS configuration — runtime-selected network, env-driven secrets.

use std::time::Duration;

use zcash_protocol::consensus::Network;

pub const DB_PATH: &str = "zns.db";
pub const RPC_PORT: u16 = 3000;
pub const POLL_INTERVAL: Duration = Duration::from_secs(10);

/// Block window during which a pending buy must be funded before expiring.
/// 144 blocks ≈ 2 hours on Zcash (75s target).
pub const BUY_WINDOW_BLOCKS: u64 = 144;

const MAINNET_LWD: &str = "https://zec.rocks:443";
const TESTNET_LWD: &str = "https://testnet.zec.rocks:443";
const MAINNET_BIRTHDAY: u64 = 2_726_400; // NU6 activation (2024-11-23)
const TESTNET_BIRTHDAY: u64 = 1_842_420; // NU5 activation

#[derive(Debug, Clone)]
pub struct Config {
    pub network: Network,
    pub lwd_url: String,
    pub birthday: u64,
    pub uivk: String,
    pub admin_pubkey: [u8; 32],
}

impl Config {
    /// Build configuration from environment.
    ///
    /// Required:
    ///   ZNS_UIVK         — Unified Incoming Viewing Key for the indexer wallet
    ///   ZNS_ADMIN_PUBKEY — hex-encoded 32-byte Ed25519 admin public key
    ///
    /// Optional:
    ///   ZNS_NETWORK      — "mainnet" (default) or "testnet"
    ///   ZNS_LWD_URL      — override the default lightwalletd URL
    ///   ZNS_BIRTHDAY     — override the default scan-start height
    pub fn from_env() -> Result<Self, String> {
        let network_str = std::env::var("ZNS_NETWORK").unwrap_or_else(|_| "mainnet".into());
        let (network, default_lwd, default_birthday) = match network_str.as_str() {
            "mainnet" => (Network::MainNetwork, MAINNET_LWD, MAINNET_BIRTHDAY),
            "testnet" => (Network::TestNetwork, TESTNET_LWD, TESTNET_BIRTHDAY),
            other => return Err(format!("ZNS_NETWORK must be 'mainnet' or 'testnet', got '{other}'")),
        };

        let lwd_url = std::env::var("ZNS_LWD_URL").unwrap_or_else(|_| default_lwd.into());
        let birthday = match std::env::var("ZNS_BIRTHDAY") {
            Ok(s) => s.parse().map_err(|e| format!("ZNS_BIRTHDAY: {e}"))?,
            Err(_) => default_birthday,
        };

        let uivk = std::env::var("ZNS_UIVK").map_err(|_| "ZNS_UIVK is required")?;
        let admin_pubkey = parse_hex_32(
            &std::env::var("ZNS_ADMIN_PUBKEY").map_err(|_| "ZNS_ADMIN_PUBKEY is required")?,
        )
        .map_err(|e| format!("ZNS_ADMIN_PUBKEY: {e}"))?;

        Ok(Self { network, lwd_url, birthday, uivk, admin_pubkey })
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
