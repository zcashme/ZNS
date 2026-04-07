//! Resolve a ZNS name through a caller-configured `reqwest::Client`.
//!
//! Demonstrates [`Client::with_http_client`], the injection point that
//! lets callers route requests through anything reqwest can talk to —
//! custom timeouts, HTTP proxies, SOCKS proxies, Arti for in-process
//! Tor, mTLS, retry middleware, etc. `zns-client` itself stays
//! transport-unaware; all of these are pure consumer-side concerns
//! that don't require any change to the SDK.
//!
//! ## Routing through Tor
//!
//! **Option A — SOCKS to a separate `tor` daemon** (requires enabling
//! reqwest's `socks` feature in your own Cargo.toml):
//!
//! ```ignore
//! let http = reqwest::Client::builder()
//!     .proxy(reqwest::Proxy::all("socks5h://127.0.0.1:9050")?)
//!     .build()?;
//! let zns = zns_client::Client::with_http_client(endpoint, http);
//! ```
//!
//! **Option B — in-process Tor via Arti** (zingolib's pattern):
//!
//! ```ignore
//! // zingolib already owns a zcash_client_backend::tor::Client.
//! let arti_http: reqwest::Client = tor_client.http_client();
//! let zns = zns_client::Client::with_http_client(endpoint, arti_http);
//! ```
//!
//! In both cases, no code in `zns-client` changes. The injection point
//! does the whole job.
//!
//! Run with:
//!     cargo run --example with_http_client -- <endpoint-url> <name>

use std::env;
use std::time::Duration;
use url::Url;
use zns_client::Client;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = env::args().skip(1);
    let endpoint: Url = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("usage: with_http_client <endpoint-url> <name>"))?
        .parse()?;
    let name = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("usage: with_http_client <endpoint-url> <name>"))?;

    // A reqwest::Client configured however the caller wants. The
    // zns-client SDK treats it as an opaque HTTP transport — anything
    // reqwest can do, this Client can do.
    let http = reqwest::Client::builder()
        .user_agent("zns-client-example/0.1")
        .timeout(Duration::from_secs(10))
        .build()?;

    let client = Client::with_http_client(endpoint, http);

    match client.resolve(&name).await? {
        Some(reg) => {
            println!("{} -> {}", reg.name, reg.address);
            println!("  (via a caller-configured reqwest::Client)");
        }
        None => println!("{name} is not registered"),
    }
    Ok(())
}
