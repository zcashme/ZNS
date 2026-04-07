//! Resolve a ZNS name from the command line.
//!
//! Run with:
//!     cargo run --example resolve -- <endpoint-url> <name>
//!
//! Example:
//!     cargo run --example resolve -- http://127.0.0.1:3000 alice

use std::env;
use url::Url;
use zns_client::Client;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = env::args().skip(1);
    let endpoint = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("usage: resolve <endpoint-url> <name>"))?;
    let name = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("usage: resolve <endpoint-url> <name>"))?;

    let endpoint: Url = endpoint.parse()?;
    let client = Client::new(endpoint);

    match client.resolve(&name).await? {
        Some(reg) => {
            println!("{} -> {}", reg.name, reg.address);
            println!("  last_action: {:?}", reg.last_action);
            println!("  nonce:       {}", reg.nonce);
            println!("  height:      {}", reg.height);
            if let Some(listing) = reg.listing {
                println!("  listed:      {} zatoshis", listing.price);
            }
        }
        None => {
            println!("{name} is not registered");
        }
    }
    Ok(())
}
