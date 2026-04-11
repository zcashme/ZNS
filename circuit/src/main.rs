//! ZNS Schnorr Signer - Interactive CLI for Pallas curve Schnorr signatures
//!
//! Signs a user-defined name binding to a Zcash unified address,
//! proving knowledge of the Orchard incoming viewing key (ivk).

use anyhow::{bail, Context, Result};
use ff::FromUniformBytes;
use inquire::{Select, Text};
use zcash_address::ZcashAddress;

use zns_schnorr::keys::{self};
use zns_schnorr::{sign, verify, Signature};

// Re-export orchard types
use orchard::keys::IncomingViewingKey;

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {:#}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let action = Select::new("Action:", vec!["sign", "verify"]).prompt()?;

    match action {
        "sign" => sign_interactive()?,
        "verify" => verify_interactive()?,
        _ => unreachable!(),
    }

    Ok(())
}

fn sign_interactive() -> Result<()> {
    println!("\n=== Sign Name Binding ===\n");

    // Step 1: Get the private witness (ivk) - this is what we're proving knowledge of
    let key_method = Select::new("Key input method:", vec!["seed phrase", "ivk hex"]).prompt()?;

    let ivk = match key_method {
        "seed phrase" => {
            let phrase = Text::new("Enter seed phrase (24 words):").prompt()?;
            keys::derive_orchard_ivk_from_seed(&phrase)?
        }
        "ivk hex" => {
            let ivk_hex = Text::new("Enter Orchard IVK (128 hex chars):").prompt()?;
            keys::parse_ivk_hex(&ivk_hex)?
        }
        _ => unreachable!(),
    };

    // Step 2: Get or derive the unified address
    let addr_input =
        Text::new("Unified address to bind to (press Enter to derive from IVK):").prompt()?;

    let (address, g_d, pk_d) = if addr_input.trim().is_empty() {
        // User pressed Enter - derive address from ivk
        let (addr_str, g, p, _d) = keys::derive_unified_address(&ivk)?;
        let addr: ZcashAddress = addr_str
            .parse()
            .context("failed to parse derived address")?;
        println!("\nDerived unified address: {}", addr);
        (addr, g, p)
    } else {
        // User entered an address - verify it belongs to the ivk
        let addr: ZcashAddress = addr_input.parse().context("invalid Zcash address")?;

        // Extract components and verify ownership
        let (g, p, _d) = keys::verify_address_ownership(&addr, &ivk)?;

        println!("\nAddress verified - belongs to your IVK");
        (addr, g, p)
    };

    // Step 3: Get the name to bind
    let name = Text::new("Name to bind:")
        .with_help_message("1-62 chars, lowercase letters and digits only")
        .prompt()?;

    validate_name(&name)?;

    // Generate signature - proves knowledge of ivk for this (name, address) binding
    let mut rng = rand::thread_rng();
    let address_str = address.to_string();

    // Convert IVK to scalar for signing
    // Orchard IVK is not directly a scalar, but we derive a signing scalar from it
    // The proper approach: derive the scalar from the raw IVK bytes
    let ivk_bytes = ivk.to_bytes();
    let ivk_scalar = Fr::from_uniform_bytes(&ivk_bytes);

    let signature = sign(&mut rng, &ivk_scalar, &g_d, &pk_d, &name, &address_str);

    println!("\n=== Signature ===");
    println!("Hex: {}", signature);
    println!("\nInclude this in your Zcash memo field:");
    println!("ZNS:SIGN:{}:{}:{}", name, address_str, signature);

    Ok(())
}

fn verify_interactive() -> Result<()> {
    println!("\n=== Verify Name Binding ===\n");

    // Get name
    let name = Text::new("Name:").prompt()?;

    // Get address
    let address_str = Text::new("Unified address:").prompt()?;

    let address: ZcashAddress = address_str.parse().context("invalid Zcash address")?;

    // Get signature
    let sig_hex = Text::new("Signature (hex):").prompt()?;

    let sig_bytes = hex::decode(&sig_hex).context("invalid hex in signature")?;

    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature must be 64 bytes"))?;

    let signature = Signature::from_bytes(&sig_array)?;

    // Extract components from address
    let (g_d, pk_d, _d) = keys::extract_address_components(&address)?;

    // Verify
    let valid = verify(&g_d, &pk_d, &name, &address_str, &signature);

    if valid {
        println!("\n✓ Signature is VALID");
        println!(
            "  The owner of {} authorized binding '{}'",
            address_str, name
        );
    } else {
        println!("\n✗ Signature is INVALID");
        println!("  Either the signature is wrong, or it was for a different name/address");
        bail!("verification failed");
    }

    Ok(())
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("name cannot be empty");
    }
    if name.len() > 62 {
        bail!("name must be 62 characters or fewer");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    {
        bail!("name must contain only lowercase ASCII letters and digits (a-z, 0-9)");
    }
    Ok(())
}

// Need to import Fr for the signing
use zns_schnorr::Fr;
