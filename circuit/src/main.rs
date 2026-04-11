//! ZNS Schnorr Signer - Interactive CLI for Pallas curve Schnorr signatures
//!
//! Signs a user-defined name binding to a Zcash unified address,
//! proving knowledge of the incoming viewing key (ivk).

use anyhow::{bail, Context, Result};
use inquire::{Select, Text};
use zcash_address::ZcashAddress;

use zns_schnorr::{keys, sign, verify, Signature};

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

    // Get name
    let name = Text::new("Name to bind:")
        .with_help_message("1-62 chars, lowercase letters and digits only")
        .prompt()?;

    validate_name(&name)?;

    // Get unified address
    let address_str = Text::new("Unified address to bind to:").prompt()?;

    let address: ZcashAddress = address_str.parse().context("invalid Zcash address")?;

    // Get key input method
    let key_method = Select::new("Key input method:", vec!["seed phrase", "ivk hex"]).prompt()?;

    let ivk = match key_method {
        "seed phrase" => {
            let phrase = Text::new("Enter seed phrase (24 words):").prompt()?;
            keys::derive_ivk_from_seed(&phrase)?
        }
        "ivk hex" => {
            let ivk_hex = Text::new("Enter ivk (64 hex chars):").prompt()?;
            keys::parse_ivk_hex(&ivk_hex)?
        }
        _ => unreachable!(),
    };

    // Extract g_d and pk_d from unified address
    // For now, we use placeholder derivation
    // In production, this should properly parse Orchard receiver
    let (g_d, pk_d) = keys::extract_address_components(&address)?;

    // Generate signature
    let mut rng = rand::thread_rng();
    let signature = sign(&mut rng, &ivk, &g_d, &pk_d, &name, &address_str);

    println!("\n=== Signature ===");
    println!("Hex: {}", signature);
    println!("\nInclude this in your Zcash memo field:");
    println!("ZNS:SIGN:{}:{}", name, signature);

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
    let (g_d, pk_d) = keys::extract_address_components(&address)?;

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
