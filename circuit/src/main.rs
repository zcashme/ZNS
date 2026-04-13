//! ZNS Schnorr Signer - Interactive CLI for Pallas curve Schnorr signatures

use anyhow::{bail, Context, Result};
use inquire::{Select, Text};
use zcash_address::ZcashAddress;

use zns_schnorr::keys;
use zns_schnorr::{sign_with_ivk, verify_with_address, Signature};

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

    let addr_input =
        Text::new("Unified address to bind to (press Enter to derive from IVK):").prompt()?;

    let (_address, address_str) = if addr_input.trim().is_empty() {
        let (addr_str, _, _, _) = keys::derive_unified_address(&ivk)?;
        let addr: ZcashAddress = addr_str
            .parse()
            .context("failed to parse derived address")?;
        println!("\nDerived unified address: {}", addr);
        (addr, addr_str)
    } else {
        let addr: ZcashAddress = addr_input.parse().context("invalid Zcash address")?;
        keys::verify_address_ownership(&addr, &ivk)?;
        println!("\nAddress verified - belongs to your IVK");
        (addr, addr_input.trim().to_string())
    };

    let name = Text::new("Name to bind:")
        .with_help_message("1-62 chars, lowercase letters and digits only")
        .prompt()?;

    validate_name(&name)?;

    let signature = sign_with_ivk(
        &mut rand::thread_rng(),
        &ivk,
        zip32::DiversifierIndex::new(),
        &name,
        &address_str,
    )?;

    let sig_hex = hex::encode(signature.to_bytes());
    println!("\n=== Signature ===");
    println!("Hex: {}", sig_hex);
    println!("\nInclude this in your Zcash memo field:");
    println!("ZNS:SIGN:{}:{}:{}", name, address_str, sig_hex);

    Ok(())
}

fn verify_interactive() -> Result<()> {
    println!("\n=== Verify Name Binding ===\n");

    let name = Text::new("Name:").prompt()?;
    let address_str = Text::new("Unified address:").prompt()?;
    let address: ZcashAddress = address_str.parse().context("invalid Zcash address")?;

    let sig_hex = Text::new("Signature (hex):").prompt()?;
    let sig_bytes = hex::decode(&sig_hex).context("invalid hex in signature")?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_array)?;

    if verify_with_address(&address, &name, &signature)? {
        println!("\n✓ Signature is VALID");
        println!(
            "  The owner of {} authorized binding '{}'",
            address_str, name
        );
    } else {
        println!("\n✗ Signature is INVALID");
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
