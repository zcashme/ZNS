use std::path::PathBuf;

use ark_bls12_381::Bls12_381;
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_snark::SNARK;
use ark_std::rand::rngs::OsRng;

use bip39::Mnemonic;
use clap::{Parser, Subcommand};
use ff::FromUniformBytes;
use group::{Curve, GroupEncoding};
use pasta_curves::arithmetic::{CurveAffine, CurveExt};
use pasta_curves::pallas;

use orchard::keys::{FullViewingKey, Scope, SpendingKey};

use ark_ff::PrimeField as ArkPrimeField;

use zns_circuit::circuit::compute_binding_hash;
use zns_circuit::fields::PallasFq;
use zns_circuit::gadgets::sinsemilla::SinsemillaTable;
use zns_circuit::hybrid_circuit::ZnsHybridCircuit;
use zns_circuit::schnorr::{build_schnorr_message, schnorr_sign, schnorr_verify};
use zns_circuit::verify::build_hybrid_public_inputs;

type NativeFr = ark_bls12_381::Fr;

#[derive(Parser)]
#[command(name = "zns-cli", about = "ZNS name registration proof generator")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a ZNS registration proof and output a ZIP 321 URI
    Register {
        /// Name to register
        #[arg(short, long)]
        name: String,

        /// BIP39 seed phrase (24 words)
        #[arg(short, long)]
        seed: String,

        /// Account index (default: 0)
        #[arg(short, long, default_value = "0")]
        account: u32,

        /// Path to hybrid proving parameters
        #[arg(short, long, default_value = "zns_hybrid_params.bin")]
        params: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Register { name, seed, account, params } => {
            register(&name, &seed, account, &params);
        }
    }
}

fn register(name: &str, seed_phrase: &str, account: u32, params_path: &PathBuf) {
    // -------------------------------------------------------
    // 1. Derive spending key from seed phrase
    // -------------------------------------------------------
    eprint!("Deriving keys from seed phrase... ");
    let mnemonic: Mnemonic = seed_phrase.parse()
        .expect("invalid BIP39 seed phrase");
    let seed = mnemonic.to_seed("");

    let account_id = zip32::AccountId::try_from(account)
        .expect("invalid account index");
    let sk = SpendingKey::from_zip32_seed(&seed, 133, account_id)
        .expect("failed to derive spending key");
    let sk_bytes: [u8; 32] = *sk.to_bytes();

    // Derive address
    let fvk = FullViewingKey::from(&sk);
    let address = fvk.address_at(0u32, Scope::External);
    let raw = address.to_raw_address_bytes();
    let diversifier: [u8; 11] = raw[..11].try_into().unwrap();
    let pk_d_bytes: [u8; 32] = raw[11..43].try_into().unwrap();

    // Encode u-address from raw Orchard receiver
    let ua_str = encode_orchard_address(&diversifier, &pk_d_bytes);

    eprintln!("done.");
    eprintln!("  u-address: {}", ua_str);

    // -------------------------------------------------------
    // 2. Derive all cryptographic components
    // -------------------------------------------------------
    eprint!("Computing key components... ");

    // ask
    let prf_ask = blake2b_simd::Params::new()
        .hash_length(64).personal(b"Zcash_ExpandSeed")
        .hash(&[sk_bytes.as_slice(), &[0x06u8]].concat());
    let ask = pallas::Scalar::from_uniform_bytes(prf_ask.as_bytes().try_into().unwrap());

    // ak
    let spend_auth_base = pallas::Point::hash_to_curve("z.cash:Orchard")(b"G");
    let ak_point = spend_auth_base * ask;
    let ak_xy = pallas_point_to_fq(&ak_point);
    let ak_bytes: [u8; 32] = ak_point.to_bytes().as_ref().try_into().unwrap();

    // nk
    let prf_nk = blake2b_simd::Params::new()
        .hash_length(64).personal(b"Zcash_ExpandSeed")
        .hash(&[sk_bytes.as_slice(), &[0x07u8]].concat());
    let nk_pasta = pallas::Base::from_uniform_bytes(prf_nk.as_bytes().try_into().unwrap());
    let nk_fq = <PallasFq as ArkPrimeField>::from_le_bytes_mod_order(&ff::PrimeField::to_repr(&nk_pasta));

    // rivk → blind_point
    let prf_rivk = blake2b_simd::Params::new()
        .hash_length(64).personal(b"Zcash_ExpandSeed")
        .hash(&[sk_bytes.as_slice(), &[0x08u8]].concat());
    let rivk = pallas::Scalar::from_uniform_bytes(prf_rivk.as_bytes().try_into().unwrap());
    let r_base = pallas::Point::hash_to_curve("z.cash:Orchard-CommitIvk-r")(&[]);
    let blind_point_pallas = r_base * rivk;
    let blind_point_xy = pallas_point_to_fq(&blind_point_pallas);
    let blind_point_bytes: [u8; 32] = blind_point_pallas.to_bytes().as_ref().try_into().unwrap();

    // g_d, pk_d
    let g_d_point = pallas::Point::hash_to_curve("z.cash:Orchard-gd")(&diversifier);
    let g_d_xy = pallas_point_to_fq(&g_d_point);
    let pk_d_affine = pallas::Affine::from_bytes(&pk_d_bytes).unwrap();
    let pk_d_point = pallas::Point::from(pk_d_affine);
    let pk_d_xy = pallas_point_to_fq(&pk_d_point);

    // binding_hash uses u-address string for domain separation
    let binding_hash = compute_binding_hash(name, &ua_str);
    // Note: verifier reconstructs u-address from receiver to compute this

    eprintln!("done.");

    // -------------------------------------------------------
    // 3. Schnorr signature
    // -------------------------------------------------------
    eprint!("Signing with Schnorr... ");
    let schnorr_msg = build_schnorr_message(&ak_bytes, &blind_point_bytes, &binding_hash);
    let schnorr_sig = schnorr_sign(&ask, &schnorr_msg);
    assert!(schnorr_verify(&ak_bytes, &schnorr_msg, &schnorr_sig));
    eprintln!("done.");

    // -------------------------------------------------------
    // 4. Groth16 proof
    // -------------------------------------------------------
    eprint!("Computing Sinsemilla table... ");
    let commit_ivk_table = compute_sinsemilla_table();
    eprintln!("done.");

    eprint!("Loading proving parameters from {}... ", params_path.display());
    if !params_path.exists() {
        eprintln!("\nERROR: Proving parameters not found at {}", params_path.display());
        eprintln!("Run the circuit binary first to generate them:");
        eprintln!("  cd circuit && cargo run --release");
        std::process::exit(1);
    }
    let file = std::fs::File::open(params_path).expect("failed to open params");
    let reader = std::io::BufReader::new(file);
    let pk: ark_groth16::ProvingKey<Bls12_381> =
        ark_serialize::CanonicalDeserialize::deserialize_uncompressed_unchecked(reader)
            .expect("failed to deserialize proving key");
    let vk = pk.vk.clone();
    eprintln!("done.");

    eprint!("Generating Groth16 proof... ");
    let circuit = ZnsHybridCircuit {
        ak: Some(ak_xy),
        blind_point: Some(blind_point_xy),
        g_d: Some(g_d_xy),
        pk_d: Some(pk_d_xy),
        binding_hash: Some(binding_hash),
        nk_witness: Some(nk_fq),
        commit_ivk_table,
    };

    let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut OsRng)
        .expect("proof generation failed");

    let mut proof_bytes = Vec::new();
    ark_serialize::CanonicalSerialize::serialize_compressed(&proof, &mut proof_bytes)
        .expect("proof serialization failed");

    // Verify locally
    let public_inputs = build_hybrid_public_inputs(ak_xy, blind_point_xy, g_d_xy, pk_d_xy, &binding_hash);
    let pvk = Groth16::<Bls12_381>::process_vk(&vk).expect("vk processing failed");
    assert!(
        Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, &public_inputs, &proof).unwrap(),
        "Groth16 self-verification failed"
    );
    eprintln!("done ({} bytes).", proof_bytes.len());

    // -------------------------------------------------------
    // 5. Build memo (all UTF-8 text)
    //    Format: zns:register:<name>:<base64 receiver>:<base91 proof>
    //    receiver = 43 bytes (diversifier + pk_d)
    //    proof = ak(32) + blind_point(32) + schnorr(64) + groth16(192) = 320 bytes
    // -------------------------------------------------------
    let mut receiver = [0u8; 43];
    receiver[..11].copy_from_slice(&diversifier);
    receiver[11..].copy_from_slice(&pk_d_bytes);
    let receiver_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &receiver,
    );

    let mut proof_blob = Vec::with_capacity(320);
    proof_blob.extend_from_slice(&ak_bytes);
    proof_blob.extend_from_slice(&blind_point_bytes);
    proof_blob.extend_from_slice(&schnorr_sig.to_bytes());
    proof_blob.extend_from_slice(&proof_bytes);

    let proof_b91 = String::from_utf8(base91::slice_encode(&proof_blob))
        .expect("base91 should produce valid UTF-8");

    let memo_str = format!("zns:register:{}:{}:{}", name, receiver_b64, proof_b91);

    eprintln!("  Memo size: {} bytes (limit: 512)", memo_str.len());
    eprintln!("    header:   {} bytes", format!("zns:register:{}:", name).len());
    eprintln!("    receiver: {} bytes (base64)", receiver_b64.len());
    eprintln!("    proof:    {} bytes (base91)", proof_b91.len());

    if memo_str.len() > 512 {
        eprintln!("ERROR: Memo exceeds 512 bytes! Name '{}' is {} chars.", name, name.len());
        std::process::exit(1);
    }

    // -------------------------------------------------------
    // 6. Output ZIP 321 URI
    // -------------------------------------------------------
    // The memo in ZIP 321 is base64url-encoded
    let memo_for_uri = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        memo_str.as_bytes(),
    );

    let uri = format!(
        "zcash:{}?amount=0.00001&memo={}",
        ua_str, memo_for_uri
    );

    eprintln!();
    println!("{}", uri);
}

// =================================================================
// Helpers
// =================================================================

fn pallas_point_to_fq(point: &pallas::Point) -> (PallasFq, PallasFq) {
    let affine = point.to_affine();
    let coords = affine.coordinates().unwrap();
    let x_bytes: [u8; 32] = ff::PrimeField::to_repr(coords.x());
    let y_bytes: [u8; 32] = ff::PrimeField::to_repr(coords.y());
    (
        <PallasFq as ArkPrimeField>::from_le_bytes_mod_order(&x_bytes),
        <PallasFq as ArkPrimeField>::from_le_bytes_mod_order(&y_bytes),
    )
}

fn compute_sinsemilla_table() -> SinsemillaTable {
    let s_entries: Vec<(PallasFq, PallasFq)> = (0..1024u32)
        .map(|j| {
            let p = pallas::Point::hash_to_curve("z.cash:SinsemillaS")(&j.to_le_bytes());
            pallas_point_to_fq(&p)
        })
        .collect();

    let q_point =
        pallas::Point::hash_to_curve("z.cash:SinsemillaQ")(b"z.cash:Orchard-CommitIvk-M");
    let q = pallas_point_to_fq(&q_point);

    SinsemillaTable {
        entries: s_entries,
        q,
    }
}

/// Encode an Orchard-only unified address from raw diversifier + pk_d.
fn encode_orchard_address(diversifier: &[u8; 11], pk_d: &[u8; 32]) -> String {
    use zcash_address::unified::{self, Encoding};

    let mut receiver_bytes = [0u8; 43];
    receiver_bytes[..11].copy_from_slice(diversifier);
    receiver_bytes[11..].copy_from_slice(pk_d);

    let receiver = unified::Receiver::Orchard(receiver_bytes);
    let ua = unified::Address::try_from_items(vec![receiver])
        .expect("failed to create unified address");
    ua.encode(&zcash_address::Network::Main)
}
