mod circuit;
mod fields;
mod gadgets;
mod hybrid_circuit;
mod memo;
mod schnorr;
mod verify;

use ark_bls12_381::Bls12_381;
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_snark::SNARK;
use ark_std::rand::rngs::OsRng;

use ark_ff::PrimeField;
use ff::FromUniformBytes;
use group::{Curve, GroupEncoding};
use pasta_curves::arithmetic::{CurveAffine, CurveExt};
use pasta_curves::pallas;

use circuit::compute_binding_hash;
use fields::PallasFq;
use gadgets::sinsemilla::SinsemillaTable;
use hybrid_circuit::ZnsHybridCircuit;
use memo::{ZnsAction, ZnsMemo};
use schnorr::{build_schnorr_message, schnorr_sign, schnorr_verify};
use verify::build_hybrid_public_inputs;

type NativeFr = ark_bls12_381::Fr;

fn main() {
    println!("=== ZNS Hybrid Binding Circuit (Schnorr + Groth16) ===\n");

    // -------------------------------------------------------
    // 1. Compute Sinsemilla constants
    // -------------------------------------------------------
    println!("[1/6] Computing Sinsemilla constants...");
    let commit_ivk_table = compute_sinsemilla_table();
    println!("       S-table (1024 entries) and Q point ready.\n");

    // -------------------------------------------------------
    // 2. Trusted setup — cached to disk
    // -------------------------------------------------------
    let params_path = std::path::Path::new("zns_hybrid_params.bin");
    let vk_path = std::path::Path::new("zns_hybrid_vk.bin");

    let (pk, vk) = if params_path.exists() {
        println!("[2/6] Loading cached hybrid Groth16 parameters...");
        let file = std::fs::File::open(params_path).expect("failed to open params");
        let reader = std::io::BufReader::new(file);
        let pk: ark_groth16::ProvingKey<Bls12_381> =
            ark_serialize::CanonicalDeserialize::deserialize_uncompressed_unchecked(reader)
                .expect("failed to deserialize pk");
        let vk = pk.vk.clone();
        println!("       Loaded from cache.\n");
        (pk, vk)
    } else {
        println!("[2/6] Generating hybrid Groth16 parameters (first run, will cache)...");
        let empty_circuit = ZnsHybridCircuit {
            ak: None,
            blind_point: None,
            g_d: None,
            pk_d: None,
            binding_hash: None,
            nk_witness: None,
            commit_ivk_table: commit_ivk_table.clone(),
        };

        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(empty_circuit, &mut OsRng)
            .expect("setup failed");

        let file = std::fs::File::create(params_path).expect("failed to create params file");
        let writer = std::io::BufWriter::new(file);
        ark_serialize::CanonicalSerialize::serialize_uncompressed(&pk, writer)
            .expect("failed to serialize pk");
        println!("       Parameters generated and cached to {}.\n", params_path.display());
        (pk, vk)
    };

    // Export VK separately.
    if !vk_path.exists() {
        let mut vk_bytes = Vec::new();
        ark_serialize::CanonicalSerialize::serialize_compressed(&vk, &mut vk_bytes)
            .expect("failed to serialize vk");
        std::fs::write(vk_path, &vk_bytes).expect("failed to write vk file");
        println!("       VK saved to {} ({} bytes)\n", vk_path.display(), vk_bytes.len());
    }

    // -------------------------------------------------------
    // 3. Key derivation from spending key
    // -------------------------------------------------------
    let sk_bytes: [u8; 32] = [
        0x42, 0x13, 0x37, 0xAB, 0xCD, 0xEF, 0x01, 0x23,
        0x45, 0x67, 0x89, 0x0A, 0xBC, 0xDE, 0xF0, 0x12,
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    ];
    let name = "jules";
    let bound_u_address = "u1placeholder_bound_address";

    println!("[3/6] Deriving key components...");
    println!("       Name: {}", name);

    // ask = ToScalar(PRF_expand(sk, 0x06))
    let prf_ask = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(b"Zcash_ExpandSeed")
        .hash(&[sk_bytes.as_slice(), &[0x06u8]].concat());
    let ask = pallas::Scalar::from_uniform_bytes(prf_ask.as_bytes().try_into().unwrap());

    // ak = [ask] * SpendAuthBase
    let spend_auth_base = pallas::Point::hash_to_curve("z.cash:Orchard")(b"G");
    let ak_point = spend_auth_base * ask;
    let ak_xy = pallas_point_to_fq(&ak_point);
    let ak_bytes: [u8; 32] = ak_point.to_bytes().as_ref().try_into().unwrap();

    // nk = ToBase(PRF_expand(sk, 0x07))
    let prf_nk = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(b"Zcash_ExpandSeed")
        .hash(&[sk_bytes.as_slice(), &[0x07u8]].concat());
    let nk_pasta = pallas::Base::from_uniform_bytes(prf_nk.as_bytes().try_into().unwrap());
    let nk_fq = PallasFq::from_le_bytes_mod_order(&ff::PrimeField::to_repr(&nk_pasta));

    // rivk = ToScalar(PRF_expand(sk, 0x08))
    let prf_rivk = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(b"Zcash_ExpandSeed")
        .hash(&[sk_bytes.as_slice(), &[0x08u8]].concat());
    let rivk = pallas::Scalar::from_uniform_bytes(prf_rivk.as_bytes().try_into().unwrap());

    // blind_point = [rivk] * R_base (precomputed out-of-circuit)
    let r_base = pallas::Point::hash_to_curve("z.cash:Orchard-CommitIvk-r")(&[]);
    let blind_point_pallas = r_base * rivk;
    let blind_point_xy = pallas_point_to_fq(&blind_point_pallas);
    let blind_point_bytes: [u8; 32] = blind_point_pallas.to_bytes().as_ref().try_into().unwrap();

    // Derive g_d and pk_d from the orchard crate
    let (g_d_xy, pk_d_xy, receiver_bytes) = derive_address_components(&sk_bytes);

    let binding_hash = compute_binding_hash(name, bound_u_address);

    println!("       ak:          {}", hex::encode(ak_bytes));
    println!("       blind_point: {}", hex::encode(blind_point_bytes));
    println!("       binding_hash:{}", hex::encode(binding_hash));

    // -------------------------------------------------------
    // 4. Schnorr signature
    // -------------------------------------------------------
    println!("\n[4/6] Creating Schnorr signature...");
    let schnorr_msg = build_schnorr_message(&ak_bytes, &blind_point_bytes, &binding_hash);
    let schnorr_sig = schnorr_sign(&ask, &schnorr_msg);

    // Verify immediately
    assert!(
        schnorr_verify(&ak_bytes, &schnorr_msg, &schnorr_sig),
        "Schnorr self-verification failed!"
    );
    println!("       Schnorr signature created and self-verified.\n");

    // -------------------------------------------------------
    // 5. Groth16 proof (hybrid circuit)
    // -------------------------------------------------------
    println!("[5/6] Creating Groth16 proof (hybrid circuit)...");

    let circuit = ZnsHybridCircuit {
        ak: Some(ak_xy),
        blind_point: Some(blind_point_xy),
        g_d: Some(g_d_xy),
        pk_d: Some(pk_d_xy),
        binding_hash: Some(binding_hash),
        nk_witness: Some(nk_fq),
        commit_ivk_table: commit_ivk_table.clone(),
    };

    // Check constraint satisfaction first
    let debug_circuit = circuit.clone();
    let cs = ConstraintSystem::<NativeFr>::new_ref();
    debug_circuit.generate_constraints(cs.clone()).unwrap();
    println!("       Constraints: {}", cs.num_constraints());
    println!("       Instance vars: {}", cs.num_instance_variables());
    println!("       Witness vars: {}", cs.num_witness_variables());
    let satisfied = cs.is_satisfied().unwrap();
    println!("       Satisfied: {}", satisfied);

    if !satisfied {
        match cs.which_is_unsatisfied() {
            Ok(Some(trace)) => println!("       FAILING constraint: {}", trace),
            Ok(None) => println!("       FAILING: unknown constraint"),
            Err(e) => println!("       Error finding unsatisfied: {:?}", e),
        }
        return;
    }

    let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut OsRng)
        .expect("proof generation failed");
    println!("       Proof created.\n");

    // Serialize proof
    let mut proof_bytes = Vec::new();
    ark_serialize::CanonicalSerialize::serialize_compressed(&proof, &mut proof_bytes)
        .expect("serialization failed");
    println!("       Proof size: {} bytes", proof_bytes.len());

    // Verify Groth16
    let public_inputs = build_hybrid_public_inputs(ak_xy, blind_point_xy, g_d_xy, pk_d_xy, &binding_hash);
    let pvk = Groth16::<Bls12_381>::process_vk(&vk).expect("vk processing failed");
    match Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, &public_inputs, &proof) {
        Ok(true) => println!("       Groth16 VALID.\n"),
        Ok(false) => {
            println!("       Groth16 INVALID.");
            return;
        }
        Err(e) => {
            println!("       Groth16 ERROR: {:?}", e);
            return;
        }
    }

    // -------------------------------------------------------
    // 6. Binary memo encoding
    // -------------------------------------------------------
    println!("[6/6] Encoding binary memo...");

    let memo = ZnsMemo {
        action: ZnsAction::Register,
        name: name.to_string(),
        receiver: receiver_bytes,
        ak: ak_bytes,
        blind_point: blind_point_bytes,
        schnorr_sig: schnorr_sig.to_bytes(),
        groth16_proof: proof_bytes,
    };

    let encoded = memo.encode();
    println!("       Memo size: {} bytes (limit: 512)", encoded.len());
    assert!(encoded.len() <= 512, "Memo exceeds 512-byte limit!");

    // Decode round-trip
    let decoded = ZnsMemo::decode(&encoded).expect("memo decode failed");
    assert_eq!(decoded.name, name);
    assert_eq!(decoded.ak, ak_bytes);
    println!("       Memo encode/decode round-trip OK.");

    println!("\n=== SUCCESS: \"{}\" bound with hybrid Schnorr+Groth16 proof ===", name);
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
        PallasFq::from_le_bytes_mod_order(&x_bytes),
        PallasFq::from_le_bytes_mod_order(&y_bytes),
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

/// Derive g_d, pk_d, and receiver bytes from a spending key.
fn derive_address_components(
    sk_bytes: &[u8; 32],
) -> ((PallasFq, PallasFq), (PallasFq, PallasFq), [u8; 43]) {
    use orchard::keys::{FullViewingKey, Scope, SpendingKey};

    let sk = SpendingKey::from_bytes(*sk_bytes).expect("invalid spending key");
    let fvk = FullViewingKey::from(&sk);
    let address = fvk.address_at(0u32, Scope::External);

    let raw = address.to_raw_address_bytes();
    let d: [u8; 11] = raw[..11].try_into().unwrap();
    let pk_d_bytes: [u8; 32] = raw[11..43].try_into().unwrap();

    // receiver = diversifier || pk_d_compressed
    let mut receiver = [0u8; 43];
    receiver[..11].copy_from_slice(&d);
    receiver[11..43].copy_from_slice(&pk_d_bytes);

    // g_d = DiversifyHash(d)
    let g_d_point = pallas::Point::hash_to_curve("z.cash:Orchard-gd")(&d);
    let g_d = pallas_point_to_fq(&g_d_point);

    // pk_d decompressed
    let pk_d_affine = pallas::Affine::from_bytes(&pk_d_bytes).unwrap();
    let pk_d_point = pallas::Point::from(pk_d_affine);
    let pk_d = pallas_point_to_fq(&pk_d_point);

    (g_d, pk_d, receiver)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSynthesizer;

    #[test]
    fn test_hybrid_circuit_satisfied() {
        let sk_bytes: [u8; 32] = [
            0x42, 0x13, 0x37, 0xAB, 0xCD, 0xEF, 0x01, 0x23,
            0x45, 0x67, 0x89, 0x0A, 0xBC, 0xDE, 0xF0, 0x12,
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        ];

        let commit_ivk_table = compute_sinsemilla_table();

        // Derive components
        let spend_auth_base = pallas::Point::hash_to_curve("z.cash:Orchard")(b"G");
        let prf_ask = blake2b_simd::Params::new()
            .hash_length(64).personal(b"Zcash_ExpandSeed")
            .hash(&[sk_bytes.as_slice(), &[0x06u8]].concat());
        let ask = pallas::Scalar::from_uniform_bytes(prf_ask.as_bytes().try_into().unwrap());
        let ak_point = spend_auth_base * ask;
        let ak_xy = pallas_point_to_fq(&ak_point);

        let prf_nk = blake2b_simd::Params::new()
            .hash_length(64).personal(b"Zcash_ExpandSeed")
            .hash(&[sk_bytes.as_slice(), &[0x07u8]].concat());
        let nk_pasta = pallas::Base::from_uniform_bytes(prf_nk.as_bytes().try_into().unwrap());
        let nk_fq = PallasFq::from_le_bytes_mod_order(&ff::PrimeField::to_repr(&nk_pasta));

        let prf_rivk = blake2b_simd::Params::new()
            .hash_length(64).personal(b"Zcash_ExpandSeed")
            .hash(&[sk_bytes.as_slice(), &[0x08u8]].concat());
        let rivk = pallas::Scalar::from_uniform_bytes(prf_rivk.as_bytes().try_into().unwrap());
        let r_base = pallas::Point::hash_to_curve("z.cash:Orchard-CommitIvk-r")(&[]);
        let blind_point_pallas = r_base * rivk;
        let blind_point_xy = pallas_point_to_fq(&blind_point_pallas);

        let (g_d_xy, pk_d_xy, _receiver) = derive_address_components(&sk_bytes);
        let binding_hash = compute_binding_hash("jules", "u1placeholder");

        let circuit = ZnsHybridCircuit {
            ak: Some(ak_xy),
            blind_point: Some(blind_point_xy),
            g_d: Some(g_d_xy),
            pk_d: Some(pk_d_xy),
            binding_hash: Some(binding_hash),
            nk_witness: Some(nk_fq),
            commit_ivk_table,
        };

        let cs = ConstraintSystem::<NativeFr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        eprintln!("Hybrid circuit constraints: {}", cs.num_constraints());
        assert!(cs.is_satisfied().unwrap(), "Hybrid circuit not satisfied!");
    }

    #[test]
    fn test_schnorr_roundtrip() {
        let sk_bytes: [u8; 32] = [
            0x42, 0x13, 0x37, 0xAB, 0xCD, 0xEF, 0x01, 0x23,
            0x45, 0x67, 0x89, 0x0A, 0xBC, 0xDE, 0xF0, 0x12,
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        ];

        let prf_ask = blake2b_simd::Params::new()
            .hash_length(64).personal(b"Zcash_ExpandSeed")
            .hash(&[sk_bytes.as_slice(), &[0x06u8]].concat());
        let ask = pallas::Scalar::from_uniform_bytes(prf_ask.as_bytes().try_into().unwrap());

        let spend_auth_base = pallas::Point::hash_to_curve("z.cash:Orchard")(b"G");
        let ak_point = spend_auth_base * ask;
        let ak_bytes: [u8; 32] = ak_point.to_bytes().as_ref().try_into().unwrap();

        let blind_point_bytes = [0xBB; 32]; // dummy for this test
        let binding_hash = compute_binding_hash("test", "u1addr");
        let msg = build_schnorr_message(&ak_bytes, &blind_point_bytes, &binding_hash);

        let sig = schnorr_sign(&ask, &msg);
        assert!(schnorr_verify(&ak_bytes, &msg, &sig));
    }

    #[test]
    fn test_memo_roundtrip() {
        let memo = ZnsMemo {
            action: ZnsAction::Register,
            name: "jules".to_string(),
            receiver: [0xAA; 43],
            ak: [0xBB; 32],
            blind_point: [0xCC; 32],
            schnorr_sig: [0xDD; 64],
            groth16_proof: vec![0xEE; 192],
        };

        let encoded = memo.encode();
        assert!(encoded.len() <= 512);

        let decoded = ZnsMemo::decode(&encoded).unwrap();
        assert_eq!(decoded.name, "jules");
        assert_eq!(decoded.action, ZnsAction::Register);
    }
}
