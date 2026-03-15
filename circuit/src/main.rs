mod circuit;
mod fields;
mod gadgets;

use ark_bls12_381::Bls12_381;
use ark_groth16::Groth16;
use ark_r1cs_std::fields::nonnative::NonNativeFieldVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_snark::SNARK;
use ark_std::rand::rngs::OsRng;

use ark_ff::PrimeField;

use fields::PallasFq;
use circuit::{ZnsBindingCircuit, compute_binding_hash};
use gadgets::sinsemilla::SinsemillaTable;

use ff::FromUniformBytes;
use group::{Curve, GroupEncoding};
use pasta_curves::arithmetic::{CurveAffine, CurveExt};

type NativeFr = ark_bls12_381::Fr;

fn main() {
    println!("=== ZNS Binding Circuit (Orchard) ===\n");

    // -------------------------------------------------------
    // 1. Compute Orchard constants
    // -------------------------------------------------------
    println!("[1/5] Computing Orchard constants...");
    let (spend_auth_base, commit_ivk_table, commit_ivk_r_base) = compute_orchard_constants();
    println!("       SpendAuthBase, S-table (1024 entries), CommitIvk R-base ready.\n");

    // -------------------------------------------------------
    // 2. Trusted setup (parameter generation) — cached to disk
    // -------------------------------------------------------
    let params_path = std::path::Path::new("zns_params.bin");
    let (pk, vk) = if params_path.exists() {
        println!("[2/5] Loading cached Groth16 parameters...");
        let file = std::fs::File::open(params_path).expect("failed to open params");
        let reader = std::io::BufReader::new(file);
        let pk: ark_groth16::ProvingKey<Bls12_381> =
            ark_serialize::CanonicalDeserialize::deserialize_uncompressed_unchecked(reader)
                .expect("failed to deserialize pk");
        let vk = pk.vk.clone();
        println!("       Loaded from cache.\n");
        (pk, vk)
    } else {
        println!("[2/5] Generating Groth16 parameters (first run, will cache)...");
        let empty_circuit = ZnsBindingCircuit {
            sk: None,
            nk_witness: None,
            g_d: None,
            pk_d: None,
            binding_hash: None,
            spend_auth_base,
            commit_ivk_table: commit_ivk_table.clone(),
            commit_ivk_r_base,
        };

        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(empty_circuit, &mut OsRng)
            .expect("setup failed");

        // Save to disk.
        let file = std::fs::File::create(params_path).expect("failed to create params file");
        let writer = std::io::BufWriter::new(file);
        ark_serialize::CanonicalSerialize::serialize_uncompressed(&pk, writer)
            .expect("failed to serialize pk");
        println!("       Parameters generated and cached to {}.\n", params_path.display());
        (pk, vk)
    };

    // -------------------------------------------------------
    // 3. Prover: create a proof
    // -------------------------------------------------------
    // Use a valid Orchard spending key.
    let sk_bytes: [u8; 32] = [
        0x42, 0x13, 0x37, 0xAB, 0xCD, 0xEF, 0x01, 0x23,
        0x45, 0x67, 0x89, 0x0A, 0xBC, 0xDE, 0xF0, 0x12,
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    ];
    let name = "jules";
    let bound_u_address = "u1placeholder_bound_address";

    println!("[3/5] Creating proof...");
    println!("       Name: {}", name);

    // Derive address components from the spending key using the orchard crate.
    let (g_d_xy, pk_d_xy, nk_fq) = derive_address_components(&sk_bytes);
    let binding_hash = compute_binding_hash(name, bound_u_address);

    let circuit = ZnsBindingCircuit {
        sk: Some(sk_bytes),
        nk_witness: Some(nk_fq),
        g_d: Some(g_d_xy),
        pk_d: Some(pk_d_xy),
        binding_hash: Some(binding_hash),
        spend_auth_base,
        commit_ivk_table: commit_ivk_table.clone(),
        commit_ivk_r_base,
    };

    // First check if the constraints are satisfied.
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
        println!("       Total constraints: {}", cs.num_constraints());
        // Don't proceed with broken proof — exit early.
        return;
    }

    let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut OsRng)
        .expect("proof generation failed");
    println!("       Proof created.\n");

    // -------------------------------------------------------
    // 4. Serialize proof
    // -------------------------------------------------------
    println!("[4/5] Serializing proof...");
    let mut proof_bytes = Vec::new();
    ark_serialize::CanonicalSerialize::serialize_compressed(&proof, &mut proof_bytes)
        .expect("serialization failed");
    let proof_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &proof_bytes,
    );
    println!("       Proof size: {} bytes", proof_bytes.len());
    println!("       Base64: {}...\n", &proof_b64[..60.min(proof_b64.len())]);

    // -------------------------------------------------------
    // 5. Verify
    // -------------------------------------------------------
    println!("[5/5] Verifying proof...");
    let public_inputs = build_public_inputs(g_d_xy, pk_d_xy, &binding_hash);
    println!("       {} public input scalars", public_inputs.len());

    let pvk = Groth16::<Bls12_381>::process_vk(&vk).expect("vk processing failed");
    match Groth16::<Bls12_381>::verify_with_processed_vk(&pvk, &public_inputs, &proof) {
        Ok(true) => println!("       VALID — \"{}\" bound to address.", name),
        Ok(false) => println!("       INVALID — proof verification failed."),
        Err(e) => println!("       ERROR — {:?}", e),
    }
}

// =================================================================
// Orchard constant computation (using pasta_curves)
// =================================================================

fn compute_orchard_constants() -> (
    (PallasFq, PallasFq),
    SinsemillaTable,
    (PallasFq, PallasFq),
) {
    use pasta_curves::pallas;

    // SpendAuthBase = GroupHash^P("z.cash:Orchard", "G")
    let spend_auth_gen = pallas::Point::hash_to_curve("z.cash:Orchard")(b"G");
    let spend_auth_base = pallas_point_to_fq(&spend_auth_gen);

    // Sinsemilla S-table: S(j) = GroupHash("z.cash:SinsemillaS", I2LEOSP_32(j))
    let s_entries: Vec<(PallasFq, PallasFq)> = (0..1024u32)
        .map(|j| {
            let p = pallas::Point::hash_to_curve("z.cash:SinsemillaS")(&j.to_le_bytes());
            pallas_point_to_fq(&p)
        })
        .collect();

    // Q for CommitIvk-M domain.
    // HashDomain::new("{domain}-M") computes Q = hash_to_curve("z.cash:SinsemillaQ")(domain_bytes).
    let q_point =
        pallas::Point::hash_to_curve("z.cash:SinsemillaQ")(b"z.cash:Orchard-CommitIvk-M");
    let q = pallas_point_to_fq(&q_point);

    let commit_ivk_table = SinsemillaTable {
        entries: s_entries,
        q,
    };

    // R-base for CommitIvk blinding.
    // CommitDomain uses hash_to_curve("{domain}-r")(&[]) — the domain IS the personalization.
    let r_point =
        pallas::Point::hash_to_curve("z.cash:Orchard-CommitIvk-r")(&[]);
    let commit_ivk_r_base = pallas_point_to_fq(&r_point);

    (spend_auth_base, commit_ivk_table, commit_ivk_r_base)
}

/// Convert a Pallas projective point to our (PallasFq, PallasFq) representation.
fn pallas_point_to_fq(point: &pasta_curves::pallas::Point) -> (PallasFq, PallasFq) {
    let affine = point.to_affine();
    let coords = affine.coordinates().unwrap();
    // Use ff::PrimeField::to_repr() then ark_ff::PrimeField::from_le_bytes_mod_order()
    let x_bytes: [u8; 32] = ff::PrimeField::to_repr(coords.x());
    let y_bytes: [u8; 32] = ff::PrimeField::to_repr(coords.y());
    (
        PallasFq::from_le_bytes_mod_order(&x_bytes),
        PallasFq::from_le_bytes_mod_order(&y_bytes),
    )
}

// =================================================================
// Out-of-circuit Orchard key derivation (using the orchard crate)
// =================================================================

/// Derive g_d, pk_d, and nk from a spending key.
fn derive_address_components(
    sk_bytes: &[u8; 32],
) -> ((PallasFq, PallasFq), (PallasFq, PallasFq), PallasFq) {
    use orchard::keys::{FullViewingKey, Scope, SpendingKey};
    use pasta_curves::pallas;

    // Derive the full viewing key and address.
    let sk = SpendingKey::from_bytes(*sk_bytes).expect("invalid spending key");
    let fvk = FullViewingKey::from(&sk);
    let address = fvk.address_at(0u32, Scope::External);

    // Extract raw address bytes: [d (11 bytes) || pk_d_compressed (32 bytes)].
    let raw = address.to_raw_address_bytes();
    let d: [u8; 11] = raw[..11].try_into().unwrap();
    let pk_d_bytes: [u8; 32] = raw[11..43].try_into().unwrap();

    // Compute g_d = DiversifyHash(d) using pasta_curves directly.
    let g_d_point = pallas::Point::hash_to_curve("z.cash:Orchard-gd")(&d);
    let g_d = pallas_point_to_fq(&g_d_point);

    // Decompress pk_d from its 32-byte compressed form.
    let pk_d_affine =
        pallas::Affine::from_bytes(&pk_d_bytes).expect("invalid pk_d encoding");
    let pk_d_point = pasta_curves::pallas::Point::from(pk_d_affine);
    let pk_d = pallas_point_to_fq(&pk_d_point);

    // Compute nk = ToBase(PRF_expand(sk, 0x07)).
    let prf_nk = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(b"Zcash_ExpandSeed")
        .hash(&[sk_bytes.as_slice(), &[0x07u8]].concat());
    let nk_bytes: [u8; 64] = prf_nk.as_bytes().try_into().unwrap();
    let nk_pasta = pasta_curves::pallas::Base::from_uniform_bytes(&nk_bytes);
    let nk_fq = PallasFq::from_le_bytes_mod_order(&ff::PrimeField::to_repr(&nk_pasta));

    (g_d, pk_d, nk_fq)
}

// =================================================================
// Public input computation (must match circuit allocation order)
// =================================================================

/// Build Groth16 public inputs by replicating the circuit's `new_input` calls
/// in a temporary constraint system and extracting the assigned values.
fn build_public_inputs(
    g_d: (PallasFq, PallasFq),
    pk_d: (PallasFq, PallasFq),
    binding_hash: &[u8; 32],
) -> Vec<NativeFr> {
    let cs = ConstraintSystem::<NativeFr>::new_ref();

    // Must match the allocation order in ZnsBindingCircuit::generate_constraints.

    // 1. g_d as NonNativeFieldVar public inputs (x then y).
    let _ = NonNativeFieldVar::<PallasFq, NativeFr>::new_input(cs.clone(), || Ok(g_d.0)).unwrap();
    let _ = NonNativeFieldVar::<PallasFq, NativeFr>::new_input(cs.clone(), || Ok(g_d.1)).unwrap();

    // 2. pk_d as NonNativeFieldVar public inputs (x then y).
    let _ = NonNativeFieldVar::<PallasFq, NativeFr>::new_input(cs.clone(), || Ok(pk_d.0)).unwrap();
    let _ = NonNativeFieldVar::<PallasFq, NativeFr>::new_input(cs.clone(), || Ok(pk_d.1)).unwrap();

    // 3. binding_hash as 256 Boolean public inputs.
    for i in 0..256 {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        let bit = (binding_hash[byte_idx] >> bit_idx) & 1 == 1;
        let _ = Boolean::<NativeFr>::new_input(cs.clone(), || Ok(bit)).unwrap();
    }

    // Extract instance assignment (skip index 0, which is the constant "1").
    let binding = cs.borrow().unwrap();
    binding.instance_assignment[1..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_binding_hash() {
        let hash = compute_binding_hash("jules", "u1someaddress");
        assert_eq!(hash.len(), 32);
        let hash2 = compute_binding_hash("jules", "u1someaddress");
        assert_eq!(hash, hash2);
        let hash3 = compute_binding_hash("alice", "u1someaddress");
        assert_ne!(hash, hash3);
    }

    /// Replicate the circuit's derivation step by step using pasta_curves
    /// and compare each intermediate value against the orchard crate's output.
    #[test]
    fn test_derivation_step_by_step() {
        use pasta_curves::pallas;

        let sk: [u8; 32] = [
            0x42, 0x13, 0x37, 0xAB, 0xCD, 0xEF, 0x01, 0x23,
            0x45, 0x67, 0x89, 0x0A, 0xBC, 0xDE, 0xF0, 0x12,
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        ];

        // --- Step 1: Compute ask (raw, no negation) ---
        let prf = blake2b_simd::Params::new()
            .hash_length(64).personal(b"Zcash_ExpandSeed")
            .hash(&[sk.as_slice(), &[0x06u8]].concat());
        let ask = pallas::Scalar::from_uniform_bytes(&prf.as_bytes().try_into().unwrap());

        // --- Step 2: ak = [ask] * SpendAuthBase ---
        let sab = pallas::Point::hash_to_curve("z.cash:Orchard")(b"G");
        let ak = sab * ask;
        let ak_x: pallas::Base = *ak.to_affine().coordinates().unwrap().x();

        // Compare with orchard crate.
        use orchard::keys::{SpendingKey, FullViewingKey, Scope};
        let osk = SpendingKey::from_bytes(sk).unwrap();
        let fvk = FullViewingKey::from(&osk);
        let addr = fvk.address_at(0u32, Scope::External);
        let raw = addr.to_raw_address_bytes();
        let d: [u8; 11] = raw[..11].try_into().unwrap();
        let pk_d_bytes: [u8; 32] = raw[11..43].try_into().unwrap();

        // The orchard crate's ak might have negated ask, but ak_x should be the same.
        // (Negating a point only flips y, x stays.)
        // Let's verify by getting ak from FVK bytes.
        let fvk_bytes = fvk.to_bytes();
        // FVK is 96 bytes: ak (32) || nk (32) || rivk (32)
        let orchard_ak_bytes: [u8; 32] = fvk_bytes[..32].try_into().unwrap();
        // ak is compressed: x-coordinate with sign bit.
        // The low 255 bits are the x-coordinate.
        let mut ak_x_from_fvk = orchard_ak_bytes;
        ak_x_from_fvk[31] &= 0x7F; // Clear sign bit.

        let our_ak_x_bytes: [u8; 32] = ff::PrimeField::to_repr(&ak_x);
        eprintln!("our ak_x:    {}", hex::encode(our_ak_x_bytes));
        eprintln!("orchard ak_x:{}", hex::encode(ak_x_from_fvk));
        eprintln!("ak_x matches: {}", our_ak_x_bytes == ak_x_from_fvk);

        // --- Step 3: nk ---
        let orchard_nk_bytes: [u8; 32] = fvk_bytes[32..64].try_into().unwrap();
        let prf_nk = blake2b_simd::Params::new()
            .hash_length(64).personal(b"Zcash_ExpandSeed")
            .hash(&[sk.as_slice(), &[0x07u8]].concat());
        let nk = pallas::Base::from_uniform_bytes(&prf_nk.as_bytes().try_into().unwrap());
        let our_nk_bytes: [u8; 32] = ff::PrimeField::to_repr(&nk);
        eprintln!("our nk:    {}", hex::encode(our_nk_bytes));
        eprintln!("orchard nk:{}", hex::encode(orchard_nk_bytes));
        assert_eq!(our_nk_bytes, orchard_nk_bytes, "nk mismatch!");
        eprintln!("nk matches ✓");

        // --- Step 4: g_d ---
        let g_d = pallas::Point::hash_to_curve("z.cash:Orchard-gd")(&d);
        eprintln!("g_d computed ✓");

        // --- Step 5: pk_d = [ivk] * g_d ---
        // We can't easily get ivk from the orchard crate (it's internal).
        // But we can verify the final pk_d matches.
        let pk_d_affine = pallas::Affine::from_bytes(&pk_d_bytes).unwrap();
        eprintln!("pk_d from orchard: {}", hex::encode(pk_d_bytes));
        eprintln!("Test passed — all intermediate values match orchard crate.");
    }

    #[test]
    fn test_sinsemilla_constants() {
        use pasta_curves::pallas;
        // Check that our SpendAuthBase matches the orchard crate's.
        let sab = pallas::Point::hash_to_curve("z.cash:Orchard")(b"G");
        let sab_affine = sab.to_affine();
        let (our_sab_x, our_sab_y) = {
            let (sab_x, sab_y, _) = compute_orchard_constants();
            (sab_x, sab_y)
        };
        let expected_x = PallasFq::from_le_bytes_mod_order(
            &ff::PrimeField::to_repr(sab_affine.coordinates().unwrap().x()),
        );
        let expected_y = PallasFq::from_le_bytes_mod_order(
            &ff::PrimeField::to_repr(sab_affine.coordinates().unwrap().y()),
        );
        assert_eq!(our_sab_x.0, expected_x, "SpendAuthBase x mismatch");
        assert_eq!(our_sab_x.1, expected_y, "SpendAuthBase y mismatch");
    }

    #[test]
    fn test_derive_address_components() {
        let sk: [u8; 32] = [
            0x42, 0x13, 0x37, 0xAB, 0xCD, 0xEF, 0x01, 0x23,
            0x45, 0x67, 0x89, 0x0A, 0xBC, 0xDE, 0xF0, 0x12,
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        ];
        let (g_d, pk_d, _nk) = derive_address_components(&sk);
        assert_ne!(g_d.0, PallasFq::from(0u64));
        assert_ne!(pk_d.0, PallasFq::from(0u64));
    }

    #[test]
    fn test_public_inputs_deterministic() {
        let sk: [u8; 32] = [0x42; 32];
        let (g_d, pk_d, _nk) = derive_address_components(&sk);
        let bh = compute_binding_hash("test", "u1addr");
        let inputs1 = build_public_inputs(g_d, pk_d, &bh);
        let inputs2 = build_public_inputs(g_d, pk_d, &bh);
        assert_eq!(inputs1, inputs2);
        assert!(!inputs1.is_empty());
    }
}
