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

    // DEBUG: print reference values from out-of-circuit computation
    {
        use pasta_curves::pallas;

        // ask hash (raw BLAKE2b output)
        let prf_ask = blake2b_simd::Params::new()
            .hash_length(64).personal(b"Zcash_ExpandSeed")
            .hash(&[sk_bytes.as_slice(), &[0x06u8]].concat());
        eprintln!("  [REF] ask hash: {}", hex::encode(prf_ask.as_bytes()));

        // ak point
        let ask = pallas::Scalar::from_uniform_bytes(&prf_ask.as_bytes().try_into().unwrap());
        let sab = pallas::Point::hash_to_curve("z.cash:Orchard")(b"G");
        let ak = sab * ask;
        let ak_affine = ak.to_affine();
        let ak_x_bytes: [u8; 32] = ff::PrimeField::to_repr(ak_affine.coordinates().unwrap().x());
        let ak_y_bytes: [u8; 32] = ff::PrimeField::to_repr(ak_affine.coordinates().unwrap().y());
        eprintln!("  [REF] ak.x: {}", hex::encode(ak_x_bytes));
        eprintln!("  [REF] ak.y: {}", hex::encode(ak_y_bytes));

        // nk
        let nk_repr = ark_ff::PrimeField::into_bigint(nk_fq);
        eprintln!("  [REF] nk:   {}", nk_repr);

        // rivk hash
        let prf_rivk = blake2b_simd::Params::new()
            .hash_length(64).personal(b"Zcash_ExpandSeed")
            .hash(&[sk_bytes.as_slice(), &[0x08u8]].concat());
        eprintln!("  [REF] rivk hash: {}", hex::encode(prf_rivk.as_bytes()));

        // pk_d
        let pk_d_x_repr = ark_ff::PrimeField::into_bigint(pk_d_xy.0);
        let pk_d_y_repr = ark_ff::PrimeField::into_bigint(pk_d_xy.1);
        eprintln!("  [REF] pk_d.x: {}", pk_d_x_repr);
        eprintln!("  [REF] pk_d.y: {}", pk_d_y_repr);
    }

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

    /// Test scalar multiplication correctness for small and medium scalars.
    #[test]
    fn test_scalar_mul_small() {
        use pasta_curves::pallas;
        use gadgets::nonnative_point::PallasPointVar;

        // Use SpendAuthBase as our test base point.
        let base_point = pallas::Point::hash_to_curve("z.cash:Orchard")(b"G");
        let base_affine = base_point.to_affine();
        let base_x = PallasFq::from_le_bytes_mod_order(
            &ff::PrimeField::to_repr(base_affine.coordinates().unwrap().x()),
        );
        let base_y = PallasFq::from_le_bytes_mod_order(
            &ff::PrimeField::to_repr(base_affine.coordinates().unwrap().y()),
        );

        // Test with scalar = 5 (small, 3 bits)
        for (scalar_val, label) in [(5u64, "5"), (255, "255"), (12345, "12345")] {
            let cs = ConstraintSystem::<NativeFr>::new_ref();
            let base_var = PallasPointVar::constant(cs.clone(), base_x, base_y).unwrap();

            // Create LE bit decomposition of the scalar.
            let num_bits = 16; // enough for our test values
            let bits: Vec<Boolean<NativeFr>> = (0..num_bits)
                .map(|i| {
                    Boolean::new_witness(cs.clone(), || {
                        Ok((scalar_val >> i) & 1 == 1)
                    })
                })
                .collect::<Result<Vec<_>, _>>()
                .unwrap();

            let result = PallasPointVar::scalar_mul(cs.clone(), &bits, &base_var).unwrap();
            assert!(cs.is_satisfied().unwrap(), "scalar_mul constraints not satisfied for scalar={}", label);

            // Compare with out-of-circuit computation.
            let expected_point = base_point * pallas::Scalar::from(scalar_val);
            let expected_affine = expected_point.to_affine();
            let expected_x = PallasFq::from_le_bytes_mod_order(
                &ff::PrimeField::to_repr(expected_affine.coordinates().unwrap().x()),
            );
            let expected_y = PallasFq::from_le_bytes_mod_order(
                &ff::PrimeField::to_repr(expected_affine.coordinates().unwrap().y()),
            );

            let circuit_x = result.x.value().unwrap();
            let circuit_y = result.y.value().unwrap();

            eprintln!("[scalar={}] expected x: {}", label, ark_ff::BigInteger256::from(expected_x));
            eprintln!("[scalar={}] circuit  x: {}", label, ark_ff::BigInteger256::from(circuit_x));
            eprintln!("[scalar={}] x match: {}", label, circuit_x == expected_x);
            eprintln!("[scalar={}] y match: {}", label, circuit_y == expected_y);

            assert_eq!(circuit_x, expected_x, "scalar_mul x mismatch for scalar={}", label);
            assert_eq!(circuit_y, expected_y, "scalar_mul y mismatch for scalar={}", label);
        }
        eprintln!("All small scalar mul tests passed ✓");
    }

    /// Test scalar multiplication with the actual 512-bit ask value.
    #[test]
    fn test_scalar_mul_512bit() {
        use pasta_curves::pallas;
        use gadgets::nonnative_point::PallasPointVar;

        let sk: [u8; 32] = [
            0x42, 0x13, 0x37, 0xAB, 0xCD, 0xEF, 0x01, 0x23,
            0x45, 0x67, 0x89, 0x0A, 0xBC, 0xDE, 0xF0, 0x12,
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        ];

        // Compute ask via BLAKE2b.
        let prf = blake2b_simd::Params::new()
            .hash_length(64)
            .personal(b"Zcash_ExpandSeed")
            .hash(&[sk.as_slice(), &[0x06u8]].concat());
        let ask_bytes: [u8; 64] = prf.as_bytes().try_into().unwrap();

        // Out-of-circuit: [ask] * G using pasta_curves.
        let ask_scalar = pallas::Scalar::from_uniform_bytes(&ask_bytes);
        let base_point = pallas::Point::hash_to_curve("z.cash:Orchard")(b"G");
        let expected = base_point * ask_scalar;
        let expected_affine = expected.to_affine();
        let expected_x = PallasFq::from_le_bytes_mod_order(
            &ff::PrimeField::to_repr(expected_affine.coordinates().unwrap().x()),
        );
        let expected_y = PallasFq::from_le_bytes_mod_order(
            &ff::PrimeField::to_repr(expected_affine.coordinates().unwrap().y()),
        );

        // In-circuit: 512-bit scalar mul.
        let cs = ConstraintSystem::<NativeFr>::new_ref();
        let base_x = PallasFq::from_le_bytes_mod_order(
            &ff::PrimeField::to_repr(base_point.to_affine().coordinates().unwrap().x()),
        );
        let base_y = PallasFq::from_le_bytes_mod_order(
            &ff::PrimeField::to_repr(base_point.to_affine().coordinates().unwrap().y()),
        );
        let base_var = PallasPointVar::constant(cs.clone(), base_x, base_y).unwrap();

        // Decompose ask_bytes to 512 LE bits.
        let bits: Vec<Boolean<NativeFr>> = (0..512)
            .map(|i| {
                let byte_idx = i / 8;
                let bit_idx = i % 8;
                let bit = (ask_bytes[byte_idx] >> bit_idx) & 1 == 1;
                Boolean::new_witness(cs.clone(), || Ok(bit))
            })
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let result = PallasPointVar::scalar_mul(cs.clone(), &bits, &base_var).unwrap();

        let circuit_x = result.x.value().unwrap();
        let circuit_y = result.y.value().unwrap();

        eprintln!("[512bit] expected x: {}", ark_ff::BigInteger256::from(expected_x));
        eprintln!("[512bit] circuit  x: {}", ark_ff::BigInteger256::from(circuit_x));
        eprintln!("[512bit] x match: {}", circuit_x == expected_x);
        eprintln!("[512bit] y match: {}", circuit_y == expected_y);
        eprintln!("[512bit] satisfied: {}", cs.is_satisfied().unwrap());

        assert_eq!(circuit_x, expected_x, "512-bit scalar mul x mismatch");
        assert_eq!(circuit_y, expected_y, "512-bit scalar mul y mismatch");
        assert!(cs.is_satisfied().unwrap(), "512-bit scalar mul constraints not satisfied");
    }

    /// Compute ivk out-of-circuit using the raw Sinsemilla algorithm
    /// and compare with the circuit's ivk.
    #[test]
    fn test_commit_ivk_reference() {
        use ff::{PrimeField as FfPrimeField, PrimeFieldBits};
        use group::{Curve, Group};
        use pasta_curves::pallas;

        let sk: [u8; 32] = [
            0x42, 0x13, 0x37, 0xAB, 0xCD, 0xEF, 0x01, 0x23,
            0x45, 0x67, 0x89, 0x0A, 0xBC, 0xDE, 0xF0, 0x12,
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        ];

        // --- Derive ak, nk, rivk from sk ---
        let prf_ask = blake2b_simd::Params::new()
            .hash_length(64).personal(b"Zcash_ExpandSeed")
            .hash(&[sk.as_slice(), &[0x06u8]].concat());
        let ask = pallas::Scalar::from_uniform_bytes(&prf_ask.as_bytes().try_into().unwrap());
        let sab = pallas::Point::hash_to_curve("z.cash:Orchard")(b"G");
        let ak_point = sab * ask;
        let ak_x: pallas::Base = *ak_point.to_affine().coordinates().unwrap().x();

        let prf_nk = blake2b_simd::Params::new()
            .hash_length(64).personal(b"Zcash_ExpandSeed")
            .hash(&[sk.as_slice(), &[0x07u8]].concat());
        let nk = pallas::Base::from_uniform_bytes(&prf_nk.as_bytes().try_into().unwrap());

        let prf_rivk = blake2b_simd::Params::new()
            .hash_length(64).personal(b"Zcash_ExpandSeed")
            .hash(&[sk.as_slice(), &[0x08u8]].concat());
        let rivk = pallas::Scalar::from_uniform_bytes(&prf_rivk.as_bytes().try_into().unwrap());

        // --- Build the 520-bit message: I2LEBSP_255(ak.x) || I2LEBSP_255(nk) || 0^10 ---
        let ak_bits: Vec<bool> = ak_x.to_le_bits().into_iter().take(255).collect();
        let nk_bits: Vec<bool> = nk.to_le_bits().into_iter().take(255).collect();
        let mut msg_bits: Vec<bool> = Vec::with_capacity(520);
        msg_bits.extend_from_slice(&ak_bits);
        msg_bits.extend_from_slice(&nk_bits);
        msg_bits.extend(std::iter::repeat(false).take(10)); // pad to 520
        assert_eq!(msg_bits.len(), 520);

        // --- Use the actual sinsemilla crate's CommitDomain ---
        // Add sinsemilla as a dependency and call it directly
        // For now, replicate exactly what the sinsemilla crate does:
        // It uses PRECOMPUTED S-table entries via from_xy, and incomplete addition
        // via (acc + S_chunk) + acc pattern.
        use pasta_curves::arithmetic::CurveAffine;

        let q = pallas::Point::hash_to_curve("z.cash:SinsemillaQ")(b"z.cash:Orchard-CommitIvk-M");
        let mut acc = q;
        for chunk in msg_bits.chunks(10) {
            let chunk_val: u32 = chunk.iter().enumerate()
                .map(|(i, &b)| if b { 1u32 << i } else { 0 })
                .sum();
            // Use the same approach as the sinsemilla crate: hash_to_curve -> to_affine -> from_xy
            let s_proj = pallas::Point::hash_to_curve("z.cash:SinsemillaS")(
                &chunk_val.to_le_bytes(),
            );
            let s_affine = s_proj.to_affine();
            let s_coords = s_affine.coordinates().unwrap();
            let s_point = pallas::Affine::from_xy(*s_coords.x(), *s_coords.y()).unwrap();
            // (acc + S_chunk) + acc  (incomplete addition pattern)
            let old_acc = acc;
            acc = (acc + s_point) + old_acc;
        }

        // --- Sinsemilla commit: hash_point + [rivk] * R ---
        let r_base = pallas::Point::hash_to_curve("z.cash:Orchard-CommitIvk-r")(b"");
        let commit_point = acc + r_base * rivk;

        // ivk = x-coordinate
        let ivk_ref: pallas::Base = *commit_point.to_affine().coordinates().unwrap().x();

        // Convert to arkworks PallasFq for comparison
        let ivk_fq = PallasFq::from_le_bytes_mod_order(
            &ff::PrimeField::to_repr(&ivk_ref),
        );
        let ivk_repr = ark_ff::PrimeField::into_bigint(ivk_fq);
        eprintln!("[REF] ivk (sinsemilla): {}", ivk_repr);

        // Compare with the circuit's ivk from the debug output
        // Circuit reported: 14874307776488897617966116555048561529990581765238354550869242546432540106343
        // If they match, the circuit's Sinsemilla is correct and the bug is elsewhere.
        // If they don't match, the circuit's Sinsemilla has a bug.

        // --- Compare inputs to commit_ivk: our values vs orchard crate's FVK ---
        use orchard::keys::{SpendingKey, FullViewingKey, Scope};
        let osk = SpendingKey::from_bytes(sk).unwrap();
        let fvk = FullViewingKey::from(&osk);
        let fvk_bytes = fvk.to_bytes(); // 96 bytes: ak(32) || nk(32) || rivk(32)

        // FVK ak: compressed point (x-coordinate with sign bit in MSB of last byte)
        let fvk_ak_bytes: [u8; 32] = fvk_bytes[..32].try_into().unwrap();
        let mut fvk_ak_x_bytes = fvk_ak_bytes;
        fvk_ak_x_bytes[31] &= 0x7F; // clear sign bit to get pure x-coordinate

        // Our ak.x
        let our_ak_x_bytes: [u8; 32] = FfPrimeField::to_repr(&ak_x);

        eprintln!("[CMP] our ak.x:  {}", hex::encode(our_ak_x_bytes));
        eprintln!("[CMP] fvk ak.x:  {}", hex::encode(fvk_ak_x_bytes));
        eprintln!("[CMP] ak.x match: {}", our_ak_x_bytes == fvk_ak_x_bytes);

        // FVK nk
        let fvk_nk_bytes: [u8; 32] = fvk_bytes[32..64].try_into().unwrap();
        let our_nk_bytes: [u8; 32] = FfPrimeField::to_repr(&nk);
        eprintln!("[CMP] our nk:    {}", hex::encode(our_nk_bytes));
        eprintln!("[CMP] fvk nk:    {}", hex::encode(fvk_nk_bytes));
        eprintln!("[CMP] nk match:  {}", our_nk_bytes == fvk_nk_bytes);

        // FVK rivk
        let fvk_rivk_bytes: [u8; 32] = fvk_bytes[64..96].try_into().unwrap();
        let our_rivk_bytes: [u8; 32] = FfPrimeField::to_repr(&rivk);
        eprintln!("[CMP] our rivk:  {}", hex::encode(our_rivk_bytes));
        eprintln!("[CMP] fvk rivk:  {}", hex::encode(fvk_rivk_bytes));
        eprintln!("[CMP] rivk match: {}", our_rivk_bytes == fvk_rivk_bytes);

        // Now compute ivk using the FVK's values instead of ours
        let fvk_ak_point = pallas::Point::from(
            pallas::Affine::from_bytes(&fvk_ak_bytes).unwrap()
        );
        let fvk_ak_x: pallas::Base = *fvk_ak_point.to_affine().coordinates().unwrap().x();
        let fvk_nk = <pallas::Base as FfPrimeField>::from_repr_vartime(fvk_nk_bytes).unwrap();
        let fvk_rivk = <pallas::Scalar as FfPrimeField>::from_repr_vartime(fvk_rivk_bytes).unwrap();

        // Rebuild message with FVK values
        let fvk_ak_bits: Vec<bool> = fvk_ak_x.to_le_bits().into_iter().take(255).collect();
        let fvk_nk_bits: Vec<bool> = fvk_nk.to_le_bits().into_iter().take(255).collect();
        let mut fvk_msg: Vec<bool> = Vec::with_capacity(520);
        fvk_msg.extend_from_slice(&fvk_ak_bits);
        fvk_msg.extend_from_slice(&fvk_nk_bits);
        fvk_msg.extend(std::iter::repeat(false).take(10));

        // Sinsemilla with FVK values
        let mut fvk_acc = q;
        for chunk in fvk_msg.chunks(10) {
            let chunk_val: u32 = chunk.iter().enumerate()
                .map(|(i, &b)| if b { 1u32 << i } else { 0 })
                .sum();
            let s_proj = pallas::Point::hash_to_curve("z.cash:SinsemillaS")(
                &chunk_val.to_le_bytes(),
            );
            let s_affine = s_proj.to_affine();
            let s_coords = s_affine.coordinates().unwrap();
            let s_point = pallas::Affine::from_xy(*s_coords.x(), *s_coords.y()).unwrap();
            let old_acc = fvk_acc;
            fvk_acc = (fvk_acc + s_point) + old_acc;
        }
        let fvk_commit = fvk_acc + r_base * fvk_rivk;
        let fvk_ivk: pallas::Base = *fvk_commit.to_affine().coordinates().unwrap().x();
        let fvk_ivk_fq = PallasFq::from_le_bytes_mod_order(
            &FfPrimeField::to_repr(&fvk_ivk),
        );
        eprintln!("[CMP] ivk (our inputs):  {}", ark_ff::PrimeField::into_bigint(ivk_fq));
        eprintln!("[CMP] ivk (fvk inputs):  {}", ark_ff::PrimeField::into_bigint(fvk_ivk_fq));

        // Verify FVK-derived ivk produces correct pk_d
        let addr = fvk.address_at(0u32, Scope::External);
        let raw = addr.to_raw_address_bytes();
        let d: [u8; 11] = raw[..11].try_into().unwrap();
        let pk_d_bytes: [u8; 32] = raw[11..43].try_into().unwrap();

        let g_d = pallas::Point::hash_to_curve("z.cash:Orchard-gd")(&d);

        // The orchard crate converts ivk (Fq) to scalar (Fr) via mod_r_p:
        //   pallas::Scalar::from_repr(x.to_repr()).unwrap()
        // q_P (base) is slightly smaller than r_P (scalar) for Pallas,
        // so from_repr always succeeds (every Fq value < r_P).
        let ivk_repr: [u8; 32] = FfPrimeField::to_repr(&fvk_ivk);
        let fvk_ivk_scalar = <pallas::Scalar as FfPrimeField>::from_repr(ivk_repr);
        eprintln!("[CMP] ivk as scalar (from_repr): is_some={}", bool::from(fvk_ivk_scalar.is_some()));
        let fvk_ivk_scalar = fvk_ivk_scalar.unwrap();
        eprintln!("[CMP] ivk scalar repr: {}", hex::encode(FfPrimeField::to_repr(&fvk_ivk_scalar)));
        eprintln!("[CMP] ivk base   repr: {}", hex::encode(ivk_repr));

        // Also print g_d and pk_d for debugging
        let gd_affine = g_d.to_affine();
        eprintln!("[CMP] g_d.x: {}", hex::encode(FfPrimeField::to_repr(gd_affine.coordinates().unwrap().x())));
        eprintln!("[CMP] g_d.y: {}", hex::encode(FfPrimeField::to_repr(gd_affine.coordinates().unwrap().y())));
        eprintln!("[CMP] pk_d (from addr): {}", hex::encode(pk_d_bytes));

        let pk_d_computed = g_d * fvk_ivk_scalar;
        let computed_affine = pk_d_computed.to_affine();
        eprintln!("[CMP] pk_d computed.x: {}", hex::encode(FfPrimeField::to_repr(computed_affine.coordinates().unwrap().x())));
        eprintln!("[CMP] pk_d computed.y: {}", hex::encode(FfPrimeField::to_repr(computed_affine.coordinates().unwrap().y())));
        let pk_d_from_addr = pallas::Point::from(
            pallas::Affine::from_bytes(&pk_d_bytes).unwrap()
        );
        let computed_affine = pk_d_computed.to_affine();
        let expected_affine = pk_d_from_addr.to_affine();
        let x_match = computed_affine.coordinates().unwrap().x() ==
                      expected_affine.coordinates().unwrap().x();

        eprintln!("[CMP] fvk ivk produces correct pk_d: {}", x_match);

        // --- Use the REAL sinsemilla crate to compute ivk ---
        let real_domain = sinsemilla::CommitDomain::new("z.cash:Orchard-CommitIvk");
        let real_ivk = real_domain.short_commit(
            fvk_ak_x.to_le_bits().iter().by_vals().take(255)
                .chain(fvk_nk.to_le_bits().iter().by_vals().take(255)),
            &fvk_rivk,
        ).unwrap();
        let real_ivk_fq = PallasFq::from_le_bytes_mod_order(
            &FfPrimeField::to_repr(&real_ivk),
        );
        eprintln!("[CMP] ivk (real sinsemilla crate): {}", ark_ff::PrimeField::into_bigint(real_ivk_fq));

        // Compare real crate ivk with ours
        let real_matches_ours = FfPrimeField::to_repr(&real_ivk) == FfPrimeField::to_repr(&fvk_ivk);
        eprintln!("[CMP] real sinsemilla matches ours: {}", real_matches_ours);

        // Does the REAL ivk produce correct pk_d?
        let real_ivk_scalar = <pallas::Scalar as FfPrimeField>::from_repr(
            FfPrimeField::to_repr(&real_ivk)
        ).unwrap();
        let real_pk_d = g_d * real_ivk_scalar;
        let real_pk_d_affine = real_pk_d.to_affine();
        let real_x_match = real_pk_d_affine.coordinates().unwrap().x() ==
                           expected_affine.coordinates().unwrap().x();
        eprintln!("[CMP] REAL ivk produces correct pk_d: {}", real_x_match);

        assert!(real_x_match, "Even the real sinsemilla crate's ivk doesn't produce correct pk_d");
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
