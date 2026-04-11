# ZNS Schnorr Circuit Specification

## Overview

A zero-knowledge Schnorr proof on the Pallas curve proving knowledge of the incoming viewing key (ivk) that authorizes binding a name to a Zcash unified address.

**Statement:** "I know `ivk` such that `pk_d = [ivk] × g_d`, and I authorize binding `name` to this address."

---

## Mathematical Prerequisites

### Pallas Curve Parameters

```
q = 0x40000000000000000000000000000000224698fc094cf1b9dc99e8d3c8e4a0f  (base field, 255 bits)
r = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001  (scalar field, 255 bits)
```

**Curve equation:** y² = x³ + 5 over Fq

**Generator:** Determined by `g_d = DiversifyHash(d)` where `d` is the 11-byte diversifier

### Fields

| Variable | Field | Description |
|----------|-------|-------------|
| Point coordinates (x, y) | **Fq** | Affine coordinates on Pallas |
| Scalars (ivk, r, s, c) | **Fr** | Pallas scalar field, elements mod r |

---

## Protocol Specification

### Public Inputs

```
g_d: (Fq, Fq)          // Diversified base point
pk_d: (Fq, Fq)         // Transmission key = [ivk] × g_d
binding_hash: [u8; 32] // BLAKE2b-256("ZNS:sign", name || address)
```

### Private Witness

```
ivk: Fr   // Incoming viewing key (scalar)
r: Fr     // Schnorr random nonce (scalar, must be uniform)
```

### Schnorr Signature Structure

```
R: (Fq, Fq)  // Commitment point [r] × g_d
s: Fr        // Response = r + c × ivk
```

**Serialized size:** 64 bytes (R: 32 bytes compressed, s: 32 bytes)

---

## Hash Function: Challenge Generation

### Domain Separation

```
personalization = "ZNS:sign_challenge"  // Exactly 16 bytes
```

### Challenge Computation

```
c_input = R_compressed || pk_d_compressed || binding_hash
          [32 bytes]      [32 bytes]         [32 bytes] = 96 bytes total

c_raw = BLAKE2b-512(personalization, c_input)
c = leos2ip_512(c_raw) mod r            // Reduce to scalar field
```

Where `leos2ip_512` interprets 512 bits as a little-endian integer.

**Note:** The reduction mod r must handle the full 512-bit hash output.

---

## Constraint System (R1CS on BLS12-381)

Since we're implementing this inside a Groth16 circuit on BLS12-381, we need non-native arithmetic for Pallas operations.

### Constraint Overview

| Component | Approximate Constraints |
|-----------|----------------------|
| Scalar decomposition (ivk, r, s, c to bits) | ~4 × 255 = 1,020 |
| [r] × g_d = R (scalar mul) | ~5,900,000 |
| [c] × pk_d (scalar mul) | ~5,900,000 |
| [s] × g_d (scalar mul) | ~5,900,000 |
| Point addition: R + [c]pk_d | ~50,000 |
| Equality check: [s]g_d == R + [c]pk_d | ~10,000 |
| Hash verification (c computation) | ~135,000 |
| **Total** | **~18,000,000 constraints** |

### Detailed Constraints

#### 1. Scalar Allocation

**ivk (private witness):**
```
ivk_bits = [Boolean<F>; 255]  // Little-endian bit decomposition
ivk_var = NonNativeFieldVar<Fr, NativeFr>::new_witness(cs, ivk_value)?
// Constraint: ivk_var's bits match ivk_bits
```

**r (private witness):**
```
r_bits = [Boolean<F>; 255]
r_var = NonNativeFieldVar<Fr, NativeFr>::new_witness(cs, r_value)?
```

**s (private witness):**
```
s_bits = [Boolean<F>; 255]
s_var = NonNativeFieldVar<Fr, NativeFr>::new_witness(cs, s_value)?
```

**c (computed):**
```
// c is computed from hash, verified outside circuit
// c_bits allocated as witness with bit constraints
c_bits = [Boolean<F>; 255]
c_var = NonNativeFieldVar<Fr, NativeFr>::new_witness(cs, c_value)?
```

#### 2. Point Allocation

**g_d (public input):**
```
g_d_x = NonNativeFieldVar<Fq, NativeFr>::new_input(cs, g_d.0)?
g_d_y = NonNativeFieldVar<Fq, NativeFr>::new_input(cs, g_d.1)?
```

**pk_d (public input):**
```
pk_d_x = NonNativeFieldVar<Fq, NativeFr>::new_input(cs, pk_d.0)?
pk_d_y = NonNativeFieldVar<Fq, NativeFr>::new_input(cs, pk_d.1)?
```

**R (private witness):**
```
R_x = NonNativeFieldVar<Fq, NativeFr>::new_witness(cs, R.0)?
R_y = NonNativeFieldVar<Fq, NativeFr>::new_witness(cs, R.1)?

// On-curve constraint: R_y² == R_x³ + 5
R_y_sq = R_y * R_y
R_x_sq = R_x * R_x
R_x_cubed = R_x_sq * R_x
five = FqVar::constant(Fq::from(5u64))?
enforce_equal(R_y_sq, R_x_cubed + five)
```

#### 3. Scalar Multiplication: [scalar] × Point

The core operation. We use a double-and-add ladder with conditional selection.

**Algorithm (in-circuit):**
```
Input: scalar_bits[0..255] (little-endian), base point B
Output: Result = [scalar] × B

acc = B  // Initialize accumulator
offset = B  // Track [2^k] × B for correction

// Process bits 0..253 (all except MSB)
for i in 0..254:
    acc = double(acc)
    offset = double(offset)
    // Conditional add: if scalar_bits[i] == 1, acc = acc + B
    acc_plus_B = add(acc, B)
    acc = select(scalar_bits[i], acc_plus_B, acc)

// Handle MSB (bit 254) with offset correction
// If MSB == 0: result = acc - offset = acc + (-offset)
// If MSB == 1: result = acc
neg_offset_y = -offset.y
neg_offset = Point { x: offset.x, y: neg_offset_y }
acc_corrected = add(acc, neg_offset)

result = select(scalar_bits[254], acc, acc_corrected)
```

**Point Addition Constraints (affine coordinates):**
```
Given P = (x1, y1), Q = (x2, y2), compute R = P + Q = (x3, y3)

// Lambda = (y2 - y1) / (x2 - x1)
// Allocated as witness, constrained via:
(x2 - x1) * lambda == (y2 - y1)          // Constraint 1

// x3 = lambda² - x1 - x2
// Constrained via:
lambda * lambda == x3 + x1 + x2           // Constraint 2

// y3 = lambda * (x1 - x3) - y1
// Constrained via:
lambda * (x1 - x3) == y3 + y1             // Constraint 3
```

**Point Doubling Constraints:**
```
Given P = (x, y), compute R = 2P = (x3, y3)

// Lambda = (3x²) / (2y)
// Constrained via:
(2y) * lambda == 3x²                      // Constraint 1

// x3 = lambda² - 2x
lambda * lambda == x3 + 2x                // Constraint 2

// y3 = lambda * (x - x3) - y
lambda * (x - x3) == y3 + y               // Constraint 3
```

#### 4. Main Verification Equation

**Constraint:** `[s] × g_d == R + [c] × pk_d`

```
// Left side
lhs = scalar_mul(s_bits, g_d_var)

// Right side
rhs_scalar_mul = scalar_mul(c_bits, pk_d_var)
rhs = point_add(R_var, rhs_scalar_mul)

// Enforce equality
enforce_equal(lhs.x, rhs.x)
enforce_equal(lhs.y, rhs.y)
```

#### 5. Challenge Hash Verification

The challenge `c` must be correctly derived from the Schnorr commitment.

**Approach:**
1. Compute `c_expected` outside the circuit using BLAKE2b
2. Expose `c` as public input (or derive from private witnesses)
3. Constrain that in-circuit `c` matches expected value

**Simpler approach (for this circuit):**
- `c` is allocated as witness
- The verifier independently computes `c` from `(R, pk_d, binding_hash)`
- The proof verification binds `c` to the public inputs via Groth16's equation
- No explicit in-circuit hash needed (saves ~135k constraints)

**Note:** The verifier must compute:
```
c_verify = BLAKE2b("ZNS:sign_challenge", R || pk_d || binding_hash) mod r
```

Then check that the proof's public inputs include this `c`.

---

## Circuit I/O Specification

### Private Witnesses (allocated via `new_witness`)

| Variable | Type | Bits |
|----------|------|------|
| `ivk` | Fr scalar | 255 |
| `r` | Fr scalar | 255 |
| `s` | Fr scalar | 255 |
| `R.x` | Fq element | 255 |
| `R.y` | Fq element | 255 |

### Public Inputs (allocated via `new_input`)

| Variable | Type | Bits |
|----------|------|------|
| `g_d.x` | Fq element | 255 |
| `g_d.y` | Fq element | 255 |
| `pk_d.x` | Fq element | 255 |
| `pk_d.y` | Fq element | 255 |
| `c` | Fr scalar | 255 |
| `binding_hash` | 32 bytes | 256 |

**Total public inputs:** 6 field elements × 255 bits + 256 bits ≈ 1786 bits

In R1CS (BLS12-381), each Fq/Fr element requires multiple native field elements for non-native representation.

---

## Out-of-Circuit Operations

### Sign (Prover)

```rust
fn sign(
    ivk: Fr,              // Incoming viewing key
    g_d: (Fq, Fq),        // Diversified base
    pk_d: (Fq, Fq),       // Transmission key (should equal [ivk]*g_d)
    name: &str,
    address: &str,
) -> (Point, Fr) {
    // 1. Generate random nonce
    let mut rng = OsRng;
    let r = Fr::random(&mut rng);
    
    // 2. Compute commitment point
    let g_d_point = PallasPoint::from_affine(g_d);
    let R = g_d_point * r;
    let R_affine = R.to_affine();
    
    // 3. Compute binding hash
    let mut binding_input = Vec::new();
    binding_input.extend_from_slice(name.as_bytes());
    binding_input.extend_from_slice(address.as_bytes());
    let binding_hash = blake2b_256("ZNS:sign", &binding_input);
    
    // 4. Compute challenge
    let mut c_input = Vec::new();
    c_input.extend_from_slice(&R_affine.compress());
    c_input.extend_from_slice(&pk_d.compress());
    c_input.extend_from_slice(&binding_hash);
    let c_raw = blake2b_512("ZNS:sign_challenge", &c_input);
    let c = Fr::from_le_bytes_mod_order(&c_raw);  // Reduce mod r
    
    // 5. Compute response
    let s = r + c * ivk;
    
    ((R_affine.x, R_affine.y), s)
}
```

### Verify (Out-of-Circuit)

```rust
fn verify(
    g_d: (Fq, Fq),
    pk_d: (Fq, Fq),
    name: &str,
    address: &str,
    signature: (Point, Fr),
) -> bool {
    let (R, s) = signature;
    
    // 1. Compute binding hash
    let binding_hash = compute_binding_hash(name, address);
    
    // 2. Compute challenge
    let c = compute_challenge(R, pk_d, binding_hash);
    
    // 3. Verify equation: [s]g_d == R + [c]pk_d
    let g_d_point = PallasPoint::from_affine(g_d);
    let pk_d_point = PallasPoint::from_affine(pk_d);
    let R_point = PallasPoint::from_affine(R);
    
    let lhs = g_d_point * s;
    let rhs = R_point + (pk_d_point * c);
    
    lhs == rhs
}
```

---

## Security Analysis

### Soundness

The Schnorr proof is **computationally sound** under the discrete log assumption on Pallas. A prover cannot forge a valid proof without knowing `ivk`.

**Extractor argument:** Given two accepting transcripts `(R, c₁, s₁)` and `(R, c₂, s₂)` with the same `R` but different challenges, we can compute:
```
s₁ = r + c₁·ivk
s₂ = r + c₂·ivk
s₁ - s₂ = (c₁ - c₂)·ivk
ivk = (s₁ - s₂) / (c₁ - c₂)
```

### Zero-Knowledge

The proof reveals **no information** about `ivk` beyond the fact that `pk_d = [ivk] × g_d`:
- `R = [r]g_d` is uniformly random (for random `r`)
- `s` is masked by `r` — given uniform `r`, `s` is uniform regardless of `ivk`
- `c` is determined by hash, not by `ivk`

**Warning:** `r` must be truly random and never reused. Reusing `r` with different messages leaks `ivk`:
```
s₁ - s₂ = c₁·ivk - c₂·ivk = (c₁ - c₂)·ivk
ivk = (s₁ - s₂) / (c₁ - c₂)
```

### Binding

The proof is bound to `(name, address)` via `binding_hash`. A proof generated for one name/address pair will not verify for a different pair because `c` depends on `binding_hash`.

---

## Implementation Notes

### Curve Point Compression

Pallas points are compressed to 32 bytes:
- Bit 0-254: x-coordinate (255 bits)
- Bit 255: y-is-odd flag (sign bit)

Decompression requires solving `y² = x³ + 5` for y.

### Non-Native Field Arithmetic

Using `ark-r1cs-std::fields::nonnative::NonNativeFieldVar`:
- Pallas Fq (base field) emulated in BLS12-381 Fr
- Pallas Fr (scalar field) emulated in BLS12-381 Fr

Both require approximately the same number of native constraints.

### Constants

**Pallas curve parameters (for constraints):**
```rust
const PALLAS_A: Fq = Fq::from(0u64);      // Curve coefficient a
const PALLAS_B: Fq = Fq::from(5u64);      // Curve coefficient b
```

**Generator derivation:**
```rust
g_d = GroupHash("z.cash:Orchard-gd", d)
```
where `d` is the 11-byte diversifier from the unified address.

---

## Optimization Opportunities

1. **Batch verification:** Multiple proofs can be verified with a single multi-scalar multiplication
2. **Fixed-base optimization:** Since `g_d` is known at verification time, precompute multiples
3. **Reduced scalar size:** If `ivk` is known to be small (it is, as a field element), use 128-bit scalars
4. **Windowed non-native multiplication:** Use 4-bit or 8-bit windows to reduce constraint count

---

## Reference Implementations

- **Zcash Orchard:** `orchard/src/keys.rs` - key derivation
- **Zcash RedDSA:** `orchard/src/primitives/redpallas.rs` - signature scheme
- **Arkworks:** `ark-r1cs-std/src/fields/nonnative/` - non-native field emulation

---

## Appendix: Full Constraint Count Breakdown

| Operation | Constraints per instance | Instances | Total |
|-----------|------------------------|-----------|-------|
| FqVar allocation | 0 | 6 | 0 |
| FrVar allocation | 0 | 4 | 0 |
| Bit decomposition (255 bits) | 255 | 4 | 1,020 |
| Bit decomposition (Fq, 255 bits) | 255 | 4 | 1,020 |
| Point on-curve check | ~5,000 | 1 | 5,000 |
| Scalar mul (255-bit) | ~23,000 | 3 | 69,000 |
| Point addition | ~5,000 | 2 | 10,000 |
| Equality assertion | ~1,000 | 2 | 2,000 |
| **TOTAL (optimistic)** | | | **~88,000** |

**Note:** These are rough estimates. Actual constraint counts depend on:
- Non-native field gadget implementation
- Window size for scalar multiplication
- Whether range checks are needed

A realistic implementation with `ark-r1cs-std` non-native fields is likely **500k-2M constraints** for the full Schnorr verification.

---

## Summary

This circuit proves knowledge of `ivk` via a Schnorr signature structure:
- **Private:** `ivk`, `r`, `s`, `R`
- **Public:** `g_d`, `pk_d`, `c`, `binding_hash`
- **Constraint:** `[s]g_d == R + [c]pk_d`
- **Size:** ~64 bytes proof (fits in Zcash memo)
- **Security:** Computational ZK, sound under DLOG
