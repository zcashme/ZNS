# ZNS Hybrid Circuit Specification

## Problem

ZNS needs to prove: "I know the spending key `sk` behind this Orchard u-address, and I authorize binding name N to address A." The proof must fit in a 512-byte Zcash shielded memo.

### Why not just Schnorr?

A Schnorr signature proves knowledge of a discrete log — "I know `x` such that `P = [x] * G`." That's a special-purpose ZKP. It can only cover one step of the Orchard key derivation.

The Orchard key hierarchy derives `pk_d` (the address) from `sk` (the spending key) through a chain:

```
sk
 ├─ ask = ToScalar(PRF_expand(sk, 0x06))
 │   └─ ak = [ask] * SpendAuthBase        ← Schnorr can prove this step
 ├─ nk  = ToBase(PRF_expand(sk, 0x07))
 └─ rivk = ToScalar(PRF_expand(sk, 0x08))
        │
        ├─ (ak, nk, rivk) → SinsemillaCommit → ivk
        └─ pk_d = [ivk] * g_d              ← needs general-purpose ZKP
```

A Schnorr signature with `ask` proves you know the secret behind `ak`. But it doesn't prove that `ak` chains through Sinsemilla and scalar multiplication to produce `pk_d`. That middle section (ak → ivk → pk_d) involves Sinsemilla hashing and elliptic curve arithmetic that only a general-purpose proof system can handle.

Proving only `ivk`-level knowledge (Schnorr with ivk against pk_d) would be insufficient — `ivk` is a viewing key, not a spending key. Someone with `ivk` can see your transactions but not spend. ZNS name binding requires spending authority.

### Why not the full Groth16 circuit?

The original circuit proves the entire chain from `sk` to `pk_d` inside a single Groth16 proof. But the Orchard derivation lives on the Pallas curve, while Groth16 runs over BLS12-381. Every Pallas field operation gets emulated with hundreds of BLS12-381 constraints (non-native field arithmetic). The result: ~97M R1CS constraints, 8.7 GB proving key, ~20 minute proving time.

### Why not recursive proofs?

A recursive approach (Halo 2 inner proof over native Pallas → Groth16 outer proof over BLS12-381) would theoretically reduce the circuit to ~500K constraints. But verifying a Halo 2 IPA proof inside a Groth16 circuit still requires non-native Pallas EC operations (~30M+ constraints). Nova folding could bridge this more cheaply, but no off-the-shelf Halo2→Nova→Groth16 pipeline exists. The implementation effort and security risk aren't justified for a one-time name registration.

## Solution: Hybrid Schnorr + Groth16

Split the proof at `ak` — the natural boundary between what Schnorr can prove and what needs a circuit:

```
Schnorr proves:   sk → ask → ak        (out-of-circuit, 64 bytes)
                              │
                         ak is the link
                              │
Groth16 proves:          ak → ivk → pk_d  (in-circuit, 192 bytes)
```

Neither proof alone is sufficient. Together they prove spending key ownership of the address.

### What the Schnorr signature proves

The prover derives `ask = ToScalar(PRF_expand(sk, 0x06))` from the spending key and signs a message with it. The verifier checks the signature against `ak`. This proves: "I know the spend authorization key behind `ak`" — and since `ask` is deterministically derived from `sk`, this proves knowledge of `sk`.

The signed message binds `ak || blind_point || binding_hash`, preventing substitution of any component between the two proofs.

Deterministic nonces (BLAKE2b-based, keyed on `ask || message`) eliminate nonce-reuse attacks. Even in the rebinding case (selling/transferring a name), every distinct binding produces a distinct nonce because the message changes.

### What the Groth16 circuit proves

Given `ak` (authenticated by the Schnorr signature), the circuit proves the rest of the Orchard CommitIvk derivation:

1. `hash_point = SinsemillaHashToPoint("z.cash:Orchard-CommitIvk-M", I2LEBSP_255(ak.x) || I2LEBSP_255(nk))`
   - 510-bit message = 51 chunks of 10 bits
   - Binary tree table lookup per chunk (~20K constraints each)
2. `commit_point = hash_point + blind_point`
   - `blind_point = [rivk] * R_base` is precomputed out-of-circuit and passed as a public input
   - One non-native point addition (~9K constraints)
3. `ivk = commit_point.x`
4. `pk_d_computed = [ivk] * g_d`
   - One 255-bit non-native scalar multiplication (~2.9M constraints)
5. `Assert pk_d_computed == pk_d`

### What's eliminated from the original circuit

| Component | Original cost | Hybrid |
|---|---|---|
| 3x BLAKE2b (PRF_expand for ask, nk, rivk) | ~405K | eliminated |
| `[ask] * SpendAuthBase` scalar mul | ~5.9M | replaced by Schnorr |
| `[rivk] * R_base` scalar mul | ~5.9M | precomputed, public input |
| `[ivk] * g_d` scalar mul | ~2.9M | kept (unavoidable) |
| Sinsemilla hash | ~1.0M | kept |
| Point addition + glue | ~9K | kept |

### Security argument

- **Schnorr** proves knowledge of `ask` (and therefore `sk`), verifiable against public `ak`
- **Groth16** proves `(ak, nk, blind_point) → ivk → pk_d` — only the correct `nk` produces the right `ivk`, and only the right `ivk` maps to `pk_d` (discrete log hardness)
- **Wrong `blind_point`** → wrong `ivk` → wrong `pk_d` → Groth16 verification fails
- **Schnorr message binds** `ak || blind_point || binding_hash` — prevents substituting any component
- **An attacker** would need to forge a Schnorr signature (break DL on Pallas) AND find a collision in the Sinsemilla→scalar-mul chain (also break DL)

## Measured Results

| | Original Circuit | Hybrid Circuit |
|---|---|---|
| R1CS constraints | ~97M | 4,118,744 |
| Proving key | 8.7 GB | 2.2 GB |
| Verification key | 16 KB | 19 KB |
| Groth16 proof | 192 bytes | 192 bytes |
| Schnorr signature | — | 64 bytes |
| Total memo payload | — | 370 bytes (for "jules") |
| Proving time (M-series Mac) | ~20 min (est.) | ~60 seconds |
| Constraint reduction | — | 24x |

## Binary Memo Format

```
[1 byte]    action type (0x01=REGISTER, 0x02=LIST, 0x03=BID, 0x04=REFUND)
[1 byte]    name length (N)
[N bytes]   name (UTF-8)
[43 bytes]  raw Orchard receiver (11-byte diversifier + 32-byte pk_d)
[32 bytes]  ak (compressed Pallas point)
[32 bytes]  blind_point (compressed Pallas point)
[64 bytes]  Schnorr signature (R || s)
[192 bytes] Groth16 proof (compressed)
```

Total: 365 + N bytes. Maximum name length: 147 characters (to fit in 512 bytes).

## Verification Flow

1. Parse binary memo
2. Extract diversifier (first 11 bytes of receiver) and pk_d (last 32 bytes)
3. Derive `g_d = DiversifyHash(diversifier)` from receiver
4. Decompress `pk_d` from receiver
5. Compute `binding_hash = BLAKE2b-512("ZNS:name_binding", name || ua)[..32]`
6. Build Schnorr message: `ak || blind_point || binding_hash`
7. **Verify Schnorr** signature against `ak`
8. Decompress `ak` and `blind_point` to (x, y) affine coordinates
9. Build Groth16 public inputs: ak, blind_point, g_d, pk_d, binding_hash
10. **Verify Groth16** proof

Both verifications must pass.

## Schnorr Signature Scheme

Standard Schnorr over Pallas with domain-separated BLAKE2b:

- **Base point:** SpendAuthBase = GroupHash^P("z.cash:Orchard", "G")
- **Secret key:** `ask` (Pallas scalar)
- **Public key:** `ak = [ask] * SpendAuthBase` (Pallas point)
- **Nonce:** `r = BLAKE2b-512("ZNS:schnorr_nonc", ask || msg) mod r_P` (deterministic)
- **Commitment:** `R = [r] * SpendAuthBase`
- **Challenge:** `e = BLAKE2b-512("ZNS:schnorr_chal", R || ak || msg) mod r_P`
- **Response:** `s = r + e * ask`
- **Signature:** `(R_compressed, s)` = 64 bytes
- **Verification:** `[s] * G == R + [e] * ak`

## File Structure

```
circuit/src/
├── hybrid_circuit.rs    — ZnsHybridCircuit (Groth16 circuit, ~4.1M constraints)
├── schnorr.rs           — Schnorr sign/verify over Pallas
├── memo.rs              — Binary memo encode/decode
├── verify.rs            — ZnsHybridVerifier (dual Schnorr + Groth16)
├── main.rs              — End-to-end prover demo
├── lib.rs               — Module exports
├── fields.rs            — PallasFq/PallasFr type definitions (unchanged)
├── circuit.rs           — Original full circuit (kept for reference)
└── gadgets/
    ├── sinsemilla.rs    — Sinsemilla hash (reused: sinsemilla_hash_to_point)
    ├── nonnative_point.rs — Pallas point arithmetic (reused: add, scalar_mul)
    ├── blake2b.rs       — BLAKE2b gadget (no longer used by hybrid circuit)
    └── word64.rs        — 64-bit word gadget (no longer used by hybrid circuit)
```

## Cached Files

- `zns_hybrid_params.bin` (2.2 GB) — Groth16 proving key, generated on first run
- `zns_hybrid_vk.bin` (19 KB) — Groth16 verification key, for verifier deployment
- `zns_params.bin` (8.7 GB) — Original circuit proving key (can be deleted)
- `zns_vk.bin` (16 KB) — Original circuit verification key (can be deleted)
