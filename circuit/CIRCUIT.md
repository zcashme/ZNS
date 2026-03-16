# ZNS Binding Circuit

Groth16 proof on BLS12-381 that proves knowledge of an Orchard spending key
and authorizes binding a name to a unified address.

## Statement

> "I know a spending key `sk` that derives to the signer's unified address,
> and I authorize binding name **N** to address **A**."

## Inputs

| Input | Visibility | Type |
|---|---|---|
| `sk` | Private witness | `[u8; 32]` |
| `g_d` | Public | `(PallasFq, PallasFq)` |
| `pk_d` | Public | `(PallasFq, PallasFq)` |
| `binding_hash` | Public | `[u8; 32]` (256 bits) |

## Constants

| Constant | Description |
|---|---|
| `SpendAuthBase` | Pallas generator for spend authorization |
| `CommitIvk table` | Sinsemilla lookup table for `z.cash:Orchard-CommitIvk` |
| `CommitIvk R base` | Blinding base point for CommitIvk |

## Circuit

```
                        sk [private, 32 bytes]
                        │
            ┌───────────┼───────────┐
            ▼           ▼           ▼
     PRF_expand(0x06)  PRF_expand(0x07)  PRF_expand(0x08)
     [BLAKE2b]         [BLAKE2b]         [BLAKE2b]
            │           │                │
            ▼           ▼                ▼
        ask (512b)   nk (512b→Fq)    rivk (512b)
            │           │                │
            ▼           │                │
    ┌───────────┐       │                │
    │ Scalar Mul│       │                │
    │[ask]×G_sa │       │                │
    └─────┬─────┘       │                │
          │             │                │
          ▼             │                │
         ak             │                │
          │             │                │
          ▼             ▼                ▼
    ┌─────────────────────────────────────────┐
    │   SinsemillaShortCommit                 │
    │   domain: "z.cash:Orchard-CommitIvk"    │
    │   msg:  I2LEBSP_255(ak.x) ‖ nk  (510b) │
    │   blind: rivk                           │
    └────────────────┬────────────────────────┘
                     │
                     ▼
                    ivk
                     │
                     ▼
               ┌───────────┐
               │ Scalar Mul│
               │ [ivk]×g_d │◄──── g_d [public input]
               └─────┬─────┘
                     │
                     ▼
               pk_d_computed
                     │
                     ▼
              ┌──────────────┐
              │ pk_d_computed│
              │   == pk_d    │◄──── pk_d [public input]
              └──────────────┘

     binding_hash(name, address) ──── [public input, no in-circuit constraints]
```

## Step-by-step

### 1. Allocate spending key
`sk` (32 bytes) is split into 4 × 64-bit words and allocated as a private witness.

### 2. PRF_expand(sk, 0x06) → ask
`PRF_expand(sk, t) = BLAKE2b-512(personalization="Zcash_ExpandSeed", msg=sk||t)`
No BLAKE2b key parameter — sk is concatenated with the domain byte as the message.
Output is 512 raw bits used as a scalar for group multiplication.

### 3. ak = [ask] × SpendAuthBase
Non-native scalar multiplication on Pallas inside BLS12-381. Produces the
spend authorization key.

### 4. PRF_expand(sk, 0x07) → nk
BLAKE2b-512 with domain separator `0x07`. Output is 512 bits, reduced
mod q_P (Pallas base field) in-circuit to produce `nk` as a `PallasFq`
element (`ToBase` operation).

### 5. PRF_expand(sk, 0x08) → rivk
BLAKE2b-512 with domain separator `0x08`. Output is 512 bits used as the
blinding scalar for the Sinsemilla commitment.

### 6. ivk = SinsemillaShortCommit(ak, nk, rivk)
```
domain:  "z.cash:Orchard-CommitIvk"
message: I2LEBSP_255(ak.x) ‖ I2LEBSP_255(nk)   (510 bits, padded to 520)
blind:   rivk
```
Produces the incoming viewing key as a Pallas field element.

### 7. pk_d = [ivk] × g_d
Non-native scalar multiplication. `g_d` is the diversified base point,
provided as a public input (derived externally from the diversifier `d`).

### 8. Enforce pk_d equality
Assert `pk_d_computed == pk_d` where `pk_d` is the transmission key
extracted from the signer's unified address (public input).
This is the core identity check.

### 9. Expose binding_hash
`binding_hash = BLAKE2b-512("ZNS:name_binding", name ‖ address)[..32]`
is computed out-of-circuit and exposed as 256 public input bits.
No in-circuit constraints — Groth16's verification equation binds the
proof to this specific (name, address) pair, preventing replay.

## Scalar handling

`ask` (step 2) and `rivk` (step 5) are used as raw 512-bit values for
scalar multiplication without explicit mod-reduction. This is sound because
`[x]G = [x mod r]G` for any group of order `r` — the group operation
performs the reduction implicitly.

`nk` (step 4) requires explicit reduction because it is used as a field
element (input to Sinsemilla), not as a scalar for point multiplication.

## Verifier responsibilities

The circuit does **not** prove:
- That `g_d` is correctly derived from a diversifier (`g_d = DiversifyHash(d)`)
- That `g_d` or `pk_d` are valid points on the Pallas curve
- That the address is well-formed

The verifier must independently compute `g_d` and `pk_d` from the claimed
unified address before checking the proof. Curve membership and correct
derivation are the verifier's responsibility.

## Security of binding_hash

`binding_hash` is exposed as 256 public input bits with no in-circuit
constraints. This is sound because Groth16's verification equation binds
all public inputs into the pairing check — a proof generated for one set
of public inputs will not verify against a different set. The hash
therefore acts as an implicit commitment: the proof is only valid for the
specific `(name, address)` pair that produced the hash.

## Cost profile

| Component | Constraints | Cumulative |
|---|---|---|
| 3 × BLAKE2b-512 | ~135k each | ~406k |
| ak scalar mul ([ask] × SpendAuthBase) | ~5.9M | ~6.0M |
| nk ToBase reduction (512b → Fq) | ~135k | ~6.2M |
| Sinsemilla CommitIvk | ~3.2M | ~9.4M |
| ivk scalar mul ([ivk] × g_d) | ~5.9M | ~15.3M |
| pk_d equality + binding_hash | ~1M | ~16.4M |
| **Total** | | **~16.4M constraints** |

324 public input scalars (BLS12-381 Fr), ~16.2M witness variables.

The non-native field arithmetic (embedding Pallas inside BLS12-381) is the
primary constraint cost — the two scalar multiplications alone account for
~72% of total constraints.
