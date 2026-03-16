#ZNS Binding Circuit — Cryptographer Spec

## Goal

Build a ZK circuit that acts as a **signature of knowledge**: the holder of an Orchard spending key authorizes binding a name to a u-address.

## What is being signed

The message: **(name, u-address)**

- `name`: a UTF-8 string, e.g. `"jules"`
- `u-address`: a Zcash Orchard-only unified address (belonging to jules)

## What the proof proves

> "I know the Orchard spending key `sk` behind u-address `A`, and I authorize binding name `N` to address `A`."

> (As a second-order effect of this circuit, I should be able to authorize binding name 'N' to address 'A', using an Orchard spending key 'sk' behind a trusted u-address 'B')

## Roles

- **Prover**: holds the spending key. Produces the proof. Proof must fit in a Zcash shielded memo
- **Verifier**: has only the name, the u-address, and the proof. No other context (no transaction, no on-chain state). Verification must be **completely standalone**.

## Constraints

1. **The proof must fit in a Zcash memo field** (~512 bytes). This is why we a reasoning model chose Groth16 — proofs are ~192 bytes (Halo2 proofs were considered too large)

2. **Groth16 operates over BLS12-381.** The native scalar field is the BLS12-381 scalar field (≈ Jubjub base field).

3. **Orchard key derivation uses the Pallas curve**, which is NOT native to BLS12-381. This is the core tension: we need to link the spending key to the Orchard u-address inside a BLS12-381 circuit.

## The open question

How do we prove, inside a BLS12-381 Groth16 circuit, that a private witness `sk` corresponds to a given Orchard u-address?

Orchard key derivation path:
```
sk → ask = ToScalar(PRF_expand(sk, 0x06))
ask → ak = [ask] * SpendAuthBase          ← Pallas scalar mul
sk → nk = ToBase(PRF_expand(sk, 0x07))
sk → rivk = ToScalar(PRF_expand(sk, 0x08))
(ak, nk, rivk) → fvk
fvk → ivk (via SinsemillaCommit)          ← Pallas operations
ivk → address (via diversified base)      ← Pallas scalar mul
```

The Pallas curve operations cannot be done natively in BLS12-381. Possible approaches:
- Non-native field arithmetic (expensive — how many constraints? does the proof still fit in a memo?)
- A different commitment scheme that avoids in-circuit Pallas ops
- Recursive proof composition
- Some other construction

## Deliverable

A circuit design (or construction) where:
- **Private witness**: An Orchard spending key `sk`
- **Public inputs**: derived from the name and u-address (the verifier knows both)
- **Verification**: given only `(name, u-address, proof)`, anyone can verify
- **Soundness**: only the holder of the spending key for that u-address can produce a valid proof
- **Proof size**: must fit in ~512 bytes (Groth16-sized)


