# SP1 Implementation Plan

Sister document to `sp1_exploration.md`. That doc describes the problem and
architecture. This doc records what the throwaway feasibility test proved and
translates it into a concrete build plan for the real `sp1-guest/` crate.

---

## Feasibility Test Results

All four angles from the test plan passed. The "key unknown" in
`sp1_exploration.md` is resolved.

### Angle 1 — `orchard 0.13` compiles for `riscv64im-succinct-zkvm-elf`

**Result: ✅ Green**

`orchard 0.13` (and its full dependency tree: `pasta_curves 0.5`, `sinsemilla
0.1`, `ff 0.13`, `group 0.13`, `reddsa`, `jubjub`, `bls12_381`) compiles clean
for the SP1 RISC-V target with no source modifications and no feature
restrictions beyond `default-features = false`.

Two compile-time obstacles existed and were solved:

1. **`getrandom` 0.3.x** — version 0.3.4 introduced a `compile_error!` for
   unknown targets. Fix: add `--cfg getrandom_backend="custom"` to rustflags.
   `sp1-zkvm` already registers the `__getrandom_v03_custom` linker symbol, so
   this is a one-liner in `.cargo/config.toml`.

2. **byte-sized atomics** — `pasta_curves 0.5`'s `sqrt-table` feature (enabled
   transitively via `alloc`) uses `lazy_static → spin::Once → AtomicU8`.
   `riscv64im` lacks the 'A' extension for sub-word atomics so the linker
   cannot resolve `__atomic_load_1` etc. Fix: add `-C passes=lower-atomic`
   to rustflags. This LLVM pass rewrites all atomic ops to plain loads/stores
   — safe in the single-threaded zkVM.

### Angle 2 — Cycle counts

**Result: ✅ Green**

All measurements from the release build, executed via `MockProver::execute`
(simulation only, no proof generation):

| Operation | Cycles |
|---|---|
| Sinsemilla `CommitDomain::commit` (direct) | ~2M |
| `Note::commitment()` × 1 | ~11M |
| `Note::commitment()` × 2 | ~22M |
| `Note::commitment()` × 2 + `Note::nullifier()` × 2 | ~52M |

Two NoteCommits (the core proof workload) sit at 22M cycles — comfortably
under SP1's practical limit and roughly 2× the `sp1_exploration.md` estimate.
Adding nullifier derivation brings the full suite to 52M, which is still
provable but worth noting: if proving cost becomes a concern, the nullifier
check may be droppable from the proof (it can be verified by the NEAR contract
against the transaction bytes directly).

### Angle 3 — `getrandom` / `rand` at runtime

**Result: ✅ Green**

All five throwaway programs ran to completion without a runtime panic. The
NoteCommit path is fully deterministic: `orchard` does not call `getrandom`
during commitment derivation. The compile-time `getrandom_backend="custom"` fix
was sufficient — no runtime stubs needed.

### Angle 4 — ELF is clean (no std leak)

**Result: ✅ Green**

```
ELF 64-bit LSB executable, UCB RISC-V, soft-float ABI,
version 1 (SYSV), statically linked, not stripped
```

No `libc`, `tokio`, `socket2`, `winapi`, or other std-only crates appear in
the guest dependency tree. The guest binary is a proper statically linked
RISC-V ELF.

### Correctness check

The throwaway host computed NoteCommitments and nullifiers using the native
`orchard` library, then fed the same inputs to the zkVM guest and asserted
byte-for-byte equality on all four outputs. All assertions passed.

---

## Required Build Infrastructure

These settings belong in `.cargo/config.toml` in any workspace that builds the
SP1 guest:

```toml
[target.riscv64im-succinct-zkvm-elf]
rustflags = [
    "--cfg", "getrandom_backend=\"custom\"",
    "-C", "passes=lower-atomic",
    "-C", "link-arg=--image-base=0x78000000",
    "-C", "panic=abort",
]
```

- `getrandom_backend="custom"` — tells `getrandom` 0.3.x to use the custom
  backend registered by `sp1-zkvm` (`__getrandom_v03_custom → sys_rand`)
- `passes=lower-atomic` — rewrites byte-sized atomic ops to plain loads/stores
  (required because `riscv64im` has no sub-word atomic instructions)
- `link-arg=--image-base=0x78000000` — places all segments above `STACK_TOP`
  (`0x7800_0000`); the SP1 executor rejects ELFs with segments below this
- `panic=abort` — required by SP1's runtime; unwinds are not supported

The guest's `Cargo.toml` needs `sp1-zkvm` with the `lib` feature (provides
`sp1_zkvm::io`):

```toml
[dependencies]
sp1-zkvm = { path = "../../sp1/crates/zkvm/entrypoint", features = ["lib"] }
orchard = { version = "0.13", default-features = false }
```

The host (proof generator) must be built with a toolchain that satisfies
`sp1-sdk`'s `rustc >= 1.88` requirement. The guest is always built with
`cargo +succinct`.

---

## Guest Program Design

The final guest takes all private witness fields for both notes from stdin, runs
the commitment and optional nullifier derivations, asserts they match the public
values, and commits the public values. The exploration doc's pseudocode is
accurate; the concrete API calls are:

```rust
#![no_main]
sp1_zkvm::entrypoint!(main);

use orchard::{
    keys::FullViewingKey,
    note::{ExtractedNoteCommitment, RandomSeed, Rho},
    value::NoteValue,
    Address, Note,
};

pub fn main() {
    // --- private witness ---
    let seller_addr = Address::from_raw_address_bytes(
        &sp1_zkvm::io::read::<Vec<u8>>().try_into().unwrap()
    ).unwrap();
    let seller_value  = NoteValue::from_raw(sp1_zkvm::io::read::<u64>());
    let seller_rho    = Rho::from_bytes(&sp1_zkvm::io::read::<[u8; 32]>()).unwrap();
    let seller_rseed  = RandomSeed::from_bytes(
        sp1_zkvm::io::read::<[u8; 32]>(), &seller_rho
    ).unwrap();
    let seller_note   = Note::from_parts(
        seller_addr, seller_value, seller_rho, seller_rseed
    ).unwrap();

    // repeat for treasury note ...

    // --- public claims ---
    let expected_seller_cmx  = sp1_zkvm::io::read::<[u8; 32]>();
    let expected_treasury_cmx = sp1_zkvm::io::read::<[u8; 32]>();
    let expected_seller_pk_d = sp1_zkvm::io::read::<[u8; 32]>();
    let expected_treasury_pk_d = sp1_zkvm::io::read::<[u8; 32]>();
    let tx_hash              = sp1_zkvm::io::read::<[u8; 32]>();

    // --- assertions ---
    let seller_cmx: [u8; 32] =
        ExtractedNoteCommitment::from(seller_note.commitment()).to_bytes();
    assert_eq!(seller_cmx, expected_seller_cmx);
    // ...

    // --- commit public values ---
    sp1_zkvm::io::commit(&expected_seller_cmx);
    sp1_zkvm::io::commit(&expected_treasury_cmx);
    sp1_zkvm::io::commit(&expected_seller_pk_d);
    sp1_zkvm::io::commit(&expected_treasury_pk_d);
    sp1_zkvm::io::commit(&tx_hash);
}
```

`pk_d` assertion: `Address::from_raw_address_bytes` decodes the 43-byte
Orchard address encoding. The `pk_d` component is the Pallas point; extracting
its 32-byte representation for comparison against `listing.seller_pk_d` requires
a small helper (the raw address bytes embed `g_d || pk_d_bytes`; `pk_d` starts
at byte 11).

---

## What Remains (Phase 1 → 4)

The exploration doc's four phases are still the right sequence. With feasibility
confirmed, the first real step is:

**Phase 1:** Create `sp1-guest/` crate in the ZNS workspace. Copy the
`.cargo/config.toml` target block above. Wire up the full guest logic. Verify
correctness with the same host-vs-zkVM equality check the throwaway used.
Measure the cycle count on the real proof payload (a live payout tx).

**Phase 2:** Add `service/src/sp1_prover.rs`. The service already has all the
note plaintext it needs (it constructs the Orchard actions). The prover module
reads those fields and calls `ProverClient::prove(...).groth16()`. Environment
variable `SP1_PROVER=network` for production, `SP1_PROVER=mock` for tests.

**Phase 3:** Adapt `near-groth16-verifier` or write an inline verifier. The
SP1 Groth16 proof is ~260 bytes; the vkey hash is a 32-byte `[u8; 32]` from
`verifying_key.bytes32()`. The main work is mapping SP1's gnark proof encoding
to the NEAR verifier's expected layout. Budget one day.

**Phase 4:** Add `sp1_proof` and `sp1_public_values` parameters to
`submit_funding`. Add `seller_pk_d: [u8; 32]` to `Listing` (extracted from
`seller_ua` at listing creation using `zcash_keys`). Verification order:
proof → public-values binding → seller/treasury pk_d check → existing burner
and admin-sig checks.

---

## Updated Risk Table

| Risk | Status |
|------|--------|
| `orchard` compiles for SP1 RISC-V | ✅ Resolved — compiles clean |
| NoteCommit cycle count too high | ✅ Resolved — 22M for 2× cmx, provable |
| `getrandom` runtime panic | ✅ Resolved — NoteCommit path is deterministic |
| SP1 gnark proof encoding vs NEAR verifier | 🔴 Still open — tackle in Phase 3 |
| NEAR gas cost of `alt_bn128_pairing_check` | ⬜ Not yet measured — low risk per exploration doc |
| `seller_pk_d` extraction from unified address | ⬜ Straightforward — `zcash_keys` exposes it |
| Nullifier derivation adds 30M cycles | 🟡 Watch — may drop from proof if cost matters |
