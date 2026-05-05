#![no_main]
sp1_zkvm::entrypoint!(main);

// Angle 2: run Sinsemilla CommitDomain (the actual NoteCommit primitive) and
// measure cycle count via cargo prove execute.
use ff::PrimeField;
use group::Curve;
use pasta_curves::arithmetic::CurveAffine;
use pasta_curves::pallas;
use sinsemilla::CommitDomain;

pub fn main() {
    let msg_bytes = sp1_zkvm::io::read::<[u8; 8]>();
    let rcm_bytes = sp1_zkvm::io::read::<[u8; 32]>();

    let msg_bits: Vec<bool> = msg_bytes
        .iter()
        .flat_map(|b| (0..8u8).map(move |i| (b >> i) & 1 == 1))
        .collect();

    let domain = CommitDomain::new("z.cash:Orchard-NoteCommit");

    let rcm = pallas::Scalar::from_repr(rcm_bytes).unwrap_or_else(|| pallas::Scalar::from(1u64));

    let commitment = domain
        .commit(msg_bits.into_iter(), &rcm)
        .expect("sinsemilla commit failed");

    let affine = commitment.to_affine();
    let x_bytes: [u8; 32] = affine.coordinates().unwrap().x().to_repr();

    sp1_zkvm::io::commit(&x_bytes);
}
