#![no_main]
sp1_zkvm::entrypoint!(main);

// Angle 3: full orchard Note::from_parts -> note.commitment() end-to-end inside the zkVM.
// We read all note fields from stdin, compute the NoteCommitment, and commit its x-coordinate.
use orchard::{
    note::{RandomSeed, Rho},
    value::NoteValue,
    Address, Note,
};

pub fn main() {
    // Recipient address: 43 bytes — read as a Vec then convert.
    let addr_vec = sp1_zkvm::io::read::<Vec<u8>>();
    let addr_bytes: [u8; 43] = addr_vec.try_into().expect("expected 43 addr bytes");
    // Note value: raw u64 (zatoshi).
    let value_raw = sp1_zkvm::io::read::<u64>();
    // rho: 32-byte canonical LE Pallas base field element.
    let rho_bytes = sp1_zkvm::io::read::<[u8; 32]>();
    // rseed: 32-byte random seed.
    let rseed_bytes = sp1_zkvm::io::read::<[u8; 32]>();

    let recipient = Address::from_raw_address_bytes(&addr_bytes)
        .expect("invalid address bytes");

    let value = NoteValue::from_raw(value_raw);

    let rho = Rho::from_bytes(&rho_bytes)
        .expect("invalid rho bytes");

    let rseed = RandomSeed::from_bytes(rseed_bytes, &rho)
        .expect("invalid rseed bytes");

    let note = Note::from_parts(recipient, value, rho, rseed)
        .expect("invalid note");

    let cmx = note.commitment();
    // ExtractedNoteCommitment is the x-coordinate of the NoteCommitment point.
    let cmx_bytes: [u8; 32] = orchard::note::ExtractedNoteCommitment::from(cmx).to_bytes();

    sp1_zkvm::io::commit(&cmx_bytes);
}
