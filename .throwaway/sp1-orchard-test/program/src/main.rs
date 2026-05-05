#![no_main]
sp1_zkvm::entrypoint!(main);

// Angle 4: two Note::commitment() calls (old note + new note), simulating the real
// ZNS marketplace proof workload.
use orchard::{
    note::{ExtractedNoteCommitment, RandomSeed, Rho},
    value::NoteValue,
    Address, Note,
};

fn read_note() -> Note {
    let addr_vec = sp1_zkvm::io::read::<Vec<u8>>();
    let addr_bytes: [u8; 43] = addr_vec.try_into().expect("expected 43 addr bytes");
    let value_raw = sp1_zkvm::io::read::<u64>();
    let rho_bytes = sp1_zkvm::io::read::<[u8; 32]>();
    let rseed_bytes = sp1_zkvm::io::read::<[u8; 32]>();

    let recipient = Address::from_raw_address_bytes(&addr_bytes).unwrap();
    let value = NoteValue::from_raw(value_raw);
    let rho = Rho::from_bytes(&rho_bytes).unwrap();
    let rseed = RandomSeed::from_bytes(rseed_bytes, &rho).unwrap();
    Note::from_parts(recipient, value, rho, rseed).unwrap()
}

pub fn main() {
    let old_note = read_note();
    let new_note = read_note();

    let old_cmx: [u8; 32] = ExtractedNoteCommitment::from(old_note.commitment()).to_bytes();
    let new_cmx: [u8; 32] = ExtractedNoteCommitment::from(new_note.commitment()).to_bytes();

    sp1_zkvm::io::commit(&old_cmx);
    sp1_zkvm::io::commit(&new_cmx);
}
