#![no_main]
sp1_zkvm::entrypoint!(main);

// Angle 5: two NoteCommitments + two nullifiers — the complete set of Orchard operations
// needed for the ZNS marketplace swap proof.
use orchard::{
    keys::FullViewingKey,
    note::{ExtractedNoteCommitment, Nullifier, RandomSeed, Rho},
    value::NoteValue,
    Address, Note,
};

fn read_note_with_fvk() -> (Note, FullViewingKey) {
    let addr_vec = sp1_zkvm::io::read::<Vec<u8>>();
    let addr_bytes: [u8; 43] = addr_vec.try_into().unwrap();
    let value_raw = sp1_zkvm::io::read::<u64>();
    let rho_bytes = sp1_zkvm::io::read::<[u8; 32]>();
    let rseed_bytes = sp1_zkvm::io::read::<[u8; 32]>();
    let fvk_bytes = sp1_zkvm::io::read::<Vec<u8>>();
    let fvk_arr: [u8; 96] = fvk_bytes.try_into().unwrap();

    let recipient = Address::from_raw_address_bytes(&addr_bytes).unwrap();
    let value = NoteValue::from_raw(value_raw);
    let rho = Rho::from_bytes(&rho_bytes).unwrap();
    let rseed = RandomSeed::from_bytes(rseed_bytes, &rho).unwrap();
    let note = Note::from_parts(recipient, value, rho, rseed).unwrap();
    let fvk = FullViewingKey::from_bytes(&fvk_arr).unwrap();
    (note, fvk)
}

pub fn main() {
    let (old_note, old_fvk) = read_note_with_fvk();
    let (new_note, new_fvk) = read_note_with_fvk();

    let old_cmx: [u8; 32] = ExtractedNoteCommitment::from(old_note.commitment()).to_bytes();
    let new_cmx: [u8; 32] = ExtractedNoteCommitment::from(new_note.commitment()).to_bytes();

    let old_nf: [u8; 32] = old_note.nullifier(&old_fvk).to_bytes();
    let new_nf: [u8; 32] = new_note.nullifier(&new_fvk).to_bytes();

    sp1_zkvm::io::commit(&old_cmx);
    sp1_zkvm::io::commit(&new_cmx);
    sp1_zkvm::io::commit(&old_nf);
    sp1_zkvm::io::commit(&new_nf);
}
