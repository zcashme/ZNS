#![no_main]
sp1_zkvm::entrypoint!(main);

// Angle 1: can orchard (default-features = false) compile for RISC-V zkVM?
use orchard::Note;

pub fn main() {
    let x = sp1_zkvm::io::read::<u64>();
    // Touch orchard::Note so the type is actually linked
    let _ = core::mem::size_of::<Note>();
    sp1_zkvm::io::commit(&(x + 1));
}
