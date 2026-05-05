#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    let x = sp1_zkvm::io::read::<u64>();
    sp1_zkvm::io::commit(&(x + 1));
}
