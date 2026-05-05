use orchard::{
    keys::{FullViewingKey, Scope, SpendingKey},
    note::{ExtractedNoteCommitment, RandomSeed, Rho},
    value::NoteValue,
    Note,
};
use sp1_sdk::{Elf, MockProver, Prover, SP1Stdin};

const ELF: &[u8] = include_bytes!(
    "../../target/riscv64im-succinct-zkvm-elf/release/sp1-orchard-test-program"
);

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();

    // Generate a valid Orchard note on the host using the real orchard library.
    // SpendingKey::random is private; generate from random bytes via from_bytes.
    let sk_bytes: [u8; 32] = rand::random();
    let sk = SpendingKey::from_bytes(sk_bytes).unwrap();
    let fvk = FullViewingKey::from(&sk);
    let recipient = fvk.address_at(0u32, Scope::External);

    // Build a dummy rho (use all-zero nullifier for simplicity).
    let rho_bytes = [1u8; 32]; // small field element, definitely valid
    let rho = orchard::note::Rho::from_bytes(&rho_bytes.into()).unwrap();
    let rseed_bytes = [2u8; 32];
    let rseed = RandomSeed::from_bytes(rseed_bytes, &rho).unwrap();

    let value = NoteValue::from_raw(1_000_000);

    let note = Note::from_parts(recipient, value, rho, rseed).unwrap();
    let expected_cmx = ExtractedNoteCommitment::from(note.commitment());
    let expected_bytes: [u8; 32] = expected_cmx.to_bytes();

    println!(
        "Host NoteCommitment x-coord: {}",
        expected_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>()
    );

    // Feed the same note fields to the guest.
    let addr_bytes: Vec<u8> = recipient.to_raw_address_bytes().to_vec();
    let mut stdin = SP1Stdin::new();
    stdin.write(&addr_bytes);
    stdin.write(&1_000_000u64);
    stdin.write(&rho_bytes);
    stdin.write(&rseed_bytes);

    let client = MockProver::new().await;
    let (mut public_values, report) = client.execute(Elf::from(ELF), stdin).await.unwrap();

    let cycles = report.total_instruction_count() + report.total_syscall_count();
    println!("Full orchard Note::commitment() — cycles: {}", cycles);

    let zkvm_bytes = public_values.read::<[u8; 32]>();
    let zkvm_hex: String = zkvm_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    println!("zkVM NoteCommitment x-coord: {}", zkvm_hex);

    assert_eq!(
        expected_bytes, zkvm_bytes,
        "MISMATCH: host and zkVM computed different NoteCommitments!"
    );
    println!("✓ Host and zkVM NoteCommitments match!");
}
