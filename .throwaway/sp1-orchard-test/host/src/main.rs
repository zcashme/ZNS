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

fn make_note(sk_seed: u8, value: u64, rho_byte: u8, rseed_byte: u8) -> Note {
    let sk_bytes = [sk_seed; 32];
    let sk = SpendingKey::from_bytes(sk_bytes).unwrap();
    let fvk = FullViewingKey::from(&sk);
    let recipient = fvk.address_at(0u32, Scope::External);
    let rho_bytes = [rho_byte; 32];
    let rho = Rho::from_bytes(&rho_bytes.into()).unwrap();
    let rseed_bytes = [rseed_byte; 32];
    let rseed = RandomSeed::from_bytes(rseed_bytes, &rho).unwrap();
    Note::from_parts(recipient, NoteValue::from_raw(value), rho, rseed).unwrap()
}

fn write_note(stdin: &mut sp1_sdk::SP1Stdin, note: &Note, rho_bytes: [u8; 32], rseed_bytes: [u8; 32]) {
    stdin.write(&note.recipient().to_raw_address_bytes().to_vec());
    stdin.write(&note.value().inner());
    stdin.write(&rho_bytes);
    stdin.write(&rseed_bytes);
}

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();

    let old_rho = [1u8; 32];
    let old_rseed = [2u8; 32];
    let new_rho = [3u8; 32];
    let new_rseed = [4u8; 32];

    let old_note = make_note(0x11, 500_000, 1, 2);
    let new_note = make_note(0x22, 500_000, 3, 4);

    let expected_old_cmx: [u8; 32] = ExtractedNoteCommitment::from(old_note.commitment()).to_bytes();
    let expected_new_cmx: [u8; 32] = ExtractedNoteCommitment::from(new_note.commitment()).to_bytes();

    let mut stdin = sp1_sdk::SP1Stdin::new();
    write_note(&mut stdin, &old_note, old_rho, old_rseed);
    write_note(&mut stdin, &new_note, new_rho, new_rseed);

    let client = MockProver::new().await;
    let (mut public_values, report) = client.execute(Elf::from(ELF), stdin).await.unwrap();

    let cycles = report.total_instruction_count() + report.total_syscall_count();
    println!("Two Note::commitment() calls — total cycles: {}", cycles);

    let zkvm_old_cmx = public_values.read::<[u8; 32]>();
    let zkvm_new_cmx = public_values.read::<[u8; 32]>();

    assert_eq!(expected_old_cmx, zkvm_old_cmx, "old note cmx mismatch");
    assert_eq!(expected_new_cmx, zkvm_new_cmx, "new note cmx mismatch");
    println!("✓ Both NoteCommitments match the host library output");
    println!(
        "  old_cmx: {}",
        zkvm_old_cmx.iter().map(|b| format!("{:02x}", b)).collect::<String>()
    );
    println!(
        "  new_cmx: {}",
        zkvm_new_cmx.iter().map(|b| format!("{:02x}", b)).collect::<String>()
    );
}
