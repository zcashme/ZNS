use orchard::{
    keys::{FullViewingKey, Scope, SpendingKey},
    note::{ExtractedNoteCommitment, Nullifier, RandomSeed, Rho},
    value::NoteValue,
    Note,
};
use sp1_sdk::{Elf, MockProver, Prover, SP1Stdin};

const ELF: &[u8] = include_bytes!(
    "../../target/riscv64im-succinct-zkvm-elf/release/sp1-orchard-test-program"
);

struct NoteFixture {
    note: Note,
    fvk: FullViewingKey,
    rho_bytes: [u8; 32],
    rseed_bytes: [u8; 32],
}

fn make_fixture(sk_seed: u8, value: u64, rho_byte: u8, rseed_byte: u8) -> NoteFixture {
    let sk = SpendingKey::from_bytes([sk_seed; 32]).unwrap();
    let fvk = FullViewingKey::from(&sk);
    let recipient = fvk.address_at(0u32, Scope::External);
    let rho_bytes = [rho_byte; 32];
    let rseed_bytes = [rseed_byte; 32];
    let rho = Rho::from_bytes(&rho_bytes.into()).unwrap();
    let rseed = RandomSeed::from_bytes(rseed_bytes, &rho).unwrap();
    let note = Note::from_parts(recipient, NoteValue::from_raw(value), rho, rseed).unwrap();
    NoteFixture { note, fvk, rho_bytes, rseed_bytes }
}

fn write_fixture(stdin: &mut SP1Stdin, f: &NoteFixture) {
    stdin.write(&f.note.recipient().to_raw_address_bytes().to_vec());
    stdin.write(&f.note.value().inner());
    stdin.write(&f.rho_bytes);
    stdin.write(&f.rseed_bytes);
    stdin.write(&f.fvk.to_bytes().to_vec());
}

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();

    let old = make_fixture(0x11, 500_000, 1, 2);
    let new = make_fixture(0x22, 500_000, 3, 4);

    let expected_old_cmx: [u8; 32] = ExtractedNoteCommitment::from(old.note.commitment()).to_bytes();
    let expected_new_cmx: [u8; 32] = ExtractedNoteCommitment::from(new.note.commitment()).to_bytes();
    let expected_old_nf: [u8; 32] = old.note.nullifier(&old.fvk).to_bytes();
    let expected_new_nf: [u8; 32] = new.note.nullifier(&new.fvk).to_bytes();

    let mut stdin = SP1Stdin::new();
    write_fixture(&mut stdin, &old);
    write_fixture(&mut stdin, &new);

    let client = MockProver::new().await;
    let (mut pv, report) = client.execute(Elf::from(ELF), stdin).await.unwrap();

    let total = report.total_instruction_count() + report.total_syscall_count();
    println!("2× NoteCommitment + 2× Nullifier — total cycles: {}", total);

    let old_cmx = pv.read::<[u8; 32]>();
    let new_cmx = pv.read::<[u8; 32]>();
    let old_nf  = pv.read::<[u8; 32]>();
    let new_nf  = pv.read::<[u8; 32]>();

    assert_eq!(expected_old_cmx, old_cmx, "old cmx mismatch");
    assert_eq!(expected_new_cmx, new_cmx, "new cmx mismatch");
    assert_eq!(expected_old_nf,  old_nf,  "old nf mismatch");
    assert_eq!(expected_new_nf,  new_nf,  "new nf mismatch");

    println!("✓ All four values match the host orchard library");
    let hex = |b: [u8; 32]| b.iter().map(|x| format!("{:02x}", x)).collect::<String>();
    println!("  old_cmx: {}", hex(old_cmx));
    println!("  new_cmx: {}", hex(new_cmx));
    println!("  old_nf:  {}", hex(old_nf));
    println!("  new_nf:  {}", hex(new_nf));
}
