use sp1_sdk::{Elf, MockProver, Prover, SP1Stdin};

const ELF: &[u8] = include_bytes!(
    "../../target/riscv64im-succinct-zkvm-elf/release/sp1-orchard-test-program"
);

#[tokio::main]
async fn main() {
    sp1_sdk::utils::setup_logger();

    let mut stdin = SP1Stdin::new();
    stdin.write(&[0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04u8]);
    let mut rcm = [0xffu8; 32];
    rcm[31] = 0x00;
    stdin.write(&rcm);

    let client = MockProver::new().await;
    let elf = Elf::from(ELF);
    let (mut public_values, report) = client.execute(elf, stdin).await.unwrap();

    let cycles = report.total_instruction_count() + report.total_syscall_count();
    println!("Sinsemilla NoteCommit domain — cycles: {}", cycles);

    let x_bytes = public_values.read::<[u8; 32]>();
    let hex_str: String = x_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    println!("Commitment x-coord: {}", hex_str);
}
