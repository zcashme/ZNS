/// Pallas curve field definitions for use with arkworks NonNativeFieldVar.
///
/// Pallas curve: y² = x³ + 5 over Fq
///   Fq (base field):   p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
///   Fr (scalar field):  r = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001
///
/// These are emulated inside the BLS12-381 scalar field via NonNativeFieldVar.
use ark_ff::{Fp256, MontBackend, MontConfig};

/// Pallas base field Fq — coordinates of curve points live here.
#[derive(MontConfig)]
#[modulus = "28948022309329048855892746252171976963363056481941560715954676764349967630337"]
#[generator = "5"]
pub struct PallasFqConfig;
pub type PallasFq = Fp256<MontBackend<PallasFqConfig, 4>>;

/// Pallas scalar field Fr — scalars for point multiplication live here.
#[derive(MontConfig)]
#[modulus = "28948022309329048855892746252171976963363056481941647379679742748393362948097"]
#[generator = "5"]
pub struct PallasFrConfig;
pub type PallasFr = Fp256<MontBackend<PallasFrConfig, 4>>;

/// Pallas curve parameter: b = 5 (in y² = x³ + 5, a = 0).
pub const PALLAS_B: u64 = 5;
