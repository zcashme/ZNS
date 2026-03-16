use zcash_keys::keys::{UnifiedIncomingViewingKey, UnifiedAddressRequest};
use zcash_protocol::consensus::MainNetwork;

fn main() {
    let uivk_str = "uivk1cpxzaa8rck580qfekjd3xma32zzk4mwm0p4c99qglpy4atgw74up0lexqvz5tq2wwj7s980c8fe9s98x7g9t9l603pjj6rsp44ufdj6dh0u3d28xm8rmcjdlej40unnvjrwtex45er8uxy3jk6tt22gu9a36t546kplsy280qq92ssz4sscev8529k347r8v2x3xzduuldjdltjjjy02sgv59hgjx2fud6u6y70nvu6g3h9p4n20gtcmmhjwsvqv2ykr2jlc3ert3qa4n99d7p0mg8g743jm5y96frmnu4aheyh6wf3wh9g4hz8jhy70s9xda9rmyg0aqdnec44j84hwjwxar9";

    let uivk = UnifiedIncomingViewingKey::decode(&MainNetwork, uivk_str)
        .expect("failed to decode UIVK");

    let request = UnifiedAddressRequest::new(true, false, false)
        .expect("invalid request");

    let (address, di) = uivk.default_address(request)
        .expect("failed to derive address");

    let ua_str = address.encode(&MainNetwork);
    println!("u-address: {}", ua_str);
    println!("length:    {} bytes", ua_str.len());

    // ZIP 321 URI: zcash:<address>?amount=0.0001&memo=<base64>
    let memo_text = "zns:register:jules";
    let memo_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        memo_text.as_bytes(),
    );
    let uri = format!("zcash:{}?amount=0.0001&memo={}", ua_str, memo_b64);
    println!("\nZIP 321 URI:\n{}", uri);
}
