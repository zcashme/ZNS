//! Zcash v5 payout transaction builder.
//!
//! Constructs a transparent → Orchard transaction in two phases so the transparent
//! input can be signed by an external MPC:
//!
//!   1. [`build_unsigned`]
//!        - Builds the Orchard bundle with proven outputs.
//!        - Builds the transparent bundle in `Unauthorized` form.
//!        - Composes a `TransactionData<Unauthorized>` and computes the v5 sighash.
//!        - Returns a [`PayoutPlan`] containing the sighash + everything needed to
//!          finalize once the MPC has signed.
//!
//!   2. [`finalize_with_mpc`]
//!        - Takes the MPC-produced ECDSA signature.
//!        - Applies it to the transparent bundle (`prepare → append → finalize`).
//!        - Finalizes the Orchard bundle's binding signature using the same sighash.
//!        - Returns the serialized v5 transaction bytes ready for `lwd::SendTransaction`.

use std::sync::OnceLock;

use anyhow::{Context, Result, anyhow};
use orchard::{
    Address as OrchardAddress, Anchor,
    builder::{Builder as OrchardBuilder, BundleType},
    bundle::Bundle as OrchardBundle,
    circuit::ProvingKey as OrchardProvingKey,
    keys::OutgoingViewingKey,
    value::NoteValue,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use secp256k1::{PublicKey as SecpPubkey, Secp256k1};
use sha2::{Digest, Sha256};
use transparent::{
    builder::TransparentBuilder,
    bundle::{Bundle as TBundle, MapAuth, OutPoint, TxOut},
};
use zcash_address::ZcashAddress;
use zcash_keys::address::{Address as ZAddress, UnifiedAddress};
use zcash_primitives::transaction::{
    Authorized, TransactionData, TxVersion, Unauthorized,
    fees::{self, FeeRule as _, zip317},
    sighash::{SignableInput, signature_hash},
    txid::TxIdDigester,
};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, MainNetwork, NetworkType, TestNetwork},
    value::{ZatBalance, Zatoshis},
};
use zcash_transparent::{self as transparent};

pub fn payout_fee() -> u64 {
    zip317::FeeRule::standard()
        .fee_required(
            &TestNetwork,
            BlockHeight::from_u32(1),
            [fees::transparent::InputSize::STANDARD_P2PKH],
            std::iter::empty::<usize>(),
            0,
            0,
            2,
        )
        .expect("ZIP-317 fee for 1 P2PKH input + 2 orchard actions")
        .into_u64()
}

/// Result of phase 1.  Hold this opaquely between the sighash request and the MPC
/// signature application.
pub struct PayoutPlan {
    pub sighash: [u8; 32],
    pub orchard_sighash: [u8; 32],
    /// Compressed secp256k1 public key the MPC must sign under.
    #[allow(dead_code)]
    pub burner_pubkey: [u8; 33],
    target_height: BlockHeight,
    consensus_branch_id: BranchId,
    proof_seed: [u8; 32],
    transparent_unauth: TBundle<transparent::builder::Unauthorized>,
    orchard_unproven: OrchardBundle<
        orchard::builder::InProgress<orchard::builder::Unproven, orchard::builder::Unauthorized>,
        ZatBalance,
    >,
}

/// All inputs required to construct a payout or refund transaction.
pub struct PayoutInputs<'a> {
    /// `"mainnet"` or `"testnet"`.
    pub network: &'a str,
    /// The current chain tip — used as `target_height` for branch-id selection.
    pub target_height: u32,
    /// Burner UTXO being spent.
    pub utxo_outpoint: OutPoint,
    pub utxo_value_zats: u64,
    /// `script_pubkey` of the burner UTXO, as returned by lightwalletd.
    pub utxo_script_pubkey: Vec<u8>,
    /// Compressed secp256k1 public key controlling the burner address.
    pub burner_pubkey: [u8; 33],
    /// Bech32m-encoded UA strings.
    pub seller_ua: &'a str,
    pub treasury_ua: &'a str,
    /// For refund bundles, the buyer's UA (used as the single recipient).
    pub buyer_ua: Option<&'a str>,
    /// Net amounts (in zatoshis) to deliver to each Orchard recipient.
    /// `seller_amount + treasury_amount + fee == utxo_value_zats`.
    pub seller_amount: u64,
    pub treasury_amount: u64,
    /// 512-byte memo attached to the treasury output (typically the BUY memo).
    pub memo: [u8; 512],
    /// Optional fee override; otherwise uses [`ZCASH_FEE_DEFAULT`].
    pub fee: Option<u64>,
}

/// Lazy, in-memory Orchard proving key.  First call takes ~5 seconds; subsequent
/// calls are free.  We keep one process-global instance.
fn orchard_proving_key() -> &'static OrchardProvingKey {
    static PK: OnceLock<OrchardProvingKey> = OnceLock::new();
    PK.get_or_init(OrchardProvingKey::build)
}

fn parse_orchard_recipient(ua_str: &str, expected_net: NetworkType) -> Result<OrchardAddress> {
    let zaddr = ZcashAddress::try_from_encoded(ua_str).context("parse zcash address")?;
    let (got_net, addr) = ZAddress::try_from_zcash_address(&MainNetwork, zaddr.clone())
        .map(|a| (NetworkType::Main, a))
        .or_else(|_| {
            ZAddress::try_from_zcash_address(&TestNetwork, zaddr).map(|a| (NetworkType::Test, a))
        })
        .map_err(|e| anyhow!("decode UA: {e:?}"))?;

    if got_net != expected_net {
        return Err(anyhow!(
            "address network mismatch: got {:?}, expected {:?}",
            got_net,
            expected_net
        ));
    }

    let ua: &UnifiedAddress = match &addr {
        ZAddress::Unified(u) => u,
        _ => return Err(anyhow!("recipient must be a Unified Address with Orchard")),
    };
    ua.orchard()
        .copied()
        .ok_or_else(|| anyhow!("UA has no Orchard receiver"))
}

fn network_type(s: &str) -> Result<NetworkType> {
    match s {
        "mainnet" => Ok(NetworkType::Main),
        "testnet" | "regtest" => Ok(NetworkType::Test),
        _ => Err(anyhow!("unknown network: {s}")),
    }
}

fn deterministic_seed(input: &PayoutInputs<'_>, label: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update(input.network.as_bytes());
    hasher.update(input.target_height.to_le_bytes());
    hasher.update(input.utxo_outpoint.hash());
    hasher.update(input.utxo_outpoint.n().to_le_bytes());
    hasher.update(input.utxo_value_zats.to_le_bytes());
    hasher.update((input.utxo_script_pubkey.len() as u64).to_le_bytes());
    hasher.update(&input.utxo_script_pubkey);
    hasher.update(input.burner_pubkey);
    hasher.update(input.seller_ua.as_bytes());
    hasher.update([0u8]);
    hasher.update(input.treasury_ua.as_bytes());
    hasher.update([0u8]);
    if let Some(buyer_ua) = input.buyer_ua {
        hasher.update(buyer_ua.as_bytes());
    }
    hasher.update([0u8]);
    hasher.update(input.seller_amount.to_le_bytes());
    hasher.update(input.treasury_amount.to_le_bytes());
    hasher.update(input.memo);
    hasher.update(input.fee.unwrap_or_else(payout_fee).to_le_bytes());
    hasher.finalize().into()
}

/// Phase 1 — build the unauthorized transaction and compute its sighash.
pub fn build_unsigned(input: PayoutInputs<'_>) -> Result<PayoutPlan> {
    let net = network_type(input.network)?;
    let target_height = BlockHeight::from_u32(input.target_height);
    let branch = match net {
        NetworkType::Main => BranchId::for_height(&MainNetwork, target_height),
        _ => BranchId::for_height(&TestNetwork, target_height),
    };

    let fee = input.fee.unwrap_or_else(payout_fee);
    let total_out = input
        .seller_amount
        .checked_add(input.treasury_amount)
        .and_then(|t| t.checked_add(fee))
        .ok_or_else(|| anyhow!("amount overflow"))?;
    if total_out != input.utxo_value_zats {
        return Err(anyhow!(
            "value not balanced: utxo={} != seller+treasury+fee={}",
            input.utxo_value_zats,
            total_out
        ));
    }

    // ── transparent input ────────────────────────────────────────────────
    let mut tbuilder = TransparentBuilder::empty();
    let burner_secp =
        SecpPubkey::from_slice(&input.burner_pubkey).context("parse burner pubkey")?;
    let coin = TxOut::new(
        Zatoshis::from_u64(input.utxo_value_zats).context("utxo value")?,
        transparent::address::Script(zcash_script::script::Code(input.utxo_script_pubkey.clone())),
    );
    tbuilder
        .add_input(burner_secp, input.utxo_outpoint.clone(), coin)
        .map_err(|e| anyhow!("add transparent input: {e:?}"))?;
    let transparent_unauth = tbuilder
        .build()
        .ok_or_else(|| anyhow!("transparent bundle empty"))?;

    // ── orchard outputs ──────────────────────────────────────────────────
    let mut obuilder = OrchardBuilder::new(BundleType::DEFAULT, Anchor::empty_tree());
    if let Some(buyer_ua) = input.buyer_ua {
        // Refund bundle: single action to buyer
        let buyer_o = parse_orchard_recipient(buyer_ua, net)?;
        obuilder
            .add_output(
                None::<OutgoingViewingKey>,
                buyer_o,
                NoteValue::from_raw(input.seller_amount),
                [0u8; 512],
            )
            .map_err(|e| anyhow!("orchard add refund output: {e:?}"))?;
    } else {
        // Payout bundle: seller + treasury
        let seller_o = parse_orchard_recipient(input.seller_ua, net)?;
        let treasury_o = parse_orchard_recipient(input.treasury_ua, net)?;
        obuilder
            .add_output(
                None::<OutgoingViewingKey>,
                seller_o,
                NoteValue::from_raw(input.seller_amount),
                [0u8; 512],
            )
            .map_err(|e| anyhow!("orchard add seller output: {e:?}"))?;
        obuilder
            .add_output(
                None::<OutgoingViewingKey>,
                treasury_o,
                NoteValue::from_raw(input.treasury_amount),
                input.memo,
            )
            .map_err(|e| anyhow!("orchard add treasury output: {e:?}"))?;
    }
    let proof_seed = deterministic_seed(&input, b"orchard-proof");
    let mut rng = ChaCha20Rng::from_seed(deterministic_seed(&input, b"orchard-build"));
    let (orchard_unproven, _meta) = obuilder
        .build::<ZatBalance>(&mut rng)
        .map_err(|e| anyhow!("orchard build: {e:?}"))?
        .ok_or_else(|| anyhow!("orchard bundle empty"))?;

    // ── compose unauthorized TransactionData and compute sighash ────────
    let td_unauth: TransactionData<Unauthorized> = TransactionData::from_parts(
        TxVersion::V5,
        branch,
        0,
        target_height + 40, // expiry: ~10 minutes ahead
        Some(transparent_unauth.clone()),
        None,
        None,
        Some(orchard_unproven.clone()),
    );

    let txid_parts = td_unauth.digest(TxIdDigester);

    let orchard_sighash =
        *signature_hash(&td_unauth, &SignableInput::Shielded, &txid_parts).as_ref();

    let script_pk =
        transparent::address::Script(zcash_script::script::Code(input.utxo_script_pubkey));
    let signable = transparent::sighash::SignableInput::from_parts(
        transparent::sighash::SighashType::ALL,
        0,
        &script_pk,
        &script_pk,
        Zatoshis::from_u64(input.utxo_value_zats).unwrap(),
    );
    let sighash = *signature_hash(
        &td_unauth,
        &SignableInput::Transparent(signable),
        &txid_parts,
    )
    .as_ref();

    Ok(PayoutPlan {
        sighash,
        orchard_sighash,
        burner_pubkey: input.burner_pubkey,
        target_height,
        consensus_branch_id: branch,
        proof_seed,
        transparent_unauth,
        orchard_unproven,
    })
}

/// Phase 2 — finalize the transaction with the MPC's ECDSA signature.
///
/// `mpc_sig_compact` must be the 64-byte compact ECDSA signature
/// `r[0..32] || s[0..32]` over [`PayoutPlan::sighash`].
pub fn finalize_with_mpc(plan: PayoutPlan, mpc_sig_compact: &[u8; 64]) -> Result<Vec<u8>> {
    let secp_verify = Secp256k1::verification_only();
    let sig = secp256k1::ecdsa::Signature::from_compact(mpc_sig_compact)
        .context("parse MPC ECDSA compact signature")?;

    // ── apply MPC signature to transparent bundle ────────────────────────
    let target_sighash = plan.sighash;
    let ctx = plan
        .transparent_unauth
        .prepare_transparent_signatures(|_input| target_sighash, &secp_verify)
        .map_err(|e| anyhow!("prepare transparent sigs: {e:?}"))?;
    let ctx = ctx
        .append_external_signatures(&[sig])
        .map_err(|e| anyhow!("append external sig: {e:?}"))?;
    let transparent_authed = ctx
        .finalize_signatures()
        .map_err(|e| anyhow!("finalize transparent: {e:?}"))?;

    // ── prove + finalize orchard bundle binding signature ────────────────
    let mut rng = ChaCha20Rng::from_seed(plan.proof_seed);
    let orchard_proven = plan
        .orchard_unproven
        .create_proof(orchard_proving_key(), &mut rng)
        .map_err(|e| anyhow!("orchard prove: {e:?}"))?;
    let orchard_authed = orchard_proven
        .apply_signatures(rng, plan.orchard_sighash, &[])
        .map_err(|e| anyhow!("orchard apply_signatures: {e:?}"))?;

    // ── compose authorized transaction and serialize ─────────────────────
    let td_auth: TransactionData<Authorized> = TransactionData::from_parts(
        TxVersion::V5,
        plan.consensus_branch_id,
        0,
        plan.target_height + 40,
        Some(transparent_authed),
        None,
        None,
        Some(orchard_authed),
    );

    let tx = td_auth.freeze().context("freeze transaction")?;
    let mut out = Vec::with_capacity(2048);
    tx.write(&mut out).context("serialize tx")?;
    Ok(out)
}

/// Mapper that converts an `Unauthorized` transparent bundle into an `Authorized`
/// one with an empty scriptSig, bypassing ECDSA signature verification.
///
/// This is used only for `build_tx_bytes` where the transaction is submitted to
/// the NEAR contract for structural validation and sighash computation. The
/// contract skips the scriptSig entirely, so it does not need to contain a valid
/// signature at this stage.
struct DummyAuth;

impl MapAuth<transparent::builder::Unauthorized, transparent::bundle::Authorized> for DummyAuth {
    fn map_script_sig(
        &self,
        _s: <transparent::builder::Unauthorized as transparent::bundle::Authorization>::ScriptSig,
    ) -> transparent::address::Script {
        transparent::address::Script(zcash_script::script::Code(vec![]))
    }

    fn map_authorization(
        &self,
        _s: transparent::builder::Unauthorized,
    ) -> transparent::bundle::Authorized {
        transparent::bundle::Authorized
    }
}

pub fn build_tx_bytes(input: PayoutInputs<'_>) -> Result<Vec<u8>> {
    let plan = build_unsigned(input)?;

    // ── prove + finalize orchard bundle binding signature ────────────────
    let mut rng = ChaCha20Rng::from_seed(plan.proof_seed);
    let orchard_proven = plan
        .orchard_unproven
        .create_proof(orchard_proving_key(), &mut rng)
        .map_err(|e| anyhow!("orchard prove: {e:?}"))?;
    let orchard_authed = orchard_proven
        .apply_signatures(rng, plan.orchard_sighash, &[])
        .map_err(|e| anyhow!("orchard apply_signatures: {e:?}"))?;

    // ── bypass transparent signature verification with empty scriptSig ──
    let transparent_authed = plan.transparent_unauth.map_authorization(DummyAuth);

    // ── compose authorized transaction and serialize ─────────────────────
    let td_auth: TransactionData<Authorized> = TransactionData::from_parts(
        TxVersion::V5,
        plan.consensus_branch_id,
        0,
        plan.target_height + 40,
        Some(transparent_authed),
        None,
        None,
        Some(orchard_authed),
    );

    let tx = td_auth.freeze().context("freeze transaction")?;
    let mut out = Vec::with_capacity(2048);
    tx.write(&mut out).context("serialize tx")?;
    Ok(out)
}

#[cfg(test)]
mod sighash_tests {
    use super::*;
    use ripemd::Ripemd160;
    use sha2::{Digest, Sha256};
    use zcash_keys::keys::{UnifiedAddressRequest, UnifiedSpendingKey};
    use zcash_protocol::consensus::TestNetwork;
    use zip32::AccountId;
    use zns_contract::zcash::{compute_sighash_all, parse_tx};

    /// Derives a testnet Unified Address with an Orchard receiver from a single seed byte.
    fn test_ua(seed_byte: u8) -> String {
        let seed = vec![seed_byte; 32];
        let usk = UnifiedSpendingKey::from_seed(&TestNetwork, &seed, AccountId::ZERO)
            .expect("USK derivation");
        let uivk = usk
            .to_unified_full_viewing_key()
            .to_unified_incoming_viewing_key();
        let (ua, _) = uivk
            .default_address(UnifiedAddressRequest::AllAvailableKeys)
            .expect("UA derivation");
        ua.encode(&TestNetwork)
    }

    /// Builds a P2PKH scriptPubKey for a compressed secp256k1 public key.
    fn p2pkh_script(pubkey: &[u8; 33]) -> Vec<u8> {
        let sha = Sha256::digest(pubkey);
        let ripe = Ripemd160::digest(sha);
        let mut script = vec![0x76u8, 0xa9, 0x14];
        script.extend_from_slice(&ripe);
        script.extend_from_slice(&[0x88, 0xac]);
        script
    }

    /// Verifies that the contract's hand-rolled ZIP-244 sighash matches
    /// zcash_primitives' reference implementation on the same transaction.
    ///
    /// Flow:
    ///   1. build_unsigned  → plan.sighash  (zcash_primitives reference via signature_hash)
    ///   2. finalize_with_mpc               → serialized tx bytes
    ///   3. parse_tx + compute_sighash_all  → contract's sighash
    ///   4. assert_eq
    #[test]
    fn contract_sighash_matches_zcash_primitives() {
        let seller_ua = test_ua(1);
        let treasury_ua = test_ua(2);

        let secp = Secp256k1::new();
        let dummy_sk = secp256k1::SecretKey::from_slice(&[7u8; 32]).expect("dummy secret key");
        let burner_pubkey: [u8; 33] =
            secp256k1::PublicKey::from_secret_key(&secp, &dummy_sk).serialize();
        let script_pubkey = p2pkh_script(&burner_pubkey);

        let utxo_value: u64 = 200_000;
        let fee: u64 = payout_fee();
        let seller_amount: u64 = 185_000;
        let treasury_amount: u64 = utxo_value
            .checked_sub(seller_amount)
            .and_then(|r| r.checked_sub(fee))
            .expect("test amounts must balance");

        let plan = build_unsigned(PayoutInputs {
            network: "testnet",
            target_height: 2_000_000,
            utxo_outpoint: transparent::bundle::OutPoint::new([42u8; 32], 1),
            utxo_value_zats: utxo_value,
            utxo_script_pubkey: script_pubkey.clone(),
            burner_pubkey,
            seller_ua: &seller_ua,
            treasury_ua: &treasury_ua,
            buyer_ua: None,
            seller_amount,
            treasury_amount,
            memo: [0u8; 512],
            fee: Some(fee),
        })
        .expect("build_unsigned");

        // zcash_primitives reference — computed inside build_unsigned via signature_hash().
        let reference_sighash = plan.sighash;

        // Sign the actual sighash so finalize_with_mpc's secp256k1 verification passes.
        // The transparent input's scriptSig is skipped by parse_tx and does not
        // affect the sighash computation on either path.
        let dummy_msg = secp256k1::Message::from_digest(reference_sighash);
        let dummy_sig = secp.sign_ecdsa(&dummy_msg, &dummy_sk);
        let mut dummy_compact = [0u8; 64];
        dummy_compact.copy_from_slice(&dummy_sig.serialize_compact());
        let tx_bytes = finalize_with_mpc(plan, &dummy_compact).expect("finalize_with_mpc");

        // Contract path: parse the finalized bytes and recompute the sighash.
        let parsed_tx = parse_tx(&tx_bytes).expect("parse_tx");
        let contract_sighash = compute_sighash_all(&parsed_tx, utxo_value, &script_pubkey);

        assert_eq!(
            contract_sighash,
            reference_sighash,
            "\ncontract:  {}\nreference: {}",
            hex::encode(contract_sighash),
            hex::encode(reference_sighash),
        );
    }
}

#[cfg(test)]
mod debug_tests {
    use super::*;
    use zcash_protocol::consensus::TestNetwork;

    #[test]
    fn debug_payout_fee() {
        println!("payout_fee = {}", payout_fee());
    }
}

#[cfg(test)]
mod debug_sighash {
    use super::*;
    use ripemd::Ripemd160;
    use sha2::{Digest, Sha256};

    fn p2pkh_script(pubkey: &[u8; 33]) -> Vec<u8> {
        let sha = Sha256::digest(pubkey);
        let ripe = Ripemd160::digest(sha);
        let mut script = vec![0x76u8, 0xa9, 0x14];
        script.extend_from_slice(&ripe);
        script.extend_from_slice(&[0x88, 0xac]);
        script
    }

    #[test]
    fn debug_rebuild_sighash() {
        let burner_pubkey: [u8; 33] = hex::decode("02cd4e7c736d3b4853ffeda3d49868d1430dd9054ce16f8412c12f4fc768d3dc28")
            .unwrap()
            .try_into()
            .unwrap();
        let script_pubkey = p2pkh_script(&burner_pubkey);

        let seller_ua = "utest1ltqheke0z42vffh8zzs2xp4t470rueevlhyanhfem5843v8nr2pn36qpphcqf90w3ax2ahc8hvap5fl5kedfv4ymmu5hdcmsqcamtlux";
        let treasury_ua = "utest1f32kn6c4zvn54xr8wfsnxmj9hzpu2mwgtxzpzwcw34906tdccdvzs0z2dx38lly7tpan77x6udt8pjczqm22ymsdhlz9j0tk5yq664nl";
        let buyer_sig = "LstUOjHhihPPubyX+mjn0TsZshzmwv5xwyPKja9pD03bnXtZZ+VRxEqxG2U9cStlJBTQxG3H8+ZGgNqJLCpZBQ==";
        let memo_str = format!("ZNS:BUY:testmarket:{}:{}", treasury_ua, buyer_sig);
        let mut memo = [0u8; 512];
        memo[..memo_str.len()].copy_from_slice(memo_str.as_bytes());

        let txid_le_bytes: [u8; 32] = hex::decode("c023517881db80146905fb2361882dfec6ff53507f88a7df141db0bf7695717f")
            .unwrap()
            .try_into()
            .unwrap();

        let outpoint = transparent::bundle::OutPoint::new(txid_le_bytes, 0);

        let plan = build_unsigned(PayoutInputs {
            network: "testnet",
            target_height: 3995088,
            utxo_outpoint: outpoint,
            utxo_value_zats: 50_000_000,
            utxo_script_pubkey: script_pubkey,
            burner_pubkey,
            seller_ua,
            treasury_ua,
            buyer_ua: None,
            seller_amount: 48_735_000,
            treasury_amount: 1_250_000,
            memo,
            fee: Some(15_000),
        }).expect("build_unsigned");

        println!("sighash: {}", hex::encode(plan.sighash));
        println!("orchard_sighash: {}", hex::encode(plan.orchard_sighash));
    }
}

#[cfg(test)]
mod debug_finalize {
    use super::*;
    use ripemd::Ripemd160;
    use sha2::{Digest, Sha256};

    fn p2pkh_script(pubkey: &[u8; 33]) -> Vec<u8> {
        let sha = Sha256::digest(pubkey);
        let ripe = Ripemd160::digest(sha);
        let mut script = vec![0x76u8, 0xa9, 0x14];
        script.extend_from_slice(&ripe);
        script.extend_from_slice(&[0x88, 0xac]);
        script
    }

    #[test]
    fn debug_finalize_with_mpc() {
        let burner_pubkey: [u8; 33] = hex::decode("02cd4e7c736d3b4853ffeda3d49868d1430dd9054ce16f8412c12f4fc768d3dc28")
            .unwrap()
            .try_into()
            .unwrap();
        let script_pubkey = p2pkh_script(&burner_pubkey);

        let seller_ua = "utest1ltqheke0z42vffh8zzs2xp4t470rueevlhyanhfem5843v8nr2pn36qpphcqf90w3ax2ahc8hvap5fl5kedfv4ymmu5hdcmsqcamtlux";
        let treasury_ua = "utest1f32kn6c4zvn54xr8wfsnxmj9hzpu2mwgtxzpzwcw34906tdccdvzs0z2dx38lly7tpan77x6udt8pjczqm22ymsdhlz9j0tk5yq664nl";
        let buyer_sig = "LstUOjHhihPPubyX+mjn0TsZshzmwv5xwyPKja9pD03bnXtZZ+VRxEqxG2U9cStlJBTQxG3H8+ZGgNqJLCpZBQ==";
        let memo_str = format!("ZNS:BUY:testmarket:{}:{}", treasury_ua, buyer_sig);
        let mut memo = [0u8; 512];
        memo[..memo_str.len()].copy_from_slice(memo_str.as_bytes());

        let txid_le_bytes: [u8; 32] = hex::decode("c023517881db80146905fb2361882dfec6ff53507f88a7df141db0bf7695717f")
            .unwrap()
            .try_into()
            .unwrap();

        let outpoint = transparent::bundle::OutPoint::new(txid_le_bytes, 0);

        let plan = build_unsigned(PayoutInputs {
            network: "testnet",
            target_height: 3995088,
            utxo_outpoint: outpoint,
            utxo_value_zats: 50_000_000,
            utxo_script_pubkey: script_pubkey,
            burner_pubkey,
            seller_ua,
            treasury_ua,
            buyer_ua: None,
            seller_amount: 48_735_000,
            treasury_amount: 1_250_000,
            memo,
            fee: Some(15_000),
        }).expect("build_unsigned");

        println!("sighash: {}", hex::encode(plan.sighash));

        // MPC signature
        let r_hex = "e36f3714f8c3ec10ce0ff4feea62b74957a3e5b07b0a72ca0dffe1cd4620cef2";
        let s_hex = "4631a64d580ad671d2bbb1da4ce72a222dab2771fa5e156eae1eff5ba3505c29";
        let mut compact = [0u8; 64];
        compact[..32].copy_from_slice(&hex::decode(r_hex).unwrap());
        compact[32..].copy_from_slice(&hex::decode(s_hex).unwrap());

        let result = finalize_with_mpc(plan, &compact);
        match &result {
            Ok(tx_bytes) => println!("SUCCESS, tx len: {}", tx_bytes.len()),
            Err(e) => println!("FAILED: {:?}", e),
        }
    }
}

#[cfg(test)]
mod debug_branch {
    use super::*;
    use zcash_protocol::consensus::{BranchId, TestNetwork};

    #[test]
    fn debug_branch_id() {
        let branch = BranchId::for_height(&TestNetwork, BlockHeight::from_u32(3995088));
        println!("branch_id for height 3995088: {:?} = {}", branch, branch.into());
    }
}
