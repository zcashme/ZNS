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
use rand::rngs::OsRng;
use secp256k1::{PublicKey as SecpPubkey, Secp256k1};
use transparent::{
    builder::TransparentBuilder,
    bundle::{Bundle as TBundle, OutPoint, TxOut},
};
use zcash_address::ZcashAddress;
use zcash_keys::address::{Address as ZAddress, UnifiedAddress};
use zcash_primitives::transaction::{
    Authorized, TransactionData, TxVersion, Unauthorized,
    fees::{self, zip317, FeeRule as _},
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
    transparent_unauth: TBundle<transparent::builder::Unauthorized>,
    orchard_unproven: OrchardBundle<
        orchard::builder::InProgress<orchard::builder::Unproven, orchard::builder::Unauthorized>,
        ZatBalance,
    >,
}

/// All inputs required to construct a payout transaction.
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
    let seller_o = parse_orchard_recipient(input.seller_ua, net)?;
    let treasury_o = parse_orchard_recipient(input.treasury_ua, net)?;

    let mut obuilder = OrchardBuilder::new(BundleType::DEFAULT, Anchor::empty_tree());
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

    let mut rng = OsRng;
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

    let orchard_sighash = *signature_hash(
        &td_unauth,
        &SignableInput::Shielded,
        &txid_parts,
    ).as_ref();

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
    let mut rng = OsRng;
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
