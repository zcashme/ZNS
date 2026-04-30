//! ZNS non-custodial marketplace escrow contract.
//!
//! Trust model
//! -----------
//! The contract sits between the relayer service and the NEAR MPC v1.signer.
//! Because the MPC derives the burner key from `predecessor=zns-contract.near
//! / path=mpc_path`, only this contract can request signatures for that key.
//!
//! What the contract verifies:
//!   * intent state, expiry, and amount math (commission snapshot)
//!   * raw_tx structure: v5 header, 1 transparent in, 0 transparent out,
//!     0 Sapling spends/outputs, exactly N Orchard actions
//!   * raw_tx consensus_branch_id matches owner-pinned value
//!   * scriptPubKey is P2PKH(burner_pubkey)
//!   * burner_pubkey first byte is 0x02/0x03 (compressed)
//!   * burner_taddr cross-checks against burner_pubkey
//!   * mpc_path is unique across all intents
//!   * the ZIP-244 SIGHASH_ALL is recomputed *from raw_tx* (not trusted from
//!     the relayer) before being sent to MPC
//!
//! What it cannot verify:
//!   * Orchard recipients (the encrypted output ciphertexts).  The relayer
//!     could direct funds to a different shielded address than the seller's
//!     committed UA.  The seller_ua field is stored at intent creation as
//!     part of the audit trail, but on-chain enforcement is not possible.
//!     This is the documented residual trust surface.
//!   * That `burner_pubkey` matches the key MPC will actually derive for
//!     `(current_account_id, mpc_path)`.  A mismatch is self-defeating
//!     (signature won't verify), but ahead-of-time verification would
//!     require an async derived_public_key call from `create_intent`.

use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::store::LookupMap;
use near_sdk::{
    env, near_bindgen, AccountId, Gas, NearToken, Promise, PromiseError,
};
use serde::{Deserialize, Serialize};

mod zcash;
use zcash::{compute_sighash_all, parse_tx, validate_burner_script, verify_burner_taddr};

const SIGN_GAS: Gas = Gas::from_tgas(250);
const CALLBACK_GAS: Gas = Gas::from_tgas(50);
const MPC_DEPOSIT: NearToken = NearToken::from_yoctonear(100);

const MAX_COMMISSION_BPS: u64 = 1_000;        // 10%
const MAX_EXPIRY_SECONDS: u64 = 30 * 86_400;  // 30 days
const MIN_EXPIRY_SECONDS: u64 = 60;
const MAX_UA_LEN: usize = 512;
const MAX_NAME_LEN: usize = 256;
const MAX_PATH_LEN: usize = 128;

const EVENT_STANDARD: &str = "zns";
const EVENT_VERSION: &str = "1.0.0";

// ─── MPC types ──────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Clone, Debug)]
#[borsh(crate = "near_sdk::borsh")]
pub struct AffinePoint {
    pub affine_point: String,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Clone, Debug)]
#[borsh(crate = "near_sdk::borsh")]
pub struct ScalarHex {
    pub scalar: String,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Clone, Debug)]
#[borsh(crate = "near_sdk::borsh")]
pub struct MpcSignature {
    pub big_r: AffinePoint,
    pub s: ScalarHex,
    pub recovery_id: u8,
}

// ─── Intent ─────────────────────────────────────────────────────────────

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq)]
#[borsh(crate = "near_sdk::borsh")]
pub enum IntentStatus {
    PendingPayment,
    PayoutInitiated,
    PayoutFailed,
    Completed,
    RefundInitiated,
    RefundFailed,
    Refunded,
    Cancelled,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
#[borsh(crate = "near_sdk::borsh")]
pub struct Intent {
    pub id: u64,
    pub name: String,
    pub buyer_ua: String,
    pub seller_ua: String,
    pub price_zat: u64,
    pub commission_bps: u64,
    pub burner_taddr: String,
    pub burner_pubkey: [u8; 33],
    pub mpc_path: String,
    pub created_at_ns: u64,
    pub expires_at_ns: u64,
    pub status: IntentStatus,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct IntentView {
    pub id: u64,
    pub name: String,
    pub buyer_ua: String,
    pub seller_ua: String,
    pub price_zat: u64,
    pub commission_bps: u64,
    pub burner_taddr: String,
    pub burner_pubkey_hex: String,
    pub mpc_path: String,
    pub created_at_ns: u64,
    pub expires_at_ns: u64,
    pub status: String,
}

// ─── Contract ───────────────────────────────────────────────────────────

#[near_bindgen(contract_state)]
#[derive(BorshSerialize, BorshDeserialize)]
#[borsh(crate = "near_sdk::borsh")]
pub struct ZnsContract {
    pub owner: AccountId,
    pub relayer: AccountId,
    pub mpc_contract: AccountId,
    pub treasury_ua: String,
    pub commission_bps: u64,
    pub default_expiry_seconds: u64,
    pub mainnet: bool,
    pub consensus_branch_id: u32,
    pub next_intent_id: u64,
    pub intents: LookupMap<u64, Intent>,
    pub signatures: LookupMap<u64, MpcSignature>,
    pub used_paths: LookupMap<String, u64>,
}

impl Default for ZnsContract {
    fn default() -> Self {
        env::panic_str("Contract must be initialized with new()")
    }
}

#[near_bindgen]
impl ZnsContract {
    #[init]
    pub fn new(
        owner: AccountId,
        relayer: AccountId,
        mpc_contract: AccountId,
        treasury_ua: String,
        commission_bps: u64,
        default_expiry_seconds: u64,
        mainnet: bool,
        consensus_branch_id: u32,
    ) -> Self {
        assert!(!env::state_exists(), "already initialized");
        assert!(commission_bps <= MAX_COMMISSION_BPS, "commission_bps too high");
        assert!(
            (MIN_EXPIRY_SECONDS..=MAX_EXPIRY_SECONDS).contains(&default_expiry_seconds),
            "expiry out of range"
        );
        assert!(
            !treasury_ua.is_empty() && treasury_ua.len() <= MAX_UA_LEN,
            "treasury_ua length"
        );
        Self {
            owner,
            relayer,
            mpc_contract,
            treasury_ua,
            commission_bps,
            default_expiry_seconds,
            mainnet,
            consensus_branch_id,
            next_intent_id: 1,
            intents: LookupMap::new(b"i"),
            signatures: LookupMap::new(b"s"),
            used_paths: LookupMap::new(b"p"),
        }
    }

    // ── Owner config ────────────────────────────────────────────────────

    pub fn set_relayer(&mut self, account: AccountId) {
        self.assert_owner();
        self.relayer = account;
    }

    pub fn set_mpc_contract(&mut self, account: AccountId) {
        self.assert_owner();
        self.mpc_contract = account;
    }

    pub fn set_treasury_ua(&mut self, ua: String) {
        self.assert_owner();
        assert!(!ua.is_empty() && ua.len() <= MAX_UA_LEN, "treasury_ua length");
        self.treasury_ua = ua;
    }

    pub fn set_commission_bps(&mut self, bps: u64) {
        self.assert_owner();
        assert!(bps <= MAX_COMMISSION_BPS, "commission_bps too high");
        self.commission_bps = bps;
    }

    pub fn set_default_expiry_seconds(&mut self, secs: u64) {
        self.assert_owner();
        assert!(
            (MIN_EXPIRY_SECONDS..=MAX_EXPIRY_SECONDS).contains(&secs),
            "expiry out of range"
        );
        self.default_expiry_seconds = secs;
    }

    pub fn set_consensus_branch_id(&mut self, branch_id: u32) {
        self.assert_owner();
        self.consensus_branch_id = branch_id;
    }

    pub fn transfer_ownership(&mut self, new_owner: AccountId) {
        self.assert_owner();
        self.owner = new_owner;
    }

    // ── Intent lifecycle ────────────────────────────────────────────────

    #[payable]
    pub fn create_intent(
        &mut self,
        name: String,
        buyer_ua: String,
        seller_ua: String,
        price_zat: u64,
        burner_taddr: String,
        burner_pubkey: Vec<u8>,
        mpc_path: String,
    ) -> u64 {
        self.assert_relayer();

        assert!(!name.is_empty() && name.len() <= MAX_NAME_LEN, "name length");
        assert!(
            !buyer_ua.is_empty() && buyer_ua.len() <= MAX_UA_LEN,
            "buyer_ua length"
        );
        assert!(
            !seller_ua.is_empty() && seller_ua.len() <= MAX_UA_LEN,
            "seller_ua length"
        );
        assert!(
            !mpc_path.is_empty() && mpc_path.len() <= MAX_PATH_LEN,
            "mpc_path length"
        );
        assert!(price_zat > 0, "price_zat must be > 0");
        assert!(
            !self.used_paths.contains_key(&mpc_path),
            "mpc_path already used"
        );

        let burner_pubkey: [u8; 33] = burner_pubkey
            .as_slice()
            .try_into()
            .unwrap_or_else(|_| env::panic_str("burner_pubkey must be 33 bytes (compressed)"));
        assert!(
            matches!(burner_pubkey[0], 0x02 | 0x03),
            "burner_pubkey not compressed (must start with 0x02/0x03)"
        );
        verify_burner_taddr(&burner_taddr, &burner_pubkey, self.mainnet)
            .unwrap_or_else(|e| env::panic_str(&format!("burner taddr/pubkey mismatch: {e}")));

        let storage_before = env::storage_usage();

        let id = self.next_intent_id;
        self.next_intent_id += 1;
        let now = env::block_timestamp();
        let expires_at_ns = now.saturating_add(
            self.default_expiry_seconds.saturating_mul(1_000_000_000),
        );
        let intent = Intent {
            id,
            name: name.clone(),
            buyer_ua: buyer_ua.clone(),
            seller_ua: seller_ua.clone(),
            price_zat,
            commission_bps: self.commission_bps,
            burner_taddr: burner_taddr.clone(),
            burner_pubkey,
            mpc_path: mpc_path.clone(),
            created_at_ns: now,
            expires_at_ns,
            status: IntentStatus::PendingPayment,
        };
        self.intents.insert(id, intent);
        self.used_paths.insert(mpc_path.clone(), id);

        // Charge the relayer for the storage they just allocated.
        let storage_used = env::storage_usage().saturating_sub(storage_before) as u128;
        let cost_yocto = env::storage_byte_cost()
            .as_yoctonear()
            .saturating_mul(storage_used);
        let deposit_yocto = env::attached_deposit().as_yoctonear();
        assert!(
            deposit_yocto >= cost_yocto,
            "insufficient storage deposit: need {} yocto, attached {}",
            cost_yocto,
            deposit_yocto
        );
        let refund_yocto = deposit_yocto - cost_yocto;
        if refund_yocto > 0 {
            let _refund = Promise::new(env::predecessor_account_id())
                .transfer(NearToken::from_yoctonear(refund_yocto));
        }

        emit_event(
            "intent_created",
            serde_json::json!({
                "id": id,
                "name": name,
                "buyer_ua": buyer_ua,
                "seller_ua": seller_ua,
                "price_zat": price_zat,
                "commission_bps": self.commission_bps,
                "burner_taddr": burner_taddr,
                "mpc_path": mpc_path,
                "expires_at_ns": expires_at_ns,
            }),
        );
        id
    }

    pub fn cancel_intent(&mut self, id: u64) {
        self.assert_owner();
        let mut intent = self.intents.get(&id).expect("not found").clone();
        assert!(
            matches!(
                intent.status,
                IntentStatus::PendingPayment | IntentStatus::PayoutFailed
            ),
            "cannot cancel in current status"
        );
        intent.status = IntentStatus::Cancelled;
        self.intents.insert(id, intent);
        emit_event("intent_cancelled", serde_json::json!({ "id": id }));
    }

    // ── Payout ──────────────────────────────────────────────────────────

    /// Validate and dispatch a payout.  Caller is the relayer, which has
    /// already built the raw Zcash v5 tx and identified the funding UTXO.
    pub fn request_payout(
        &mut self,
        intent_id: u64,
        raw_tx: Vec<u8>,
        utxo_value_zats: u64,
        utxo_script_pubkey: Vec<u8>,
        seller_amount: u64,
        treasury_amount: u64,
        fee: u64,
    ) -> Promise {
        self.assert_relayer();
        let mut intent = self.intents.get(&intent_id).expect("not found").clone();
        assert!(
            matches!(
                intent.status,
                IntentStatus::PendingPayment | IntentStatus::PayoutFailed
            ),
            "intent not payable in current status"
        );
        assert!(
            env::block_timestamp() < intent.expires_at_ns,
            "intent expired"
        );

        // Buyer must have funded at least the asking price.
        assert!(
            utxo_value_zats >= intent.price_zat,
            "underfunded: utxo {} < price {}",
            utxo_value_zats,
            intent.price_zat
        );

        // Amount math against the *snapshotted* commission.
        let expected_treasury = intent
            .price_zat
            .checked_mul(intent.commission_bps)
            .and_then(|v| v.checked_div(10_000))
            .expect("commission overflow");
        assert_eq!(
            treasury_amount, expected_treasury,
            "treasury amount mismatch"
        );
        let total = seller_amount
            .checked_add(treasury_amount)
            .and_then(|v| v.checked_add(fee))
            .expect("amount overflow");
        assert_eq!(total, utxo_value_zats, "value not balanced");
        assert!(seller_amount > 0, "seller_amount must be > 0");

        // Structural validation of the raw tx.
        let tx = parse_tx(&raw_tx)
            .unwrap_or_else(|e| env::panic_str(&format!("tx parse: {e}")));
        assert_eq!(
            tx.consensus_branch_id, self.consensus_branch_id,
            "consensus_branch_id mismatch"
        );
        validate_burner_script(&utxo_script_pubkey, &intent.burner_pubkey)
            .unwrap_or_else(|e| env::panic_str(e));
        let bundle = tx
            .orchard
            .as_ref()
            .unwrap_or_else(|| env::panic_str("orchard bundle required"));
        assert_eq!(
            bundle.actions.len(),
            2,
            "payout must have exactly 2 orchard actions (seller + treasury)"
        );

        // Recompute the sighash from raw_tx so the relayer cannot present a
        // hash that does not match what they want to sign.
        let sighash = compute_sighash_all(&tx, utxo_value_zats, &utxo_script_pubkey);

        let path = intent.mpc_path.clone();
        intent.status = IntentStatus::PayoutInitiated;
        self.intents.insert(intent_id, intent);

        emit_event(
            "payout_initiated",
            serde_json::json!({
                "id": intent_id,
                "sighash": hex::encode(sighash),
            }),
        );
        self.dispatch_mpc(intent_id, &path, sighash, true)
    }

    /// Refund the burner UTXO to the buyer.  Callable when:
    ///   * the intent is `Cancelled` (regardless of expiry), or
    ///   * the intent is `PendingPayment | PayoutFailed | RefundFailed` and
    ///     the expiry has passed.
    pub fn request_refund(
        &mut self,
        intent_id: u64,
        raw_tx: Vec<u8>,
        utxo_value_zats: u64,
        utxo_script_pubkey: Vec<u8>,
        fee: u64,
    ) -> Promise {
        self.assert_relayer();
        let mut intent = self.intents.get(&intent_id).expect("not found").clone();
        assert!(
            matches!(
                intent.status,
                IntentStatus::PendingPayment
                    | IntentStatus::PayoutFailed
                    | IntentStatus::RefundFailed
                    | IntentStatus::Cancelled
            ),
            "intent not refundable in current status"
        );
        if !matches!(intent.status, IntentStatus::Cancelled) {
            assert!(
                env::block_timestamp() >= intent.expires_at_ns,
                "intent not yet expired"
            );
        }
        assert!(fee < utxo_value_zats, "fee >= utxo value");

        let tx = parse_tx(&raw_tx)
            .unwrap_or_else(|e| env::panic_str(&format!("tx parse: {e}")));
        assert_eq!(
            tx.consensus_branch_id, self.consensus_branch_id,
            "consensus_branch_id mismatch"
        );
        validate_burner_script(&utxo_script_pubkey, &intent.burner_pubkey)
            .unwrap_or_else(|e| env::panic_str(e));
        let bundle = tx
            .orchard
            .as_ref()
            .unwrap_or_else(|| env::panic_str("orchard bundle required"));
        assert_eq!(
            bundle.actions.len(),
            1,
            "refund must have exactly 1 orchard action (buyer)"
        );

        let sighash = compute_sighash_all(&tx, utxo_value_zats, &utxo_script_pubkey);
        let path = intent.mpc_path.clone();
        intent.status = IntentStatus::RefundInitiated;
        self.intents.insert(intent_id, intent);

        emit_event(
            "refund_initiated",
            serde_json::json!({
                "id": intent_id,
                "sighash": hex::encode(sighash),
            }),
        );
        self.dispatch_mpc(intent_id, &path, sighash, false)
    }

    fn dispatch_mpc(
        &self,
        intent_id: u64,
        path: &str,
        sighash: [u8; 32],
        is_payout: bool,
    ) -> Promise {
        let args = serde_json::json!({
            "request": {
                "payload": sighash.to_vec(),
                "path": path,
                "key_version": 0,
            }
        });
        Promise::new(self.mpc_contract.clone())
            .function_call(
                "sign".to_string(),
                args.to_string().into_bytes(),
                MPC_DEPOSIT,
                SIGN_GAS,
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(CALLBACK_GAS)
                    .mpc_sign_callback(intent_id, is_payout),
            )
    }

    #[private]
    pub fn mpc_sign_callback(
        &mut self,
        #[callback_result] result: Result<MpcSignature, PromiseError>,
        intent_id: u64,
        is_payout: bool,
    ) {
        let mut intent = self.intents.get(&intent_id).expect("intent gone").clone();
        match result {
            Ok(sig) => {
                self.signatures.insert(intent_id, sig);
                intent.status = if is_payout {
                    IntentStatus::Completed
                } else {
                    IntentStatus::Refunded
                };
                emit_event(
                    if is_payout { "payout_completed" } else { "refund_completed" },
                    serde_json::json!({ "id": intent_id }),
                );
            }
            Err(e) => {
                intent.status = if is_payout {
                    IntentStatus::PayoutFailed
                } else {
                    IntentStatus::RefundFailed
                };
                emit_event(
                    if is_payout { "payout_failed" } else { "refund_failed" },
                    serde_json::json!({
                        "id": intent_id,
                        "error": format!("{:?}", e),
                    }),
                );
            }
        }
        self.intents.insert(intent_id, intent);
    }

    // ── Maintenance ─────────────────────────────────────────────────────

    /// Owner-only: drop the stored signature for a terminal intent.  The
    /// relayer is expected to have fetched it already.
    pub fn prune_signature(&mut self, intent_id: u64) {
        self.assert_owner();
        let intent = self.intents.get(&intent_id).expect("not found");
        assert!(
            matches!(
                intent.status,
                IntentStatus::Completed | IntentStatus::Refunded | IntentStatus::Cancelled
            ),
            "intent not terminal"
        );
        self.signatures.remove(&intent_id);
    }

    // ── Views ───────────────────────────────────────────────────────────

    pub fn get_intent(&self, id: u64) -> Option<IntentView> {
        self.intents.get(&id).map(|i| IntentView {
            id: i.id,
            name: i.name.clone(),
            buyer_ua: i.buyer_ua.clone(),
            seller_ua: i.seller_ua.clone(),
            price_zat: i.price_zat,
            commission_bps: i.commission_bps,
            burner_taddr: i.burner_taddr.clone(),
            burner_pubkey_hex: hex::encode(i.burner_pubkey),
            mpc_path: i.mpc_path.clone(),
            created_at_ns: i.created_at_ns,
            expires_at_ns: i.expires_at_ns,
            status: status_str(&i.status).to_string(),
        })
    }

    pub fn get_signature(&self, id: u64) -> Option<MpcSignature> {
        self.signatures.get(&id).cloned()
    }

    pub fn get_config(&self) -> serde_json::Value {
        serde_json::json!({
            "owner": self.owner,
            "relayer": self.relayer,
            "mpc_contract": self.mpc_contract,
            "treasury_ua": self.treasury_ua,
            "commission_bps": self.commission_bps,
            "default_expiry_seconds": self.default_expiry_seconds,
            "mainnet": self.mainnet,
            "consensus_branch_id": self.consensus_branch_id,
            "next_intent_id": self.next_intent_id,
        })
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    fn assert_owner(&self) {
        assert_eq!(
            env::predecessor_account_id(),
            self.owner,
            "owner only"
        );
    }

    fn assert_relayer(&self) {
        assert_eq!(
            env::predecessor_account_id(),
            self.relayer,
            "relayer only"
        );
    }
}

fn emit_event(event: &str, data: serde_json::Value) {
    let payload = serde_json::json!({
        "standard": EVENT_STANDARD,
        "version": EVENT_VERSION,
        "event": event,
        "data": [data],
    });
    env::log_str(&format!("EVENT_JSON:{}", payload));
}

fn status_str(s: &IntentStatus) -> &'static str {
    match s {
        IntentStatus::PendingPayment => "PendingPayment",
        IntentStatus::PayoutInitiated => "PayoutInitiated",
        IntentStatus::PayoutFailed => "PayoutFailed",
        IntentStatus::Completed => "Completed",
        IntentStatus::RefundInitiated => "RefundInitiated",
        IntentStatus::RefundFailed => "RefundFailed",
        IntentStatus::Refunded => "Refunded",
        IntentStatus::Cancelled => "Cancelled",
    }
}
