//! ZNS non-custodial marketplace escrow contract.
//!
//! The contract is the authority for:
//!   * listing terms (seller, treasury, price, commission, fee)
//!   * the deterministic burner address derived from MPC root key + path
//!   * the required BUY memo commitment for a purchase
//!   * the exact funded payout/refund transaction bytes and sighashes that may be signed
//!
//! The relayer service becomes only a transaction builder and submitter.
//! The MPC is only a signer invoked by this contract.

use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::store::LookupMap;
use near_sdk::{
    env, ext_contract, near_bindgen, AccountId, Gas, NearToken, PanicOnDefault, Promise,
    PromiseError,
};
use serde::{Deserialize, Serialize};

mod zcash;
use zcash::{compute_sighash_all, derive_burner, parse_tx, sha256, validate_burner_script};

const SIGN_GAS: Gas = Gas::from_tgas(250);
const CALLBACK_GAS: Gas = Gas::from_tgas(50);
const MPC_DEPOSIT: NearToken = NearToken::from_yoctonear(100);

const MAX_COMMISSION_BPS: u64 = 1_000; // 10%
const MAX_EXPIRY_SECONDS: u64 = 30 * 86_400;
const MIN_EXPIRY_SECONDS: u64 = 60;
const MAX_UA_LEN: usize = 512;
const MAX_NAME_LEN: usize = 256;
const MAX_PATH_LEN: usize = 128;
const MAX_TX_BYTES: usize = 20_000;

const EVENT_STANDARD: &str = "zns";
const EVENT_VERSION: &str = "1.0.0";

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

#[derive(Serialize, Deserialize)]
pub struct SignRequestArgs {
    pub request: SignPayload,
}

#[derive(Serialize, Deserialize)]
pub struct SignPayload {
    pub payload: Vec<u8>,
    pub path: String,
    pub key_version: u32,
}

#[ext_contract(ext_mpc)]
trait ExtMpc {
    fn sign(&self, request: SignRequestArgs) -> MpcSignature;
}

#[ext_contract(ext_self)]
trait ExtSelf {
    fn mpc_sign_callback(
        &mut self,
        #[callback_result] result: Result<MpcSignature, PromiseError>,
        purchase_id: u64,
        is_payout: bool,
    );
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq)]
#[borsh(crate = "near_sdk::borsh")]
pub enum ListingStatus {
    Open,
    Sold,
    Cancelled,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
#[borsh(crate = "near_sdk::borsh")]
pub struct Listing {
    pub id: u64,
    pub name: String,
    pub seller_ua: String,
    pub price_zat: u64,
    pub commission_bps: u64,
    pub treasury_ua: String,
    pub status: ListingStatus,
    pub created_at_ns: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ListingView {
    pub id: u64,
    pub name: String,
    pub seller_ua: String,
    pub price_zat: u64,
    pub commission_bps: u64,
    pub treasury_ua: String,
    pub status: String,
    pub created_at_ns: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq)]
#[borsh(crate = "near_sdk::borsh")]
pub enum PurchaseStatus {
    AwaitingPayment,
    PayoutAuthorized,
    Completed,
    Refundable,
    Refunded,
    Expired,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
#[borsh(crate = "near_sdk::borsh")]
pub struct Purchase {
    pub id: u64,
    pub listing_id: u64,
    pub buyer_ua: String,
    pub required_memo: String,
    pub price_zat: u64,
    pub commission_zat: u64,
    pub payout_fee_zat: u64,
    pub seller_receives_zat: u64,
    pub refund_receives_zat: u64,
    pub burner_taddr: String,
    pub burner_pubkey: [u8; 33],
    pub mpc_path: String,
    pub status: PurchaseStatus,
    pub created_at_ns: u64,
    pub expires_at_ns: u64,
    pub funding_outpoint: Option<([u8; 32], u32)>,
    pub utxo_value_zats: Option<u64>,
    pub payout_tx: Option<Vec<u8>>,
    pub refund_tx: Option<Vec<u8>>,
    pub payout_tx_hash: Option<[u8; 32]>,
    pub refund_tx_hash: Option<[u8; 32]>,
    pub payout_sighash: Option<[u8; 32]>,
    pub refund_sighash: Option<[u8; 32]>,
    pub payout_signature: Option<MpcSignature>,
    pub refund_signature: Option<MpcSignature>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PurchaseView {
    pub id: u64,
    pub listing_id: u64,
    pub buyer_ua: String,
    pub required_memo: String,
    pub price_zat: u64,
    pub commission_zat: u64,
    pub payout_fee_zat: u64,
    pub seller_receives_zat: u64,
    pub refund_receives_zat: u64,
    pub burner_taddr: String,
    pub burner_pubkey_hex: String,
    pub mpc_path: String,
    pub status: String,
    pub created_at_ns: u64,
    pub expires_at_ns: u64,
    pub funding_outpoint_txid_hex: Option<String>,
    pub funding_vout: Option<u32>,
    pub utxo_value_zats: Option<u64>,
    pub payout_tx_hash_hex: Option<String>,
    pub refund_tx_hash_hex: Option<String>,
    pub payout_sighash_hex: Option<String>,
    pub refund_sighash_hex: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PurchaseAcceptedView {
    pub purchase_id: u64,
    pub listing_id: u64,
    pub burner_taddr: String,
    pub burner_pubkey_hex: String,
    pub mpc_path: String,
    pub required_memo: String,
    pub price_zat: u64,
    pub commission_zat: u64,
    pub payout_fee_zat: u64,
    pub seller_receives_zat: u64,
    pub refund_receives_zat: u64,
    pub expires_at_ns: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SubmittedFundingView {
    pub purchase_id: u64,
    pub payout_tx_hash_hex: String,
    pub refund_tx_hash_hex: String,
    pub payout_sighash_hex: String,
    pub refund_sighash_hex: String,
    pub status: String,
}

#[near_bindgen(contract_state)]
#[derive(BorshSerialize, BorshDeserialize, PanicOnDefault)]
#[borsh(crate = "near_sdk::borsh")]
pub struct ZnsContract {
    pub owner: AccountId,
    pub relayer: AccountId,
    pub mpc_contract: AccountId,
    pub mpc_root_pubkey: String,
    pub treasury_ua: String,
    pub commission_bps: u64,
    pub payout_fee_zat: u64,
    pub default_expiry_seconds: u64,
    pub mainnet: bool,
    pub consensus_branch_id: u32,
    pub next_listing_id: u64,
    pub next_purchase_id: u64,
    pub listings: LookupMap<u64, Listing>,
    pub listing_ids_by_name: LookupMap<String, u64>,
    pub purchases: LookupMap<u64, Purchase>,
    pub used_paths: LookupMap<String, u64>,
}

#[near_bindgen]
impl ZnsContract {
    #[init]
    pub fn new(
        owner: AccountId,
        relayer: AccountId,
        mpc_contract: AccountId,
        mpc_root_pubkey: String,
        treasury_ua: String,
        commission_bps: u64,
        payout_fee_zat: u64,
        default_expiry_seconds: u64,
        mainnet: bool,
        consensus_branch_id: u32,
    ) -> Self {
        assert!(!env::state_exists(), "already initialized");
        assert!(
            commission_bps <= MAX_COMMISSION_BPS,
            "commission_bps too high"
        );
        assert!(
            (MIN_EXPIRY_SECONDS..=MAX_EXPIRY_SECONDS).contains(&default_expiry_seconds),
            "expiry out of range"
        );
        validate_unified_address(&treasury_ua, mainnet)
            .unwrap_or_else(|e| env::panic_str(&format!("treasury_ua invalid: {e}")));
        assert!(payout_fee_zat > 0, "payout_fee_zat must be > 0");
        Self {
            owner,
            relayer,
            mpc_contract,
            mpc_root_pubkey,
            treasury_ua,
            commission_bps,
            payout_fee_zat,
            default_expiry_seconds,
            mainnet,
            consensus_branch_id,
            next_listing_id: 1,
            next_purchase_id: 1,
            listings: LookupMap::new(b"L"),
            listing_ids_by_name: LookupMap::new(b"N"),
            purchases: LookupMap::new(b"P"),
            used_paths: LookupMap::new(b"p"),
        }
    }

    pub fn set_relayer(&mut self, account: AccountId) {
        self.assert_owner();
        self.relayer = account;
    }

    pub fn set_mpc_contract(&mut self, account: AccountId) {
        self.assert_owner();
        self.mpc_contract = account;
    }

    pub fn set_mpc_root_pubkey(&mut self, pubkey: String) {
        self.assert_owner();
        self.mpc_root_pubkey = pubkey;
    }

    pub fn set_treasury_ua(&mut self, ua: String) {
        self.assert_owner();
        validate_unified_address(&ua, self.mainnet)
            .unwrap_or_else(|e| env::panic_str(&format!("treasury_ua invalid: {e}")));
        self.treasury_ua = ua;
    }

    pub fn set_commission_bps(&mut self, bps: u64) {
        self.assert_owner();
        assert!(bps <= MAX_COMMISSION_BPS, "commission_bps too high");
        self.commission_bps = bps;
    }

    pub fn set_payout_fee_zat(&mut self, fee: u64) {
        self.assert_owner();
        assert!(fee > 0, "payout_fee_zat must be > 0");
        self.payout_fee_zat = fee;
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

    #[payable]
    pub fn create_listing(
        &mut self,
        name: String,
        seller_ua: String,
        price_zat: u64,
    ) -> ListingView {
        self.assert_relayer();
        assert!(
            !name.is_empty() && name.len() <= MAX_NAME_LEN,
            "name length"
        );
        validate_unified_address(&seller_ua, self.mainnet)
            .unwrap_or_else(|e| env::panic_str(&format!("seller_ua invalid: {e}")));
        assert!(
            price_zat > self.payout_fee_zat,
            "price_zat must exceed payout fee"
        );

        if let Some(existing_id) = self.listing_ids_by_name.get(&name) {
            let existing = self
                .listings
                .get(existing_id)
                .expect("listing index out of sync");
            assert!(
                !matches!(existing.status, ListingStatus::Open),
                "listing already open for name"
            );
        }

        let storage_before = env::storage_usage();
        let id = self.next_listing_id;
        self.next_listing_id += 1;
        let now = env::block_timestamp();
        let listing = Listing {
            id,
            name: name.clone(),
            seller_ua: seller_ua.clone(),
            price_zat,
            commission_bps: self.commission_bps,
            treasury_ua: self.treasury_ua.clone(),
            status: ListingStatus::Open,
            created_at_ns: now,
        };
        self.listings.insert(id, listing.clone());
        self.listing_ids_by_name.insert(name.clone(), id);

        self.refund_unused_storage(storage_before);

        emit_event(
            "listing_created",
            serde_json::json!({
                "id": id,
                "name": name,
                "seller_ua": seller_ua,
                "price_zat": price_zat,
                "commission_bps": self.commission_bps,
                "treasury_ua": self.treasury_ua,
                "payout_fee_zat": self.payout_fee_zat,
                "created_at_ns": now,
            }),
        );
        self.listing_to_view(&listing)
    }

    pub fn cancel_listing(&mut self, id: u64) {
        self.assert_owner();
        let mut listing = self.listings.get(&id).expect("not found").clone();
        assert!(
            matches!(listing.status, ListingStatus::Open),
            "listing not open"
        );
        listing.status = ListingStatus::Cancelled;
        self.listings.insert(id, listing);
        emit_event("listing_cancelled", serde_json::json!({ "id": id }));
    }

    #[payable]
    pub fn accept_listing(
        &mut self,
        listing_id: u64,
        buyer_ua: String,
        mpc_path: String,
    ) -> PurchaseAcceptedView {

        let listing = self
            .listings
            .get(&listing_id)
            .expect("listing not found")
            .clone();
        assert!(
            matches!(listing.status, ListingStatus::Open),
            "listing not open"
        );

        validate_unified_address(&buyer_ua, self.mainnet)
            .unwrap_or_else(|e| env::panic_str(&format!("buyer_ua invalid: {e}")));
        assert!(
            !mpc_path.is_empty() && mpc_path.len() <= MAX_PATH_LEN,
            "mpc_path length"
        );
        assert!(
            !self.used_paths.contains_key(&mpc_path),
            "mpc_path already used"
        );

        let (burner_taddr, burner_pubkey) = derive_burner(
            &self.mpc_root_pubkey,
            env::current_account_id().as_str(),
            &mpc_path,
            self.mainnet,
        )
        .unwrap_or_else(|e| env::panic_str(&format!("burner derivation failed: {e}")));

        let commission_zat = listing.price_zat.saturating_mul(listing.commission_bps) / 10_000;
        let seller_receives_zat = listing
            .price_zat
            .checked_sub(commission_zat)
            .and_then(|v| v.checked_sub(self.payout_fee_zat))
            .unwrap_or_else(|| env::panic_str("price too small to cover commission + payout fee"));
        let refund_receives_zat = listing
            .price_zat
            .checked_sub(self.payout_fee_zat)
            .unwrap_or_else(|| env::panic_str("price too small to cover refund fee"));

        let storage_before = env::storage_usage();
        let id = self.next_purchase_id;
        self.next_purchase_id += 1;
        let now = env::block_timestamp();
        let expires_at_ns =
            now.saturating_add(self.default_expiry_seconds.saturating_mul(1_000_000_000));
        let required_memo = required_buy_memo(listing_id, id, &listing.name, &buyer_ua);

        let purchase = Purchase {
            id,
            listing_id,
            buyer_ua: buyer_ua.clone(),
            required_memo: required_memo.clone(),
            price_zat: listing.price_zat,
            commission_zat,
            payout_fee_zat: self.payout_fee_zat,
            seller_receives_zat,
            refund_receives_zat,
            burner_taddr: burner_taddr.clone(),
            burner_pubkey,
            mpc_path: mpc_path.clone(),
            status: PurchaseStatus::AwaitingPayment,
            created_at_ns: now,
            expires_at_ns,
            funding_outpoint: None,
            utxo_value_zats: None,
            payout_tx: None,
            refund_tx: None,
            payout_tx_hash: None,
            refund_tx_hash: None,
            payout_sighash: None,
            refund_sighash: None,
            payout_signature: None,
            refund_signature: None,
        };
        self.purchases.insert(id, purchase);
        self.used_paths.insert(mpc_path.clone(), id);

        let mut updated_listing = listing.clone();
        updated_listing.status = ListingStatus::Sold;
        self.listings.insert(listing_id, updated_listing);

        self.refund_unused_storage(storage_before);

        emit_event(
            "purchase_accepted",
            serde_json::json!({
                "purchase_id": id,
                "listing_id": listing_id,
                "buyer_ua": buyer_ua,
                "burner_taddr": burner_taddr,
                "mpc_path": mpc_path,
                "required_memo": required_memo,
                "price_zat": listing.price_zat,
                "commission_zat": commission_zat,
                "payout_fee_zat": self.payout_fee_zat,
                "seller_receives_zat": seller_receives_zat,
                "refund_receives_zat": refund_receives_zat,
                "expires_at_ns": expires_at_ns,
            }),
        );

        PurchaseAcceptedView {
            purchase_id: id,
            listing_id,
            burner_taddr,
            burner_pubkey_hex: hex::encode(burner_pubkey),
            mpc_path,
            required_memo,
            price_zat: listing.price_zat,
            commission_zat,
            payout_fee_zat: self.payout_fee_zat,
            seller_receives_zat,
            refund_receives_zat,
            expires_at_ns,
        }
    }

    pub fn submit_funding(
        &mut self,
        purchase_id: u64,
        utxo_value_zats: u64,
        utxo_script_pubkey: Vec<u8>,
        payout_tx: Vec<u8>,
        refund_tx: Vec<u8>,
    ) -> SubmittedFundingView {
        let mut purchase = self
            .purchases
            .get(&purchase_id)
            .expect("purchase not found")
            .clone();
        assert!(
            matches!(purchase.status, PurchaseStatus::AwaitingPayment),
            "purchase not awaiting payment"
        );
        assert!(
            utxo_value_zats == purchase.price_zat,
            "utxo value must equal listed price"
        );
        validate_burner_script(&utxo_script_pubkey, &purchase.burner_pubkey)
            .unwrap_or_else(|e| env::panic_str(&format!("burner script invalid: {e}")));
        assert!(
            !payout_tx.is_empty() && payout_tx.len() <= MAX_TX_BYTES,
            "payout_tx size"
        );
        assert!(
            !refund_tx.is_empty() && refund_tx.len() <= MAX_TX_BYTES,
            "refund_tx size"
        );

        let payout_parsed = parse_tx(&payout_tx)
            .unwrap_or_else(|e| env::panic_str(&format!("payout_tx invalid: {e}")));
        let refund_parsed = parse_tx(&refund_tx)
            .unwrap_or_else(|e| env::panic_str(&format!("refund_tx invalid: {e}")));

        assert_eq!(
            payout_parsed.consensus_branch_id, self.consensus_branch_id,
            "payout_tx wrong consensus branch id"
        );
        assert_eq!(
            refund_parsed.consensus_branch_id, self.consensus_branch_id,
            "refund_tx wrong consensus branch id"
        );
        assert_eq!(
            payout_parsed.tx_in.prevout_txid, refund_parsed.tx_in.prevout_txid,
            "payout/refund txid mismatch"
        );
        assert_eq!(
            payout_parsed.tx_in.prevout_vout, refund_parsed.tx_in.prevout_vout,
            "payout/refund vout mismatch"
        );

        let payout_sighash =
            compute_sighash_all(&payout_parsed, utxo_value_zats, &utxo_script_pubkey);
        let refund_sighash =
            compute_sighash_all(&refund_parsed, utxo_value_zats, &utxo_script_pubkey);
        let now = env::block_timestamp();
        let status = if now >= purchase.expires_at_ns {
            PurchaseStatus::Refundable
        } else {
            PurchaseStatus::PayoutAuthorized
        };

        purchase.funding_outpoint = Some((
            payout_parsed.tx_in.prevout_txid,
            payout_parsed.tx_in.prevout_vout,
        ));
        purchase.utxo_value_zats = Some(utxo_value_zats);
        purchase.payout_tx_hash = Some(sha256(&payout_tx));
        purchase.refund_tx_hash = Some(sha256(&refund_tx));
        purchase.payout_tx = Some(payout_tx);
        purchase.refund_tx = Some(refund_tx);
        purchase.payout_sighash = Some(payout_sighash);
        purchase.refund_sighash = Some(refund_sighash);
        purchase.status = status.clone();
        self.purchases.insert(purchase_id, purchase);

        emit_event(
            "funding_submitted",
            serde_json::json!({
                "purchase_id": purchase_id,
                "utxo_txid": hex::encode(payout_parsed.tx_in.prevout_txid),
                "utxo_vout": payout_parsed.tx_in.prevout_vout,
                "utxo_value_zats": utxo_value_zats,
                "payout_tx_hash": hex::encode(sha256(&self.purchases.get(&purchase_id).unwrap().payout_tx.as_ref().unwrap())),
                "refund_tx_hash": hex::encode(sha256(&self.purchases.get(&purchase_id).unwrap().refund_tx.as_ref().unwrap())),
                "status": purchase_status_str(&status),
            }),
        );

        SubmittedFundingView {
            purchase_id,
            payout_tx_hash_hex: hex::encode(
                self.purchases
                    .get(&purchase_id)
                    .unwrap()
                    .payout_tx_hash
                    .unwrap(),
            ),
            refund_tx_hash_hex: hex::encode(
                self.purchases
                    .get(&purchase_id)
                    .unwrap()
                    .refund_tx_hash
                    .unwrap(),
            ),
            payout_sighash_hex: hex::encode(
                self.purchases
                    .get(&purchase_id)
                    .unwrap()
                    .payout_sighash
                    .unwrap(),
            ),
            refund_sighash_hex: hex::encode(
                self.purchases
                    .get(&purchase_id)
                    .unwrap()
                    .refund_sighash
                    .unwrap(),
            ),
            status: purchase_status_str(&status).to_string(),
        }
    }

    pub fn request_payout_signature(&mut self, purchase_id: u64) -> Promise {
        let purchase = self
            .purchases
            .get(&purchase_id)
            .expect("purchase not found")
            .clone();
        assert!(
            matches!(purchase.status, PurchaseStatus::PayoutAuthorized),
            "purchase not payout authorized"
        );
        let sighash = purchase.payout_sighash.expect("payout_sighash missing");
        emit_event(
            "payout_signature_requested",
            serde_json::json!({
                "purchase_id": purchase_id,
                "payout_sighash": hex::encode(sighash),
            }),
        );
        self.request_signature(purchase_id, purchase.mpc_path, sighash, true)
    }

    pub fn authorize_refund(&mut self, purchase_id: u64) {
        let mut purchase = self
            .purchases
            .get(&purchase_id)
            .expect("purchase not found")
            .clone();
        assert!(
            env::block_timestamp() >= purchase.expires_at_ns,
            "purchase not expired"
        );
        purchase.status = if purchase.funding_outpoint.is_some() {
            PurchaseStatus::Refundable
        } else {
            PurchaseStatus::Expired
        };
        self.purchases.insert(purchase_id, purchase.clone());
        emit_event(
            "refund_authorized",
            serde_json::json!({
                "purchase_id": purchase_id,
                "status": purchase_status_str(&purchase.status),
            }),
        );
    }

    pub fn request_refund_signature(&mut self, purchase_id: u64) -> Promise {
        let purchase = self
            .purchases
            .get(&purchase_id)
            .expect("purchase not found")
            .clone();
        assert!(
            matches!(purchase.status, PurchaseStatus::Refundable),
            "purchase not refundable"
        );
        let sighash = purchase.refund_sighash.expect("refund_sighash missing");
        emit_event(
            "refund_signature_requested",
            serde_json::json!({
                "purchase_id": purchase_id,
                "refund_sighash": hex::encode(sighash),
            }),
        );
        self.request_signature(purchase_id, purchase.mpc_path, sighash, false)
    }

    #[private]
    pub fn mpc_sign_callback(
        &mut self,
        #[callback_result] result: Result<MpcSignature, PromiseError>,
        purchase_id: u64,
        is_payout: bool,
    ) {
        let mut purchase = self
            .purchases
            .get(&purchase_id)
            .expect("purchase not found")
            .clone();
        match result {
            Ok(signature) => {
                if is_payout {
                    purchase.payout_signature = Some(signature.clone());
                    purchase.status = PurchaseStatus::Completed;
                } else {
                    purchase.refund_signature = Some(signature.clone());
                    purchase.status = PurchaseStatus::Refunded;
                }
                self.purchases.insert(purchase_id, purchase.clone());
                emit_event(
                    "signature_ready",
                    serde_json::json!({
                        "purchase_id": purchase_id,
                        "kind": if is_payout { "payout" } else { "refund" },
                        "status": purchase_status_str(&purchase.status),
                    }),
                );
            }
            Err(err) => {
                emit_event(
                    "signature_failed",
                    serde_json::json!({
                        "purchase_id": purchase_id,
                        "kind": if is_payout { "payout" } else { "refund" },
                        "error": format!("{:?}", err),
                    }),
                );
            }
        }
    }

    pub fn prune_terminal(&mut self, purchase_id: u64) {
        self.assert_owner();
        let mut purchase = self
            .purchases
            .get(&purchase_id)
            .expect("purchase not found")
            .clone();
        assert!(
            matches!(
                purchase.status,
                PurchaseStatus::Completed | PurchaseStatus::Refunded | PurchaseStatus::Expired
            ),
            "purchase not terminal"
        );
        purchase.payout_tx = None;
        purchase.refund_tx = None;
        self.purchases.insert(purchase_id, purchase);
    }

    pub fn get_listing(&self, id: u64) -> Option<ListingView> {
        self.listings.get(&id).map(|l| self.listing_to_view(l))
    }

    pub fn get_listing_by_name(&self, name: String) -> Option<ListingView> {
        self.listing_ids_by_name
            .get(&name)
            .and_then(|id| self.listings.get(id))
            .map(|l| self.listing_to_view(l))
    }

    pub fn get_purchase(&self, id: u64) -> Option<PurchaseView> {
        self.purchases.get(&id).map(|p| self.purchase_to_view(p))
    }

    pub fn get_payout_signature(&self, purchase_id: u64) -> Option<MpcSignature> {
        self.purchases
            .get(&purchase_id)
            .and_then(|p| p.payout_signature.clone())
    }

    pub fn get_refund_signature(&self, purchase_id: u64) -> Option<MpcSignature> {
        self.purchases
            .get(&purchase_id)
            .and_then(|p| p.refund_signature.clone())
    }

    pub fn get_config(&self) -> serde_json::Value {
        serde_json::json!({
            "owner": self.owner,
            "relayer": self.relayer,
            "mpc_contract": self.mpc_contract,
            "mpc_root_pubkey": self.mpc_root_pubkey,
            "treasury_ua": self.treasury_ua,
            "commission_bps": self.commission_bps,
            "payout_fee_zat": self.payout_fee_zat,
            "default_expiry_seconds": self.default_expiry_seconds,
            "mainnet": self.mainnet,
            "consensus_branch_id": self.consensus_branch_id,
            "next_listing_id": self.next_listing_id,
            "next_purchase_id": self.next_purchase_id,
        })
    }
}

impl ZnsContract {
    fn assert_owner(&self) {
        assert_eq!(env::predecessor_account_id(), self.owner, "owner only");
    }

    fn assert_relayer(&self) {
        assert_eq!(env::predecessor_account_id(), self.relayer, "relayer only");
    }

    fn refund_unused_storage(&self, storage_before: u64) {
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
            let _ = Promise::new(env::predecessor_account_id())
                .transfer(NearToken::from_yoctonear(refund_yocto));
        }
    }

    fn request_signature(
        &self,
        purchase_id: u64,
        mpc_path: String,
        sighash: [u8; 32],
        is_payout: bool,
    ) -> Promise {
        ext_mpc::ext(self.mpc_contract.clone())
            .with_static_gas(SIGN_GAS)
            .with_attached_deposit(MPC_DEPOSIT)
            .sign(SignRequestArgs {
                request: SignPayload {
                    payload: sighash.to_vec(),
                    path: mpc_path,
                    key_version: 0,
                },
            })
            .then(
                ext_self::ext(env::current_account_id())
                    .with_static_gas(CALLBACK_GAS)
                    .mpc_sign_callback(purchase_id, is_payout),
            )
    }

    fn listing_to_view(&self, listing: &Listing) -> ListingView {
        ListingView {
            id: listing.id,
            name: listing.name.clone(),
            seller_ua: listing.seller_ua.clone(),
            price_zat: listing.price_zat,
            commission_bps: listing.commission_bps,
            treasury_ua: listing.treasury_ua.clone(),
            status: listing_status_str(&listing.status).to_string(),
            created_at_ns: listing.created_at_ns,
        }
    }

    fn purchase_to_view(&self, purchase: &Purchase) -> PurchaseView {
        PurchaseView {
            id: purchase.id,
            listing_id: purchase.listing_id,
            buyer_ua: purchase.buyer_ua.clone(),
            required_memo: purchase.required_memo.clone(),
            price_zat: purchase.price_zat,
            commission_zat: purchase.commission_zat,
            payout_fee_zat: purchase.payout_fee_zat,
            seller_receives_zat: purchase.seller_receives_zat,
            refund_receives_zat: purchase.refund_receives_zat,
            burner_taddr: purchase.burner_taddr.clone(),
            burner_pubkey_hex: hex::encode(purchase.burner_pubkey),
            mpc_path: purchase.mpc_path.clone(),
            status: purchase_status_str(&purchase.status).to_string(),
            created_at_ns: purchase.created_at_ns,
            expires_at_ns: purchase.expires_at_ns,
            funding_outpoint_txid_hex: purchase
                .funding_outpoint
                .as_ref()
                .map(|(txid, _)| hex::encode(txid)),
            funding_vout: purchase.funding_outpoint.map(|(_, vout)| vout),
            utxo_value_zats: purchase.utxo_value_zats,
            payout_tx_hash_hex: purchase.payout_tx_hash.map(hex::encode),
            refund_tx_hash_hex: purchase.refund_tx_hash.map(hex::encode),
            payout_sighash_hex: purchase.payout_sighash.map(hex::encode),
            refund_sighash_hex: purchase.refund_sighash.map(hex::encode),
        }
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

fn required_buy_memo(listing_id: u64, purchase_id: u64, name: &str, buyer_ua: &str) -> String {
    let commitment = sha256(format!("{listing_id}:{purchase_id}:{name}:{buyer_ua}").as_bytes());
    format!(
        "ZNS:BUY:{listing_id}:{purchase_id}:{}",
        hex::encode(commitment)
    )
}

fn validate_unified_address(ua: &str, mainnet: bool) -> Result<(), &'static str> {
    if ua.is_empty() || ua.len() > MAX_UA_LEN {
        return Err("UA length invalid");
    }
    let parsed = bech32::primitives::decode::CheckedHrpstring::new::<bech32::Bech32m>(ua)
        .map_err(|_| "invalid Bech32m encoding")?;
    let hrp_binding = parsed.hrp();
    let hrp = hrp_binding.as_str();
    let expected = if mainnet { "u" } else { "utest" };
    if hrp != expected {
        return Err("wrong HRP for network");
    }
    let data: Vec<u8> = parsed.byte_iter().collect();
    if data.is_empty() {
        return Err("empty receiver list");
    }
    let mut offset = 0;
    let mut count = 0;
    while offset < data.len() {
        if offset + 2 > data.len() {
            return Err("truncated receiver header");
        }
        let typecode = data[offset];
        let len = data[offset + 1] as usize;
        offset += 2;
        if len == 0 {
            return Err("empty receiver payload");
        }
        if offset + len > data.len() {
            return Err("truncated receiver payload");
        }
        match typecode {
            0x00 | 0x01 => {
                if len != 20 {
                    return Err("invalid transparent receiver length");
                }
            }
            0x02 | 0x03 => {
                if len != 43 {
                    return Err("invalid shielded receiver length");
                }
            }
            _ => {}
        }
        offset += len;
        count += 1;
    }
    if count == 0 {
        return Err("no receivers");
    }
    Ok(())
}

fn listing_status_str(s: &ListingStatus) -> &'static str {
    match s {
        ListingStatus::Open => "Open",
        ListingStatus::Sold => "Sold",
        ListingStatus::Cancelled => "Cancelled",
    }
}

fn purchase_status_str(s: &PurchaseStatus) -> &'static str {
    match s {
        PurchaseStatus::AwaitingPayment => "AwaitingPayment",
        PurchaseStatus::PayoutAuthorized => "PayoutAuthorized",
        PurchaseStatus::Completed => "Completed",
        PurchaseStatus::Refundable => "Refundable",
        PurchaseStatus::Refunded => "Refunded",
        PurchaseStatus::Expired => "Expired",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ua(hrp: &str, receivers: &[(u8, &[u8])]) -> String {
        let hrp = bech32::Hrp::parse(hrp).unwrap();
        let mut data = vec![];
        for (tc, payload) in receivers {
            data.push(*tc);
            data.push(payload.len() as u8);
            data.extend_from_slice(payload);
        }
        bech32::encode::<bech32::Bech32m>(hrp, &data).unwrap()
    }

    #[test]
    fn valid_mainnet_ua_orchard() {
        let ua = make_ua("u", &[(0x03, &[0u8; 43])]);
        assert!(validate_unified_address(&ua, true).is_ok());
    }

    #[test]
    fn valid_mainnet_ua_mixed() {
        let ua = make_ua("u", &[(0x00, &[0u8; 20]), (0x03, &[0u8; 43])]);
        assert!(validate_unified_address(&ua, true).is_ok());
    }

    #[test]
    fn valid_testnet_ua() {
        let ua = make_ua("utest", &[(0x02, &[0u8; 43])]);
        assert!(validate_unified_address(&ua, false).is_ok());
    }

    #[test]
    fn invalid_wrong_hrp_mainnet() {
        let ua = make_ua("utest", &[(0x03, &[0u8; 43])]);
        assert!(validate_unified_address(&ua, true).is_err());
    }

    #[test]
    fn required_memo_is_deterministic() {
        let a = required_buy_memo(1, 2, "alice", "u1test");
        let b = required_buy_memo(1, 2, "alice", "u1test");
        assert_eq!(a, b);
        assert!(a.starts_with("ZNS:BUY:1:2:"));
    }
}
