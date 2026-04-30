//! ZNS non-custodial marketplace escrow contract.
//!
//! Two top-level entities:
//!   * Listing  — created by seller, immutable terms
//!   * Purchase — created by buyer, binds a listing to a burner + pre-built bundles

use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::store::LookupMap;
use near_sdk::{env, near_bindgen, AccountId, Gas, NearToken, Promise, PromiseError};
use serde::{Deserialize, Serialize};

mod zcash;
use zcash::{validate_burner_script, verify_burner_taddr};

const SIGN_GAS: Gas = Gas::from_tgas(250);
const CALLBACK_GAS: Gas = Gas::from_tgas(50);
const MPC_DEPOSIT: NearToken = NearToken::from_yoctonear(100);

const MAX_COMMISSION_BPS: u64 = 1_000; // 10%
const MAX_EXPIRY_SECONDS: u64 = 30 * 86_400;
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

// ─── Listing ────────────────────────────────────────────────────────────

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

// ─── Purchase ───────────────────────────────────────────────────────────

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
    pub burner_taddr: String,
    pub burner_pubkey: [u8; 33],
    pub mpc_path: String,
    /// Pre-built payout bundle bytes (~3-5 KB).
    pub payout_bundle: Vec<u8>,
    /// Pre-built refund bundle bytes (~3-5 KB).
    pub refund_bundle: Vec<u8>,
    pub status: PurchaseStatus,
    pub created_at_ns: u64,
    pub expires_at_ns: u64,
    /// Set at submit_funding.
    pub funding_outpoint: Option<( [u8; 32], u32 )>, // txid le, vout
    /// Set at submit_funding.
    pub sighash: Option<[u8; 32]>,
    /// Set at request_signature callback.
    pub signature: Option<MpcSignature>,
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
    pub next_listing_id: u64,
    pub next_purchase_id: u64,
    pub listings: LookupMap<u64, Listing>,
    pub purchases: LookupMap<u64, Purchase>,
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
        Self {
            owner,
            relayer,
            mpc_contract,
            treasury_ua,
            commission_bps,
            default_expiry_seconds,
            mainnet,
            consensus_branch_id,
            next_listing_id: 1,
            next_purchase_id: 1,
            listings: LookupMap::new(b"L"),
            purchases: LookupMap::new(b"P"),
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

    // ── Listing lifecycle ─────────────────────────────────────────────

    #[payable]
    pub fn create_listing(
        &mut self,
        name: String,
        seller_ua: String,
        price_zat: u64,
    ) -> u64 {
        self.assert_relayer();
        assert!(!name.is_empty() && name.len() <= MAX_NAME_LEN, "name length");
        validate_unified_address(&seller_ua, self.mainnet)
            .unwrap_or_else(|e| env::panic_str(&format!("seller_ua invalid: {e}")));
        assert!(price_zat > 0, "price_zat must be > 0");

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
        self.listings.insert(id, listing);

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
            "listing_created",
            serde_json::json!({
                "id": id,
                "name": name,
                "seller_ua": seller_ua,
                "price_zat": price_zat,
                "commission_bps": self.commission_bps,
                "treasury_ua": self.treasury_ua,
                "created_at_ns": now,
            }),
        );
        id
    }

    pub fn cancel_listing(&mut self, id: u64) {
        self.assert_owner();
        let mut listing = self.listings.get(&id).expect("not found").clone();
        assert!(matches!(listing.status, ListingStatus::Open), "listing not open");
        listing.status = ListingStatus::Cancelled;
        self.listings.insert(id, listing);
        emit_event("listing_cancelled", serde_json::json!({ "id": id }));
    }

    // ── Purchase lifecycle ──────────────────────────────────────────────

    #[payable]
    pub fn accept_listing(
        &mut self,
        listing_id: u64,
        buyer_ua: String,
        burner_taddr: String,
        burner_pubkey: Vec<u8>,
        mpc_path: String,
        payout_bundle: Vec<u8>,
        refund_bundle: Vec<u8>,
    ) -> u64 {
        self.assert_relayer();
        // TODO: validate bundle sizes, burner matches pubkey, path unused, expiry;
        // charge storage; emit event
        todo!("accept_listing")
    }

    pub fn submit_funding(
        &mut self,
        purchase_id: u64,
        utxo_txid: [u8; 32], // little-endian
        utxo_vout: u32,
        utxo_value_zats: u64,
        utxo_script_pubkey: Vec<u8>,
    ) {
        self.assert_relayer();
        // TODO: validate script == P2PKH(burner_pubkey), value == price,
        // splice outpoint into stored bundle, compute sighash, status -> PayoutAuthorized
        todo!("submit_funding")
    }

    pub fn request_payout_signature(&mut self, purchase_id: u64) -> Promise {
        self.assert_relayer();
        // TODO: verify status == PayoutAuthorized; dispatch MPC; emit event
        todo!("request_payout_signature")
    }

    pub fn authorize_refund(&mut self, purchase_id: u64) {
        self.assert_relayer();
        // TODO: verify status in (AwaitingPayment post-expiry | PayoutAuthorized post-expiry);
        // status -> Refundable; emit event
        todo!("authorize_refund")
    }

    pub fn request_refund_signature(&mut self, purchase_id: u64) -> Promise {
        self.assert_relayer();
        // TODO: verify status == Refundable; dispatch MPC on refund sighash; emit event
        todo!("request_refund_signature")
    }

    // ── MPC callbacks ───────────────────────────────────────────────────

    #[private]
    pub fn mpc_sign_callback(
        &mut self,
        #[callback_result] result: Result<MpcSignature, PromiseError>,
        purchase_id: u64,
        is_payout: bool,
    ) {
        // TODO: store signature, update status (Completed or Refunded), emit event
        todo!("mpc_sign_callback")
    }

    // ── Maintenance ─────────────────────────────────────────────────────

    pub fn prune_terminal(&mut self, purchase_id: u64) {
        self.assert_owner();
        // TODO: drop signature/bundles for terminal purchases to reclaim storage
        todo!("prune_terminal")
    }

    // ── Views ───────────────────────────────────────────────────────────

    pub fn get_listing(&self, id: u64) -> Option<Listing> {
        self.listings.get(&id).cloned()
    }

    pub fn get_purchase(&self, id: u64) -> Option<Purchase> {
        self.purchases.get(&id).cloned()
    }

    pub fn get_signature(&self, purchase_id: u64) -> Option<MpcSignature> {
        self.purchases.get(&purchase_id).and_then(|p| p.signature.clone())
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
            "next_listing_id": self.next_listing_id,
            "next_purchase_id": self.next_purchase_id,
        })
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    fn assert_owner(&self) {
        assert_eq!(env::predecessor_account_id(), self.owner, "owner only");
    }

    fn assert_relayer(&self) {
        assert_eq!(env::predecessor_account_id(), self.relayer, "relayer only");
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

/// Validate a Zcash Unified Address (ZIP-316).
fn validate_unified_address(ua: &str, mainnet: bool) -> Result<(), &'static str> {
    if ua.is_empty() || ua.len() > MAX_UA_LEN {
        return Err("UA length invalid");
    }
    let parsed = bech32::primitives::decode::CheckedHrpstring::new::<bech32::Bech32m>(ua)
        .map_err(|_| "invalid Bech32m encoding")?;
    let hrp = parsed.hrp().as_str();
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
    fn invalid_empty_receivers() {
        let ua = make_ua("u", &[]);
        assert!(validate_unified_address(&ua, true).is_err());
    }

    #[test]
    fn invalid_truncated_receiver() {
        let ua = make_ua("u", &[(0x03, &[0u8; 10])]);
        assert!(validate_unified_address(&ua, true).is_err());
    }
}
