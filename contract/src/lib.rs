//! ZNS non-custodial marketplace escrow contract.
//!
//! ## Architecture
//!
//! The contract is the authority for:
//!
//! * **Listing terms** — seller, treasury, price, commission, fee
//! * **Deterministic burner address** — one per listing, derived from
//!   `mpc_root_pubkey + zns-<name>-<listing_nonce>`
//! * **Payout tx bytes and sighash** — the contract validates and stores
//!   them so the MPC can sign them later
//!
//! ## Separation of concerns
//!
//! | Role      | Responsibility                                      |
//! |-----------|-----------------------------------------------------|
//! | Relayer   | Off-chain buyer registration, tx builder, submitter |
//! | Contract  | Listing state machine, validation, MPC orchestration |
//! | MPC       | Signer (stateless, invoked by this contract)        |
//!
//! ## Listing state machine
//!
//! ```text
//!   [create_listing] → Open
//!         |
//!     [submit_funding] (one-shot — relayer attaches buyer info from its DB)
//!         |
//!         ▼
//!      Funded
//!         |
//!  [request_payout_signature]
//!         |
//!         ▼
//!     Completed
//!
//!   [cancel_listing] (only valid while Open — no funding submitted yet)
//! ```
//!
//! Refunds for wrong-amount or losing-race UTXOs are deferred — those UTXOs
//! sit at the burner address until a future `request_refund` flow is added.

use near_sdk::store::LookupMap;
use near_sdk::{
    env, ext_contract, near, near_bindgen, AccountId, Gas, NearToken, PanicOnDefault, Promise,
    PromiseError,
};

pub mod zcash;
use zcash::{compute_sighash_all, derive_burner, parse_tx, sha256, validate_burner_script};

// ───────────────────────────────────────────────────────────────────────────
// Constants
// ───────────────────────────────────────────────────────────────────────────

const SIGN_GAS: Gas = Gas::from_tgas(250);
const CALLBACK_GAS: Gas = Gas::from_tgas(3);
const MPC_DEPOSIT: NearToken = NearToken::from_yoctonear(100);

const MAX_COMMISSION_BPS: u64 = 1_000; // 10 %
const MAX_UA_LEN: usize = 512;
const MAX_NAME_LEN: usize = 256;
const MAX_PATH_LEN: usize = 384;
const MAX_TX_BYTES: usize = 20_000;

const EVENT_STANDARD: &str = "zns";
const EVENT_VERSION: &str = "1.0.0";

// ───────────────────────────────────────────────────────────────────────────
// MPC primitive types
// ───────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
#[near(serializers = [json, borsh])]
pub struct AffinePoint {
    pub affine_point: String,
}

#[derive(Clone, Debug)]
#[near(serializers = [json, borsh])]
pub struct ScalarHex {
    pub scalar: String,
}

#[derive(Clone, Debug)]
#[near(serializers = [json, borsh])]
pub struct MpcSignature {
    pub big_r: AffinePoint,
    pub s: ScalarHex,
    pub recovery_id: u8,
}

#[near(serializers = [json, borsh])]
pub struct SignRequestArgs {
    pub path: String,
    pub payload: [u8; 32],
    pub key_version: u32,
}

// ───────────────────────────────────────────────────────────────────────────
// Cross-contract call interfaces
// ───────────────────────────────────────────────────────────────────────────

#[ext_contract(ext_mpc)]
#[allow(dead_code)]
trait ExtMpc {
    fn sign(&self, request: SignRequestArgs) -> MpcSignature;
}

#[ext_contract(ext_self)]
#[allow(dead_code)]
trait ExtSelf {
    fn mpc_sign_callback(
        &mut self,
        #[callback_result] result: Result<MpcSignature, PromiseError>,
        listing_id: u64,
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Domain types
// ───────────────────────────────────────────────────────────────────────────

/// On-chain listing for a name sale.
///
/// One listing carries one burner t-addr, derived at `create_listing` time
/// from `mpc_root_pubkey + zns-<name>-<listing_nonce>`. After
/// `submit_funding` succeeds, the listing is locked to a single buyer's
/// payout and cannot be re-funded.
#[derive(Clone, Debug)]
#[near(serializers = [borsh, json])]
pub struct Listing {
    pub id: u64,
    pub name: String,
    pub seller_ua: String,
    pub price_zat: u64,
    pub commission_bps: u64,
    pub treasury_ua: String,
    pub created_at_ns: u64,
    pub listing_nonce: u64,

    // Derived burner key + path.
    pub burner_taddr: String,
    pub burner_pubkey: Vec<u8>,
    pub mpc_path: String,

    // Funding state — populated by submit_funding.
    pub funded: bool,
    pub buyer_ua: Option<String>,
    pub buyer_pubkey_b64: Option<String>,
    pub funding_outpoint: Option<([u8; 32], u32)>,
    pub utxo_value_zats: Option<u64>,
    pub payout_tx_hash: Option<[u8; 32]>,
    pub payout_sighash: Option<[u8; 32]>,
    pub payout_signature: Option<MpcSignature>,

    // Ed25519 pubkey that authorized this listing (None = admin key).
    pub listing_pubkey: Option<[u8; 32]>,
}


// ───────────────────────────────────────────────────────────────────────────
// Contract state
// ───────────────────────────────────────────────────────────────────────────

#[near_bindgen(contract_state)]
#[derive(PanicOnDefault)]
#[near(serializers = [borsh])]
pub struct ZnsContract {
    pub owner: AccountId,
    pub mpc_contract: AccountId,
    pub mpc_root_pubkey: String,
    pub treasury_ua: String,
    pub commission_bps: u64,
    pub payout_fee_zat: u64,
    pub mainnet: bool,
    pub consensus_branch_id: u32,
    pub admin_pubkey: [u8; 32],
    pub next_listing_id: u64,
    pub listings: LookupMap<u64, Listing>,
    pub listing_ids_by_name: LookupMap<String, u64>,
}

// ───────────────────────────────────────────────────────────────────────────
// Public entry points
// ───────────────────────────────────────────────────────────────────────────

#[near_bindgen]
impl ZnsContract {
    // ── Constructor ──────────────────────────────────────────────────────

    #[init]
    pub fn new(
        owner: AccountId,
        mpc_contract: AccountId,
        mpc_root_pubkey: String,
        treasury_ua: String,
        commission_bps: u64,
        payout_fee_zat: u64,
        mainnet: bool,
        consensus_branch_id: u32,
        admin_pubkey_b64: String,
    ) -> Self {
        assert!(!env::state_exists(), "already initialized");
        assert!(
            commission_bps <= MAX_COMMISSION_BPS,
            "commission_bps too high"
        );
        validate_unified_address(&treasury_ua, mainnet)
            .unwrap_or_else(|e| env::panic_str(&format!("treasury_ua invalid: {e}")));
        assert!(payout_fee_zat > 0, "payout_fee_zat must be > 0");
        let admin_pubkey = decode_pubkey_b64(&admin_pubkey_b64)
            .unwrap_or_else(|e| env::panic_str(&format!("admin_pubkey invalid: {e}")));
        Self {
            owner,
            mpc_contract,
            mpc_root_pubkey,
            treasury_ua,
            commission_bps,
            payout_fee_zat,
            mainnet,
            consensus_branch_id,
            admin_pubkey,
            next_listing_id: 1,
            listings: LookupMap::new(b"L"),
            listing_ids_by_name: LookupMap::new(b"N"),
        }
    }

    // ── Admin setters ────────────────────────────────────────────────────

    pub fn set_mpc_contract(&mut self, account: AccountId) {
        self.assert_owner();
        self.mpc_contract = account;
    }

    pub fn set_mpc_root_pubkey(&mut self, pubkey: String) {
        self.assert_owner();
        self.mpc_root_pubkey = pubkey;
    }

    pub fn set_admin_pubkey(&mut self, pubkey_b64: String) {
        self.assert_owner();
        let pk = decode_pubkey_b64(&pubkey_b64)
            .unwrap_or_else(|e| env::panic_str(&format!("admin_pubkey invalid: {e}")));
        self.admin_pubkey = pk;
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

    pub fn set_consensus_branch_id(&mut self, branch_id: u32) {
        self.assert_owner();
        self.consensus_branch_id = branch_id;
    }

    pub fn transfer_ownership(&mut self, new_owner: AccountId) {
        self.assert_owner();
        self.owner = new_owner;
    }

    // ── Listing lifecycle ────────────────────────────────────────────────

    /// Create or replace a listing, deriving its burner t-address.
    ///
    /// Replacing an existing listing requires a strictly higher `nonce`. Each
    /// (name, nonce) pair derives a unique burner key via path
    /// `zns-<name>-<nonce>`, so a relisted name always gets a fresh t-addr.
    #[payable]
    pub fn create_listing(
        &mut self,
        name: String,
        seller_ua: String,
        price_zat: u64,
        nonce: u64,
        signature_b64: String,
        user_pubkey_b64: Option<String>,
    ) -> Listing {
        self.assert_owner();
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

        let (pubkey, listing_pubkey) = if let Some(pk_b64) = user_pubkey_b64 {
            let pk = decode_pubkey_b64(&pk_b64)
                .unwrap_or_else(|e| env::panic_str(&format!("user_pubkey invalid: {e}")));
            (pk, Some(pk))
        } else {
            (self.admin_pubkey, None)
        };

        let payload = format!("LIST:{name}:{price_zat}:{nonce}");
        assert!(
            ed25519_verify_b64(&signature_b64, &payload, &pubkey),
            "listing signature invalid"
        );

        // Replacement: previous listing for this name (if any) must be
        // unfunded and have a strictly lower nonce.
        if let Some(existing_id) = self.listing_ids_by_name.get(&name).copied() {
            let existing = self
                .listings
                .get(&existing_id)
                .expect("listing index out of sync")
                .clone();
            assert!(
                nonce > existing.listing_nonce,
                "listing nonce must increase for replacement"
            );
            assert!(!existing.funded, "cannot replace a funded listing");
            // Remove the stale listing entry before inserting the new one.
            self.listings.remove(&existing_id);
        }

        let mpc_path = build_listing_path(&name, nonce);
        assert!(
            !mpc_path.is_empty() && mpc_path.len() <= MAX_PATH_LEN,
            "mpc_path length"
        );

        let (burner_taddr, burner_pubkey) = derive_burner(
            &self.mpc_root_pubkey,
            env::current_account_id().as_str(),
            &mpc_path,
            self.mainnet,
        )
        .unwrap_or_else(|e| env::panic_str(&format!("burner derivation failed: {e}")));

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
            created_at_ns: now,
            listing_nonce: nonce,
            burner_taddr: burner_taddr.clone(),
            burner_pubkey: burner_pubkey.to_vec(),
            mpc_path: mpc_path.clone(),
            funded: false,
            buyer_ua: None,
            buyer_pubkey_b64: None,
            funding_outpoint: None,
            utxo_value_zats: None,
            payout_tx_hash: None,
            payout_sighash: None,
            payout_signature: None,
            listing_pubkey,
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
                "listing_nonce": nonce,
                "burner_taddr": burner_taddr,
                "burner_pubkey_hex": hex::encode(burner_pubkey),
                "mpc_path": mpc_path,
            }),
        );
        listing
    }

    /// Cancel a listing.  Only valid while the listing is unfunded.
    pub fn cancel_listing(
        &mut self,
        id: u64,
        nonce: u64,
        signature_b64: String,
        user_pubkey_b64: Option<String>,
    ) {
        let listing = self.listings.get(&id).expect("not found").clone();
        assert!(!listing.funded, "cannot cancel a funded listing");
        assert_eq!(
            nonce,
            listing.listing_nonce,
            "nonce mismatch"
        );

        let pubkey: [u8; 32] = if let Some(pk_b64) = user_pubkey_b64 {
            let pk = decode_pubkey_b64(&pk_b64)
                .unwrap_or_else(|e| env::panic_str(&format!("user_pubkey invalid: {e}")));
            // Must match the key that created this listing.
            assert_eq!(
                listing.listing_pubkey,
                Some(pk),
                "cancel pubkey does not match listing creator"
            );
            pk
        } else {
            // Admin path: listing must have been admin-created (no stored pubkey).
            assert!(
                listing.listing_pubkey.is_none(),
                "sovereign listing requires user pubkey to cancel"
            );
            self.admin_pubkey
        };

        let payload = format!("DELIST:{}:{nonce}", listing.name);
        assert!(
            ed25519_verify_b64(&signature_b64, &payload, &pubkey),
            "cancel signature invalid"
        );

        self.listings.remove(&id);
        self.listing_ids_by_name.remove(&listing.name);
        emit_event("listing_cancelled", serde_json::json!({ "id": id }));
    }

    // ── Funding ──────────────────────────────────────────────────────────

    /// Submit a funding UTXO + pre-built payout transaction, locking the
    /// listing to a specific buyer.
    ///
    /// Admin signature over `BUY:<name>:<buyer_ua>` is verified unconditionally.
    /// The UTXO is expected at the listing-level burner address and the MPC
    /// signs with the listing's derivation path.
    ///
    /// If `buyer_pubkey_b64` is `Some`, it is stored on the listing as a
    /// sovereign-mode flag for the indexer. The BUY preimage is always
    /// admin-signed; the buyer's pubkey signals that subsequent operations
    /// on this name (e.g. updates) must be signed by that key rather than
    /// the admin key.
    ///
    /// The contract then validates the UTXO scriptPubKey, payout tx structure,
    /// and value balance before computing the sighash and marking the listing
    /// funded.
    pub fn submit_funding(
        &mut self,
        listing_id: u64,
        utxo_value_zats: u64,
        utxo_script_pubkey: Vec<u8>,
        payout_tx: Vec<u8>,
        buyer_ua: String,
        admin_signature_b64: String,
        buyer_pubkey_b64: Option<String>,
    ) {
        let mut listing = self
            .listings
            .get(&listing_id)
            .expect("listing not found")
            .clone();

        assert!(!listing.funded, "listing already funded");
        assert_eq!(
            utxo_value_zats, listing.price_zat,
            "utxo value must equal price"
        );
        assert!(utxo_value_zats > self.payout_fee_zat, "price <= fee");

        validate_unified_address(&buyer_ua, self.mainnet)
            .unwrap_or_else(|e| env::panic_str(&format!("buyer_ua invalid: {e}")));

        let admin_payload = format!("BUY:{}:{buyer_ua}", listing.name);
        assert!(
            ed25519_verify_b64(&admin_signature_b64, &admin_payload, &self.admin_pubkey),
            "admin signature invalid"
        );

        if let Some(pk_b64) = &buyer_pubkey_b64 {
            let _buyer_pubkey = decode_pubkey_b64(pk_b64)
                .unwrap_or_else(|e| env::panic_str(&format!("buyer_pubkey invalid: {e}")));
        }

        let mut burner_pubkey = [0u8; 33];
        burner_pubkey.copy_from_slice(&listing.burner_pubkey);

        validate_burner_script(&utxo_script_pubkey, &burner_pubkey)
            .unwrap_or_else(|e| env::panic_str(&format!("burner script invalid: {e}")));

        assert!(
            !payout_tx.is_empty() && payout_tx.len() <= MAX_TX_BYTES,
            "payout_tx size"
        );
        let payout_parsed = parse_tx(&payout_tx)
            .unwrap_or_else(|e| env::panic_str(&format!("payout_tx invalid: {e}")));
        assert_eq!(
            payout_parsed.consensus_branch_id, self.consensus_branch_id,
            "payout_tx wrong consensus branch id"
        );

        let payout_orchard = payout_parsed
            .orchard
            .as_ref()
            .expect("payout missing orchard bundle");
        assert!(
            payout_orchard.actions.len() == 2,
            "payout must have exactly 2 orchard actions"
        );
        let expected_value_balance =
            -(listing.price_zat as i64 - self.payout_fee_zat as i64);
        assert_eq!(
            payout_orchard.value_balance, expected_value_balance,
            "payout value_balance mismatch"
        );

        let payout_sighash =
            compute_sighash_all(&payout_parsed, utxo_value_zats, &utxo_script_pubkey);
        let payout_tx_hash = sha256(&payout_tx);
        let funding_outpoint = (
            payout_parsed.tx_in.prevout_txid,
            payout_parsed.tx_in.prevout_vout,
        );

        listing.funded = true;
        listing.buyer_ua = Some(buyer_ua.clone());
        listing.buyer_pubkey_b64 = buyer_pubkey_b64;
        listing.funding_outpoint = Some(funding_outpoint);
        listing.utxo_value_zats = Some(utxo_value_zats);
        listing.payout_tx_hash = Some(payout_tx_hash);
        listing.payout_sighash = Some(payout_sighash);
        self.listings.insert(listing_id, listing);

        emit_event(
            "funding_submitted",
            serde_json::json!({
                "listing_id": listing_id,
                "buyer_ua": buyer_ua,
                "utxo_txid": hex::encode(funding_outpoint.0),
                "utxo_vout": funding_outpoint.1,
                "utxo_value_zats": utxo_value_zats,
                "payout_tx_hash": hex::encode(payout_tx_hash),
                "payout_sighash": hex::encode(payout_sighash),
            }),
        );
    }

    // ── MPC signing flow ─────────────────────────────────────────────────

    /// Request the MPC to sign the payout transaction for a funded listing.
    pub fn request_payout_signature(&mut self, listing_id: u64) -> Promise {
        let listing = self
            .listings
            .get(&listing_id)
            .expect("listing not found")
            .clone();
        assert!(listing.funded, "listing not funded");
        assert!(
            listing.payout_signature.is_none(),
            "payout already signed"
        );
        let sighash = listing.payout_sighash.expect("payout_sighash missing");
        let mpc_path = listing.mpc_path.clone();
        emit_event(
            "payout_signature_requested",
            serde_json::json!({
                "listing_id": listing_id,
                "payout_sighash": hex::encode(sighash),
                "mpc_path": mpc_path,
            }),
        );
        self.request_signature(listing_id, mpc_path, sighash)
    }

    #[private]
    pub fn mpc_sign_callback(
        &mut self,
        #[callback_result] result: Result<MpcSignature, PromiseError>,
        listing_id: u64,
    ) {
        let gas_start = env::used_gas();
        let mut listing = self
            .listings
            .get(&listing_id)
            .expect("listing not found")
            .clone();
        match result {
            Ok(signature) => {
                listing.payout_signature = Some(signature);
                self.listings.insert(listing_id, listing);
                emit_event(
                    "signature_ready",
                    serde_json::json!({
                        "listing_id": listing_id,
                        "callback_gas_used": (env::used_gas().as_gas() - gas_start.as_gas()),
                    }),
                );
            }
            Err(err) => {
                emit_event(
                    "signature_failed",
                    serde_json::json!({
                        "listing_id": listing_id,
                        "error": format!("{:?}", err),
                        "callback_gas_used": (env::used_gas().as_gas() - gas_start.as_gas()),
                    }),
                );
            }
        }
    }

    // ── Read-only queries ────────────────────────────────────────────────

    pub fn get_listing(&self, id: u64) -> Option<Listing> {
        self.listings.get(&id).cloned()
    }

    pub fn get_listing_by_name(&self, name: String) -> Option<Listing> {
        self.listing_ids_by_name
            .get(&name)
            .and_then(|id| self.listings.get(id))
            .cloned()
    }

    pub fn get_payout_signature(&self, listing_id: u64) -> Option<MpcSignature> {
        self.listings
            .get(&listing_id)
            .and_then(|l| l.payout_signature.clone())
    }

    pub fn get_config(&self) -> serde_json::Value {
        serde_json::json!({
            "owner": self.owner,
            "mpc_contract": self.mpc_contract,
            "mpc_root_pubkey": self.mpc_root_pubkey,
            "treasury_ua": self.treasury_ua,
            "commission_bps": self.commission_bps,
            "payout_fee_zat": self.payout_fee_zat,
            "mainnet": self.mainnet,
            "consensus_branch_id": self.consensus_branch_id,
            "admin_pubkey_b64": base64::encode(self.admin_pubkey),
            "next_listing_id": self.next_listing_id,
        })
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Private helpers
// ───────────────────────────────────────────────────────────────────────────

impl ZnsContract {
    fn assert_owner(&self) {
        assert_eq!(env::predecessor_account_id(), self.owner, "owner only");
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

    fn request_signature(&self, listing_id: u64, mpc_path: String, sighash: [u8; 32]) -> Promise {
        ext_mpc::ext(self.mpc_contract.clone())
            .with_static_gas(SIGN_GAS)
            .with_attached_deposit(MPC_DEPOSIT)
            .sign(SignRequestArgs {
                path: mpc_path,
                payload: sighash,
                domain_id: 0,
            })
            .then(
                ext_self::ext(env::current_account_id())
                    .with_static_gas(CALLBACK_GAS)
                    .mpc_sign_callback(listing_id),
            )
    }

}

// ───────────────────────────────────────────────────────────────────────────
// Standalone utilities
// ───────────────────────────────────────────────────────────────────────────

fn emit_event(event: &str, data: serde_json::Value) {
    let payload = serde_json::json!({
        "standard": EVENT_STANDARD,
        "version": EVENT_VERSION,
        "event": event,
        "data": [data],
    });
    env::log_str(&format!("EVENT_JSON:{}", payload));
}

/// Build the MPC derivation path for a listing.
///
/// Format: `zns-<name>-<nonce>` — uniqueness is guaranteed because each
/// replacement listing for the same name must use a strictly higher nonce.
fn build_listing_path(name: &str, nonce: u64) -> String {
    format!("zns-{name}-{nonce}")
}

fn decode_pubkey_b64(b64: &str) -> Result<[u8; 32], &'static str> {
    let bytes = base64::decode(b64).map_err(|_| "invalid base64 pubkey")?;
    if bytes.len() != 32 {
        return Err("pubkey must be 32 bytes");
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn ed25519_verify_b64(signature_b64: &str, data: &str, pubkey: &[u8; 32]) -> bool {
    let Ok(sig_bytes) = base64::decode(signature_b64) else {
        return false;
    };
    if sig_bytes.len() != 64 {
        return false;
    }
    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(&sig_bytes);
    env::ed25519_verify(&sig_array, data.as_bytes(), pubkey)
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

    let mut data: Vec<u8> = parsed.byte_iter().collect();
    f4jumble::f4jumble_inv_mut(&mut data).map_err(|_| "F4Jumble decode failed")?;

    if data.len() < 16 {
        return Err("payload too short for padding");
    }
    let padding_len = hrp.len().min(16);
    let (payload, padding) = data.split_at(data.len() - 16);
    if &padding[..padding_len] != hrp.as_bytes() {
        return Err("invalid padding");
    }

    let mut cursor: &[u8] = payload;
    let mut prev_typecode: Option<u32> = None;
    let mut has_shielded = false;
    let mut has_orchard = false;
    let mut has_p2pkh = false;
    let mut has_p2sh = false;

    while !cursor.is_empty() {
        let typecode = zcash_encoding::CompactSize::read(&mut cursor)
            .map_err(|_| "invalid typecode")? as u32;
        let len = zcash_encoding::CompactSize::read(&mut cursor)
            .map_err(|_| "invalid receiver length")? as usize;

        if len == 0 {
            return Err("empty receiver payload");
        }
        if cursor.len() < len {
            return Err("truncated receiver payload");
        }

        if let Some(prev) = prev_typecode {
            if typecode <= prev {
                return Err("duplicate or out-of-order typecode");
            }
        }
        prev_typecode = Some(typecode);

        match typecode {
            0x00 => {
                if len != 20 {
                    return Err("invalid P2PKH receiver length");
                }
                has_p2pkh = true;
            }
            0x01 => {
                if len != 20 {
                    return Err("invalid P2SH receiver length");
                }
                has_p2sh = true;
            }
            0x02 => {
                if len != 43 {
                    return Err("invalid Sapling receiver length");
                }
                has_shielded = true;
            }
            0x03 => {
                if len != 43 {
                    return Err("invalid Orchard receiver length");
                }
                has_shielded = true;
                has_orchard = true;
            }
            _ => {
                has_shielded = true;
            }
        }

        cursor = &cursor[len..];
    }

    if has_p2pkh && has_p2sh {
        return Err("UA contains both P2PKH and P2SH");
    }
    if !has_shielded {
        return Err("UA contains only transparent receivers");
    }
    if !has_orchard {
        return Err("UA has no Orchard receiver");
    }

    Ok(())
}

// ───────────────────────────────────────────────────────────────────────────
// Tests
// ───────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ua(hrp: &str, receivers: &[(u8, &[u8])]) -> String {
        let hrp_parsed = bech32::Hrp::parse(hrp).unwrap();
        let mut raw = vec![];
        for (tc, payload) in receivers {
            zcash_encoding::CompactSize::write(&mut raw, *tc as usize).unwrap();
            zcash_encoding::CompactSize::write(&mut raw, payload.len()).unwrap();
            raw.extend_from_slice(payload);
        }
        let mut padding = [0u8; 16];
        padding[..hrp.len()].copy_from_slice(hrp.as_bytes());
        raw.extend_from_slice(&padding);
        f4jumble::f4jumble_mut(&mut raw).unwrap();
        bech32::encode::<bech32::Bech32m>(hrp_parsed, &raw).unwrap()
    }

    fn make_ua_raw(hrp: &str, raw: &[u8]) -> String {
        let hrp_parsed = bech32::Hrp::parse(hrp).unwrap();
        bech32::encode::<bech32::Bech32m>(hrp_parsed, raw).unwrap()
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
        let ua = make_ua("utest", &[(0x02, &[0u8; 43]), (0x03, &[0u8; 43])]);
        assert!(validate_unified_address(&ua, false).is_ok());
    }

    #[test]
    fn invalid_wrong_hrp_mainnet() {
        let ua = make_ua("utest", &[(0x03, &[0u8; 43])]);
        assert!(validate_unified_address(&ua, true).is_err());
    }

    #[test]
    fn invalid_f4jumble_length() {
        let hrp = bech32::Hrp::parse("utest").unwrap();
        let short = vec![0u8; 10];
        let ua = bech32::encode::<bech32::Bech32m>(hrp, &short).unwrap();
        assert!(validate_unified_address(&ua, false).is_err());
    }

    #[test]
    fn invalid_padding() {
        let mut raw = vec![0x03u8];
        zcash_encoding::CompactSize::write(&mut raw, 43usize).unwrap();
        raw.extend_from_slice(&[0u8; 43]);
        let mut padding = [0u8; 16];
        padding[..5].copy_from_slice(b"wrong");
        raw.extend_from_slice(&padding);
        f4jumble::f4jumble_mut(&mut raw).unwrap();
        let ua = make_ua_raw("utest", &raw);
        assert!(validate_unified_address(&ua, false).is_err());
    }

    #[test]
    fn invalid_orchard_length() {
        let ua = make_ua("u", &[(0x03, &[0u8; 42])]);
        assert!(validate_unified_address(&ua, true).is_err());
    }

    #[test]
    fn invalid_duplicate_typecode() {
        let ua = make_ua("u", &[(0x03, &[0u8; 43]), (0x03, &[0u8; 43])]);
        assert!(validate_unified_address(&ua, true).is_err());
    }

    #[test]
    fn invalid_both_p2pkh_and_p2sh() {
        let ua = make_ua("u", &[(0x00, &[0u8; 20]), (0x01, &[0u8; 20]), (0x03, &[0u8; 43])]);
        assert!(validate_unified_address(&ua, true).is_err());
    }

    #[test]
    fn invalid_no_orchard() {
        let ua = make_ua("u", &[(0x02, &[0u8; 43])]);
        assert!(validate_unified_address(&ua, true).is_err());
    }

    #[test]
    fn listing_path_format() {
        assert_eq!(build_listing_path("alice.zcash", 3), "zns-alice.zcash-3");
    }
}
