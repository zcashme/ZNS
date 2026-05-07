/**
 * Internal types that mirror the Rust indexer API exactly (snake_case).
 * These are used for raw data passthrough and debugging.
 * Public SDK consumers should use the camelCase types exported below.
 */
export type Zats = number;

/** Commission sent with a BUY claim memo (0.0001 ZEC = 10,000 zats). */
export const BUY_COMMISSION: Zats = 10_000;
/** Listing commission sent with a LIST memo (0.01 ZEC = 1,000,000 zats).
 *  Mirrors the indexer's formula: min_tier × 1000. */
export const LIST_COMMISSION: Zats = 1_000_000;

/* ── Raw types (API passthrough) ─────────────────────────────────────── */

/** @deprecated Use camelCase types below. Raw type matching Rust API. */
export interface RawRegistration {
  name: string;
  address: string;
  txid: string;
  height: number;
  nonce: number;
  signature: string | null;
  last_action: LastAction;
  pubkey: string | null;
  listing: RawListing | null;
}

/** @deprecated Use camelCase types below. Raw type matching Rust API. */
export interface RawListing {
  name: string;
  price: Zats;
  pay_taddr: string;
  nonce: number;
  txid: string;
  height: number;
  signature: string;
  pubkey: string | null;
  pending_buy: RawPendingBuy | null;
}

/** @deprecated Use camelCase types below. Raw type matching Rust API. */
export interface RawPendingBuy {
  buyer_ua: string;
  price: Zats;
  claim_height: number;
  expires_at: number;
  txid: string;
}

/** @deprecated Use camelCase types below. Raw type matching Rust API. */
export interface RawStatus {
  synced_height: number;
  admin_pubkey: string;
  uivk: string;
  address: string;
  registered: number;
  listed: number;
  pricing: RawPricing | null;
}

/** @deprecated Use camelCase types below. Raw type matching Rust API. */
export interface RawPricing {
  nonce: number;
  height: number;
  tiers: Zats[];
}

/** @deprecated Use camelCase types below. Raw type matching Rust API. */
export interface RawEvent {
  id: number;
  name: string;
  action: EventAction;
  txid: string;
  height: number;
  ua: string | null;
  price: Zats | null;
  nonce: number | null;
  signature: string | null;
  pubkey: string | null;
}

/** @deprecated Use camelCase types below. Raw type matching Rust API. */
export interface RawEventsFilter {
  name?: string;
  action?: EventAction;
  since_height?: number;
  limit?: number;
  offset?: number;
}

/** @deprecated Use camelCase types below. Raw type matching Rust API. */
export interface RawEventsResult {
  events: RawEvent[];
  total: number;
}

/* ── Actions ─────────────────────────────────────────────────────────── */

/** Actions that can be the 'last action' on a Registration (ownership-changing actions) */
export type LastAction = "CLAIM" | "BUY" | "UPDATE" | "DELIST" | "RELEASE";

/** All actions that can appear in the Event log (includes non-ownership actions like LIST) */
export type EventAction =
  | "CLAIM"
  | "LIST"
  | "DELIST"
  | "RELEASE"
  | "UPDATE"
  | "BUY"
  | "SETPRICE";

/* ── Public types (camelCase, TypeScript conventions) ───────────────── */

/** Pending purchase for a listed name. */
export interface PendingBuy {
  buyer: string;
  price: Zats;
  claimHeight: number;
  expiresAt: number;
  txid: string;
}

/** A name listing in the marketplace. */
export interface Listing {
  name: string;
  price: Zats;
  payTaddr: string;
  nonce: number;
  txid: string;
  height: number;
  signature: string;
  pubkey: string | null;
  pendingBuy: PendingBuy | undefined;
}

/** A registered ZNS name. */
export interface Registration {
  name: string;
  address: string;
  txid: string;
  height: number;
  nonce: number;
  signature: string | null;
  lastAction: LastAction;
  pubkey: string | null;
  listing: Listing | null;
}

/** Pricing tiers for name registration. */
export interface Pricing {
  nonce: number;
  height: number;
  tiers: Zats[];
}

/** Current indexer status including pricing configuration. */
export interface Status {
  syncedHeight: number;
  adminPubkey: string;
  uivk: string;
  address: string;
  registered: number;
  listed: number;
  pricing: Pricing | null;
}

/** An event in the ZNS event log. */
export interface Event {
  id: number;
  name: string;
  action: EventAction;
  txid: string;
  height: number;
  ua: string | null;
  price: Zats | null;
  nonce: number | null;
  signature: string | null;
  pubkey: string | null;
}

/** Filter options for querying events. */
export interface EventsFilter {
  name?: string;
  action?: EventAction;
  sinceHeight?: number;
  limit?: number;
  offset?: number;
}

/** Paginated events result. */
export interface EventsResult {
  events: Event[];
  total: number;
}

/* ── Prepared actions ───────────────────────────────────────────────── */

/** Completed action ready to be used in a Zcash transaction */
export interface CompletedAction {
  memo: string;
  uri: string;
}

/** Base interface for prepared actions that can be completed with a signature */
export interface PreparedAction {
  /** The signing payload - what needs to be signed */
  readonly payload: string;

  /** Complete the action with a signature.
   *  @param signature - Base64-encoded Ed25519 signature of the payload
   *  @param userPubkey - Optional user pubkey for sovereign names
   *  @returns The completed action with memo and URI for the Zcash transaction
   */
  complete(signature: string, userPubkey?: string): CompletedAction;
}

/** Prepared CLAIM action */
export interface PreparedClaim extends PreparedAction {
  readonly name: string;
  readonly address: string;
  readonly cost: Zats;
}

/** Prepared LIST action */
export interface PreparedList extends PreparedAction {
  readonly name: string;
  readonly price: Zats;
  readonly payTaddr: string;
  readonly nonce: number;
}

/** Prepared DELIST action */
export interface PreparedDelist extends PreparedAction {
  readonly name: string;
  readonly nonce: number;
}

/** Prepared UPDATE action */
export interface PreparedUpdate extends PreparedAction {
  readonly name: string;
  readonly newAddress: string;
  readonly nonce: number;
}

/** Prepared BUY action */
export interface PreparedBuy extends PreparedAction {
  readonly name: string;
  readonly buyerAddress: string;
  readonly price: Zats;
}

/** Prepared RELEASE action */
export interface PreparedRelease extends PreparedAction {
  readonly name: string;
  readonly nonce: number;
}

/** Prepared SETPRICE action (admin only) */
export interface PreparedSetPrice extends PreparedAction {
  readonly prices: readonly Zats[];
  readonly nonce: number;
}

/* ── Validation ─────────────────────────────────────────────────────── */

/** Validation result for a signing payload.
 *  Mirrors the Rust indexer's parse_memo format validation.
 *  @see https://github.com/zcashme/ZNS/blob/main/src/memo.rs */
export type PayloadValidationLevel = "valid" | "invalid" | "unrecognized";

export interface PayloadValidationResult {
  /** Whether the payload is valid for signing. */
  readonly valid: boolean;
  /** Parsed action name (uppercase), e.g. "CLAIM", "LIST" */
  readonly action: string;
  /** Canonical action used internally (lowercase), e.g. "claim", "list" */
  readonly canonicalAction: string | null;
  /** Human-readable validation message */
  readonly message: string;
  /** Validation level: valid | invalid | unrecognized */
  readonly level: PayloadValidationLevel;
}

/* ── Internal converters (snake_case ↔ camelCase) ──────────────────── */

function toPendingBuy(raw: RawPendingBuy): PendingBuy {
  return {
    buyer: raw.buyer_ua,
    price: raw.price,
    claimHeight: raw.claim_height,
    expiresAt: raw.expires_at,
    txid: raw.txid,
  };
}

function toListing(raw: RawListing): Listing {
  return {
    name: raw.name,
    price: raw.price,
    payTaddr: raw.pay_taddr,
    nonce: raw.nonce,
    txid: raw.txid,
    height: raw.height,
    signature: raw.signature,
    pubkey: raw.pubkey,
    pendingBuy: raw.pending_buy ? toPendingBuy(raw.pending_buy) : undefined,
  };
}

export function toRegistration(raw: RawRegistration): Registration {
  return {
    name: raw.name,
    address: raw.address,
    txid: raw.txid,
    height: raw.height,
    nonce: raw.nonce,
    signature: raw.signature,
    lastAction: raw.last_action,
    pubkey: raw.pubkey,
    listing: raw.listing ? toListing(raw.listing) : null,
  };
}

function toPricing(raw: RawPricing): Pricing {
  return {
    nonce: raw.nonce,
    height: raw.height,
    tiers: raw.tiers,
  };
}

export function toStatus(raw: RawStatus): Status {
  return {
    syncedHeight: raw.synced_height,
    adminPubkey: raw.admin_pubkey,
    uivk: raw.uivk,
    address: raw.address,
    registered: raw.registered,
    listed: raw.listed,
    pricing: raw.pricing ? toPricing(raw.pricing) : null,
  };
}

export function toEvent(raw: RawEvent): Event {
  return {
    id: raw.id,
    name: raw.name,
    action: raw.action,
    txid: raw.txid,
    height: raw.height,
    ua: raw.ua,
    price: raw.price,
    nonce: raw.nonce,
    signature: raw.signature,
    pubkey: raw.pubkey,
  };
}

export function toEventsFilter(raw: EventsFilter): RawEventsFilter {
  return {
    name: raw.name,
    action: raw.action,
    since_height: raw.sinceHeight,
    limit: raw.limit,
    offset: raw.offset,
  };
}

export function toEventsResult(raw: RawEventsResult): EventsResult {
  return {
    events: raw.events.map(toEvent),
    total: raw.total,
  };
}

/** @internal Exported for testing and advanced use cases */
export const _converters = {
  toPendingBuy,
  toListing,
  toRegistration,
  toPricing,
  toStatus,
  toEvent,
  toEventsFilter,
};
