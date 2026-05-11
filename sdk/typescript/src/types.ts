/**
 * ZNS TypeScript SDK types.
 *
 * API responses are converted from snake_case (Rust convention) to camelCase
 * (TypeScript convention) using the snakeToCamel utility. Types below are the
 * user-facing shape — Raw* types and manual converters have been removed.
 */

export type Zats = number;

/** Target network for ZNS operations. */
export type Network = "testnet" | "mainnet";

/* ── Actions ─────────────────────────────────────────────────────────── */

/** All user-signable ZNS actions. Single source of truth — ZnsAction is derived from this. */
export const ZNS_ACTIONS = ["CLAIM", "BUY", "UPDATE", "LIST", "DELIST", "RELEASE"] as const;

/** Union of all user-signable action names. Derived from ZNS_ACTIONS. */
export type ZnsAction = (typeof ZNS_ACTIONS)[number];

/** Ownership-changing actions — can appear as Registration.lastAction. */
export type LastAction = Exclude<ZnsAction, "LIST">;

/** All actions that appear in the event log — user actions plus admin SETPRICE. */
export type EventAction = ZnsAction | "SETPRICE";

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
  /** Human-readable validation message */
  readonly message: string;
  /** Validation level: valid | invalid | unrecognized */
  readonly level: PayloadValidationLevel;
}
