/** Amount in zatoshis (1 ZEC = 100,000,000 zats).
 *  All monetary values in ZNS are denominated in zats.
 *  Note: JavaScript number precision degrades above 2^53 (~9e15 zats, or ~90M ZEC) */
export type Zats = number;

export interface Registration {
  name: string;
  address: string;
  txid: string;
  height: number;
  nonce: number;
  signature: string | null;
  last_action: LastAction;
  pubkey: string | null;
  listing: Listing | null;
}

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

export interface Listing {
  name: string;
  price: Zats;
  nonce: number;
  txid: string;
  height: number;
  signature: string;
  pubkey: string | null;
}

export interface Pricing {
  nonce: number;
  height: number;
  tiers: Zats[];
}

export interface Status {
  synced_height: number;
  admin_pubkey: string;
  uivk: string;
  address: string;
  registered: number;
  listed: number;
  pricing: Pricing | null;
}

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

export interface EventsFilter {
  name?: string;
  action?: EventAction;
  since_height?: number;
  limit?: number;
  offset?: number;
}

export interface EventsResult {
  events: Event[];
  total: number;
}

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
