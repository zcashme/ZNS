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
export type EventAction = "CLAIM" | "LIST" | "DELIST" | "RELEASE" | "UPDATE" | "BUY" | "SETPRICE";

export interface Listing {
  name: string;
  /** Asking price in zatoshis */
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
  /** Claim costs in zatoshis. tiers[i] is the cost for a name of length i+1 */
  tiers: Zats[];
}

export interface StatusResult {
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
  /** Transaction price in zatoshis, if applicable */
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

export interface PreparedAction {
  payload: string;
  /** Claim cost in zatoshis */
  cost?: Zats;
  uri?: string;
}

export interface CompletedAction {
  memo: string;
  uri: string;
}
