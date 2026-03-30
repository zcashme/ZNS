export interface Registration {
  name: string;
  address: string;
  txid: string;
  height: number;
  nonce: number;
  signature: string | null;
}

export interface Listing {
  name: string;
  price: number;
  txid: string;
  height: number;
  signature: string;
}

export interface ResolveResult extends Registration {
  listing: Listing | null;
}

export interface ListForSaleResult {
  listings: Listing[];
}

export interface Pricing {
  nonce: number;
  height: number;
  /** Per-character claim prices in zats.
   *  Index 0 = 1-char names, index 1 = 2-char, etc.
   *  Names longer than the array clamp to the last entry. */
  tiers: number[];
}

export interface StatusResult {
  synced_height: number;
  admin_pubkey: string;
  uivk: string;
  registered: number;
  listed: number;
  pricing: Pricing | null;
}

export interface Event {
  id: number;
  name: string;
  action: "CLAIM" | "LIST" | "DELIST" | "UPDATE" | "BUY";
  txid: string;
  height: number;
  ua: string | null;
  price: number | null;
  nonce: number | null;
  signature: string | null;
}

export interface EventsFilter {
  name?: string;
  action?: string | string[];
  since_height?: number;
  limit?: number;
  offset?: number;
}

export interface EventsResult {
  events: Event[];
  total: number;
}
