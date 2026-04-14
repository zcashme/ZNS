export interface Registration {
  name: string;
  address: string;
  txid: string;
  height: number;
  nonce: number;
  signature: string | null;
  last_action: LastAction;
  pubkey: string | null;
}

export type LastAction = "CLAIM" | "BUY" | "UPDATE" | "DELIST" | "RELEASE";

export interface Listing {
  name: string;
  price: number;
  nonce: number;
  txid: string;
  height: number;
  signature: string;
}

export interface ResolveResult extends Registration {
  listing: Listing | null;
  verified: boolean;
  sovereign: boolean;
}

export interface VerifiedListing extends Listing {
  verified: boolean;
}

export interface Pricing {
  nonce: number;
  height: number;
  tiers: number[];
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
  action: Action;
  txid: string;
  height: number;
  ua: string | null;
  price: number | null;
  nonce: number | null;
  signature: string | null;
  pubkey: string | null;
  verified?: boolean;
}

export type Action = "CLAIM" | "LIST" | "DELIST" | "RELEASE" | "UPDATE" | "BUY" | "SETPRICE";

export interface EventsFilter {
  name?: string;
  action?: string;
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
  cost?: number;
  uri?: string;
}

export interface CompletedAction {
  memo: string;
  uri: string;
}