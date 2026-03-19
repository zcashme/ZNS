// ZNS TypeScript SDK

// ── Types ───────────────────────────────────────────────────────────────────

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

export interface StatusResult {
  synced_height: number;
  admin_pubkey: string;
  ufvk: string;
  registered: number;
  listed: number;
}

// ── Errors ──────────────────────────────────────────────────────────────────

export enum ErrorType {
  ParseError = -32700,
  InvalidRequest = -32600,
  MethodNotFound = -32601,
  InvalidParams = -32602,
  InternalError = -32603,
  HttpError = -1,
}

export class ZNSError extends Error {
  type: ErrorType;

  constructor(type: ErrorType, message?: string) {
    super(message ?? ErrorType[type]);
    this.name = "ZNSError";
    this.type = type;
  }
}

// ── Default endpoint ────────────────────────────────────────────────────────

export const DEFAULT_URL = "https://names.zcash.me";

// ── Pricing ─────────────────────────────────────────────────────────────────

const CLAIM_PRICES: Record<number, number> = {
  1: 600_000_000, // 6 ZEC
  2: 425_000_000, // 4.25 ZEC
  3: 300_000_000, // 3 ZEC
  4: 150_000_000, // 1.5 ZEC
  5: 75_000_000, // 0.75 ZEC
  6: 50_000_000, // 0.50 ZEC
};
const DEFAULT_CLAIM_PRICE = 25_000_000; // 0.25 ZEC (7+)

/** Returns the claim cost in zatoshis for a name of the given length. */
export function claimCost(nameLength: number): number {
  return CLAIM_PRICES[nameLength] ?? DEFAULT_CLAIM_PRICE;
}

// ── Validation ──────────────────────────────────────────────────────────────

/** Validate a name locally (1-62 chars, lowercase alphanumeric + hyphens, no leading/trailing/consecutive hyphens). */
export function isValidName(name: string): boolean {
  return /^[a-z0-9](?:[a-z0-9-]{0,60}[a-z0-9])?$/.test(name) && !name.includes("--");
}

// ── Signing payloads ────────────────────────────────────────────────────────
// These return the exact string that must be signed with the admin ed25519 key.
// The caller signs externally and passes the base64 signature to the memo builder.

/** Returns the payload to sign for a LIST action. */
export function listPayload(name: string, price: number, nonce: number): string {
  return `LIST:${name}:${price}:${nonce}`;
}

/** Returns the payload to sign for a DELIST action. */
export function delistPayload(name: string, nonce: number): string {
  return `DELIST:${name}:${nonce}`;
}

/** Returns the payload to sign for an UPDATE action. */
export function updatePayload(name: string, newUa: string, nonce: number): string {
  return `UPDATE:${name}:${newUa}:${nonce}`;
}

// ── Memo builders ───────────────────────────────────────────────────────────

/** Build the memo for claiming a name. */
export function buildClaimMemo(name: string, ua: string): string {
  if (!isValidName(name)) throw new Error(`Invalid name: ${name}`);
  return `ZNS:CLAIM:${name}:${ua}`;
}

/** Build the memo for listing a name for sale (admin-signed). */
export function buildListMemo(
  name: string,
  price: number,
  nonce: number,
  signature: string,
): string {
  if (!isValidName(name)) throw new Error(`Invalid name: ${name}`);
  return `ZNS:LIST:${name}:${price}:${nonce}:${signature}`;
}

/** Build the memo for delisting a name (admin-signed). */
export function buildDelistMemo(name: string, nonce: number, signature: string): string {
  if (!isValidName(name)) throw new Error(`Invalid name: ${name}`);
  return `ZNS:DELIST:${name}:${nonce}:${signature}`;
}

/** Build the memo for updating a name's address (admin-signed). */
export function buildUpdateMemo(
  name: string,
  newUa: string,
  nonce: number,
  signature: string,
): string {
  if (!isValidName(name)) throw new Error(`Invalid name: ${name}`);
  return `ZNS:UPDATE:${name}:${newUa}:${nonce}:${signature}`;
}

/** Build the memo for buying a listed name. */
export function buildBuyMemo(name: string, buyerUa: string): string {
  if (!isValidName(name)) throw new Error(`Invalid name: ${name}`);
  return `ZNS:BUY:${name}:${buyerUa}`;
}

// ── RPC transport ───────────────────────────────────────────────────────────

let nextId = 1;

async function rpc<T>(
  url: string,
  method: string,
  params: Record<string, unknown> = {},
): Promise<T> {
  const id = nextId++;
  const body = JSON.stringify({ jsonrpc: "2.0", id, method, params });

  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
  });

  if (!res.ok) {
    throw new ZNSError(ErrorType.HttpError, `HTTP ${res.status}: ${res.statusText}`);
  }

  const json = (await res.json()) as {
    result?: T;
    error?: { code: number; message: string };
  };

  if (json.error) {
    const type = Object.values(ErrorType).includes(json.error.code as ErrorType)
      ? (json.error.code as ErrorType)
      : ErrorType.InternalError;
    throw new ZNSError(type, json.error.message);
  }

  return json.result as T;
}

// ── Query API ───────────────────────────────────────────────────────────────

/** Look up a ZNS name or Zcash address. Returns null if not found. */
export async function resolve(
  query: string,
  url = DEFAULT_URL,
): Promise<ResolveResult | null> {
  return rpc<ResolveResult | null>(url, "resolve", { query });
}

/** Get all names currently listed for sale. */
export async function listings(url = DEFAULT_URL): Promise<Listing[]> {
  const result = await rpc<{ listings: Listing[] }>(url, "list_for_sale");
  return result.listings;
}

/** Get indexer sync status. */
export async function status(url = DEFAULT_URL): Promise<StatusResult> {
  return rpc<StatusResult>(url, "status");
}

/** Check if a name is available for claiming. */
export async function isAvailable(name: string, url = DEFAULT_URL): Promise<boolean> {
  const result = await resolve(name, url);
  return result === null;
}

/** Get the current nonce for a registered name. Returns null if not registered. */
export async function getNonce(name: string, url = DEFAULT_URL): Promise<number | null> {
  const result = await resolve(name, url);
  return result?.nonce ?? null;
}
