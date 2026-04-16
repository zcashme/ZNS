import * as ed25519 from "@noble/ed25519";
import { bech32m } from "bech32";
import type {
  Zats,
  Registration,
  Listing,
  StatusResult,
  Event,
  EventsFilter,
  EventsResult,
  Pricing,
  PreparedAction,
  CompletedAction,
} from "./types.js";

export type {
  Zats,
  Registration,
  Listing,
  StatusResult,
  Event,
  EventsFilter,
  EventsResult,
  Pricing,
  PreparedAction,
  CompletedAction,
  LastAction,
  EventAction,
} from "./types.js";

export const DEFAULT_URL = "https://light.zcash.me/zns-testnet";

export const TESTNET_UIVK =
  "uivktest1hzw7wyadutvzfgpna80yftsk5l7jeyu2p5me5quvp28tytxueta00cx4068wnlzcv7tx9n3t3gfhsy83pe4y6jrhxtzaq0hj6xtg5zrk2dn7zen3vns2a5pgs4fxdjlletmqrhfa42";

export const MAINNET_UIVK =
  "uivk1gl26qy0xjja7lqhyg3pf0x4j4j66kqwewrjkdcg28eqq4wgtzjmujpee7x9cs2ec9xhnlgrm8ptlw8z80j2aryw8nqtssser2ys778a0s00uvgkdjnfr58sndhfvc3f4zqjs6ywva6";

const KNOWN_UIVKS = [TESTNET_UIVK, MAINNET_UIVK];

const NAME_RE = /^[a-z0-9]{1,62}$/;

export class ZNS {
  private url: string;
  private rpcId = 0;
  private _adminPubkey: string | null = null;
  private _pricing: Pricing | null = null;
  private _registryAddress: string | null = null;
  private _verified = false;

  private constructor(url: string) {
    this.url = url;
  }

  static async create(options?: { url?: string; skipVerify?: boolean }): Promise<ZNS> {
    const url = options?.url ?? DEFAULT_URL;
    const zns = new ZNS(url);

    const status = await zns.rpc<StatusResult>("status");

    if (!options?.skipVerify) {
      if (!KNOWN_UIVKS.includes(status.uivk)) {
        throw new Error(
          `UIVK mismatch: indexer returned "${status.uivk.slice(0, 20)}..." which is not a known ZNS instance`,
        );
      }
      zns._verified = true;
    }

    zns.pinStatus(status);
    return zns;
  }

  private pinStatus(status: StatusResult): void {
    this._adminPubkey = status.admin_pubkey;
    this._pricing = status.pricing;
    this._registryAddress = status.address;
  }

  get verified(): boolean {
    return this._verified;
  }

  get adminPubkey(): string | null {
    return this._adminPubkey;
  }

  get pricing(): Pricing | null {
    return this._pricing;
  }

  get registryAddress(): string | null {
    return this._registryAddress;
  }

  /** Resolve a ZNS name to its registration. Returns null if not registered. */
  async resolveName(name: string): Promise<Registration | null> {
    return this.rpc<Registration | null>("resolve", { query: name });
  }

  /** Resolve a Zcash Unified Address to all names pointing to it. Returns empty array if none. */
  async resolveAddress(address: string): Promise<Registration[]> {
    return this.rpc<Registration[]>("resolve", { query: address });
  }

  /** Check if a name is available for registration. */
  async isAvailable(name: string): Promise<boolean> {
    const result = await this.resolveName(name);
    return result === null;
  }

  /** Validate a Zcash Unified Address format (bech32m encoding with 'u' prefix).
   *  Performs format validation but NOT cryptographic verification of the address.
   *  Returns true if the address is syntactically valid, false otherwise. */
  isValidUnifiedAddress(address: string): boolean {
    try {
      const decoded = bech32m.decode(address);
      return decoded.prefix === "u";
    } catch {
      return false;
    }
  }

  async listings(): Promise<Listing[]> {
    const result = await this.rpc<{ listings: Listing[] }>("list_for_sale");
    return result.listings;
  }

  async status(): Promise<StatusResult> {
    return this.rpc<StatusResult>("status");
  }

  async events(filter?: EventsFilter): Promise<EventsResult> {
    return this.rpc<EventsResult>("events", (filter ?? {}) as Record<string, unknown>);
  }

  /** Verify a listing's signature. Returns true if the signature is valid. */
  async verifyListing(listing: Listing): Promise<boolean> {
    const pubkey = listing.pubkey ?? this._adminPubkey;
    if (!pubkey) return false;
    const payload = `LIST:${listing.name}:${listing.price}:${listing.nonce}`;
    return this.verifyEd25519(payload, listing.signature, pubkey);
  }

  /** Verify a registration's signature. Returns true if the signature is valid. */
  async verifyRegistration(reg: Registration): Promise<boolean> {
    if (!reg.signature) return false;
    const pubkey = reg.pubkey ?? this._adminPubkey;
    if (!pubkey) return false;
    const payload = this.registrationPayload(reg);
    if (!payload) return false;
    return this.verifyEd25519(payload, reg.signature, pubkey);
  }

  /** Check if a name is valid format (lowercase alphanumeric, 1-62 chars). */
  isValidName(name: string): boolean {
    return NAME_RE.test(name);
  }

  /** Get the claim cost in zatoshis for a name of given length. Returns null if pricing unavailable. */
  claimCost(nameLength: number): Zats | null {
    if (!this._pricing || this._pricing.tiers.length === 0) return null;
    const idx = Math.min(Math.max(nameLength - 1, 0), this._pricing.tiers.length - 1);
    return this._pricing.tiers[idx];
  }

  /** Parse a ZIP-321 URI into its components. */
  parseZip321Uri(uri: string): { address: string; amount: string; memoRaw: string; memoDecoded: string } {
    const withoutScheme = String(uri ?? "").replace(/^zcash:/i, "");
    const [addressPart, queryPart = ""] = withoutScheme.split("?");
    const address = addressPart.trim();
    const params = new URLSearchParams(queryPart);
    const amount = String(params.get("amount") ?? "").trim();
    const memoRaw = String(params.get("memo") ?? "").trim();
    const memoDecoded = memoRaw ? this.decodeBase64Url(memoRaw) : "";
    return { address, amount, memoRaw, memoDecoded };
  }

  // ── Action Helpers ─────────────────────────────────────────────────────────

  prepareClaim(name: string, address: string): PreparedAction {
    this.requireValidName(name);
    const payload = `CLAIM:${name}:${address}`;
    const cost = this.claimCost(name.length);
    const uri = cost != null && this._registryAddress
      ? this.buildZcashUri(this._registryAddress, cost / 1e8)
      : undefined;
    return { payload, cost: cost ?? undefined, uri };
  }

  completeClaim(name: string, address: string, signature: string, userPubkey?: string): CompletedAction {
    this.requireValidName(name);
    const memo = userPubkey
      ? `ZNS:CLAIM:${name}:${address}:${signature}:${userPubkey}`
      : `ZNS:CLAIM:${name}:${address}:${signature}`;
    const cost = this.claimCost(name.length);
    const uri = this.buildZcashUri(this._registryAddress ?? "", cost != null ? cost / 1e8 : undefined, memo);
    return { memo, uri };
  }

  prepareList(name: string, price: Zats, nonce: number): PreparedAction {
    this.requireValidName(name);
    return { payload: `LIST:${name}:${price}:${nonce}` };
  }

  completeList(name: string, price: Zats, nonce: number, signature: string, userPubkey?: string): CompletedAction {
    this.requireValidName(name);
    const memo = userPubkey
      ? `ZNS:LIST:${name}:${price}:${nonce}:${signature}:${userPubkey}`
      : `ZNS:LIST:${name}:${price}:${nonce}:${signature}`;
    return { memo, uri: this.memoUri(memo) };
  }

  prepareDelist(name: string, nonce: number): PreparedAction {
    this.requireValidName(name);
    return { payload: `DELIST:${name}:${nonce}` };
  }

  completeDelist(name: string, nonce: number, signature: string, userPubkey?: string): CompletedAction {
    this.requireValidName(name);
    const memo = userPubkey
      ? `ZNS:DELIST:${name}:${nonce}:${signature}:${userPubkey}`
      : `ZNS:DELIST:${name}:${nonce}:${signature}`;
    return { memo, uri: this.memoUri(memo) };
  }

  prepareUpdate(name: string, newAddress: string, nonce: number): PreparedAction {
    this.requireValidName(name);
    return { payload: `UPDATE:${name}:${newAddress}:${nonce}` };
  }

  completeUpdate(name: string, newAddress: string, nonce: number, signature: string, userPubkey?: string): CompletedAction {
    this.requireValidName(name);
    const memo = userPubkey
      ? `ZNS:UPDATE:${name}:${newAddress}:${nonce}:${signature}:${userPubkey}`
      : `ZNS:UPDATE:${name}:${newAddress}:${nonce}:${signature}`;
    return { memo, uri: this.memoUri(memo) };
  }

  prepareBuy(name: string, buyerAddress: string): PreparedAction {
    this.requireValidName(name);
    return { payload: `BUY:${name}:${buyerAddress}` };
  }

  completeBuy(name: string, buyerAddress: string, signature: string, userPubkey?: string): CompletedAction {
    this.requireValidName(name);
    const memo = userPubkey
      ? `ZNS:BUY:${name}:${buyerAddress}:${signature}:${userPubkey}`
      : `ZNS:BUY:${name}:${buyerAddress}:${signature}`;
    return { memo, uri: this.memoUri(memo) };
  }

  prepareRelease(name: string, nonce: number): PreparedAction {
    this.requireValidName(name);
    return { payload: `RELEASE:${name}:${nonce}` };
  }

  completeRelease(name: string, nonce: number, signature: string, userPubkey?: string): CompletedAction {
    this.requireValidName(name);
    const memo = userPubkey
      ? `ZNS:RELEASE:${name}:${nonce}:${signature}:${userPubkey}`
      : `ZNS:RELEASE:${name}:${nonce}:${signature}`;
    return { memo, uri: this.memoUri(memo) };
  }

  prepareSetPrice(prices: Zats[], nonce: number): PreparedAction {
    return { payload: `SETPRICE:${prices.length}:${prices.join(":")}:${nonce}` };
  }

  completeSetPrice(prices: Zats[], nonce: number, signature: string): CompletedAction {
    const memo = `ZNS:SETPRICE:${prices.length}:${prices.join(":")}:${nonce}:${signature}`;
    return { memo, uri: this.memoUri(memo) };
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  private registrationPayload(reg: Registration): string {
    switch (reg.last_action) {
      case "CLAIM": return `CLAIM:${reg.name}:${reg.address}`;
      case "BUY": return `BUY:${reg.name}:${reg.address}`;
      case "UPDATE": return `UPDATE:${reg.name}:${reg.address}:${reg.nonce}`;
      case "DELIST": return `DELIST:${reg.name}:${reg.nonce}`;
      case "RELEASE": return `RELEASE:${reg.name}:${reg.nonce}`;
      default: return "";
    }
  }

  private async verifyEd25519(payload: string, signatureB64: string, pubkeyB64: string): Promise<boolean> {
    const sigBytes = this.decodeBase64(signatureB64);
    const pkBytes = this.decodeBase64(pubkeyB64);
    if (sigBytes.length !== 64 || pkBytes.length !== 32) return false;
    try {
      const message = new TextEncoder().encode(payload);
      return await ed25519.verifyAsync(sigBytes, message, pkBytes);
    } catch {
      return false;
    }
  }

  private requireValidName(name: string): void {
    if (!NAME_RE.test(name)) throw new Error(`Invalid ZNS name: ${name}`);
  }

  private memoUri(memo: string): string {
    return this._registryAddress
      ? this.buildZcashUri(this._registryAddress, undefined, memo)
      : `zcash:?memo=${this.toBase64Url(memo)}`;
  }

  private buildZcashUri(address: string, amount?: number, memo?: string): string {
    if (!address) return "";
    const base = `zcash:${address}`;
    const params: string[] = [];
    if (amount !== undefined && amount > 0) params.push(`amount=${amount}`);
    if (memo) params.push(`memo=${this.toBase64Url(memo)}`);
    return params.length ? `${base}?${params.join("&")}` : base;
  }

  private toBase64Url(text: string): string {
    try {
      return btoa(unescape(encodeURIComponent(text)))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
    } catch {
      return "";
    }
  }

  private decodeBase64Url(value: string): string {
    try {
      const normalized = String(value).replace(/-/g, "+").replace(/_/g, "/");
      const padLen = normalized.length % 4 === 0 ? 0 : 4 - (normalized.length % 4);
      const padded = normalized + "=".repeat(padLen);
      const binary = atob(padded);
      const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
      return new TextDecoder().decode(bytes);
    } catch {
      return "";
    }
  }

  private decodeBase64(s: string): Uint8Array {
    const bin = atob(s);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  private async rpc<T>(method: string, params: Record<string, unknown> = {}): Promise<T> {
    const id = ++this.rpcId;
    const body = JSON.stringify({ jsonrpc: "2.0", id, method, params });

    const res = await fetch(this.url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    });

    if (!res.ok) {
      throw new Error(`ZNS HTTP ${res.status}: ${res.statusText}`);
    }

    const json = (await res.json()) as {
      result?: T;
      error?: { code: number; message: string };
    };

    if (json.error) {
      throw new Error(`ZNS RPC error ${json.error.code}: ${json.error.message}`);
    }

    return json.result as T;
  }
}
