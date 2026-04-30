import * as ed25519 from "@noble/ed25519";
import { bech32m } from "bech32";
import type {
  Zats,
  Registration,
  Listing,
  Status,
  Event,
  EventsFilter,
  EventsResult,
  Pricing,
  CompletedAction,
  PreparedClaim,
  PreparedList,
  PreparedDelist,
  PreparedUpdate,
  PreparedBuy,
  PreparedRelease,
} from "./types.js";

export type {
  Zats,
  Registration,
  Listing,
  Status,
  Event,
  EventsFilter,
  EventsResult,
  Pricing,
  CompletedAction,
  PreparedClaim,
  PreparedList,
  PreparedDelist,
  PreparedUpdate,
  PreparedBuy,
  PreparedRelease,
  LastAction,
  EventAction,
} from "./types.js";

export const DEFAULT_URL = "https://light.zcash.me/zns-testnet";

export const TESTNET_UIVK =
  "uivktest1hzw7wyadutvzfgpna80yftsk5l7jeyu2p5me5quvp28tytxueta00cx4068wnlzcv7tx9n3t3gfhsy83pe4y6jrhxtzaq0hj6xtg5zrk2dn7zen3vns2a5pgs4fxdjlletmqrhfa42";

export const MAINNET_UIVK =
  "uivk1gl26qy0xjja7lqhyg3pf0x4j4j66kqwewrjkdcg28eqq4wgtzjmujpee7x9cs2ec9xhnlgrm8ptlw8z80j2aryw8nqtssser2ys778a0s00uvgkdjnfr58sndhfvc3f4zqjs6ywva6";

const KNOWN_UIVKS = [TESTNET_UIVK, MAINNET_UIVK];

// Registry addresses where ZNS memos are sent
const REGISTRY_ADDRESSES: Record<string, string> = {
  testnet: "utest1f32kn6c4zvn54xr8wfsnxmj9hzpu2mwgtxzpzwcw34906tdccdvzs0z2dx38lly7tpan77x6udt8pjczqm22ymsdhlz9j0tk5yq664nl",
  mainnet: "u1k0evt0ahj5qdt6y9ftsxndl8lrkm4ff6rp00u04cjpmqj6hxl9t8hfsxftmn3ht34e03lljh89czn2h8qn67rwrs8x0hm3lsxsucp9q9",
};

const NAME_RE = /^[a-z0-9]{1,62}$/;

export type Network = "testnet" | "mainnet";

export class ZNS {
  private url: string;
  private network: Network;
  private rpcId = 0;
  private _verified = false;

  /**
   * Creates a new ZNS client.
   * @param options - Configuration options
   * @param options.network - Network to connect to ("testnet" | "mainnet"), defaults to "testnet"
   * @param options.url - Custom indexer URL (optional)
   */
  constructor(options?: { network?: Network; url?: string }) {
    this.network = options?.network ?? "testnet";
    this.url = options?.url ?? DEFAULT_URL;
  }

  /**
   * Verifies that the connected server is a known ZNS instance.
   * @throws Error if the server's UIVK is not recognized
   */
  async verify(): Promise<void> {
    const status = await this.rpc<Status>("status");
    if (!KNOWN_UIVKS.includes(status.uivk)) {
      throw new Error(
        `UIVK mismatch: indexer returned "${status.uivk.slice(0, 20)}..." which is not a known ZNS instance`,
      );
    }
    this._verified = true;
  }

  /** Returns true if {@link verify} has been called and passed. */
  get verified(): boolean {
    return this._verified;
  }

  /** Get the registry address for the current network. */
  get registryAddress(): string {
    const addr = REGISTRY_ADDRESSES[this.network];
    if (!addr) {
      throw new Error(`Unknown network: ${this.network}`);
    }
    return addr;
  }

  /** Fetch current server status including pricing and configuration. */
  async status(): Promise<Status> {
    return this.rpc<Status>("status");
  }

  /** Resolve a ZNS name to its registration. Returns null if not registered. */
  async resolveName(name: string): Promise<Registration | null> {
    return this.rpc<Registration | null>("resolve", { query: name });
  }

  /** Resolve a Zcash Unified Address to all names pointing to it. Returns empty array if none.
   *  Supports pagination with limit (default 50, max 500) and offset (default 0). */
  async resolveAddress(address: string, limit?: number, offset?: number): Promise<Registration[]> {
    return this.rpc<Registration[]>("resolve", {
      query: address,
      limit,
      offset,
    });
  }

  /** List all registered names. Useful for explorers or browsers.
   *  Supports pagination with limit (default 50, max 500) and offset (default 0). */
  async listAllRegistrations(limit?: number, offset?: number): Promise<Registration[]> {
    return this.rpc<Registration[]>("resolve", {
      query: "",
      limit,
      offset,
    });
  }

  /** Check if a name is available for registration.
   *  Returns false immediately for invalid names without hitting the server. */
  async isAvailable(name: string): Promise<boolean> {
    if (!this.isValidName(name)) return false;
    const result = await this.resolveName(name);
    return result === null;
  }

  /** Validate a Zcash Unified Address format.
   *  Accepts both mainnet ('u') and testnet ('utest') prefixes.
   *  Performs basic format validation but NOT full bech32m checksum verification.
   *  Returns true if the address looks like a unified address, false otherwise. */
  isValidUnifiedAddress(address: string): boolean {
    // Unified addresses start with 'u' (mainnet) or 'utest' (testnet)
    // followed by '1' separator and alphanumeric characters
    if (!address) return false;
    if (address.startsWith("utest1")) return true;
    if (address.startsWith("u1")) return true;
    // Fall back to strict bech32m validation
    try {
      const decoded = bech32m.decode(address);
      return decoded.prefix === "u" || decoded.prefix === "utest";
    } catch {
      return false;
    }
  }

  async listings(limit?: number, offset?: number): Promise<{ listings: Listing[]; total: number }> {
    const result = await this.rpc<{ listings: Listing[]; total: number }>("listings", {
      limit,
      offset,
    });
    return result;
  }

  async events(filter?: EventsFilter): Promise<EventsResult> {
    return this.rpc<EventsResult>(
      "events",
      (filter ?? {}) as Record<string, unknown>,
    );
  }

  /**
   * Verify a listing's signature.
   * @param listing The listing to verify
   * @param adminPubkey The admin Ed25519 public key (base64) - obtain from {@link status}
   * @returns true if the signature is valid
   */
  async verifyListing(listing: Listing, adminPubkey: string): Promise<boolean> {
    const pubkey = listing.pubkey ?? adminPubkey;
    const payload = `LIST:${listing.name}:${listing.price}:${listing.nonce}`;
    return this.verifyEd25519(payload, listing.signature, pubkey);
  }

  /**
   * Verify a registration's signature.
   * @param reg The registration to verify
   * @param adminPubkey The admin Ed25519 public key (base64) - obtain from {@link status}
   * @returns true if the signature is valid
   */
  async verifyRegistration(
    reg: Registration,
    adminPubkey: string,
  ): Promise<boolean> {
    if (!reg.signature) return false;
    const pubkey = reg.pubkey ?? adminPubkey;
    const payload = this.registrationPayload(reg);
    if (!payload) return false;
    return this.verifyEd25519(payload, reg.signature, pubkey);
  }

  /** Check if a name is valid format (lowercase alphanumeric, 1-62 chars). */
  isValidName(name: string): boolean {
    return NAME_RE.test(name);
  }

  /**
   * Get the claim cost in zatoshis for a name of given length.
   * @param nameLength The length of the name (1-62)
   * @param pricing The pricing configuration - obtain from {@link status}
   * @returns The cost in zatoshis, or null if pricing is unavailable
   */
  claimCost(nameLength: number, pricing: Pricing): Zats | null {
    if (pricing.tiers.length === 0) return null;
    const idx = Math.min(Math.max(nameLength - 1, 0), pricing.tiers.length - 1);
    return pricing.tiers[idx];
  }

  /** Parse a ZIP-321 URI into its components. */
  parseZip321Uri(uri: string): {
    address: string;
    amount: string;
    memoRaw: string;
    memoDecoded: string;
  } {
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

  /**
   * Prepare a name claim transaction.
   * @param name The name to claim (1-62 lowercase alphanumeric chars)
   * @param address Your Zcash Unified Address
   * @param cost The claim cost in zatoshis - obtain from {@link claimCost}
   * @returns Prepared claim ready for signature completion
   */
  prepareClaim(
    name: string,
    address: string,
    cost: Zats,
  ): PreparedClaim {
    this.requireValidName(name);
    if (!this.isValidUnifiedAddress(address)) {
      throw new Error(`Invalid Zcash Unified Address: ${address}`);
    }

    return {
      name,
      address,
      cost,
      payload: `CLAIM:${name}:${address}`,
      complete: (signature: string, userPubkey?: string): CompletedAction => {
        const memo = userPubkey
          ? `ZNS:CLAIM:${name}:${address}:${signature}:${userPubkey}`
          : `ZNS:CLAIM:${name}:${address}:${signature}`;
        const uri = this.buildZcashUri(this.registryAddress, cost, memo);
        return { memo, uri };
      },
    };
  }

  prepareList(
    name: string,
    price: Zats,
    nonce: number,
  ): PreparedList {
    this.requireValidName(name);

    return {
      name,
      price,
      nonce,
      payload: `LIST:${name}:${price}:${nonce}`,
      complete: (signature: string, userPubkey?: string): CompletedAction => {
        const memo = userPubkey
          ? `ZNS:LIST:${name}:${price}:${nonce}:${signature}:${userPubkey}`
          : `ZNS:LIST:${name}:${price}:${nonce}:${signature}`;
        return { memo, uri: this.buildZcashUri(this.registryAddress, undefined, memo) };
      },
    };
  }

  prepareDelist(
    name: string,
    nonce: number,
  ): PreparedDelist {
    this.requireValidName(name);

    return {
      name,
      nonce,
      payload: `DELIST:${name}:${nonce}`,
      complete: (signature: string, userPubkey?: string): CompletedAction => {
        const memo = userPubkey
          ? `ZNS:DELIST:${name}:${nonce}:${signature}:${userPubkey}`
          : `ZNS:DELIST:${name}:${nonce}:${signature}`;
        return { memo, uri: this.buildZcashUri(this.registryAddress, undefined, memo) };
      },
    };
  }

  prepareUpdate(
    name: string,
    newAddress: string,
    nonce: number,
  ): PreparedUpdate {
    this.requireValidName(name);
    if (!this.isValidUnifiedAddress(newAddress)) {
      throw new Error(`Invalid Zcash Unified Address: ${newAddress}`);
    }

    return {
      name,
      newAddress,
      nonce,
      payload: `UPDATE:${name}:${newAddress}:${nonce}`,
      complete: (signature: string, userPubkey?: string): CompletedAction => {
        const memo = userPubkey
          ? `ZNS:UPDATE:${name}:${newAddress}:${nonce}:${signature}:${userPubkey}`
          : `ZNS:UPDATE:${name}:${newAddress}:${nonce}:${signature}`;
        return { memo, uri: this.buildZcashUri(this.registryAddress, undefined, memo) };
      },
    };
  }

  prepareBuy(
    name: string,
    buyerAddress: string,
  ): PreparedBuy {
    this.requireValidName(name);
    if (!this.isValidUnifiedAddress(buyerAddress)) {
      throw new Error(`Invalid Zcash Unified Address: ${buyerAddress}`);
    }

    return {
      name,
      buyerAddress,
      payload: `BUY:${name}:${buyerAddress}`,
      complete: (signature: string, userPubkey?: string): CompletedAction => {
        const memo = userPubkey
          ? `ZNS:BUY:${name}:${buyerAddress}:${signature}:${userPubkey}`
          : `ZNS:BUY:${name}:${buyerAddress}:${signature}`;
        return { memo, uri: this.buildZcashUri(this.registryAddress, undefined, memo) };
      },
    };
  }

  prepareRelease(
    name: string,
    nonce: number,
  ): PreparedRelease {
    this.requireValidName(name);

    return {
      name,
      nonce,
      payload: `RELEASE:${name}:${nonce}`,
      complete: (signature: string, userPubkey?: string): CompletedAction => {
        const memo = userPubkey
          ? `ZNS:RELEASE:${name}:${nonce}:${signature}:${userPubkey}`
          : `ZNS:RELEASE:${name}:${nonce}:${signature}`;
        return { memo, uri: this.buildZcashUri(this.registryAddress, undefined, memo) };
      },
    };
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  private registrationPayload(reg: Registration): string {
    switch (reg.last_action) {
      case "CLAIM":
        return `CLAIM:${reg.name}:${reg.address}`;
      case "BUY":
        return `BUY:${reg.name}:${reg.address}`;
      case "UPDATE":
        return `UPDATE:${reg.name}:${reg.address}:${reg.nonce}`;
      case "DELIST":
        return `DELIST:${reg.name}:${reg.nonce}`;
      case "RELEASE":
        return `RELEASE:${reg.name}:${reg.nonce}`;
      default:
        return "";
    }
  }

  private async verifyEd25519(
    payload: string,
    signatureB64: string,
    pubkeyB64: string,
  ): Promise<boolean> {
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

  /** Build a ZIP-321 URI. Amount is in zatoshis and will be converted to ZEC for the URI. */
  buildZcashUri(
    address: string,
    amountZats?: Zats,
    memo?: string,
  ): string {
    if (!address) return "";
    const base = `zcash:${address}`;
    const params: string[] = [];
    if (amountZats !== undefined && amountZats > 0) {
      const amountZec = amountZats / 1e8;
      params.push(`amount=${amountZec}`);
    }
    if (memo) params.push(`memo=${this.toBase64Url(memo)}`);
    return params.length ? `${base}?${params.join("&")}` : base;
  }

  private toBase64Url(text: string): string {
    try {
      const bytes = new TextEncoder().encode(text);
      const bin = String.fromCharCode(...bytes);
      return btoa(bin)
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
      const padLen =
        normalized.length % 4 === 0 ? 0 : 4 - (normalized.length % 4);
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

  private async rpc<T>(
    method: string,
    params: Record<string, unknown> = {},
  ): Promise<T> {
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
      throw new Error(
        `ZNS RPC error ${json.error.code}: ${json.error.message}`,
      );
    }

    return json.result as T;
  }
}
