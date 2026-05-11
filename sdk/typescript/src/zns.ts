import * as ed25519 from "@noble/ed25519";
import { bech32m } from "bech32";
import { ZNS_ACTIONS } from "./types.js";
import type {
  Zats,
  ZnsAction,
  Network,
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
  PreparedSetPrice,
  PendingBuy,
  PayloadValidationResult,
} from "./types.js";

/** Commission sent with a BUY claim memo (0.0001 ZEC = 10,000 zats). */
export const BUY_COMMISSION: Zats = 10_000;

/** Listing commission sent with a LIST memo (0.01 ZEC = 1,000,000 zats).
 *  Mirrors the indexer's formula: min_tier × 1000. */
export const LIST_COMMISSION: Zats = 1_000_000;

/** Network-specific configuration for ZNS. */
export const NETWORKS = {
  testnet: {
    url: "https://light.zcash.me/zns-testnet",
    registryAddress:
      "utest1f32kn6c4zvn54xr8wfsnxmj9hzpu2mwgtxzpzwcw34906tdccdvzs0z2dx38lly7tpan77x6udt8pjczqm22ymsdhlz9j0tk5yq664nl",
    uivk: "utest1hzw7wyadutvzfgpna80yftsk5l7jeyu2p5me5quvp28tytxueta00cx4068wnlzcv7tx9n3t3gfhsy83pe4y6jrhxtzaq0hj6xtg5zrk2dn7zen3vns2a5pgs4fxdjlletmqrhfa42",
  },
  mainnet: {
    url: "https://light.zcash.me/zns-mainnet",
    registryAddress:
      "u1k0evt0ahj5qdt6y9ftsxndl8lrkm4ff6rp00u04cjpmqj6hxl9t8hfsxftmn3ht34e03lljh89czn2h8qn67rwrs8x0hm3lsxsucp9q9",
    uivk: "u1k0evt0ahj5qdt6y9ftsxndl8lrkm4ff6rp00u04cjpmqj6hxl9t8hfsxftmn3ht34e03lljh89czn2h8qn67rwrs8x0hm3lsxsucp9q9",
  },
} as const;

/** Valid ZNS name pattern: 1-62 lowercase alphanumeric chars. */
const NAME_RE = /^[a-z0-9]{1,62}$/;

/** Validates a ZNS name format (lowercase alphanumeric, 1-62 chars). */
function isValidName(name: string): boolean {
  return NAME_RE.test(name);
}

/**
 * Normalizes indexer API responses from snake_case (Rust) to camelCase (TypeScript).
 */
function normalizeApiResponse<T>(obj: unknown): T {
  if (Array.isArray(obj))
    return obj.map((item) => normalizeApiResponse(item)) as T;
  if (obj && typeof obj === "object") {
    return Object.fromEntries(
      Object.entries(obj).map(([k, v]) => [
        k.replace(/_([a-z])/g, (_, c) => c.toUpperCase()),
        normalizeApiResponse(v),
      ]),
    ) as T;
  }
  return obj as T;
}

function isWholeNumber(value: string): boolean {
  return (/^\d+$/.test(value) && !value.startsWith("0")) || value === "0";
}

/** Validates a Zcash unified (u-) address. */
function isValidUnifiedAddress(address: string): boolean {
  if (!address) return false;
  if (address.startsWith("utest1")) return true;
  if (address.startsWith("u1")) return true;
  try {
    const decoded = bech32m.decode(address);
    return decoded.prefix === "u" || decoded.prefix === "utest";
  } catch {
    return false;
  }
}

/** Validates a Zcash transparent (t-) address. */
function isValidTransparentAddress(address: string): boolean {
  if (!address) return false;
  const validPrefixes = ["t1", "t3", "tm", "tn"];
  if (!validPrefixes.some((p) => address.startsWith(p))) return false;
  if (address.length < 26 || address.length > 36) return false;
  const base58Regex =
    /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/;
  return base58Regex.test(address);
}

type PayloadCheck = "name" | "ua" | "price" | "nonce" | "pay_taddr";

const PAYLOAD_RULES = {
  CLAIM: { format: "CLAIM:<name>:<ua>", checks: ["name", "ua"] },
  BUY: { format: "BUY:<name>:<ua>", checks: ["name", "ua"] },
  UPDATE: {
    format: "UPDATE:<name>:<ua>:<nonce>",
    checks: ["name", "ua", "nonce"],
  },
  LIST: {
    format: "LIST:<name>:<price>:<pay_taddr>:<nonce>",
    checks: ["name", "price", "pay_taddr", "nonce"],
  },
  DELIST: { format: "DELIST:<name>:<nonce>", checks: ["name", "nonce"] },
  RELEASE: { format: "RELEASE:<name>:<nonce>", checks: ["name", "nonce"] },
} as const satisfies Record<
  ZnsAction,
  { format: string; checks: readonly PayloadCheck[] }
>;

function validateField(value: string, type: PayloadCheck): string | null {
  switch (type) {
    case "name":
      return NAME_RE.test(value)
        ? null
        : "Invalid name. Use lowercase a-z and 0-9, 1 to 62 chars.";
    case "ua":
      return isValidUnifiedAddress(value)
        ? null
        : `Invalid unified address: "${value}".`;
    case "price":
      return isWholeNumber(value) && Number(value) > 0
        ? null
        : "Price must be a positive whole number in zats.";
    case "nonce":
      return isWholeNumber(value) ? null : "Nonce must be a whole number.";
    case "pay_taddr":
      return isValidTransparentAddress(value)
        ? null
        : `Invalid transparent address: "${value}".`;
  }
}

type ValidationLevel = "valid" | "invalid" | "unrecognized";

/** Builds a PayloadValidationResult from validatePayload(). */
function buildValidationResult(
  level: ValidationLevel,
  action: string,
  message: string,
): PayloadValidationResult {
  return { valid: level === "valid", action, message, level };
}

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
    this.url = options?.url ?? NETWORKS[this.network].url;
  }

  /**
   * Verifies that the connected server is a known ZNS instance.
   * @throws Error if the server's UIVK is not recognized
   */
  async verify(): Promise<void> {
    const status = await this.status();
    if (status.uivk !== NETWORKS[this.network].uivk) {
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
    return NETWORKS[this.network].registryAddress;
  }

  /** Fetch current server status including pricing and configuration. */
  async status(): Promise<Status> {
    const raw = await this.rpc<Record<string, unknown>>("status");
    return normalizeApiResponse<Status>(raw);
  }

  /** Resolve a ZNS name to its registration. Returns null if not registered. */
  async resolveName(name: string): Promise<Registration | null> {
    const raw = await this.rpc<Record<string, unknown> | null>("resolve", {
      query: name,
    });
    return raw ? normalizeApiResponse<Registration>(raw) : null;
  }

  /** Resolve a Zcash Unified Address to all names pointing to it. Returns empty array if none.
   *  Supports pagination with limit (default 50, max 500) and offset (default 0). */
  async resolveAddress(
    address: string,
    limit?: number,
    offset?: number,
  ): Promise<Registration[]> {
    const raw = await this.rpc<Record<string, unknown>[]>("resolve", {
      query: address,
      limit,
      offset,
    });
    return raw.map((r) => normalizeApiResponse<Registration>(r));
  }

  /** List all registered names. Useful for explorers or browsers.
   *  Supports pagination with limit (default 50, max 500) and offset (default 0). */
  async listAllRegistrations(
    limit?: number,
    offset?: number,
  ): Promise<Registration[]> {
    const raw = await this.rpc<Record<string, unknown>[]>("resolve", {
      query: "",
      limit,
      offset,
    });
    return raw.map((r) => normalizeApiResponse<Registration>(r));
  }

  /** Check if a name is available for registration.
   *  Returns false immediately for invalid names without hitting the server. */
  async isAvailable(name: string): Promise<boolean> {
    if (!isValidName(name)) return false;
    const result = await this.resolveName(name);
    return result === null;
  }

  /** Validate a Zcash Unified Address format.
   *  Accepts both mainnet ('u') and testnet ('utest') prefixes.
   *  Performs basic format validation but NOT full bech32m checksum verification.
   *  Returns true if the address looks like a unified address, false otherwise.
   *
   *  @todo(F4Jumble) Upgrade to full ZIP-316 decoding with F4Jumble to:
   *    - Parse actual typecodes from address items
   *    - Validate F4Jumble checksum (not just bech32m)
   *    - Optionally enforce: address must contain at least one Orchard receiver (typecode 0x03)
   *    Requires @noble/hashes (blake2b) implementation of F4Jumble inverse. */
  isValidName = isValidName;
  isValidUnifiedAddress = isValidUnifiedAddress;
  isValidTransparentAddress = isValidTransparentAddress;

  async listings(
    limit?: number,
    offset?: number,
  ): Promise<{ listings: Listing[]; total: number }> {
    const raw = await this.rpc<{
      listings: Record<string, unknown>[];
      total: number;
    }>("listings", {
      limit,
      offset,
    });
    return {
      listings: raw.listings.map((l) => normalizeApiResponse<Listing>(l)),
      total: raw.total,
    };
  }

  async events(filter?: EventsFilter): Promise<EventsResult> {
    const raw = await this.rpc<Record<string, unknown>>(
      "events",
      normalizeApiResponse(filter ?? {}) as Record<string, unknown>,
    );
    return normalizeApiResponse<EventsResult>(raw);
  }

  /**
   * Verify a listing's signature.
   * @param listing The listing to verify
   * @param adminPubkey The admin Ed25519 public key (base64) - obtain from {@link status}
   * @returns true if the signature is valid
   */
  async verifyListing(listing: Listing, adminPubkey: string): Promise<boolean> {
    const pubkey = listing.pubkey ?? adminPubkey;
    // Use snake_case internally for signature verification (matches Rust)
    const payload = `LIST:${listing.name}:${listing.price}:${listing.payTaddr}:${listing.nonce}`;
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

  /**
   * Verify a sovereign Ed25519 signature before sending a transaction.
   * Call this after signing but before calling `complete()` to catch invalid signatures early.
   *
   * @param payload The signing payload string (e.g. `CLAIM:foo:u1abc`)
   * @param signature The Ed25519 signature (base64)
   * @param pubkey The Ed25519 public key (base64)
   * @returns true if the signature is valid for the given payload and pubkey
   *
   * @example
   * ```ts
   * const claim = zns.prepareClaim(name, address, cost);
   * const isValid = await zns.verifySoverignSignature(claim.payload, signature, userPubkey);
   * if (!isValid) throw new Error("Invalid signature");
   * const { memo, uri } = claim.complete(signature, userPubkey);
   * ```
   */
  async verifySoverignSignature(
    payload: string,
    signature: string,
    pubkey: string,
  ): Promise<boolean> {
    return this.verifyEd25519(payload, signature, pubkey);
  }

  /**
   * Validate a signing payload string against the ZNS memo format spec.
   *
   * This is the single source of truth for payload format validation —
   * it mirrors the Rust indexer's `parse_memo` and `signing_payload` logic.
   *
   * Does NOT validate the signature (see {@link verifyEd25519} for that).
   * Does NOT validate the name against the blockchain (see {@link isAvailable} for that).
   *
   * @param payload - Raw payload string, e.g. `CLAIM:foo:u1abc`
   * @returns Validation result with level and human-readable message
   *
   * @example
   * ```ts
   * const result = zns.validatePayload("CLAIM:alice:u1qvs2...");
   * if (!result.valid) {
   *   console.error(result.message);
   * }
   * ```
   */
  validatePayload(payload: string): PayloadValidationResult {
    const raw = String(payload ?? "").trim();
    if (!raw) {
      return {
        valid: false,
        action: "",
        message: "Empty payload.",
        level: "invalid",
      };
    }

    const colonIdx = raw.indexOf(":");
    if (colonIdx === -1) {
      return {
        valid: false,
        action: raw.toUpperCase(),
        message:
          "Missing colon separator. Expected format: ACTION:field1:field2:...",
        level: "invalid",
      };
    }

    const action = raw.slice(0, colonIdx).toUpperCase();
    const rest = raw.slice(colonIdx + 1);
    const parts = rest.split(":");

    if (!ZNS_ACTIONS.includes(action as ZnsAction)) {
      return {
        valid: false,
        action: action,
        message: `Unrecognized action "${action}". Valid actions: ${ZNS_ACTIONS.join(", ")}.`,
        level: "unrecognized",
      };
    }

    const rule = PAYLOAD_RULES[action as ZnsAction];
    if (parts.length !== rule.checks.length)
      return buildValidationResult(
        "invalid",
        action,
        `Expected ${rule.format}.`,
      );
    for (let i = 0; i < rule.checks.length; i++) {
      const err = validateField(parts[i], rule.checks[i]);
      if (err) return buildValidationResult("invalid", action, err);
    }
    return buildValidationResult("valid", action, `Valid ${action} payload.`);
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

  /**
   * Get the listing commission in zatoshis (10% of the minimum pricing tier).
   * @param pricing The pricing configuration - obtain from {@link status}
   * @returns The commission in zatoshis, or null if pricing is unavailable
   */
  listCommission(pricing: Pricing): Zats | null {
    if (pricing.tiers.length === 0) return null;
    return Math.min(...pricing.tiers) * 0.1;
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
  prepareClaim(name: string, address: string, cost: Zats): PreparedClaim {
    this.requireValidName(name);
    if (!isValidUnifiedAddress(address)) {
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
    payTaddr: string,
    nonce: number,
  ): PreparedList {
    this.requireValidName(name);

    return {
      name,
      price,
      payTaddr,
      nonce,
      payload: `LIST:${name}:${price}:${payTaddr}:${nonce}`,
      complete: (signature: string, userPubkey?: string): CompletedAction => {
        const memo = userPubkey
          ? `ZNS:LIST:${name}:${price}:${payTaddr}:${nonce}:${signature}:${userPubkey}`
          : `ZNS:LIST:${name}:${price}:${payTaddr}:${nonce}:${signature}`;
        return {
          memo,
          uri: this.buildZcashUri(this.registryAddress, LIST_COMMISSION, memo),
        };
      },
    };
  }

  prepareDelist(name: string, nonce: number): PreparedDelist {
    this.requireValidName(name);

    return {
      name,
      nonce,
      payload: `DELIST:${name}:${nonce}`,
      complete: (signature: string, userPubkey?: string): CompletedAction => {
        const memo = userPubkey
          ? `ZNS:DELIST:${name}:${nonce}:${signature}:${userPubkey}`
          : `ZNS:DELIST:${name}:${nonce}:${signature}`;
        return {
          memo,
          uri: this.buildZcashUri(this.registryAddress, undefined, memo),
        };
      },
    };
  }

  prepareUpdate(
    name: string,
    newAddress: string,
    nonce: number,
  ): PreparedUpdate {
    this.requireValidName(name);
    if (!isValidUnifiedAddress(newAddress)) {
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
        return {
          memo,
          uri: this.buildZcashUri(this.registryAddress, undefined, memo),
        };
      },
    };
  }

  prepareBuy(name: string, buyerAddress: string, price: Zats): PreparedBuy {
    this.requireValidName(name);
    if (!this.isValidUnifiedAddress(buyerAddress)) {
      throw new Error(`Invalid Zcash Unified Address: ${buyerAddress}`);
    }

    return {
      name,
      buyerAddress,
      price,
      payload: `BUY:${name}:${buyerAddress}`,
      complete: (signature: string, userPubkey?: string): CompletedAction => {
        const memo = userPubkey
          ? `ZNS:BUY:${name}:${buyerAddress}:${price}:${signature}:${userPubkey}`
          : `ZNS:BUY:${name}:${buyerAddress}:${price}:${signature}`;
        return {
          memo,
          uri: this.buildZcashUri(this.registryAddress, BUY_COMMISSION, memo),
        };
      },
    };
  }

  prepareRelease(name: string, nonce: number): PreparedRelease {
    this.requireValidName(name);

    return {
      name,
      nonce,
      payload: `RELEASE:${name}:${nonce}`,
      complete: (signature: string, userPubkey?: string): CompletedAction => {
        const memo = userPubkey
          ? `ZNS:RELEASE:${name}:${nonce}:${signature}:${userPubkey}`
          : `ZNS:RELEASE:${name}:${nonce}:${signature}`;
        return {
          memo,
          uri: this.buildZcashUri(this.registryAddress, undefined, memo),
        };
      },
    };
  }

  prepareSetPrice(prices: Zats[], nonce: number): PreparedSetPrice {
    return {
      prices,
      nonce,
      payload: `SETPRICE:${prices.length}:${prices.join(":")}:${nonce}`,
      complete: (signature: string): CompletedAction => {
        const memo = `ZNS:SETPRICE:${prices.length}:${prices.join(":")}:${nonce}:${signature}`;
        return {
          memo,
          uri: this.buildZcashUri(this.registryAddress, undefined, memo),
        };
      },
    };
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  private registrationPayload(reg: Registration): string {
    switch (reg.lastAction) {
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
    if (!isValidName(name)) throw new Error(`Invalid ZNS name: ${name}`);
  }

  /** Build a ZIP-321 URI. Amount is in zatoshis and will be converted to ZEC for the URI. */
  private buildZcashUri(
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
