// ── Core types & errors (all consumers) ──────────────────────────────────────

export type {
  Registration,
  Listing,
  Pricing,
  ResolveResult,
  ListForSaleResult,
  StatusResult,
  Event,
  EventsFilter,
  EventsResult,
} from "./types.js";

export { ZNSError, ErrorType } from "./errors.js";

// ── Validation (all consumers) ───────────────────────────────────────────────

export { isValidName } from "./validation.js";

// ── RPC client + constants (explorers, indexer consumers) ────────────────────

export { createClient } from "./client.js";
export type { ZNSClient, ClientOptions } from "./client.js";
export { DEFAULT_URL, TESTNET_UIVK, MAINNET_UIVK, KNOWN_UIVKS } from "./constants.js";

// ── Pricing (needs tiers from client.status()) ──────────────────────────────

export { claimCost } from "./pricing.js";

// ── Memo builders + signing payloads (wallets) ──────────────────────────────

export {
  claimPayload,
  buyPayload,
  listPayload,
  delistPayload,
  updatePayload,
  setPricePayload,
  buildClaimMemo,
  buildBuyMemo,
  buildListMemo,
  buildDelistMemo,
  buildUpdateMemo,
  buildSetPriceMemo,
} from "./memo.js";

// ── ZIP-321 URI helpers (wallets) ────────────────────────────────────────────

export { toBase64Url, decodeBase64Url, buildZcashUri, parseZip321Uri } from "./zip321.js";
export type { Zip321Parts } from "./zip321.js";
