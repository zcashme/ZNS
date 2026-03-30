import { isValidName } from "./validation.js";

// ── Signing payloads ────────────────────────────────────────────────────────

export function claimPayload(name: string, ua: string): string {
  return `CLAIM:${name}:${ua}`;
}

export function buyPayload(name: string, buyerUa: string): string {
  return `BUY:${name}:${buyerUa}`;
}

export function listPayload(name: string, price: number, nonce: number): string {
  return `LIST:${name}:${price}:${nonce}`;
}

export function delistPayload(name: string, nonce: number): string {
  return `DELIST:${name}:${nonce}`;
}

export function updatePayload(name: string, newUa: string, nonce: number): string {
  return `UPDATE:${name}:${newUa}:${nonce}`;
}

export function setPricePayload(prices: number[], nonce: number): string {
  return `SETPRICE:${prices.length}:${prices.join(":")}:${nonce}`;
}

// ── Memo builders ───────────────────────────────────────────────────────────

export function buildClaimMemo(name: string, ua: string, signature: string): string {
  if (!isValidName(name)) throw new Error(`Invalid name: ${name}`);
  return `ZNS:CLAIM:${name}:${ua}:${signature}`;
}

export function buildBuyMemo(name: string, buyerUa: string, signature: string): string {
  if (!isValidName(name)) throw new Error(`Invalid name: ${name}`);
  return `ZNS:BUY:${name}:${buyerUa}:${signature}`;
}

export function buildListMemo(
  name: string,
  price: number,
  nonce: number,
  signature: string,
): string {
  if (!isValidName(name)) throw new Error(`Invalid name: ${name}`);
  return `ZNS:LIST:${name}:${price}:${nonce}:${signature}`;
}

export function buildDelistMemo(name: string, nonce: number, signature: string): string {
  if (!isValidName(name)) throw new Error(`Invalid name: ${name}`);
  return `ZNS:DELIST:${name}:${nonce}:${signature}`;
}

export function buildUpdateMemo(
  name: string,
  newUa: string,
  nonce: number,
  signature: string,
): string {
  if (!isValidName(name)) throw new Error(`Invalid name: ${name}`);
  return `ZNS:UPDATE:${name}:${newUa}:${nonce}:${signature}`;
}

export function buildSetPriceMemo(
  prices: number[],
  nonce: number,
  signature: string,
): string {
  return `ZNS:SETPRICE:${prices.length}:${prices.join(":")}:${nonce}:${signature}`;
}
