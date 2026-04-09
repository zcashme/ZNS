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

export function buildClaimMemo(name: string, ua: string, signature: string, userPubkey?: string): string {
  if (!isValidName(name)) throw new Error(`Invalid name: ${name}`);
  const base = `ZNS:CLAIM:${name}:${ua}:${signature}`;
  return userPubkey ? `${base}:${userPubkey}` : base;
}

export function buildBuyMemo(name: string, buyerUa: string, signature: string, userPubkey?: string): string {
  if (!isValidName(name)) throw new Error(`Invalid name: ${name}`);
  const base = `ZNS:BUY:${name}:${buyerUa}:${signature}`;
  return userPubkey ? `${base}:${userPubkey}` : base;
}

export function buildListMemo(
  name: string,
  price: number,
  nonce: number,
  signature: string,
  userPubkey?: string,
): string {
  if (!isValidName(name)) throw new Error(`Invalid name: ${name}`);
  const base = `ZNS:LIST:${name}:${price}:${nonce}:${signature}`;
  return userPubkey ? `${base}:${userPubkey}` : base;
}

export function buildDelistMemo(name: string, nonce: number, signature: string, userPubkey?: string): string {
  if (!isValidName(name)) throw new Error(`Invalid name: ${name}`);
  const base = `ZNS:DELIST:${name}:${nonce}:${signature}`;
  return userPubkey ? `${base}:${userPubkey}` : base;
}

export function buildUpdateMemo(
  name: string,
  newUa: string,
  nonce: number,
  signature: string,
  userPubkey?: string,
): string {
  if (!isValidName(name)) throw new Error(`Invalid name: ${name}`);
  const base = `ZNS:UPDATE:${name}:${newUa}:${nonce}:${signature}`;
  return userPubkey ? `${base}:${userPubkey}` : base;
}

export function buildSetPriceMemo(
  prices: number[],
  nonce: number,
  signature: string,
): string {
  return `ZNS:SETPRICE:${prices.length}:${prices.join(":")}:${nonce}:${signature}`;
}
