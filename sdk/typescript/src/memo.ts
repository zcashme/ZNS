import { isValidName } from "./validation.js";

// ── Signing payloads ────────────────────────────────────────────────────────

export function listPayload(name: string, price: number, nonce: number): string {
  return `LIST:${name}:${price}:${nonce}`;
}

export function delistPayload(name: string, nonce: number): string {
  return `DELIST:${name}:${nonce}`;
}

export function updatePayload(name: string, newUa: string, nonce: number): string {
  return `UPDATE:${name}:${newUa}:${nonce}`;
}

// ── Memo builders ───────────────────────────────────────────────────────────

export function buildClaimMemo(name: string, ua: string): string {
  if (!isValidName(name)) throw new Error(`Invalid name: ${name}`);
  return `ZNS:CLAIM:${name}:${ua}`;
}

export function buildBuyMemo(name: string, buyerUa: string): string {
  if (!isValidName(name)) throw new Error(`Invalid name: ${name}`);
  return `ZNS:BUY:${name}:${buyerUa}`;
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
