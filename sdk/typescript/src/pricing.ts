import { CLAIM_PRICES, DEFAULT_CLAIM_PRICE } from "./constants.js";

export function claimCost(nameLength: number): number {
  return CLAIM_PRICES[nameLength] ?? DEFAULT_CLAIM_PRICE;
}
