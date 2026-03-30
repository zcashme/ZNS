/**
 * Compute the claim cost in zatoshis for a name of the given length.
 *
 * @param tiers  The pricing tiers from `StatusResult.pricing.tiers` (already in zatoshis).
 *               Index 0 = 1-char names, index 1 = 2-char, etc.
 *               Names longer than the array clamp to the last entry.
 * @param nameLength  Character length of the name (must be >= 1).
 * @returns Cost in zatoshis, or `null` if tiers is empty.
 */
export function claimCost(tiers: number[], nameLength: number): number | null {
  if (tiers.length === 0) return null;
  const idx = Math.min(Math.max(nameLength - 1, 0), tiers.length - 1);
  return tiers[idx];
}
