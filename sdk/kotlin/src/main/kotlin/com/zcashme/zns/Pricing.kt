package com.zcashme.zns

/**
 * Pricing utilities for ZNS name claims.
 */
object ZnsPricing {

    /**
     * Compute the claim cost in zatoshis for a name of the given length.
     *
     * @param tiers  The pricing tiers from [Pricing.tiers] (already in zatoshis).
     *               Index 0 = 1-char names, index 1 = 2-char, etc.
     *               Names longer than the array clamp to the last entry.
     * @param nameLength  Character length of the name (must be >= 1).
     * @return Cost in zatoshis, or `null` if [tiers] is empty.
     */
    fun claimCost(tiers: List<Long>, nameLength: Int): Long? {
        if (tiers.isEmpty()) return null
        val idx = (nameLength - 1).coerceIn(0, tiers.size - 1)
        return tiers[idx]
    }
}

/**
 * Top-level convenience function. See [ZnsPricing.claimCost].
 */
fun claimCost(tiers: List<Long>, nameLength: Int): Long? = ZnsPricing.claimCost(tiers, nameLength)
