package com.zcashme.zns

// ── Signing payloads ────────────────────────────────────────────────────────

/**
 * Build the signing payload for a CLAIM action.
 */
fun claimPayload(name: String, ua: String): String = "CLAIM:$name:$ua"

/**
 * Build the signing payload for a BUY action.
 */
fun buyPayload(name: String, buyerUa: String): String = "BUY:$name:$buyerUa"

/**
 * Build the signing payload for a LIST action.
 */
fun listPayload(name: String, price: Long, nonce: Int): String = "LIST:$name:$price:$nonce"

/**
 * Build the signing payload for a DELIST action.
 */
fun delistPayload(name: String, nonce: Int): String = "DELIST:$name:$nonce"

/**
 * Build the signing payload for a RELEASE action.
 */
fun releasePayload(name: String, nonce: Int): String = "RELEASE:$name:$nonce"

/**
 * Build the signing payload for an UPDATE action.
 */
fun updatePayload(name: String, newUa: String, nonce: Int): String = "UPDATE:$name:$newUa:$nonce"

/**
 * Build the signing payload for a SETPRICE action.
 */
fun setPricePayload(prices: List<Long>, nonce: Int): String =
    "SETPRICE:${prices.size}:${prices.joinToString(":")}:$nonce"

// ── Memo builders ───────────────────────────────────────────────────────────

private fun requireValid(name: String) {
    require(isValidName(name)) { "Invalid name: $name" }
}

/**
 * Build the memo string for a CLAIM transaction.
 *
 * @throws IllegalArgumentException if [name] is not a valid ZNS name.
 */
fun buildClaimMemo(name: String, ua: String, signature: String, userPubkey: String? = null): String {
    requireValid(name)
    val base = "ZNS:CLAIM:$name:$ua:$signature"
    return userPubkey?.let { "$base:$it" } ?: base
}

/**
 * Build the memo string for a BUY transaction.
 *
 * @throws IllegalArgumentException if [name] is not a valid ZNS name.
 */
fun buildBuyMemo(name: String, buyerUa: String, signature: String, userPubkey: String? = null): String {
    requireValid(name)
    val base = "ZNS:BUY:$name:$buyerUa:$signature"
    return userPubkey?.let { "$base:$it" } ?: base
}

/**
 * Build the memo string for a LIST transaction.
 *
 * @throws IllegalArgumentException if [name] is not a valid ZNS name.
 */
fun buildListMemo(name: String, price: Long, nonce: Int, signature: String, userPubkey: String? = null): String {
    requireValid(name)
    val base = "ZNS:LIST:$name:$price:$nonce:$signature"
    return userPubkey?.let { "$base:$it" } ?: base
}

/**
 * Build the memo string for a DELIST transaction.
 *
 * @throws IllegalArgumentException if [name] is not a valid ZNS name.
 */
fun buildDelistMemo(name: String, nonce: Int, signature: String, userPubkey: String? = null): String {
    requireValid(name)
    val base = "ZNS:DELIST:$name:$nonce:$signature"
    return userPubkey?.let { "$base:$it" } ?: base
}

/**
 * Build the memo string for a RELEASE transaction.
 *
 * @throws IllegalArgumentException if [name] is not a valid ZNS name.
 */
fun buildReleaseMemo(name: String, nonce: Int, signature: String, userPubkey: String? = null): String {
    requireValid(name)
    val base = "ZNS:RELEASE:$name:$nonce:$signature"
    return userPubkey?.let { "$base:$it" } ?: base
}

/**
 * Build the memo string for an UPDATE transaction.
 *
 * @throws IllegalArgumentException if [name] is not a valid ZNS name.
 */
fun buildUpdateMemo(name: String, newUa: String, nonce: Int, signature: String, userPubkey: String? = null): String {
    requireValid(name)
    val base = "ZNS:UPDATE:$name:$newUa:$nonce:$signature"
    return userPubkey?.let { "$base:$it" } ?: base
}

/**
 * Build the memo string for a SETPRICE transaction.
 */
fun buildSetPriceMemo(prices: List<Long>, nonce: Int, signature: String): String =
    "ZNS:SETPRICE:${prices.size}:${prices.joinToString(":")}:$nonce:$signature"
