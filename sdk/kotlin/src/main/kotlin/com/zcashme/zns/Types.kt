package com.zcashme.zns

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * A registered ZNS name.
 */
@Serializable
data class Registration(
    val name: String,
    val address: String,
    val txid: String,
    val height: Int,
    val nonce: Int,
    val signature: String? = null,
)

/**
 * A name listed for sale on the ZNS marketplace.
 */
@Serializable
data class Listing(
    val name: String,
    val price: Long,
    val txid: String,
    val height: Int,
    val signature: String,
)

/**
 * The result of resolving a ZNS name, including an optional marketplace listing.
 */
@Serializable
data class ResolveResult(
    val name: String,
    val address: String,
    val txid: String,
    val height: Int,
    val nonce: Int,
    val signature: String? = null,
    val listing: Listing? = null,
)

/**
 * Pricing tiers and metadata for name claims.
 *
 * Index 0 = 1-char names, index 1 = 2-char, etc.
 * Names longer than the array clamp to the last entry.
 */
@Serializable
data class Pricing(
    val nonce: Int,
    val height: Int,
    val tiers: List<Long>,
)

/**
 * Status of the ZNS indexer.
 */
@Serializable
data class StatusResult(
    @SerialName("synced_height") val syncedHeight: Int,
    @SerialName("admin_pubkey") val adminPubkey: String,
    val uivk: String,
    val registered: Int,
    val listed: Int,
    val pricing: Pricing? = null,
)

/**
 * A single event from the ZNS event log.
 */
@Serializable
data class ZnsEvent(
    val id: Int,
    val name: String,
    val action: String,
    val txid: String,
    val height: Int,
    val ua: String? = null,
    val price: Long? = null,
    val nonce: Int? = null,
    val signature: String? = null,
)

/**
 * Optional filters for querying events.
 *
 * This is a local filter specification; it is not itself serialized.
 * The [Client] converts it to JSON-RPC params with snake_case keys.
 */
data class EventsFilter(
    val name: String? = null,
    val action: String? = null,
    val sinceHeight: Int? = null,
    val limit: Int? = null,
    val offset: Int? = null,
)

/**
 * A page of events returned by the `events` RPC method.
 */
@Serializable
data class EventsResult(
    val events: List<ZnsEvent>,
    val total: Int,
)

/**
 * Wrapper for the `list_for_sale` RPC result.
 */
@Serializable
data class ListForSaleResult(
    val listings: List<Listing>,
)
