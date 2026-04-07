package com.zcashme.zns

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.jsonArray

/**
 * Client for the Zcash Name System (ZNS) JSON-RPC API.
 *
 * Use the [create] factory method to build a verified client instance.
 *
 * ```kotlin
 * val client = ZnsClient.create()
 * val result = client.resolveName("satoshi")
 * println(result?.address)
 * ```
 */
class ZnsClient private constructor(
    /** The JSON-RPC endpoint URL. */
    val url: String,
    /** Whether the server UIVK was verified against [ZnsConstants.KNOWN_UIVKS]. */
    val verified: Boolean,
) {
    private val json = Json { ignoreUnknownKeys = true }
    private var nextId = 0

    private fun id(): Int = ++nextId

    private suspend fun call(method: String, params: JsonElement = JsonObject(emptyMap())): JsonElement {
        return Rpc.call(url, method, params, id())
    }

    companion object {
        /**
         * Create a new [ZnsClient], optionally verifying the server's UIVK.
         *
         * @param url         The JSON-RPC endpoint URL.
         * @param skipVerify  If `true`, skip UIVK verification (not recommended for production).
         * @throws ZnsError if the server is unreachable or UIVK verification fails.
         */
        suspend fun create(
            url: String = ZnsConstants.DEFAULT_URL,
            skipVerify: Boolean = false,
        ): ZnsClient {
            val client = ZnsClient(url, verified = false)
            val verifiedResult: Boolean

            if (skipVerify) {
                verifiedResult = false
            } else {
                val status = client.status()
                if (status.uivk !in ZnsConstants.KNOWN_UIVKS) {
                    throw ZnsError(
                        ZnsErrorType.UIVK_MISMATCH,
                        "UIVK mismatch: indexer returned \"${status.uivk.take(20)}...\" which is not a known ZNS instance",
                    )
                }
                verifiedResult = true
            }

            return ZnsClient(url, verified = verifiedResult)
        }
    }

    // ── Query methods ───────────────────────────────────────────────────────

    /**
     * Raw resolve query. The return type depends on the query:
     * - A name returns a single object or `JsonNull`
     * - An address returns an array or `JsonNull`
     *
     * Prefer [resolveName] or [resolveAddress] for typed results.
     */
    suspend fun resolve(query: String): JsonElement {
        return call("resolve", JsonObject(mapOf("query" to JsonPrimitive(query))))
    }

    /**
     * Resolve a single ZNS name. Returns `null` if the name is not registered.
     */
    suspend fun resolveName(name: String): ResolveResult? {
        val result = resolve(name)
        if (result is JsonNull) return null
        return json.decodeFromJsonElement<ResolveResult>(result)
    }

    /**
     * Resolve all names registered to an address. Returns an empty list if none are found.
     */
    suspend fun resolveAddress(address: String): List<ResolveResult> {
        val result = resolve(address)
        if (result is JsonNull) return emptyList()
        return result.jsonArray.map { json.decodeFromJsonElement<ResolveResult>(it) }
    }

    /**
     * Retrieve all names currently listed for sale.
     */
    suspend fun listings(): List<Listing> {
        val result = call("list_for_sale")
        val wrapper = json.decodeFromJsonElement<ListForSaleResult>(result)
        return wrapper.listings
    }

    /**
     * Retrieve the current status of the ZNS indexer.
     */
    suspend fun status(): StatusResult {
        val result = call("status")
        return json.decodeFromJsonElement<StatusResult>(result)
    }

    /**
     * Query the event log with optional filters.
     */
    suspend fun events(filter: EventsFilter = EventsFilter()): EventsResult {
        val params = buildMap<String, JsonElement> {
            filter.name?.let { put("name", JsonPrimitive(it)) }
            filter.action?.let { put("action", JsonPrimitive(it)) }
            filter.sinceHeight?.let { put("since_height", JsonPrimitive(it)) }
            filter.limit?.let { put("limit", JsonPrimitive(it)) }
            filter.offset?.let { put("offset", JsonPrimitive(it)) }
        }
        val result = call("events", JsonObject(params))
        return json.decodeFromJsonElement<EventsResult>(result)
    }

    /**
     * Check whether a name is available for registration.
     */
    suspend fun isAvailable(name: String): Boolean {
        return resolveName(name) == null
    }

    /**
     * Get the current nonce for a registered name.
     * Returns `null` if the name is not registered.
     */
    suspend fun getNonce(name: String): Int? {
        return resolveName(name)?.nonce
    }
}
