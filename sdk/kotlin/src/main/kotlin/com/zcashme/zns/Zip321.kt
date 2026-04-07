package com.zcashme.zns

import java.util.Base64

/**
 * Components parsed from a ZIP-321 `zcash:` URI.
 */
data class Zip321Parts(
    val address: String,
    val amount: String,
    val memoRaw: String,
    val memoDecoded: String,
)

/**
 * Encode a UTF-8 string as a URL-safe Base64 string (no padding).
 */
fun toBase64Url(text: String): String {
    return try {
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(text.toByteArray(Charsets.UTF_8))
    } catch (_: Exception) {
        ""
    }
}

/**
 * Decode a URL-safe Base64 string back to a UTF-8 string.
 */
fun decodeBase64Url(value: String): String {
    return try {
        // Normalize: the input may use standard base64 characters (+/) or URL-safe (-/_)
        val normalized = value.replace('-', '+').replace('_', '/')
        // Add padding if needed
        val paddingLength = when (normalized.length % 4) {
            0 -> 0
            else -> 4 - (normalized.length % 4)
        }
        val padded = normalized + "=".repeat(paddingLength)
        String(Base64.getDecoder().decode(padded), Charsets.UTF_8)
    } catch (_: Exception) {
        ""
    }
}

/**
 * Build a ZIP-321 `zcash:` payment URI.
 *
 * @param address  The Zcash address.
 * @param amount   Optional amount (in ZEC, as a decimal string).
 * @param memo     Optional memo text (will be Base64-URL encoded).
 * @return The formatted `zcash:` URI, or an empty string if [address] is blank.
 */
fun buildZcashUri(address: String, amount: String? = null, memo: String? = null): String {
    if (address.isBlank()) return ""
    val base = "zcash:$address"
    val params = mutableListOf<String>()
    if (!amount.isNullOrBlank()) {
        val numericAmount = amount.toDoubleOrNull()
        if (numericAmount != null && numericAmount > 0) {
            params.add("amount=$amount")
        }
    }
    if (!memo.isNullOrBlank()) {
        params.add("memo=${toBase64Url(memo)}")
    }
    return if (params.isEmpty()) base else "$base?${params.joinToString("&")}"
}

/**
 * Parse a ZIP-321 `zcash:` URI into its components.
 *
 * @param uri  The URI string (with or without the `zcash:` scheme prefix).
 * @return Parsed [Zip321Parts].
 */
fun parseZip321Uri(uri: String): Zip321Parts {
    val withoutScheme = uri.replace(Regex("^zcash:", RegexOption.IGNORE_CASE), "")
    val parts = withoutScheme.split("?", limit = 2)
    val address = parts[0].trim()
    val queryPart = if (parts.size > 1) parts[1] else ""

    val queryParams = mutableMapOf<String, String>()
    if (queryPart.isNotEmpty()) {
        for (pair in queryPart.split("&")) {
            val kv = pair.split("=", limit = 2)
            if (kv.size == 2) {
                queryParams[kv[0].trim()] = kv[1].trim()
            }
        }
    }

    val amount = queryParams["amount"]?.trim() ?: ""
    val memoRaw = queryParams["memo"]?.trim() ?: ""
    val memoDecoded = if (memoRaw.isNotEmpty()) decodeBase64Url(memoRaw) else ""

    return Zip321Parts(
        address = address,
        amount = amount,
        memoRaw = memoRaw,
        memoDecoded = memoDecoded,
    )
}
