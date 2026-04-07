package com.zcashme.zns

/**
 * Error types for ZNS operations.
 *
 * Standard JSON-RPC 2.0 error codes are negative integers in the -32xxx range.
 * SDK-specific codes use small negative integers.
 */
enum class ZnsErrorType(val code: Int) {
    PARSE_ERROR(-32700),
    INVALID_REQUEST(-32600),
    METHOD_NOT_FOUND(-32601),
    INVALID_PARAMS(-32602),
    INTERNAL_ERROR(-32603),
    HTTP_ERROR(-1),
    UIVK_MISMATCH(-2),
}

/**
 * Exception thrown by ZNS SDK operations.
 */
class ZnsError(
    val type: ZnsErrorType,
    message: String,
) : Exception(message) {
    override fun toString(): String = "ZnsError(${type.name}/$code): $message"

    /** The numeric error code. */
    val code: Int get() = type.code

    companion object {
        /**
         * Map a numeric JSON-RPC error code to the corresponding [ZnsErrorType],
         * falling back to [ZnsErrorType.INTERNAL_ERROR] for unknown codes.
         */
        internal fun fromCode(code: Int, message: String): ZnsError {
            val type = ZnsErrorType.entries.firstOrNull { it.code == code }
                ?: ZnsErrorType.INTERNAL_ERROR
            return ZnsError(type, message)
        }
    }
}
