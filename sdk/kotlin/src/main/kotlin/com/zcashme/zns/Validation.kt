package com.zcashme.zns

/**
 * Validation utilities for ZNS names.
 */
object ZnsValidation {

    private val NAME_PATTERN = Regex("^[a-z0-9]{1,62}\$")

    /**
     * Returns `true` if [name] is a valid ZNS name.
     *
     * A valid name is 1-62 characters of lowercase ASCII letters (a-z) and
     * digits (0-9). No hyphens, no underscores, no unicode.
     */
    fun isValidName(name: String): Boolean {
        return NAME_PATTERN.matches(name)
    }
}

/**
 * Top-level convenience function. See [ZnsValidation.isValidName].
 */
fun isValidName(name: String): Boolean = ZnsValidation.isValidName(name)
