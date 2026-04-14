package com.zcashme.zns

import java.security.KeyFactory
import java.security.Signature
import java.util.Base64

fun verifySignature(payload: String, signatureB64: String, pubkeyB64: String): Boolean {
    return try {
        val sigBytes = Base64.getDecoder().decode(signatureB64)
        val pkBytes = Base64.getDecoder().decode(pubkeyB64)
        if (sigBytes.size != 64 || pkBytes.size != 32) return false
        val pkSpec = java.security.spec.EdECPublicKeySpec(
            java.security.spec.NamedParameterSpec("Ed25519"),
            java.security.spec.EdECPoint(false, decodeUint256(pkBytes))
        )
        val pk = KeyFactory.getInstance("Ed25519").generatePublic(pkSpec)
        val verifier = Signature.getInstance("Ed25519")
        verifier.initVerify(pk)
        verifier.update(payload.toByteArray(Charsets.UTF_8))
        verifier.verify(sigBytes)
    } catch (_: Exception) {
        false
    }
}

private fun decodeUint256(littleEndian: ByteArray): java.math.BigInteger {
    val reversed = littleEndian.copyOf().also { it.reverse() }
    return java.math.BigInteger(1, reversed)
}

fun registrationPayload(reg: Registration): String = when (reg.lastAction) {
    "CLAIM" -> "CLAIM:${reg.name}:${reg.address}"
    "BUY" -> "BUY:${reg.name}:${reg.address}"
    "UPDATE" -> "UPDATE:${reg.name}:${reg.address}:${reg.nonce}"
    "DELIST" -> "DELIST:${reg.name}:${reg.nonce}"
    "RELEASE" -> "RELEASE:${reg.name}:${reg.nonce}"
    else -> ""
}

fun listingPayload(listing: Listing): String =
    "LIST:${listing.name}:${listing.price}:${listing.nonce}"

fun verifyRegistration(reg: Registration, adminPubkey: String): Boolean {
    val sig = reg.signature ?: return false
    val payload = registrationPayload(reg)
    if (payload.isEmpty()) return false
    val pubkey = reg.pubkey ?: adminPubkey
    return verifySignature(payload, sig, pubkey)
}

fun verifyListing(listing: Listing, adminPubkey: String): Boolean {
    val payload = listingPayload(listing)
    return verifySignature(payload, listing.signature, adminPubkey)
}