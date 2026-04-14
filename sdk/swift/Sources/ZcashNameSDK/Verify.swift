import Foundation
import CryptoKit

public func verifySignature(payload: String, signatureB64: String, pubkeyB64: String) -> Bool {
    guard let sigData = Data(base64Encoded: signatureB64), sigData.count == 64,
          let pkData = Data(base64Encoded: pubkeyB64), pkData.count == 32
    else { return false }
    let payloadData = Data(payload.utf8)
    do {
        let pk = try Curve25519.Signing.PublicKey(rawRepresentation: pkData)
        return pk.isValidSignature(sigData, for: payloadData)
    } catch {
        return false
    }
}

public func registrationPayload(reg: Registration) -> String {
    switch reg.lastAction {
    case "CLAIM": return "CLAIM:\(reg.name):\(reg.address)"
    case "BUY": return "BUY:\(reg.name):\(reg.address)"
    case "UPDATE": return "UPDATE:\(reg.name):\(reg.address):\(reg.nonce)"
    case "DELIST": return "DELIST:\(reg.name):\(reg.nonce)"
    case "RELEASE": return "RELEASE:\(reg.name):\(reg.nonce)"
    default: fatalError("Unknown last_action: \(reg.lastAction)")
    }
}

public func listingPayload(listing: Listing) -> String {
    "LIST:\(listing.name):\(listing.price):\(listing.nonce)"
}

public func verifyRegistration(reg: Registration, adminPubkey: String) -> Bool {
    guard let sig = reg.signature else { return false }
    let payload = registrationPayload(reg: reg)
    let pubkey = reg.pubkey ?? adminPubkey
    return verifySignature(payload: payload, signatureB64: sig, pubkeyB64: pubkey)
}

public func verifyListing(listing: Listing, adminPubkey: String) -> Bool {
    let payload = listingPayload(listing: listing)
    return verifySignature(payload: payload, signatureB64: listing.signature, pubkeyB64: adminPubkey)
}