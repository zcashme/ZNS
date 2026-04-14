import Foundation

// MARK: - Signing payloads

/// Build the signing payload for a CLAIM action.
public func claimPayload(name: String, ua: String) -> String {
    "CLAIM:\(name):\(ua)"
}

/// Build the signing payload for a BUY action.
public func buyPayload(name: String, buyerUa: String) -> String {
    "BUY:\(name):\(buyerUa)"
}

/// Build the signing payload for a LIST action.
public func listPayload(name: String, price: Int, nonce: Int) -> String {
    "LIST:\(name):\(price):\(nonce)"
}

/// Build the signing payload for a DELIST action.
public func delistPayload(name: String, nonce: Int) -> String {
    "DELIST:\(name):\(nonce)"
}

/// Build the signing payload for a RELEASE action.
public func releasePayload(name: String, nonce: Int) -> String {
    "RELEASE:\(name):\(nonce)"
}

/// Build the signing payload for an UPDATE action.
public func updatePayload(name: String, newUa: String, nonce: Int) -> String {
    "UPDATE:\(name):\(newUa):\(nonce)"
}

/// Build the signing payload for a SETPRICE action.
public func setPricePayload(prices: [Int], nonce: Int) -> String {
    let joined = prices.map(String.init).joined(separator: ":")
    return "SETPRICE:\(prices.count):\(joined):\(nonce)"
}

// MARK: - Memo builders

/// Build a memo string for a CLAIM transaction.
///
/// - Throws: If the name is invalid.
public func buildClaimMemo(name: String, ua: String, signature: String, userPubkey: String? = nil) throws -> String {
    guard isValidName(name) else {
        throw ZNSError(type: .invalidParams, message: "Invalid name: \(name)")
    }
    let base = "ZNS:CLAIM:\(name):\(ua):\(signature)"
    return userPubkey.map { "\(base):\($0)" } ?? base
}

/// Build a memo string for a BUY transaction.
///
/// - Throws: If the name is invalid.
public func buildBuyMemo(name: String, buyerUa: String, signature: String, userPubkey: String? = nil) throws -> String {
    guard isValidName(name) else {
        throw ZNSError(type: .invalidParams, message: "Invalid name: \(name)")
    }
    let base = "ZNS:BUY:\(name):\(buyerUa):\(signature)"
    return userPubkey.map { "\(base):\($0)" } ?? base
}

/// Build a memo string for a LIST transaction.
///
/// - Throws: If the name is invalid.
public func buildListMemo(name: String, price: Int, nonce: Int, signature: String, userPubkey: String? = nil) throws -> String {
    guard isValidName(name) else {
        throw ZNSError(type: .invalidParams, message: "Invalid name: \(name)")
    }
    let base = "ZNS:LIST:\(name):\(price):\(nonce):\(signature)"
    return userPubkey.map { "\(base):\($0)" } ?? base
}

/// Build a memo string for a DELIST transaction.
///
/// - Throws: If the name is invalid.
public func buildDelistMemo(name: String, nonce: Int, signature: String, userPubkey: String? = nil) throws -> String {
    guard isValidName(name) else {
        throw ZNSError(type: .invalidParams, message: "Invalid name: \(name)")
    }
    let base = "ZNS:DELIST:\(name):\(nonce):\(signature)"
    return userPubkey.map { "\(base):\($0)" } ?? base
}

/// Build a memo string for a RELEASE transaction.
///
/// - Throws: If the name is invalid.
public func buildReleaseMemo(name: String, nonce: Int, signature: String, userPubkey: String? = nil) throws -> String {
    guard isValidName(name) else {
        throw ZNSError(type: .invalidParams, message: "Invalid name: \(name)")
    }
    let base = "ZNS:RELEASE:\(name):\(nonce):\(signature)"
    return userPubkey.map { "\(base):\($0)" } ?? base
}

/// Build a memo string for an UPDATE transaction.
///
/// - Throws: If the name is invalid.
public func buildUpdateMemo(name: String, newUa: String, nonce: Int, signature: String, userPubkey: String? = nil) throws -> String {
    guard isValidName(name) else {
        throw ZNSError(type: .invalidParams, message: "Invalid name: \(name)")
    }
    let base = "ZNS:UPDATE:\(name):\(newUa):\(nonce):\(signature)"
    return userPubkey.map { "\(base):\($0)" } ?? base
}

/// Build a memo string for a SETPRICE transaction.
public func buildSetPriceMemo(prices: [Int], nonce: Int, signature: String) -> String {
    let joined = prices.map(String.init).joined(separator: ":")
    return "ZNS:SETPRICE:\(prices.count):\(joined):\(nonce):\(signature)"
}
