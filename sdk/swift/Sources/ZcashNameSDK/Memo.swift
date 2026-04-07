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
public func buildClaimMemo(name: String, ua: String, signature: String) throws -> String {
    guard isValidName(name) else {
        throw ZNSError(type: .invalidParams, message: "Invalid name: \(name)")
    }
    return "ZNS:CLAIM:\(name):\(ua):\(signature)"
}

/// Build a memo string for a BUY transaction.
///
/// - Throws: If the name is invalid.
public func buildBuyMemo(name: String, buyerUa: String, signature: String) throws -> String {
    guard isValidName(name) else {
        throw ZNSError(type: .invalidParams, message: "Invalid name: \(name)")
    }
    return "ZNS:BUY:\(name):\(buyerUa):\(signature)"
}

/// Build a memo string for a LIST transaction.
///
/// - Throws: If the name is invalid.
public func buildListMemo(name: String, price: Int, nonce: Int, signature: String) throws -> String {
    guard isValidName(name) else {
        throw ZNSError(type: .invalidParams, message: "Invalid name: \(name)")
    }
    return "ZNS:LIST:\(name):\(price):\(nonce):\(signature)"
}

/// Build a memo string for a DELIST transaction.
///
/// - Throws: If the name is invalid.
public func buildDelistMemo(name: String, nonce: Int, signature: String) throws -> String {
    guard isValidName(name) else {
        throw ZNSError(type: .invalidParams, message: "Invalid name: \(name)")
    }
    return "ZNS:DELIST:\(name):\(nonce):\(signature)"
}

/// Build a memo string for an UPDATE transaction.
///
/// - Throws: If the name is invalid.
public func buildUpdateMemo(name: String, newUa: String, nonce: Int, signature: String) throws -> String {
    guard isValidName(name) else {
        throw ZNSError(type: .invalidParams, message: "Invalid name: \(name)")
    }
    return "ZNS:UPDATE:\(name):\(newUa):\(nonce):\(signature)"
}

/// Build a memo string for a SETPRICE transaction.
public func buildSetPriceMemo(prices: [Int], nonce: Int, signature: String) -> String {
    let joined = prices.map(String.init).joined(separator: ":")
    return "ZNS:SETPRICE:\(prices.count):\(joined):\(nonce):\(signature)"
}
