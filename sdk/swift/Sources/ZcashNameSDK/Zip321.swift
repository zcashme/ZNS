import Foundation

// MARK: - Zip321Parts

/// Parsed components of a ZIP-321 payment URI.
public struct Zip321Parts: Sendable {
    public let address: String
    public let amount: String
    public let memoRaw: String
    public let memoDecoded: String

    public init(address: String, amount: String, memoRaw: String, memoDecoded: String) {
        self.address = address
        self.amount = amount
        self.memoRaw = memoRaw
        self.memoDecoded = memoDecoded
    }
}

// MARK: - Base64URL encoding/decoding

/// Encode a UTF-8 string to Base64URL (no padding).
public func toBase64URL(_ text: String) -> String {
    guard let data = text.data(using: .utf8) else { return "" }
    return data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

/// Decode a Base64URL string back to a UTF-8 string.
public func decodeBase64URL(_ value: String) -> String {
    var normalized = value
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")

    // Add padding if needed.
    let remainder = normalized.count % 4
    if remainder != 0 {
        normalized += String(repeating: "=", count: 4 - remainder)
    }

    guard let data = Data(base64Encoded: normalized) else { return "" }
    return String(data: data, encoding: .utf8) ?? ""
}

// MARK: - URI building / parsing

/// Build a `zcash:` payment URI (ZIP-321 format).
///
/// - Parameters:
///   - address: The Zcash address.
///   - amount: Optional amount string (e.g. "0.001").
///   - memo: Optional plain-text memo (will be Base64URL-encoded).
/// - Returns: A `zcash:` URI string.
public func buildZcashURI(address: String, amount: String? = nil, memo: String? = nil) -> String {
    guard !address.isEmpty else { return "" }
    let base = "zcash:\(address)"
    var params: [String] = []
    if let amount, let amountValue = Double(amount), amountValue > 0 {
        params.append("amount=\(amount)")
    }
    if let memo, !memo.isEmpty {
        params.append("memo=\(toBase64URL(memo))")
    }
    return params.isEmpty ? base : "\(base)?\(params.joined(separator: "&"))"
}

/// Parse a ZIP-321 `zcash:` URI into its component parts.
///
/// - Parameter uri: The URI string to parse.
/// - Returns: A `Zip321Parts` struct with the extracted components.
public func parseZip321URI(_ uri: String) -> Zip321Parts {
    let raw = uri.trimmingCharacters(in: .whitespaces)
    let withoutScheme: String
    if raw.lowercased().hasPrefix("zcash:") {
        withoutScheme = String(raw.dropFirst("zcash:".count))
    } else {
        withoutScheme = raw
    }

    let parts = withoutScheme.split(separator: "?", maxSplits: 1)
    let address = String(parts.first ?? "").trimmingCharacters(in: .whitespaces)
    let queryPart = parts.count > 1 ? String(parts[1]) : ""

    let queryItems = parseQueryString(queryPart)
    let amount = (queryItems["amount"] ?? "").trimmingCharacters(in: .whitespaces)
    let memoRaw = (queryItems["memo"] ?? "").trimmingCharacters(in: .whitespaces)
    let memoDecoded = memoRaw.isEmpty ? "" : decodeBase64URL(memoRaw)

    return Zip321Parts(address: address, amount: amount, memoRaw: memoRaw, memoDecoded: memoDecoded)
}

// MARK: - Private helpers

/// Simple query string parser (avoids URLComponents dependency quirks with zcash: scheme).
private func parseQueryString(_ query: String) -> [String: String] {
    guard !query.isEmpty else { return [:] }
    var result: [String: String] = [:]
    for pair in query.split(separator: "&") {
        let kv = pair.split(separator: "=", maxSplits: 1)
        if kv.count == 2 {
            result[String(kv[0])] = String(kv[1])
        } else if kv.count == 1 {
            result[String(kv[0])] = ""
        }
    }
    return result
}
