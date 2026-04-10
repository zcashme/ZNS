import Foundation

// MARK: - Registration

public struct Registration: Codable, Sendable {
    public let name: String
    public let address: String
    public let txid: String
    public let height: Int
    public let nonce: Int
    public let signature: String?
    public let lastAction: String
    public let pubkey: String?

    public init(name: String, address: String, txid: String, height: Int, nonce: Int, signature: String?, lastAction: String, pubkey: String?) {
        self.name = name
        self.address = address
        self.txid = txid
        self.height = height
        self.nonce = nonce
        self.signature = signature
        self.lastAction = lastAction
        self.pubkey = pubkey
    }

    enum CodingKeys: String, CodingKey {
        case name, address, txid, height, nonce, signature, pubkey
        case lastAction = "last_action"
    }
}

// MARK: - Listing

public struct Listing: Codable, Sendable {
    public let name: String
    public let price: Int
    public let nonce: Int
    public let txid: String
    public let height: Int
    public let signature: String

    public init(name: String, price: Int, nonce: Int, txid: String, height: Int, signature: String) {
        self.name = name
        self.price = price
        self.nonce = nonce
        self.txid = txid
        self.height = height
        self.signature = signature
    }
}

// MARK: - ResolveResult

public struct ResolveResult: Codable, Sendable {
    public let name: String
    public let address: String
    public let txid: String
    public let height: Int
    public let nonce: Int
    public let signature: String?
    public let lastAction: String
    public let pubkey: String?
    public let listing: Listing?

    public init(name: String, address: String, txid: String, height: Int, nonce: Int, signature: String?, lastAction: String, pubkey: String?, listing: Listing?) {
        self.name = name
        self.address = address
        self.txid = txid
        self.height = height
        self.nonce = nonce
        self.signature = signature
        self.lastAction = lastAction
        self.pubkey = pubkey
        self.listing = listing
    }

    enum CodingKeys: String, CodingKey {
        case name, address, txid, height, nonce, signature, pubkey, listing
        case lastAction = "last_action"
    }
}

// MARK: - Pricing

public struct Pricing: Codable, Sendable {
    public let nonce: Int
    public let height: Int
    public let tiers: [Int]

    public init(nonce: Int, height: Int, tiers: [Int]) {
        self.nonce = nonce
        self.height = height
        self.tiers = tiers
    }
}

// MARK: - StatusResult

public struct StatusResult: Codable, Sendable {
    public let syncedHeight: Int
    public let adminPubkey: String
    public let uivk: String
    public let address: String
    public let registered: Int
    public let listed: Int
    public let pricing: Pricing?

    public init(syncedHeight: Int, adminPubkey: String, uivk: String, address: String, registered: Int, listed: Int, pricing: Pricing?) {
        self.syncedHeight = syncedHeight
        self.adminPubkey = adminPubkey
        self.uivk = uivk
        self.address = address
        self.registered = registered
        self.listed = listed
        self.pricing = pricing
    }

    enum CodingKeys: String, CodingKey {
        case syncedHeight = "synced_height"
        case adminPubkey = "admin_pubkey"
        case uivk, address, registered, listed, pricing
    }
}

// MARK: - ZNSEvent

public struct ZNSEvent: Codable, Sendable {
    public let id: Int
    public let name: String
    public let action: String
    public let txid: String
    public let height: Int
    public let ua: String?
    public let price: Int?
    public let nonce: Int?
    public let signature: String?
    public let pubkey: String?

    public init(id: Int, name: String, action: String, txid: String, height: Int, ua: String?, price: Int?, nonce: Int?, signature: String?, pubkey: String?) {
        self.id = id
        self.name = name
        self.action = action
        self.txid = txid
        self.height = height
        self.ua = ua
        self.price = price
        self.nonce = nonce
        self.signature = signature
        self.pubkey = pubkey
    }
}

// MARK: - EventsFilter

public struct EventsFilter: Sendable {
    public var name: String?
    public var action: String?
    public var sinceHeight: Int?
    public var limit: Int?
    public var offset: Int?

    public init(name: String? = nil, action: String? = nil, sinceHeight: Int? = nil, limit: Int? = nil, offset: Int? = nil) {
        self.name = name
        self.action = action
        self.sinceHeight = sinceHeight
        self.limit = limit
        self.offset = offset
    }

    /// Convert to a dictionary suitable for JSON-RPC params.
    func toParams() -> [String: Any] {
        var params: [String: Any] = [:]
        if let name { params["name"] = name }
        if let action { params["action"] = action }
        if let sinceHeight { params["since_height"] = sinceHeight }
        if let limit { params["limit"] = limit }
        if let offset { params["offset"] = offset }
        return params
    }
}

// MARK: - EventsResult

public struct EventsResult: Codable, Sendable {
    public let events: [ZNSEvent]
    public let total: Int

    public init(events: [ZNSEvent], total: Int) {
        self.events = events
        self.total = total
    }
}

// MARK: - ResolveResponse

/// The result of a `resolve` call. The server may return a single result,
/// multiple results (for wildcard/multi queries), or null (not found).
public enum ResolveResponse: Sendable {
    case single(ResolveResult)
    case multiple([ResolveResult])
    case notFound
}

// MARK: - ListForSaleResult (internal)

struct ListForSaleResult: Codable {
    let listings: [Listing]
}
