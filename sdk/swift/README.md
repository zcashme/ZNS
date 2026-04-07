# ZcashNameSDK (Swift)

A Swift SDK for the Zcash Name System (ZNS) JSON-RPC API. Zero external dependencies -- uses only Foundation and URLSession.

## Requirements

- Swift 5.9+
- macOS 12+ / iOS 15+

## Installation

### Swift Package Manager

Add to your `Package.swift`:

```swift
dependencies: [
    .package(path: "../path/to/sdk/swift")
]
```

Or from a git URL:

```swift
dependencies: [
    .package(url: "https://github.com/example/ZcashNameSDK.git", from: "1.0.0")
]
```

Then add `"ZcashNameSDK"` as a dependency of your target.

## Quick start

```swift
import ZcashNameSDK

// Create a verified client (checks UIVK against known values)
let client = try await ZNSClient.create()

// Resolve a name
let result = try await client.resolve(query: "alice")
switch result {
case .single(let r):
    print("\(r.name) -> \(r.address)")
case .multiple(let results):
    for r in results { print("\(r.name) -> \(r.address)") }
case .notFound:
    print("Not found")
}

// Check availability
let available = try await client.isAvailable(name: "bob")

// Get marketplace listings
let listings = try await client.listings()

// Get indexer status
let status = try await client.status()

// Query events
let events = try await client.events(filter: EventsFilter(action: "CLAIM", limit: 10))
```

## API reference

### Client

| Method | Returns | Description |
|--------|---------|-------------|
| `ZNSClient.create(url:skipVerify:)` | `ZNSClient` | Create and optionally verify a client |
| `resolve(query:)` | `ResolveResponse` | Resolve a name |
| `listings()` | `[Listing]` | Fetch marketplace listings |
| `status()` | `StatusResult` | Get indexer status |
| `events(filter:)` | `EventsResult` | Query events with filters |
| `isAvailable(name:)` | `Bool` | Check name availability |
| `getNonce(name:)` | `Int?` | Get current nonce for a name |

### Validation

```swift
isValidName("alice")    // true
isValidName("ALICE")    // false (uppercase)
isValidName("a--b")     // false (consecutive hyphens)
```

### Pricing

```swift
let cost = claimCost(tiers: [100_000, 50_000, 10_000], nameLength: 2)
// cost == 50_000
```

### Memo builders

```swift
let memo = try buildClaimMemo(name: "alice", ua: "u1abc...", signature: "sig123")
// "ZNS:CLAIM:alice:u1abc...:sig123"
```

### ZIP-321

```swift
let uri = buildZcashURI(address: "u1abc...", amount: "0.001", memo: "hello")
let parts = parseZip321URI(uri)
// parts.address == "u1abc..."
// parts.memoDecoded == "hello"
```

## License

See the project root for license information.
