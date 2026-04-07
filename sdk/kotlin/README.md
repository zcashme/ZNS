# ZNS Kotlin SDK

Kotlin SDK for the Zcash Name System (ZNS) JSON-RPC API. Built with coroutines and kotlinx.serialization for Android/JVM use.

## Installation

Add the dependency to your `build.gradle.kts`:

```kotlin
dependencies {
    implementation("com.zcashme:zns-sdk:0.4.0")
}
```

## Quick start

```kotlin
import com.zcashme.zns.*

// Create a verified client
val client = ZnsClient.create()

// Resolve a name to an address
val result = client.resolveName("alice")
println(result?.address)
// "utest1gygneuhu84vxjuhjhpdtrd67ukalu22ncqn3mm3nkda3vskc450dl5v..."
```

## Resolve a name

The primary use case. A wallet has a name, needs an address.

```kotlin
val result = client.resolveName("alice")
// ResolveResult(name="alice", address="utest1...", txid="abc123...",
//   height=3907441, nonce=2, signature="...", listing=null)
```

Returns `null` if the name is not registered.

## Reverse resolve

A wallet or explorer has an address, wants to show the name.

```kotlin
val results = client.resolveAddress("utest1gygneuhu84vxjuhjhpdtrd67uk...")
// [ResolveResult(name="alice", address="utest1...", ...)]
```

## Check availability

```kotlin
if (client.isAvailable("myname")) {
    // name is not registered
}
```

## Name history

Full activity chain for a name. Useful for explorers showing ownership history, sales, updates.

```kotlin
val history = client.events(EventsFilter(name = "alice"))
// EventsResult(events=[...], total=2)
```

## All activity

Global feed across all names. Filter by action type, block height, or combine.

```kotlin
// Everything
client.events()

// All registered names
client.events(EventsFilter(action = "CLAIM"))

// Recent activity
client.events(EventsFilter(sinceHeight = 3910000))

// Paginate
client.events(EventsFilter(limit = 50, offset = 50))
```

## Register a name

Registration is a two-step process: build the memo, then send a Zcash transaction with that memo and the correct payment amount.

```kotlin
val name = "alice"
val ua = "utest1abc..." // the address this name should resolve to

// 1. Build the memo
val memo = buildClaimMemo(name, ua, signature)
// "ZNS:CLAIM:alice:utest1abc...:signature"

// 2. Get the cost in zatoshis
val status = client.status()
val cost = claimCost(status.pricing!!.tiers, name.length)
// 75_000_000 (0.75 ZEC for a 5-letter name)

// 3. Build a payment URI
val uri = buildZcashUri(ua, "${cost!! / 1_0000_0000.0}", memo)
// "zcash:utest1abc...?amount=0.75&memo=..."
```

## Marketplace actions

### List a name for sale

```kotlin
val nonce = client.getNonce("alice")!! + 1

// 1. Build the signing payload
val payload = listPayload("alice", 50_000_000L, nonce)
// "LIST:alice:50000000:1"

// 2. Sign it with Ed25519 (your signing logic)
val signature = sign(payload)

// 3. Build the memo
val memo = buildListMemo("alice", 50_000_000L, nonce, signature)
```

### Buy a listed name

```kotlin
val memo = buildBuyMemo("alice", "utest1buyer...", signature)
```

### Delist a name

```kotlin
val nonce = client.getNonce("alice")!! + 1
val payload = delistPayload("alice", nonce)
val signature = sign(payload)
val memo = buildDelistMemo("alice", nonce, signature)
```

### Update a name's address

```kotlin
val nonce = client.getNonce("alice")!! + 1
val payload = updatePayload("alice", "utest1newaddr...", nonce)
val signature = sign(payload)
val memo = buildUpdateMemo("alice", "utest1newaddr...", nonce, signature)
```

## Name validation

Names must be 1-62 characters. Lowercase letters, digits, and hyphens only. No leading/trailing hyphens, no double hyphens.

```kotlin
isValidName("alice")    // true
isValidName("my-name")  // true
isValidName("Alice")    // false -- uppercase
isValidName("my--name") // false -- double hyphen
isValidName("-name")    // false -- leading hyphen
```

## Pricing

```kotlin
val status = client.status()
val cost = claimCost(status.pricing!!.tiers, 5) // 5-char name
```

Index 0 = 1-char names, index 1 = 2-char, etc. Names longer than the tiers array clamp to the last entry.

## ZIP-321 URIs

```kotlin
// Build
val uri = buildZcashUri("utest1abc...", "0.75", "ZNS:CLAIM:alice:utest1abc...:sig")

// Parse
val parts = parseZip321Uri(uri)
// Zip321Parts(address="utest1abc...", amount="0.75", memoRaw="...", memoDecoded="ZNS:CLAIM:...")
```

## Custom endpoint

By default the SDK connects to `https://light.zcash.me/zns-testnet`. Point it at your own instance:

```kotlin
val client = ZnsClient.create("http://localhost:3000")
```

On connect, the SDK verifies the indexer's UIVK matches a known ZNS key. Skip this if you trust the endpoint:

```kotlin
val client = ZnsClient.create("http://localhost:3000", skipVerify = true)
```
