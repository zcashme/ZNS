# ZNS SDK

ZNS maps human-readable names to Zcash shielded addresses. Names are registered on-chain via Orchard memos and indexed into a queryable API. This SDK talks to that API.

Testnet: `zcashna.me`

```ts
import { resolve } from "zns-sdk";

const alice = await resolve("alice");
console.log(alice?.address);
// "utest1gygneuhu84vxjuhjhpdtrd67ukalu22ncqn3mm3nkda3vskc450dl5v..."
```

## Resolve a name

The primary use case. A wallet has a name, needs an address.

```ts
const result = await resolve("alice");
// {
//   name: "alice",
//   address: "utest1...",
//   txid: "abc123...",
//   height: 3907441,
//   nonce: 2,
//   signature: "...",
//   listing: null
// }
```

Returns `null` if the name doesn't exist.

## Reverse resolve

A wallet or explorer has an address, wants to show the name.

```ts
const result = await resolve("utest1gygneuhu84vxjuhjhpdtrd67uk...");
// { name: "alice", address: "utest1...", ... }
```

Same method, same response. The indexer detects whether the query is a name or an address.

## Check availability

```ts
import { isAvailable } from "zns-sdk";

if (await isAvailable("myname")) {
  // name is not registered
}
```

## Name history

Full activity chain for a name. Useful for explorers showing ownership history, sales, updates.

```ts
import { events } from "zns-sdk";

const history = await events({ name: "alice" });
// {
//   events: [
//     { id: 2, name: "alice", action: "UPDATE", txid: "...", height: 3907445, ua: "utest1new...", price: null, nonce: 1, signature: "..." },
//     { id: 1, name: "alice", action: "CLAIM",  txid: "...", height: 3907441, ua: "utest1old...", price: null, nonce: null, signature: null },
//   ],
//   total: 2
// }
```

Events are ordered newest-first. Each event records the action, the transaction that triggered it, the block height, and action-specific data.

## All activity

Global feed across all names. Filter by action type, block height, or combine.

```ts
// Everything
await events();

// All registered names
await events({ action: "CLAIM" });

// Recent sales
await events({ action: "BUY", since_height: 3910000 });

// Listing and delisting activity
await events({ action: ["LIST", "DELIST"] });

// Paginate
await events({ limit: 50, offset: 50 });
```

`total` in the response gives you the full count before pagination, so you know how many pages exist.

## Register a name

Registration is a two-step process: build the memo, then send a Zcash transaction with that memo and the correct payment amount.

```ts
import { buildClaimMemo, claimCost, buildZcashUri } from "zns-sdk";

const name = "alice";
const ua = "utest1abc..."; // the address this name should resolve to

// 1. Build the memo
const memo = buildClaimMemo(name, ua);
// "ZNS:CLAIM:alice:utest1abc..."

// 2. Get the cost in zatoshis
const cost = claimCost(name.length);
// 75_000_000 (0.75 ZEC for a 5-letter name)

// 3. Build a payment URI (useful for wallet integrations)
const uri = buildZcashUri(ua, cost / 1e8, memo);
// "zcash:utest1abc...?amount=0.75&memo=..."
```

The transaction must be sent to the ZNS registry address with at least `claimCost` zatoshis. The indexer picks up the memo from the shielded transaction and processes the claim.

### Pricing

| Length | Cost |
|--------|------|
| 1 char | 6 ZEC |
| 2 chars | 4.25 ZEC |
| 3 chars | 3 ZEC |
| 4 chars | 1.5 ZEC |
| 5 chars | 0.75 ZEC |
| 6 chars | 0.50 ZEC |
| 7+ chars | 0.25 ZEC |

## Marketplace actions

LIST, DELIST, UPDATE, and BUY. The first three require an Ed25519 admin signature. BUY just requires payment.

### List a name for sale

```ts
import { listPayload, buildListMemo, getNonce } from "zns-sdk";

const nonce = (await getNonce("alice"))! + 1;

// 1. Build the signing payload
const payload = listPayload("alice", 50_000_000, nonce);
// "LIST:alice:50000000:1"

// 2. Sign it with Ed25519 (your signing logic)
const signature = sign(payload);

// 3. Build the memo
const memo = buildListMemo("alice", 50_000_000, nonce, signature);
// "ZNS:LIST:alice:50000000:1:<base64-signature>"
```

### Buy a listed name

```ts
import { buildBuyMemo } from "zns-sdk";

const memo = buildBuyMemo("alice", "utest1buyer...");
// "ZNS:BUY:alice:utest1buyer..."
```

Send a transaction with this memo and at least the listing price in zatoshis.

### Delist a name

```ts
import { delistPayload, buildDelistMemo, getNonce } from "zns-sdk";

const nonce = (await getNonce("alice"))! + 1;
const payload = delistPayload("alice", nonce);
const signature = sign(payload);
const memo = buildDelistMemo("alice", nonce, signature);
```

### Update a name's address

```ts
import { updatePayload, buildUpdateMemo, getNonce } from "zns-sdk";

const nonce = (await getNonce("alice"))! + 1;
const payload = updatePayload("alice", "utest1newaddr...", nonce);
const signature = sign(payload);
const memo = buildUpdateMemo("alice", "utest1newaddr...", nonce, signature);
```

## Name rules

Names must be 1-62 characters. Lowercase letters, digits, and hyphens only. No leading/trailing hyphens, no double hyphens.

```ts
import { isValidName } from "zns-sdk";

isValidName("alice");     // true
isValidName("my-name");   // true
isValidName("Alice");     // false -- uppercase
isValidName("my--name");  // false -- double hyphen
isValidName("-name");     // false -- leading hyphen
```

## Run your own indexer

By default the SDK connects to `https://names.zcash.me`. Point it at your own instance:

```ts
import { createClient } from "zns-sdk";

const client = await createClient("http://localhost:3000");
```

On connect, the SDK verifies the indexer's UFVK matches the expected testnet key. Skip this if you trust the endpoint:

```ts
const client = await createClient("http://localhost:3000", { skipVerify: true });
```

## Verify independently

Every LIST, DELIST, and UPDATE action is signed with an Ed25519 key. The indexer verifies signatures before accepting actions, but you don't have to trust the indexer.

The events endpoint returns the `signature` and `nonce` for every signed action. The signing payloads are deterministic:

- LIST: `LIST:{name}:{price}:{nonce}`
- DELIST: `DELIST:{name}:{nonce}`
- UPDATE: `UPDATE:{name}:{new_ua}:{nonce}`

Reconstruct the payload, verify the signature against the admin pubkey (available via `status()`), and you have independent proof the action was authorized. No chain access required.

CLAIM and BUY actions are authenticated by the Zcash transaction itself -- the sender paid ZEC, which is proof enough.

## Types

```ts
import type {
  Registration,
  Listing,
  ResolveResult,
  StatusResult,
  Event,
  EventsFilter,
  EventsResult,
  ZNSClient,
  Zip321Parts,
} from "zns-sdk";
```
