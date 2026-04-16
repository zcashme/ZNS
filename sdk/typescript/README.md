# ZNS SDK

TypeScript SDK for the Zcash Name System. Register names, manage listings, and resolve addresses on Zcash.

```bash
npm install zcashname-sdk
```

## Quick Start

```ts
import { ZNS } from "zcashname-sdk";

// Create client (synchronous, no network calls)
const zns = new ZNS();

// Resolve a name to get its Zcash address
const reg = await zns.resolveName("alice");
if (reg) console.log(`alice.zcash → ${reg.address}`);

// Check availability
const available = await zns.isAvailable("bob");

// Verify server identity (optional but recommended)
await zns.verify();
```

## Actions Flow

Every state-changing action follows the same pattern: **prepare → sign → complete**.

```ts
import * as ed25519 from "@noble/ed25519";

// 1. Fetch status to get current pricing
const status = await zns.status();
const cost = zns.claimCost(5, status.pricing);

// 2. Prepare the action
const claim = zns.prepareClaim("myname", "u1qqlzrf9...", status.address, cost);

// 3. Sign the payload with your Ed25519 private key
const privateKey = ed25519.utils.randomPrivateKey();
const signature = await ed25519.signAsync(
  new TextEncoder().encode(claim.payload),
  privateKey
);

// 4. Complete and get the payment URI
const { memo, uri } = claim.complete(
  Buffer.from(signature).toString("base64"),
  Buffer.from(ed25519.getPublicKey(privateKey)).toString("base64")
);

// 5. Send the transaction using your Zcash wallet
console.log("Payment URI:", uri);
console.log("Memo:", memo);
```

## Available Actions

| Action | Description |
|--------|-------------|
| `prepareClaim(name, address, registryAddress, cost)` | Register a new name |
| `prepareList(name, price, nonce, registryAddress)` | List name for sale |
| `prepareDelist(name, nonce, registryAddress)` | Remove listing |
| `prepareUpdate(name, newAddress, nonce, registryAddress)` | Change address |
| `prepareBuy(name, buyerAddress, registryAddress)` | Buy a listed name |
| `prepareRelease(name, nonce, registryAddress)` | Release name (burn) |
| `prepareSetPrice(prices, nonce, registryAddress)` | Admin: set pricing tiers |

## Reading Data

```ts
// Resolve name → address
const reg = await zns.resolveName("alice");

// Resolve address → names (reverse lookup)
const names = await zns.resolveAddress("u1qqlzrf9...");

// Check availability
const available = await zns.isAvailable("bob");

// Get all listings
const listings = await zns.listings();

// Query events
const { events, total } = await zns.events({ action: "CLAIM", limit: 10 });

// Get current pricing from status
const status = await zns.status();
const cost = zns.claimCost(5, status.pricing); // cost for 5-char name
```

## Server Verification (Optional)

For security-sensitive applications, verify the server identity:

```ts
const zns = new ZNS({ url: "https://your-indexer.com/zns" });

// Verify this is a legitimate ZNS instance
await zns.verify();
console.log("Verified:", zns.verified); // true

// Now proceed with operations
const status = await zns.status();
```

## Validation & Utilities

```ts
// Validate a Zcash Unified Address
const valid = zns.isValidUnifiedAddress("u1qqlzrf9..."); // true/false

// Validate a ZNS name
const validName = zns.isValidName("alice"); // true
const invalid = zns.isValidName("Alice");   // false (uppercase)

// Parse ZIP-321 URI
const parts = zns.parseZip321Uri("zcash:u1...?amount=1&memo=...");
// { address: "u1...", amount: "1", memoRaw: "...", memoDecoded: "..." }
```

## Signature Verification

```ts
// Get admin pubkey from status
const status = await zns.status();

// Verify a listing signature
const listing = await zns.listings().then(l => l[0]);
const valid = await zns.verifyListing(listing, status.admin_pubkey);

// Verify a registration
const reg = await zns.resolveName("alice");
const validReg = await zns.verifyRegistration(reg, status.admin_pubkey);
```

## Configuration

```ts
// Custom endpoint
const zns = new ZNS({ url: "https://your-indexer.com/zns" });

// Optional: verify server identity
await zns.verify(); // throws if not a known ZNS instance

// Access current status
const status = await zns.status();
console.log(status.admin_pubkey);  // Registry admin pubkey
console.log(status.pricing);       // Current pricing tiers
console.log(status.address);       // Registry payment address
```

## Constants

```ts
import { DEFAULT_URL, TESTNET_UIVK, MAINNET_UIVK } from "zcashname-sdk";

console.log(DEFAULT_URL);  // "https://light.zcash.me/zns-testnet"
```

## CLI Example

See `examples/cli/` for a working command-line interface:

```bash
# Resolve a name
npx tsx src/index.ts resolve alice

# Check availability
npx tsx src/index.ts available bob

# List all names for sale
npx tsx src/index.ts listings

# Prepare a claim (outputs payload to sign)
npx tsx src/index.ts prepare-claim myname u1qqlzrf9...

# Sign and complete with a private key
npx tsx src/index.ts sign-claim myname u1qqlzrf9... --key-file ./key.txt
```

## Types

```ts
type Zats = number; // 1 ZEC = 100,000,000 zats

interface Registration {
  name: string;
  address: string;
  txid: string;
  height: number;
  nonce: number;
  signature: string | null;
  last_action: "CLAIM" | "BUY" | "UPDATE" | "DELIST" | "RELEASE";
  pubkey: string | null;    // null = admin-registered
  listing: Listing | null;
}

interface Listing {
  name: string;
  price: Zats;
  nonce: number;
  txid: string;
  height: number;
  signature: string;
  pubkey: string | null;
}

interface Status {
  synced_height: number;
  admin_pubkey: string;
  uivk: string;
  address: string;
  registered: number;
  listed: number;
  pricing: Pricing;
}

interface Pricing {
  nonce: number;
  height: number;
  tiers: Zats[]; // cost for names of length 1, 2, 3...
}

interface PreparedClaim {
  readonly name: string;
  readonly address: string;
  readonly cost: Zats;
  readonly payload: string;  // sign this
  complete(signature: string, userPubkey?: string): CompletedAction;
}

interface CompletedAction {
  memo: string;  // ZNS:CLAIM:name:address:sig:pubkey
  uri: string;   // zcash:addr?amount=...&memo=...
}
```

## License

MIT
