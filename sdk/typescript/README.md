# Zcash Name System (ZNS) SDK

TypeScript SDK for interacting with the Zcash Name System — a decentralized naming system built on Zcash.

## Install

```bash
npm install zcashname-sdk
```

## Quick Start

```ts
import { ZNS } from "zcashname-sdk";

const zns = await ZNS.create();

const name = "alice";
const resolved = await zns.resolve(name);
if (resolved === null) {
  console.log(`${name} is available`);
} else {
  console.log(`${name} resolves to ${resolved.address}`);
}
```

## API

### `ZNS.create(options?)`
Create a new ZNS instance connected to the default testnet endpoint.

```ts
const zns = await ZNS.create();
const znsMainnet = await ZNS.create({ url: "https://light.zcash.me/zns-mainnet" });
```

### `zns.resolve(query)`
Resolve a name to its registered address. Returns `null` if the name is available.

```ts
const result = await zns.resolve("alice");
```

### `zns.isAvailable(name)`
Check if a name is available for registration.

```ts
const available = await zns.isAvailable("bob");
```

### `zns.listings()`
Get all names currently listed for sale.

```ts
const listings = await zns.listings();
```

### `zns.events(filter?)`
Query blockchain events (claims, buys, lists, delists, updates, releases).

```ts
const { events } = await zns.events({ action: "CLAIM", limit: 50 });
```

### Action Helpers

The SDK provides prepare/complete pairs for all ZNS actions:

- `zns.prepareClaim(name, address)` / `zns.completeClaim(...)` — claim a name
- `zns.prepareList(name, price, nonce)` / `zns.completeList(...)` — list a name for sale
- `zns.prepareDelist(name, nonce)` / `zns.completeDelist(...)` — delist a name
- `zns.prepareUpdate(name, newAddress, nonce)` / `zns.completeUpdate(...)` — update a name's address
- `zns.prepareBuy(name, buyerAddress)` / `zns.completeBuy(...)` — buy a name
- `zns.prepareRelease(name, nonce)` / `zns.completeRelease(...)` — release a name

Each `complete*` method returns a `{ memo, uri }` object suitable for constructing a ZIP 321 URI.

### `zns.parseZip321Uri(uri)`
Parse a ZIP 321 URI into its components.

```ts
const parsed = zns.parseZip321Uri("zcash:addr?amount=0.1&memo=...");
```

## Constants

- `DEFAULT_URL` — default testnet endpoint
- `TESTNET_UIVK` — expected testnet UIVK for verification
- `MAINNET_UIVK` — expected mainnet UIVK for verification

## License

MIT