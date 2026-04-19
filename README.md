<h1 align="center">ZNS</h1>

<p align="center">
  <em>A shielded name service for Zcash.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-experimental-red" alt="status">
  <img src="https://img.shields.io/badge/rust-2024-orange?logo=rust" alt="rust 2024">
  <img src="https://img.shields.io/github/stars/zcashme/ZNS?style=flat" alt="stars">
  <br />
  <a href="https://x.com/zcashme"><img src="https://img.shields.io/badge/X-@zcashme-000?logo=x" alt="X"></a>
  <a href="https://discord.gg/z2H23QgAGf"><img src="https://img.shields.io/badge/Discord-zcashme-5865F2?logo=discord&logoColor=white" alt="Discord"></a>
  <a href="https://t.me/zcashme"><img src="https://img.shields.io/badge/Telegram-zcashme-26A5E4?logo=telegram&logoColor=white" alt="Telegram"></a>
</p>

<p align="center">
  <a href="#indexer">Indexer</a>
  &nbsp;·&nbsp;
  <a href="#protocol">Protocol</a>
  &nbsp;·&nbsp;
  <a href="#try-it">Try it</a>
  &nbsp;·&nbsp;
  <a href="#claim-a-name">Claim a name</a>
  &nbsp;·&nbsp;
  <a href="#self-hosting">Self-hosting</a>
  &nbsp;·&nbsp;
  <a href="./openrpc.json">OpenRPC</a>
</p>

<br />

ZNS maps human-readable names like `alice.zcash` to Zcash shielded addresses. Each protocol action (claim, list, buy, etc.) is an Ed25519-signed memo inside an Orchard note, authorized by a single **admin key** held by the registry operator. An indexer scans the chain, verifies every signature, and exposes a JSON-RPC API; any client can re-verify the indexer's responses against the admin pubkey it publishes via its `status` method.

## Indexer

The indexer turns the chain into a name service:

- Streams blocks from lightwalletd
- Decodes ZNS memos out of shielded Orchard payments
- Verifies the admin signature on each one
- Writes the result to a local SQLite database
- Serves it over JSON-RPC

State is a pure function of `(chain, viewing key, admin pubkey)`, so two indexers given the same inputs converge on the same database. Don't trust the public one? Run your own.

## Protocol

ZNS lives in the 512-byte Orchard memo field as a colon-delimited UTF-8 string. The `:` byte is the only delimiter and is forbidden inside fields.

| Action  | Memo                                                        | Accepted if                            |
|---------|-------------------------------------------------------------|----------------------------------------|
| Claim   | `ZNS:CLAIM:<name>:<ua>:<sig>[:<user_pubkey>]`               | name free, payment ≥ tier cost         |
| List    | `ZNS:LIST:<name>:<price>:<nonce>:<sig>[:<user_pubkey>]`     | name owned, nonce strictly increasing  |
| Delist  | `ZNS:DELIST:<name>:<nonce>:<sig>[:<user_pubkey>]`           | name listed, nonce strictly increasing |
| Release | `ZNS:RELEASE:<name>:<nonce>:<sig>[:<user_pubkey>]`          | name owned, nonce strictly increasing  |
| Update  | `ZNS:UPDATE:<name>:<new_ua>:<nonce>:<sig>[:<user_pubkey>]`  | name owned, nonce strictly increasing  |
| Buy     | `ZNS:BUY:<name>:<buyer_ua>:<sig>[:<user_pubkey>]`           | name listed, payment ≥ listing price   |

`[:<user_pubkey>]` is optional. When present, `<sig>` must be signed by that key instead of the admin key, and all future actions on the name must be signed by the same key. This is **sovereign ownership** - the name is controlled by the user's key, not the registry operator's.

`<sig>` is base64 Ed25519 over everything between `ZNS:` and `:<sig>`:

```
CLAIM:<name>:<ua>
UPDATE:<name>:<new_ua>:<nonce>
BUY:<name>:<buyer_ua>
LIST:<name>:<price>:<nonce>
DELIST:<name>:<nonce>
RELEASE:<name>:<nonce>
```

To verify, reconstruct one of these byte-for-byte from the API response. If the response includes a non-null `pubkey` field, Ed25519-verify against that key; otherwise verify against `status.admin_pubkey`.

Field encoding:

- **Names**: `[a-z0-9]{1,62}`
- **Numbers**: decimal ASCII, no leading zeros
- **Addresses**: exact bech32m, verbatim
- **Nonces**: per-name, strictly increasing, reset to 0 on `BUY`

Reference implementation: [src/memo.rs](./src/memo.rs).

Shorter names cost more zatoshis to claim; current tiers live in `status.pricing.tiers` (indexed by length, last entry catchall, `0` free).

## Try it

ZcashMe runs a public read-only deployment:

| Network | URL                                       |
|---------|-------------------------------------------|
| Testnet | `https://light.zcash.me/zns-testnet`      |
| Mainnet | `https://light.zcash.me/zns-mainnet-test` |

The admin pubkey for both is `ce86eb1b2030a4cde6b42d15a3850e9346dcf58820d20743783f1d09000e5c8e`, also returned as `status.admin_pubkey`. Examples below are `curl`s you can paste straight into a terminal, showing only the `result` field (full schema in [openrpc.json](./openrpc.json)).

### resolve

Who is `alice`? Pass an empty string as the query to list **all** registrations, paginated with `limit`/`offset` just like the `listings` method.

```sh
# Exact name lookup (returns object or null)
curl -s https://light.zcash.me/zns-mainnet-test \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"resolve","params":["alice"]}'

# List all registrations (first 50 results)
curl -s https://light.zcash.me/zns-mainnet-test \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"resolve","params":["", 50, 0]}'

# List all registrations (next page)
curl -s https://light.zcash.me/zns-mainnet-test \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"resolve","params":["", 50, 50]}'

# Query by address to get all names for that address (paginated)
curl -s https://light.zcash.me/zns-mainnet-test \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"resolve","params":["u1qqlzrf9...", 100, 0]}'
```

Single name query returns an object or `null`:
```json
{
  "name": "alice",
  "address": "u1qq...fff",
  "height": 3901200,
  "nonce": 2,
  "last_action": "UPDATE",
  "signature": "AQID...",
  "pubkey": null,
  "listing": null
}
```

Listing all registrations or querying by address returns an array:
```json
[
  {
    "name": "alice",
    "address": "u1qq...fff",
    "height": 3901200,
    ...
  },
  {
    "name": "bob",
    "address": "u1qq...aaa",
    "height": 3901100,
    ...
  }
]
```

- **Empty query** (`""`) with `limit`/`offset` lists all registered names, useful for explorers or browsers.
- **Exact name** query returns single object or `null` if not found.
- **Address** query returns array of all names registered to that address (paginated).
- If a name is listed for sale, `listing` contains details (`price`, `nonce`, `signature`).
- `pubkey` is `null` for admin-signed names; for sovereign names it's the owner's Ed25519 public key.
- Pagination follows the same `limit`/`offset` pattern as the `listings` and `events` endpoints.

### listings

What's on the market? Use `limit` and `offset` to paginate – defaults are `limit=50`, `offset=0`, and `limit` caps at 500.

```sh
# First 50 listings (default)
curl -s https://light.zcash.me/zns-mainnet-test \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"listings","params":[]}'

# Next page (offset 50)
curl -s https://light.zcash.me/zns-mainnet-test \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"listings","params":[50, 50]}'
```

```json
{
  "listings": [
    { "name": "bob",   "price": 100000000, "nonce": 3, "height": 3901300, "signature": "..." },
    { "name": "carol", "price":  50000000, "nonce": 1, "height": 3901250, "signature": "..." }
  ],
  "total": 2
}
```

Prices in zatoshis (1 ZEC = 100M zats): `bob` wants a full ZEC, `carol` half.

### status

Sync height, admin pubkey, current pricing. The first call any client makes.

```sh
curl -s https://light.zcash.me/zns-mainnet-test \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"status"}'
```

```json
{
  "synced_height": 3902500,
  "admin_pubkey": "ce86eb1b2030a4cde6b42d15a3850e9346dcf58820d20743783f1d09000e5c8e",
  "uivk": "uivk1...",
  "registered": 42,
  "listed": 3,
  "pricing": {
    "nonce": 1,
    "height": 3901000,
    "tiers": [500000000, 100000000, 50000000, 10000000, 5000000]
  }
}
```

### events

The full activity log. Filter by `name`, `action`, or `since_height`; paginate with `limit` / `offset`. Every event carries its signature, so the log is auditable years later.

```sh
# Filter by name
curl -s https://light.zcash.me/zns-mainnet-test \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"events","params":{"name":"alice"}}'

# Paginate results (first 50 events, starting from position 0)
curl -s https://light.zcash.me/zns-mainnet-test \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"events","params":{"name":"alice","limit":50,"offset":0}}'

# Next page (events 51-100)
curl -s https://light.zcash.me/zns-mainnet-test \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"events","params":{"name":"alice","limit":50,"offset":50}}'

# Get all CLAIM actions
curl -s https://light.zcash.me/zns-mainnet-test \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"events","params":{"action":"CLAIM","limit":100}}'
```

```json
{
  "events": [
    { "id": 45, "name": "alice", "action": "LIST",  "txid": "def...", "height": 3901300, "ua": "u1qq...fff", "price": 50000000, "nonce": 1,    "signature": "..." },
    { "id": 12, "name": "alice", "action": "CLAIM", "txid": "abc...", "height": 3901200, "ua": "u1qq...fff", "price": null,     "nonce": null, "signature": "..." }
  ],
  "total": 2
}
```

`alice`'s whole story: claimed at block 3,901,200, listed half a ZEC later.

**Pagination parameters:**
- `limit`: Maximum number of results (default 50, max 500)
- `offset`: Number of results to skip (default 0)
- `total`: Total count of matching events (for UI pagination)

All three endpoints (`resolve`, `listings`, `events`) follow the same pagination pattern.

## Claim a name

To claim a name on the public ZcashMe instance, sign with your own Ed25519 key - no admin involvement required. The key can be derived deterministically from your Zcash seed phrase using SLIP-0010, so no separate key management is needed.

```ts
import { claimPayload, buildClaimMemo } from "zns-sdk";

const payload = claimPayload("alice", "u1...");
const signature = sign(payload);       // Ed25519 sign with your key
const userPubkey = getPublicKey();     // base64-encoded Ed25519 public key

const memo = buildClaimMemo("alice", "u1...", signature, userPubkey);
```

Once claimed, all subsequent actions on the name must be signed by the same key. The ZcashMe admin key is used only for protocol-level operations (pricing tiers, etc.) - it cannot authorize actions on names you own.

## Self-hosting

The indexer is deterministic. Two instances given the same UIVK and admin pubkey converge on the same database.

### 1. Generate an admin keypair

The admin key authorizes SETPRICE and any admin-signed actions. Generate a fresh Ed25519 keypair - any standard tool works. The indexer needs the hex-encoded 32-byte public key.

```sh
# example using openssl
openssl genpkey -algorithm ed25519 -out admin.pem
openssl pkey -in admin.pem -pubout -out admin_pub.pem
```

### 2. Get a UIVK

The indexer needs a Unified Incoming Viewing Key to decrypt incoming Orchard notes. Create a Zcash wallet, export the UFVK, then extract the UIVK:

```sh
cargo run --manifest-path tools/ufvk-to-uivk/Cargo.toml -- mainnet <your-ufvk>
```

### 3. Run the indexer

```sh
docker build --build-arg FEATURES=mainnet -t zns-indexer .

docker run -d \
  -e ZNS_UIVK=uivk1... \
  -e ZNS_ADMIN_PUBKEY=<your-hex-pubkey> \
  -p 3000:3000 \
  zns-indexer
```

Substitute `FEATURES=testnet` for testnet. Everything else (network, lightwalletd URL, birthday, SQLite path) bakes in at build time via [src/config.rs](./src/config.rs).

## License

[MIT](./LICENSE)
