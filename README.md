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

| Action  | Memo                                       | Accepted if                            |
|---------|--------------------------------------------|----------------------------------------|
| Claim   | `ZNS:CLAIM:<name>:<ua>:<sig>`              | name free, payment ≥ tier cost         |
| List    | `ZNS:LIST:<name>:<price>:<nonce>:<sig>`    | name owned, nonce strictly increasing  |
| Delist  | `ZNS:DELIST:<name>:<nonce>:<sig>`          | name listed, nonce strictly increasing |
| Release | `ZNS:RELEASE:<name>:<nonce>:<sig>`         | name owned, nonce strictly increasing  |
| Update  | `ZNS:UPDATE:<name>:<new_ua>:<nonce>:<sig>` | name owned, nonce strictly increasing  |
| Buy     | `ZNS:BUY:<name>:<buyer_ua>:<sig>`          | name listed, payment ≥ listing price   |

`<sig>` is base64 Ed25519 over everything between `ZNS:` and `:<sig>`:

```
CLAIM:<name>:<ua>
UPDATE:<name>:<new_ua>:<nonce>
BUY:<name>:<buyer_ua>
LIST:<name>:<price>:<nonce>
DELIST:<name>:<nonce>
RELEASE:<name>:<nonce>
```

To verify, reconstruct one of these byte-for-byte from the API response and Ed25519-verify against `status.admin_pubkey`.

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

Who is `alice`?

```sh
curl -s https://light.zcash.me/zns-mainnet-test \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"resolve","params":{"query":"alice"}}'
```

```json
{
  "name": "alice",
  "address": "u1qq...fff",
  "height": 3901200,
  "nonce": 2,
  "last_action": "UPDATE",
  "signature": "AQID...",
  "listing": null
}
```

- If `alice` were for sale, `listing` would be a `{price, nonce, signature, ...}` object instead of `null`
- Query by address (not name) to get an array of every name resolving to it

### list_for_sale

What's on the market?

```sh
curl -s https://light.zcash.me/zns-mainnet-test \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"list_for_sale"}'
```

```json
{
  "listings": [
    { "name": "bob",   "price": 100000000, "nonce": 3, "height": 3901300, "signature": "..." },
    { "name": "carol", "price":  50000000, "nonce": 1, "height": 3901250, "signature": "..." }
  ]
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
curl -s https://light.zcash.me/zns-mainnet-test \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"events","params":{"name":"alice"}}'
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

## Claim a name

Names need an admin signature. Ask in [Discord](https://discord.gg/z2H23QgAGf), then build and submit the memo with the [TypeScript SDK](./sdk/typescript).

## Self-hosting

The indexer is deterministic. Two instances given the same UIVK and admin pubkey converge on the same database.

```sh
docker build --build-arg FEATURES=mainnet -t zns-indexer .

docker run -d \
  -e ZNS_UIVK=uivk1... \
  -e ZNS_ADMIN_PUBKEY=ce86eb1b2030a4cde6b42d15a3850e9346dcf58820d20743783f1d09000e5c8e \
  -p 3000:3000 \
  zns-indexer
```

Substitute `FEATURES=testnet` for testnet. Everything else (network, lightwalletd URL, birthday, SQLite path) bakes in at build time via [src/config.rs](./src/config.rs).

## License

[MIT](./LICENSE)
