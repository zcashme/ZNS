# zcashname-sdk

Python SDK for the Zcash Name System (ZNS) JSON-RPC API.

## Installation

```bash
pip install zcashname-sdk
```

## Quick start

```python
import asyncio
from zcashname import ZNSClient, is_valid_name, claim_cost

async def main():
    # Create a client (verifies the indexer UIVK by default)
    client = await ZNSClient.create()

    # Check indexer status
    status = await client.status()
    print(f"Synced to height {status.synced_height}")
    print(f"Registered names: {status.registered}")

    # Resolve a name
    result = await client.resolve("satoshi")
    if result is not None and not isinstance(result, list):
        print(f"satoshi -> {result.address}")
    else:
        print("satoshi is not registered")

    # Check availability
    available = await client.is_available("myname")
    print(f"myname available: {available}")

    # Validate a name
    print(is_valid_name("hello"))    # True
    print(is_valid_name("HELLO"))    # False
    print(is_valid_name("a--b"))     # False

    # Compute claim cost
    if status.pricing:
        cost = claim_cost(status.pricing.tiers, len("myname"))
        print(f"Cost to claim 'myname': {cost} zats")

asyncio.run(main())
```

## Memo building

```python
from zcashname import build_claim_memo, claim_payload

# Build the signing payload
payload = claim_payload("myname", "u1address...")

# After signing the payload with your wallet, build the memo
memo = build_claim_memo("myname", "u1address...", "signature_hex")
```

## ZIP-321 URIs

```python
from zcashname import build_zcash_uri, parse_zip321_uri

uri = build_zcash_uri("u1addr...", amount=0.001, memo="ZNS:CLAIM:myname:u1addr...:sig")
parts = parse_zip321_uri(uri)
print(parts.address, parts.amount, parts.memo_decoded)
```

## API reference

### Client

- `ZNSClient.create(url?, skip_verify?)` -- create a verified client
- `client.resolve(query)` -- resolve a name or address
- `client.listings()` -- list all names for sale
- `client.status()` -- indexer status and pricing info
- `client.events(filter?)` -- query the event log
- `client.is_available(name)` -- check name availability
- `client.get_nonce(name)` -- get current nonce for a name

### Validation

- `is_valid_name(name)` -- validate a ZNS name

### Pricing

- `claim_cost(tiers, name_length)` -- compute claim cost in zats

### Memo helpers

- `claim_payload`, `buy_payload`, `list_payload`, `delist_payload`, `update_payload`, `set_price_payload`
- `build_claim_memo`, `build_buy_memo`, `build_list_memo`, `build_delist_memo`, `build_update_memo`, `build_set_price_memo`

### ZIP-321

- `to_base64_url(text)` / `decode_base64_url(value)`
- `build_zcash_uri(address, amount?, memo?)`
- `parse_zip321_uri(uri)`

## License

MIT
