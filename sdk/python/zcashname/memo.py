from __future__ import annotations

from .validation import is_valid_name

# ---------------------------------------------------------------------------
# Signing payloads
# ---------------------------------------------------------------------------


def claim_payload(name: str, ua: str) -> str:
    return f"CLAIM:{name}:{ua}"


def buy_payload(name: str, buyer_ua: str) -> str:
    return f"BUY:{name}:{buyer_ua}"


def list_payload(name: str, price: int, nonce: int) -> str:
    return f"LIST:{name}:{price}:{nonce}"


def delist_payload(name: str, nonce: int) -> str:
    return f"DELIST:{name}:{nonce}"


def release_payload(name: str, nonce: int) -> str:
    return f"RELEASE:{name}:{nonce}"


def update_payload(name: str, new_ua: str, nonce: int) -> str:
    return f"UPDATE:{name}:{new_ua}:{nonce}"


def set_price_payload(prices: list[int], nonce: int) -> str:
    joined = ":".join(str(p) for p in prices)
    return f"SETPRICE:{len(prices)}:{joined}:{nonce}"


# ---------------------------------------------------------------------------
# Memo builders
# ---------------------------------------------------------------------------


def _require_valid(name: str) -> None:
    if not is_valid_name(name):
        raise ValueError(f"Invalid name: {name}")


def build_claim_memo(name: str, ua: str, signature: str, user_pubkey: str | None = None) -> str:
    _require_valid(name)
    base = f"ZNS:CLAIM:{name}:{ua}:{signature}"
    return f"{base}:{user_pubkey}" if user_pubkey else base


def build_buy_memo(name: str, buyer_ua: str, signature: str, user_pubkey: str | None = None) -> str:
    _require_valid(name)
    base = f"ZNS:BUY:{name}:{buyer_ua}:{signature}"
    return f"{base}:{user_pubkey}" if user_pubkey else base


def build_list_memo(name: str, price: int, nonce: int, signature: str, user_pubkey: str | None = None) -> str:
    _require_valid(name)
    base = f"ZNS:LIST:{name}:{price}:{nonce}:{signature}"
    return f"{base}:{user_pubkey}" if user_pubkey else base


def build_delist_memo(name: str, nonce: int, signature: str, user_pubkey: str | None = None) -> str:
    _require_valid(name)
    base = f"ZNS:DELIST:{name}:{nonce}:{signature}"
    return f"{base}:{user_pubkey}" if user_pubkey else base


def build_release_memo(name: str, nonce: int, signature: str, user_pubkey: str | None = None) -> str:
    _require_valid(name)
    base = f"ZNS:RELEASE:{name}:{nonce}:{signature}"
    return f"{base}:{user_pubkey}" if user_pubkey else base


def build_update_memo(name: str, new_ua: str, nonce: int, signature: str, user_pubkey: str | None = None) -> str:
    _require_valid(name)
    base = f"ZNS:UPDATE:{name}:{new_ua}:{nonce}:{signature}"
    return f"{base}:{user_pubkey}" if user_pubkey else base


def build_set_price_memo(prices: list[int], nonce: int, signature: str) -> str:
    joined = ":".join(str(p) for p in prices)
    return f"ZNS:SETPRICE:{len(prices)}:{joined}:{nonce}:{signature}"
