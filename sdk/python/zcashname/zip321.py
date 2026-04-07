from __future__ import annotations

import base64
from dataclasses import dataclass
from urllib.parse import parse_qs


def to_base64_url(text: str) -> str:
    """Base64url-encode a UTF-8 string (no padding)."""
    try:
        encoded = base64.urlsafe_b64encode(text.encode("utf-8"))
        return encoded.rstrip(b"=").decode("ascii")
    except Exception:
        return ""


def decode_base64_url(value: str) -> str:
    """Decode a base64url-encoded string back to UTF-8."""
    try:
        normalized = value.replace("-", "+").replace("_", "/")
        padding = (4 - len(normalized) % 4) % 4
        padded = normalized + "=" * padding
        raw = base64.b64decode(padded)
        return raw.decode("utf-8")
    except Exception:
        return ""


@dataclass
class Zip321Parts:
    address: str
    amount: str
    memo_raw: str
    memo_decoded: str


def build_zcash_uri(
    address: str,
    amount: str | float | None = None,
    memo: str | None = None,
) -> str:
    """Build a ``zcash:`` payment URI following ZIP-321."""
    if not address:
        return ""
    base = f"zcash:{address}"
    params: list[str] = []
    if amount is not None and float(amount) > 0:
        params.append(f"amount={amount}")
    if memo:
        params.append(f"memo={to_base64_url(memo)}")
    return f"{base}?{'&'.join(params)}" if params else base


def parse_zip321_uri(uri: str) -> Zip321Parts:
    """Parse a ``zcash:`` payment URI into its constituent parts."""
    without_scheme = (uri or "").removeprefix("zcash:").removeprefix("ZCASH:")
    parts = without_scheme.split("?", 1)
    address = parts[0].strip()
    query = parts[1] if len(parts) > 1 else ""

    parsed = parse_qs(query, keep_blank_values=True)
    amount = (parsed.get("amount", [""])[0] or "").strip()
    memo_raw = (parsed.get("memo", [""])[0] or "").strip()
    memo_decoded = decode_base64_url(memo_raw) if memo_raw else ""

    return Zip321Parts(
        address=address,
        amount=amount,
        memo_raw=memo_raw,
        memo_decoded=memo_decoded,
    )
