"""Python SDK for the Zcash Name System (ZNS) JSON-RPC API."""

from __future__ import annotations

# Core types
from .types import (
    Event,
    EventsFilter,
    EventsResult,
    Listing,
    Pricing,
    Registration,
    ResolveResult,
    StatusResult,
)

# Errors
from .errors import ErrorType, ZNSError

# Validation
from .validation import is_valid_name

# Client
from .client import ZNSClient

# Constants
from .constants import DEFAULT_URL, KNOWN_UIVKS, MAINNET_UIVK, TESTNET_UIVK

# Pricing
from .pricing import claim_cost

# Memo builders and signing payloads
from .memo import (
    build_buy_memo,
    build_claim_memo,
    build_delist_memo,
    build_list_memo,
    build_release_memo,
    build_set_price_memo,
    build_update_memo,
    buy_payload,
    claim_payload,
    delist_payload,
    list_payload,
    release_payload,
    set_price_payload,
    update_payload,
)

# Verification
from .verify import (
    verify_signature,
    verify_registration,
    verify_listing,
    registration_payload,
    listing_payload,
)

# ZIP-321 URI helpers
from .zip321 import (
    Zip321Parts,
    build_zcash_uri,
    decode_base64_url,
    parse_zip321_uri,
    to_base64_url,
)

__all__ = [
    # Types
    "Registration",
    "Listing",
    "ResolveResult",
    "Pricing",
    "StatusResult",
    "Event",
    "EventsFilter",
    "EventsResult",
    # Errors
    "ZNSError",
    "ErrorType",
    # Validation
    "is_valid_name",
    # Client
    "ZNSClient",
    # Constants
    "DEFAULT_URL",
    "TESTNET_UIVK",
    "MAINNET_UIVK",
    "KNOWN_UIVKS",
    # Pricing
    "claim_cost",
    # Memo
    "claim_payload",
    "buy_payload",
    "list_payload",
    "delist_payload",
    "release_payload",
    "update_payload",
    "set_price_payload",
    "build_claim_memo",
    "build_buy_memo",
    "build_list_memo",
    "build_delist_memo",
    "build_release_memo",
    "build_update_memo",
    "build_set_price_memo",
    # Verification
    "verify_signature",
    "verify_registration",
    "verify_listing",
    "registration_payload",
    "listing_payload",
    # ZIP-321
    "to_base64_url",
    "decode_base64_url",
    "build_zcash_uri",
    "parse_zip321_uri",
    "Zip321Parts",
]
