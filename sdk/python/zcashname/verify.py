from __future__ import annotations

import base64
from typing import TYPE_CHECKING

from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

if TYPE_CHECKING:
    from .types import Registration, Listing


def verify_signature(payload: str, signature_b64: str, pubkey_b64: str) -> bool:
    try:
        sig_bytes = base64.b64decode(signature_b64)
        pk_bytes = base64.b64decode(pubkey_b64)
        if len(sig_bytes) != 64 or len(pk_bytes) != 32:
            return False
        vk = VerifyKey(pk_bytes)
        vk.verify(payload.encode(), sig_bytes)
        return True
    except (BadSignatureError, Exception):
        return False


def registration_payload(reg: Registration) -> str:
    match reg.last_action:
        case "CLAIM":
            return f"CLAIM:{reg.name}:{reg.address}"
        case "BUY":
            return f"BUY:{reg.name}:{reg.address}"
        case "UPDATE":
            return f"UPDATE:{reg.name}:{reg.address}:{reg.nonce}"
        case "DELIST":
            return f"DELIST:{reg.name}:{reg.nonce}"
        case "RELEASE":
            return f"RELEASE:{reg.name}:{reg.nonce}"
        case _:
            return ""


def listing_payload(listing: Listing) -> str:
    return f"LIST:{listing.name}:{listing.price}:{listing.nonce}"


def verify_registration(reg: Registration, admin_pubkey: str) -> bool:
    if not reg.signature:
        return False
    payload = registration_payload(reg)
    if not payload:
        return False
    pubkey = reg.pubkey or admin_pubkey
    return verify_signature(payload, reg.signature, pubkey)


def verify_listing(listing: Listing, admin_pubkey: str) -> bool:
    payload = listing_payload(listing)
    return verify_signature(payload, listing.signature, admin_pubkey)