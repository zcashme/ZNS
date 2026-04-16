from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


Action = Literal[
    "CLAIM", "LIST", "DELIST", "RELEASE", "UPDATE", "BUY", "SETPRICE"
]


@dataclass
class Registration:
    name: str
    address: str
    txid: str
    height: int
    nonce: int
    signature: str | None
    last_action: str
    pubkey: str | None


@dataclass
class Listing:
    name: str
    price: int
    nonce: int
    txid: str
    height: int
    signature: str
    pubkey: str | None = None


@dataclass
class ResolveResult(Registration):
    listing: Listing | None = None


@dataclass
class Pricing:
    nonce: int
    height: int
    tiers: list[int]


@dataclass
class StatusResult:
    synced_height: int
    admin_pubkey: str
    uivk: str
    address: str
    registered: int
    listed: int
    pricing: Pricing | None


@dataclass
class Event:
    id: int
    name: str
    action: Action
    txid: str
    height: int
    ua: str | None
    price: int | None
    nonce: int | None
    signature: str | None
    pubkey: str | None


@dataclass
class EventsFilter:
    name: str | None = None
    action: str | None = None
    since_height: int | None = None
    limit: int | None = None
    offset: int | None = None


@dataclass
class EventsResult:
    events: list[Event]
    total: int
