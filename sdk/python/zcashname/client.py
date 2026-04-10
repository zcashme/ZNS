from __future__ import annotations

from typing import Any

from .constants import DEFAULT_URL, KNOWN_UIVKS
from .errors import ErrorType, ZNSError
from .rpc import rpc
from .types import (
    Event,
    EventsFilter,
    EventsResult,
    Listing,
    Pricing,
    ResolveResult,
    StatusResult,
)


def _parse_listing(data: dict[str, Any]) -> Listing:
    return Listing(
        name=data["name"],
        price=data["price"],
        nonce=data["nonce"],
        txid=data["txid"],
        height=data["height"],
        signature=data["signature"],
    )


def _parse_pricing(data: dict[str, Any] | None) -> Pricing | None:
    if data is None:
        return None
    return Pricing(
        nonce=data["nonce"],
        height=data["height"],
        tiers=data["tiers"],
    )


def _parse_status(data: dict[str, Any]) -> StatusResult:
    return StatusResult(
        synced_height=data["synced_height"],
        admin_pubkey=data["admin_pubkey"],
        uivk=data["uivk"],
        address=data["address"],
        registered=data["registered"],
        listed=data["listed"],
        pricing=_parse_pricing(data.get("pricing")),
    )


def _parse_resolve(data: dict[str, Any]) -> ResolveResult:
    listing_data = data.get("listing")
    return ResolveResult(
        name=data["name"],
        address=data["address"],
        txid=data["txid"],
        height=data["height"],
        nonce=data["nonce"],
        signature=data.get("signature"),
        last_action=data["last_action"],
        pubkey=data.get("pubkey"),
        listing=_parse_listing(listing_data) if listing_data else None,
    )


def _parse_event(data: dict[str, Any]) -> Event:
    return Event(
        id=data["id"],
        name=data["name"],
        action=data["action"],
        txid=data["txid"],
        height=data["height"],
        ua=data.get("ua"),
        price=data.get("price"),
        nonce=data.get("nonce"),
        signature=data.get("signature"),
        pubkey=data.get("pubkey"),
    )


class ZNSClient:
    """Async client for the Zcash Name System JSON-RPC API."""

    def __init__(self, url: str, verified: bool) -> None:
        self._url = url
        self._verified = verified
        self._next_id = 1

    @property
    def url(self) -> str:
        return self._url

    @property
    def verified(self) -> bool:
        return self._verified

    @classmethod
    async def create(
        cls,
        url: str = DEFAULT_URL,
        skip_verify: bool = False,
    ) -> ZNSClient:
        """Create a new client, optionally verifying the indexer UIVK."""
        client = cls(url=url, verified=False)

        if not skip_verify:
            status = await client.status()
            if status.uivk not in KNOWN_UIVKS:
                raise ZNSError(
                    ErrorType.UIVK_MISMATCH,
                    f'UIVK mismatch: indexer returned "{status.uivk[:20]}..." '
                    f"which is not a known ZNS instance",
                )
            client._verified = True

        return client

    async def _call(self, method: str, params: dict[str, Any] | None = None) -> Any:
        result = await rpc(self._url, method, params, self._next_id)
        self._next_id += 1
        return result

    async def resolve(self, query: str) -> ResolveResult | list[ResolveResult] | None:
        """Resolve a name or address. Returns a single result, a list, or None."""
        result = await self._call("resolve", {"query": query})
        if result is None:
            return None
        if isinstance(result, list):
            return [_parse_resolve(r) for r in result]
        return _parse_resolve(result)

    async def listings(self) -> list[Listing]:
        """Return all names currently listed for sale."""
        result = await self._call("list_for_sale")
        return [_parse_listing(item) for item in result.get("listings", [])]

    async def status(self) -> StatusResult:
        """Return the current indexer status."""
        result = await self._call("status")
        return _parse_status(result)

    async def events(self, filter: EventsFilter | None = None) -> EventsResult:
        """Query the event log with optional filters."""
        params: dict[str, Any] = {}
        if filter is not None:
            if filter.name is not None:
                params["name"] = filter.name
            if filter.action is not None:
                params["action"] = filter.action
            if filter.since_height is not None:
                params["since_height"] = filter.since_height
            if filter.limit is not None:
                params["limit"] = filter.limit
            if filter.offset is not None:
                params["offset"] = filter.offset

        result = await self._call("events", params)
        return EventsResult(
            events=[_parse_event(e) for e in result.get("events", [])],
            total=result.get("total", 0),
        )

    async def is_available(self, name: str) -> bool:
        """Check whether a name is available for registration."""
        result = await self.resolve(name)
        return result is None

    async def get_nonce(self, name: str) -> int | None:
        """Return the current nonce for a registered name, or None."""
        result = await self.resolve(name)
        if result is None or isinstance(result, list):
            return None
        return result.nonce
