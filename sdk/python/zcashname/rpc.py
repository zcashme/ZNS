from __future__ import annotations

from typing import Any

import httpx

from .errors import ErrorType, ZNSError

_ERROR_CODES: set[int] = {e.value for e in ErrorType}


async def rpc(
    url: str,
    method: str,
    params: dict[str, Any] | None = None,
    id: int = 1,
) -> Any:
    """Send a JSON-RPC 2.0 request and return the result."""
    payload = {
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params or {},
    }

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
        except httpx.HTTPError as exc:
            raise ZNSError(ErrorType.HTTP_ERROR, str(exc)) from exc

    if response.status_code != 200:
        raise ZNSError(
            ErrorType.HTTP_ERROR,
            f"HTTP {response.status_code}: {response.reason_phrase}",
        )

    body = response.json()

    if "error" in body and body["error"] is not None:
        err = body["error"]
        code = err.get("code", ErrorType.INTERNAL_ERROR)
        error_type = ErrorType(code) if code in _ERROR_CODES else ErrorType.INTERNAL_ERROR
        raise ZNSError(error_type, err.get("message", "Unknown error"))

    return body.get("result")
