from __future__ import annotations

from enum import IntEnum


class ErrorType(IntEnum):
    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603
    HTTP_ERROR = -1
    UIVK_MISMATCH = -2


class ZNSError(Exception):
    """Base exception for all ZNS SDK errors."""

    def __init__(self, error_type: ErrorType, message: str | None = None) -> None:
        self.error_type = error_type
        super().__init__(message or error_type.name)
