from __future__ import annotations

import re

# Valid ZNS names: 1-62 lowercase ASCII letters and digits. No hyphens.
_NAME_PATTERN = re.compile(r"^[a-z0-9]{1,62}$")


def is_valid_name(name: str) -> bool:
    """Return True if *name* is a valid ZNS name."""
    return bool(_NAME_PATTERN.match(name))
