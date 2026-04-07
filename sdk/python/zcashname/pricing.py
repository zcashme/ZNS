from __future__ import annotations


def claim_cost(tiers: list[int], name_length: int) -> int | None:
    """Compute the claim cost in zatoshis for a name of the given length.

    *tiers* comes from ``StatusResult.pricing.tiers`` (already in zatoshis).
    Index 0 corresponds to 1-char names, index 1 to 2-char names, etc.
    Names longer than the array clamp to the last entry.

    Returns ``None`` if *tiers* is empty.
    """
    if not tiers:
        return None
    idx = min(max(name_length - 1, 0), len(tiers) - 1)
    return tiers[idx]
