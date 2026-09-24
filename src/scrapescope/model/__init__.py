"""Cost and what-if model.

Costs are "estimated billable transfer" at the user's own rate (there is no
default rate); what-if savings are on the "allocated" basis and always carry
caveats. See ``model.cost`` and ``model.what_if`` for the accuracy limits.
Contract: docs/dev/contracts.md section 9.
"""

from __future__ import annotations

from .cost import MONEY_DECIMALS, compute_cost
from .what_if import (
    BLOCKABLE_TYPES,
    BLOCKING_CAVEAT,
    CACHE_CAVEAT,
    COMPARE_CAVEAT,
    background_bytes,
    blockable_bytes,
    compute_what_if,
    share_of,
)

__all__ = [
    "BLOCKABLE_TYPES",
    "BLOCKING_CAVEAT",
    "CACHE_CAVEAT",
    "COMPARE_CAVEAT",
    "MONEY_DECIMALS",
    "background_bytes",
    "blockable_bytes",
    "compute_cost",
    "compute_what_if",
    "share_of",
]
