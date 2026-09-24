"""Integer proportional allocation (largest-remainder method).

Used to share one host's tunnel-measured bytes over the requests helpers saw
for that host. Exact integer arithmetic: the parts always sum to the total,
and ties are broken by position so results are deterministic.
"""

from __future__ import annotations

from collections.abc import Sequence


def largest_remainder(total: int, weights: Sequence[int]) -> list[int]:
    """Split ``total`` into ``len(weights)`` non-negative integers proportional to ``weights``.

    - ``sum(result) == total`` exactly (for ``total >= 0``).
    - Each part is ``floor(total * w / W)`` plus at most one extra unit; the
      extra units go to the largest fractional remainders, earlier positions
      first on ties.
    - When every weight is zero (or negative), the split is by count (equal
      weights).
    - Negative weights are treated as zero; a negative total is treated as 0.
    """
    n = len(weights)
    if n == 0:
        return []
    total = max(0, int(total))
    clean = [max(0, int(w)) for w in weights]
    weight_sum = sum(clean)
    if weight_sum == 0:
        clean = [1] * n
        weight_sum = n
    products = [total * w for w in clean]
    parts = [p // weight_sum for p in products]
    remainder = total - sum(parts)
    if remainder:
        order = sorted(range(n), key=lambda i: (-(products[i] % weight_sum), i))
        for i in order[:remainder]:
            parts[i] += 1
    return parts


__all__ = ["largest_remainder"]
