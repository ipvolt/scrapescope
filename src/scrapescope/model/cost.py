"""Costs: metered transfer times the user's own rate.

Accuracy limits, stated honestly:

- The result is "estimated billable transfer", not a bill. It multiplies the
  meter's tunnel-measured bytes by a rate the user typed; a provider may meter
  at a different point, round per request or per session, bill failed requests
  differently, or charge for bytes that were in flight when a job stopped.
- There is no default rate anywhere in scrapescope. ``compute_cost`` is called
  only when ``--rate`` is given.
- GB means 10**9 bytes by default; ``--gib`` switches to GiB (2**30 bytes), and
  the rate is then read as USD per GiB.
- Per-1,000 figures divide by the ``units`` denominator (helper-counted
  navigations, hook-counted requests or ``--units N``); below 20 units they are
  noisy, and the report says so.
"""

from __future__ import annotations

import math

from ..config import unit_bytes
from ..types import CostInfo, GbUnit, SuccessInfo, Totals, UnitsInfo

#: Decimal places kept for USD figures in report.json.
MONEY_DECIMALS = 6


def _money(value: float) -> float:
    rounded = round(value, MONEY_DECIMALS)
    return 0.0 if rounded == 0 else rounded  # avoid -0.0


def compute_cost(
    totals: Totals,
    units: UnitsInfo,
    success: SuccessInfo | None,
    *,
    rate: float,
    gb_unit: GbUnit,
) -> CostInfo:
    """Cost of the run's transfer at ``rate`` USD per GB (or per GiB).

    ``with_connect`` prices every upstream socket byte (CONNECT or SOCKS
    negotiation included); ``without_connect`` prices the bytes after
    negotiation. Which one a provider bills is not known in general, so both
    are reported. Per-1,000 figures are computed from the exact byte counts and
    rounded once, to 6 decimals, at the end.

    Raises ``ValueError`` for a negative, NaN or infinite rate.
    """
    if isinstance(rate, bool) or not isinstance(rate, (int, float)) or not math.isfinite(rate) or rate < 0:
        raise ValueError("rate must be a finite, non-negative number (USD per GB or GiB)")
    if gb_unit not in ("GB", "GiB"):
        raise ValueError("gb_unit must be 'GB' or 'GiB'")
    per_byte = float(rate) / unit_bytes(gb_unit)
    with_connect = totals.with_connect * per_byte
    without_connect = totals.without_connect * per_byte
    per_1000_units = with_connect / units.count * 1000 if units.count > 0 else None
    per_1000_successes = (
        with_connect / success.count * 1000 if success is not None and success.count > 0 else None
    )
    return CostInfo(
        rate=float(rate),
        rate_unit="USD per GiB" if gb_unit == "GiB" else "USD per GB",
        with_connect=_money(with_connect),
        without_connect=_money(without_connect),
        per_1000_units=None if per_1000_units is None else _money(per_1000_units),
        per_1000_successes=None if per_1000_successes is None else _money(per_1000_successes),
    )


__all__ = ["MONEY_DECIMALS", "compute_cost"]
