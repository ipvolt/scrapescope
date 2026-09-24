"""Model tests: cost arithmetic in GB and GiB, per-1,000 figures, what-if savings and caveats."""

from __future__ import annotations

import math

import pytest

from scrapescope.catalog import load_catalogs
from scrapescope.model import (
    BLOCKING_CAVEAT,
    CACHE_CAVEAT,
    COMPARE_CAVEAT,
    blockable_bytes,
    compute_cost,
    compute_what_if,
    share_of,
)
from scrapescope.types import (
    AttributionResult,
    Buckets,
    SuccessInfo,
    Totals,
    TypeAllocation,
    UnitsInfo,
)


def _totals(with_connect: int, without_connect: int | None = None) -> Totals:
    return Totals(
        with_connect=with_connect,
        without_connect=with_connect if without_connect is None else without_connect,
        bytes_sent=0,
        bytes_received=with_connect,
        tunnels=1,
        failed_tunnels=0,
        denied_tunnels=0,
        with_connect_estimated=False,
    )


# ---------------------------------------------------------------------------- cost


def test_cost_per_gb_is_decimal() -> None:
    cost = compute_cost(_totals(2 * 10**9, 10**9), UnitsInfo(), None, rate=3.0, gb_unit="GB")
    assert cost.with_connect == 6.0
    assert cost.without_connect == 3.0
    assert cost.rate == 3.0
    assert cost.rate_unit == "USD per GB"
    assert cost.label == "estimated billable transfer"
    assert cost.currency == "USD"
    assert cost.per_1000_units is None
    assert cost.per_1000_successes is None


def test_cost_per_gib_is_binary() -> None:
    cost = compute_cost(_totals(2**30), UnitsInfo(), None, rate=2.5, gb_unit="GiB")
    assert cost.with_connect == 2.5
    assert cost.rate_unit == "USD per GiB"
    # The same bytes priced per GB cost more (2^30 > 10^9).
    per_gb = compute_cost(_totals(2**30), UnitsInfo(), None, rate=2.5, gb_unit="GB")
    assert per_gb.with_connect == round(2**30 / 1e9 * 2.5, 6) == 2.684355


def test_per_1000_units_and_successes() -> None:
    totals = _totals(11_507_680, 11_506_007)
    units = UnitsInfo(count=25, source="navigations", low_sample_warning=False)
    success = SuccessInfo(count=24, basis="navigations", rate=0.96)
    cost = compute_cost(totals, units, success, rate=3.0, gb_unit="GB")
    exact = 11_507_680 / 1e9 * 3.0
    assert cost.with_connect == round(exact, 6) == 0.034523
    assert cost.without_connect == round(11_506_007 / 1e9 * 3.0, 6)
    assert cost.per_1000_units == round(exact / 25 * 1000, 6)
    assert cost.per_1000_successes == round(exact / 24 * 1000, 6)
    # Computed from exact bytes, not from the rounded total.
    assert cost.per_1000_units == 1.380922


def test_no_units_or_zero_successes_give_none() -> None:
    cost = compute_cost(_totals(10**9), UnitsInfo(count=0), SuccessInfo(count=0, basis="requests", rate=0.0), rate=1.0, gb_unit="GB")
    assert cost.per_1000_units is None
    assert cost.per_1000_successes is None


def test_zero_rate_and_zero_bytes() -> None:
    assert compute_cost(_totals(10**9), UnitsInfo(), None, rate=0, gb_unit="GB").with_connect == 0.0
    cost = compute_cost(_totals(0), UnitsInfo(count=5, source="override"), None, rate=5.0, gb_unit="GB")
    assert cost.with_connect == 0.0 and cost.per_1000_units == 0.0
    assert math.copysign(1.0, cost.with_connect) == 1.0


def test_rounding_to_six_decimals() -> None:
    cost = compute_cost(_totals(1), UnitsInfo(), None, rate=3.0, gb_unit="GB")
    assert cost.with_connect == 0.0  # 3e-9 rounds away
    cost = compute_cost(_totals(123_456_789), UnitsInfo(), None, rate=1.0, gb_unit="GB")
    assert cost.with_connect == 0.123457


@pytest.mark.parametrize("rate", [-1.0, float("nan"), float("inf"), True, "3"])
def test_invalid_rates_are_rejected(rate) -> None:
    with pytest.raises(ValueError):
        compute_cost(_totals(1), UnitsInfo(), None, rate=rate, gb_unit="GB")  # type: ignore[arg-type]


def test_invalid_unit_is_rejected() -> None:
    with pytest.raises(ValueError):
        compute_cost(_totals(1), UnitsInfo(), None, rate=1.0, gb_unit="MB")  # type: ignore[arg-type]


def test_cost_serialises_for_the_report() -> None:
    d = compute_cost(_totals(10**9), UnitsInfo(count=1), None, rate=1.0, gb_unit="GB").to_dict()
    assert set(d) == {"rate", "rate_unit", "with_connect", "without_connect", "per_1000_units", "per_1000_successes", "label", "currency"}


# ---------------------------------------------------------------------------- what-if


def _attribution(types=(), background=None, multi_page=False) -> AttributionResult:
    return AttributionResult(
        types=[TypeAllocation(type=t, requests=1, reported_bytes=b, allocated_bytes=b) for t, b in types],
        buckets=Buckets(attributed=sum(b for _, b in types), background=dict(background or {})),
        multi_page_context=multi_page,
    )


def test_block_images_media_fonts_arithmetic() -> None:
    attribution = _attribution(types=[("image", 3_200_000), ("font", 800_000), ("media", 500_000), ("document", 3_000_000), ("script", 1_500_000)])
    total = _totals(10_000_000)
    [w] = compute_what_if(attribution, total, load_catalogs())
    assert w.id == "block-images-media-fonts"
    assert w.bytes_saved == 4_500_000 == blockable_bytes(attribution)
    assert w.share == 0.45
    assert w.basis == "allocated"
    assert w.caveats == [BLOCKING_CAVEAT]


def test_block_caveat_text_is_exact() -> None:
    assert BLOCKING_CAVEAT == "blocking can break extraction or attract anti-bot scrutiny; compare a second run"
    assert CACHE_CAVEAT == "cache loss not modelled"


def test_cache_caveat_only_for_multi_page_contexts() -> None:
    attribution = _attribution(types=[("image", 100)], multi_page=True)
    [w] = compute_what_if(attribution, _totals(1000), load_catalogs())
    assert w.caveats == [BLOCKING_CAVEAT, CACHE_CAVEAT]


def test_nothing_to_block_emits_nothing() -> None:
    attribution = _attribution(types=[("document", 1000), ("image", 0)])
    assert compute_what_if(attribution, _totals(1000), load_catalogs()) == []


def test_deny_background_arithmetic_and_tradeoffs() -> None:
    cats = load_catalogs()
    attribution = _attribution(background={"component-updater": 200_000, "optimization-guide": 1_500_000, "safe-browsing": 0})
    [w] = compute_what_if(attribution, _totals(3_400_000), cats)
    assert w.id == "deny-background-catalog"
    assert w.bytes_saved == 1_700_000
    assert w.share == 0.5
    og = next(e for e in cats.background if e.id == "optimization-guide")
    cu = next(e for e in cats.background if e.id == "component-updater")
    # Heaviest entry first, zero-byte entries omitted, "compare a second run" last.
    assert w.caveats == [f"optimization-guide: {og.security_tradeoff}", f"component-updater: {cu.security_tradeoff}", COMPARE_CAVEAT]


def test_unknown_background_id_still_gets_a_caveat() -> None:
    attribution = _attribution(background={"retired-entry": 10})
    [w] = compute_what_if(attribution, _totals(100), load_catalogs())
    assert w.caveats[0].startswith("retired-entry: ")
    assert w.caveats[-1] == COMPARE_CAVEAT


def test_both_what_ifs_in_order() -> None:
    attribution = _attribution(types=[("image", 50)], background={"optimization-guide": 25})
    ids = [w.id for w in compute_what_if(attribution, _totals(100), load_catalogs())]
    assert ids == ["block-images-media-fonts", "deny-background-catalog"]


def test_share_edge_cases() -> None:
    assert share_of(10, 0) == 0.0
    assert share_of(0, 10) == 0.0
    assert share_of(20, 10) == 1.0  # clamped
    assert share_of(1, 3) == 0.333333
    attribution = _attribution(types=[("image", 50)])
    [w] = compute_what_if(attribution, _totals(0), load_catalogs())
    assert w.share == 0.0 and w.bytes_saved == 50


def test_unreported_bytes_never_count_as_savings() -> None:
    # meas-1: tunnel bytes nobody reported (an aborted download) are not images, media or fonts.
    attribution = _attribution(types=[("unreported", 4_000_000), ("image", 600_000), ("document", 400_000)])
    [w] = compute_what_if(attribution, _totals(5_000_000), load_catalogs())
    assert w.bytes_saved == 600_000 and w.share == 0.12
