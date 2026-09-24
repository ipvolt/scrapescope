"""Attribution unit tests: synthetic snapshots and events, no network.

Covers allocation arithmetic, every bucket, bypass-detector exclusions,
service-worker dedup, units/success/timeline figures, non-target and denied
hosts, warnings, and schema conformance of the produced pieces.
"""

from __future__ import annotations

import json
import random
import re
from importlib import resources
from typing import Any

import pytest

from scrapescope.attribution import attribute, is_loopback_host, largest_remainder
from scrapescope.attribution.core import (
    MAX_TYPES,
    NON_CDP_WARNING_PREFIX,

    NO_EVENTS_WARNING,
    NO_UNITS_WARNING,
    OVERHEAD_PER_TUNNEL_BYTES,
    PER_UNIT_WITHHELD_PREFIX,
    UNREPORTED_TYPE,
)
from scrapescope.config import PRECONNECT_IDLE_MAX_RECEIVED, PRECONNECT_IDLE_MAX_SENT
from scrapescope.types import (
    AttachEvent,
    Catalogs,
    LaunchEvent,
    MeterSnapshot,
    RequestEvent,
    TimelinePoint,
    TunnelRecord,
)

T0 = 1_790_000_000.0


# ---------------------------------------------------------------------------- builders


def _catalogs() -> Catalogs:
    background = {
        "version": "test",
        "entries": [
            {
                "id": "optimization-guide",
                "hosts": ["optimizationguide-pa.googleapis.com"],
                "component": "Optimization guide",
                "evidence": ["https://news.ycombinator.com/item?id=41593410"],
                "security_tradeoff": "none",
                "last_verified": "2026-09-23",
            },
            {
                "id": "component-updater",
                "hosts": ["update.googleapis.com", "clients2.google.com", "*.gvt1.com"],
                "component": "Component updater",
                "evidence": ["https://github.com/puppeteer/puppeteer/issues/7042"],
                "security_tradeoff": "updates carry revocation data",
                "last_verified": "2026-09-23",
            },
        ],
    }
    challenges = {"version": "test", "vendors": []}
    direct = {"version": "test", "entries": [{"id": "openai", "hosts": ["api.openai.com"], "reason": "LLM API"}]}
    return Catalogs.from_documents(background, challenges, direct)


CATALOGS = _catalogs()
_ids = iter(range(1, 10**6))


def tun(host: str = "origin-a.test", *, sent: int = 1000, received: int = 9000, neg_sent: int = 0,
        neg_received: int = 0, opened: float = T0 + 1, route: str = "http-connect", status: str = "ok",
        port: int = 443, rule: str | None = None, synthetic: tuple[int, int] = (0, 0)) -> TunnelRecord:
    return TunnelRecord(
        id=next(_ids), host=host, port=port, kind="connect", route=route,  # type: ignore[arg-type]
        opened_at=opened, closed_at=opened + 5, status=status,
        upstream_bytes_sent=sent + neg_sent, upstream_bytes_received=received + neg_received,
        negotiation_bytes_sent=neg_sent, negotiation_bytes_received=neg_received,
        synthetic_negotiation_bytes_sent=synthetic[0], synthetic_negotiation_bytes_received=synthetic[1],
        rule=rule,
    )


def snap(tunnels: list[TunnelRecord], *, mode: str = "http-connect", timeline: list[TimelinePoint] | None = None,
         internal_errors: int = 0) -> MeterSnapshot:
    return MeterSnapshot(
        taken_at=T0 + 100, started_at=T0, mode=mode, port=5555, auth_port=5556,  # type: ignore[arg-type]
        tunnels=tunnels, counted_bytes=sum(t.counted_bytes for t in tunnels if t.is_target),
        budget_bytes=None, max_tunnel_bytes=None, budget_tripped=False,
        timeline=timeline or [], internal_errors=internal_errors,
    )


def req(host: str = "origin-a.test", *, ts: float = T0 + 2, body: int | None = 1000, rh: int | None = 200,
        qh: int | None = 500, qb: int | None = 0, rtype: str = "document", status: int | None = 200,
        failed: bool = False, from_cache: bool = False, from_sw: bool = False, frame: str = "main",
        nav: bool = False, source: str = "playwright", scheme: str = "https", path: str | None = None,
        context: str | None = "1-1") -> RequestEvent:
    return RequestEvent(
        ts=ts, source=source, host=host, port=443, scheme=scheme, path=path, method="GET",  # type: ignore[arg-type]
        resource_type=rtype, status=status, failed=failed, from_cache=from_cache, from_service_worker=from_sw,
        frame=frame, is_navigation=nav, encoded_body_bytes=body, response_header_bytes=rh,  # type: ignore[arg-type]
        request_header_bytes=qh, request_body_bytes=qb, context=context,
    )


def attach(ts: float = T0 + 0.5, context: str = "1-1") -> AttachEvent:
    return AttachEvent(ts=ts, source="playwright", pid=1, context=context)


def nav(ts: float, status: int | None = 200, **kw: Any) -> RequestEvent:
    return req(ts=ts, status=status, nav=True, frame="main", rtype="document", **kw)


def assert_buckets_sum(result, snapshot: MeterSnapshot) -> None:
    b = result.buckets
    total = b.attributed + b.preconnect_idle + b.before_attach + b.unattributed + sum(b.background.values())
    assert total == snapshot.totals().with_connect
    assert sum(t.allocated_bytes for t in result.types) == b.attributed
    for host in result.hosts:
        assert sum(t.bytes for t in host.buckets.values()) == host.bytes_with_connect
        assert sum(t.tunnels for t in host.buckets.values()) == host.tunnels
        if host.allocated_by_type:
            assert sum(host.allocated_by_type.values()) == host.bytes_with_connect


def host_row(result, host: str):
    return next(h for h in result.hosts if h.host == host)


# ---------------------------------------------------------------------------- allocation arithmetic


def test_largest_remainder_basic_cases() -> None:
    assert largest_remainder(10, [1, 1, 1]) == [4, 3, 3]
    assert largest_remainder(0, [5, 7]) == [0, 0]
    assert largest_remainder(7, [0, 0]) == [4, 3]  # all-zero weights: split by count
    assert largest_remainder(100, [3, 5, 0]) == [38, 62, 0]
    assert largest_remainder(5, []) == []
    assert largest_remainder(9, [-4, 1]) == [0, 9]  # negative weights count as zero
    assert largest_remainder(-3, [1, 2]) == [0, 0]


def test_largest_remainder_is_exact_and_proportional() -> None:
    rng = random.Random(1618)
    for _ in range(500):
        n = rng.randint(1, 30)
        weights = [rng.choice([0, rng.randint(0, 10**7)]) for _ in range(n)]
        total = rng.randint(0, 10**9)
        parts = largest_remainder(total, weights)
        assert sum(parts) == total
        assert all(p >= 0 for p in parts)
        w_sum = sum(weights) or n
        eff = weights if sum(weights) else [1] * n
        for part, w in zip(parts, eff):
            exact = total * w / w_sum
            assert abs(part - exact) < 1.0 + 1e-9


def test_largest_remainder_ties_go_to_earlier_positions() -> None:
    assert largest_remainder(2, [1, 1, 1]) == [1, 1, 0]
    assert largest_remainder(1, [1, 1]) == [1, 0]


def test_host_allocation_shares_tunnel_overhead_in_proportion() -> None:
    # Two tunnels to one host: 20,039 bytes with CONNECT. Reported bytes: 3,000 + 1,000 + 0.
    t1 = tun(sent=1000, received=9000, neg_sent=100, neg_received=39)
    t2 = tun(sent=500, received=9400)
    snapshot = snap([t1, t2])
    events = [
        attach(),
        req(rtype="document", body=2300, rh=200, qh=500, qb=0),  # reported 3,000
        req(rtype="image", body=600, rh=150, qh=250, qb=0),  # reported 1,000
        req(rtype="xhr", body=0, rh=0, qh=0, qb=0),  # reported 0 (e.g. unknown sizes)
    ]
    result = attribute(snapshot, events, CATALOGS)
    row = host_row(result, "origin-a.test")
    assert row.bytes_with_connect == 20_039
    assert row.requests == 3
    assert row.buckets == {"attributed": row.buckets["attributed"]}
    assert row.buckets["attributed"].tunnels == 2 and row.buckets["attributed"].bytes == 20_039
    # 3:1:0 split of 20,039 with largest remainders: 15,029.25 / 5,009.75 / 0.
    assert row.allocated_by_type == {"document": 15_029, "image": 5_010, "xhr": 0}
    types = {t.type: t for t in result.types}
    assert types["document"].reported_bytes == 3000 and types["document"].allocated_bytes == 15_029
    assert types["xhr"].requests == 1 and types["xhr"].allocated_bytes == 0
    assert [t.type for t in result.types] == ["document", "image", "xhr"]  # by allocated bytes
    assert_buckets_sum(result, snapshot)


def test_allocation_scales_down_when_reported_exceeds_tunnel_bytes() -> None:
    # Negative overhead (e.g. hook sizes or decompressed lengths): allocations still sum to the tunnel bytes.
    snapshot = snap([tun(sent=100, received=900)])
    events = [attach(), req(rtype="script", body=5000, rh=0, qh=0), req(rtype="image", body=15000, rh=0, qh=0)]
    result = attribute(snapshot, events, CATALOGS)
    assert host_row(result, "origin-a.test").allocated_by_type == {"image": 750, "script": 250}
    assert_buckets_sum(result, snapshot)


def test_allocation_by_count_when_no_sizes_are_known() -> None:
    snapshot = snap([tun(sent=1, received=2)])  # 3 bytes over 3 requests with unknown sizes
    events = [req(body=None, rh=None, qh=None, qb=None, rtype=t) for t in ("font", "image", "media")]
    result = attribute(snapshot, events, CATALOGS)
    assert host_row(result, "origin-a.test").allocated_by_type == {"font": 1, "image": 1, "media": 1}


def test_direct_mode_synthetic_connect_is_part_of_the_allocated_total() -> None:
    t = tun(route="direct", synthetic=(60, 39))
    snapshot = snap([t], mode="direct")
    result = attribute(snapshot, [attach(), req()], CATALOGS)
    row = host_row(result, "origin-a.test")
    assert row.bytes_with_connect == 10_099 and row.bytes_without_connect == 10_000
    assert sum(row.allocated_by_type.values()) == 10_099
    assert_buckets_sum(result, snapshot)


# ---------------------------------------------------------------------------- buckets


def test_every_bucket_and_first_match_order() -> None:
    tunnels = [
        # Catalogued background host, opened before attach: background wins.
        tun("optimizationguide-pa.googleapis.com", sent=3000, received=1_500_000, opened=T0 + 0.1),
        # Uncatalogued, opened before attach: before_attach (even though it is tiny).
        tun("early.test", sent=10, received=10, opened=T0 + 0.2),
        # Uncatalogued, after attach, tiny payload with a large negotiation: preconnect_idle.
        tun("origin-c.test", sent=517, received=5000, neg_sent=400, neg_received=39, opened=T0 + 3),
        # Uncatalogued, after attach, above the idle limits: unattributed.
        tun("www.google.com", sent=PRECONNECT_IDLE_MAX_SENT + 1, received=100, opened=T0 + 3),
        tun("www.google.com", sent=10, received=PRECONNECT_IDLE_MAX_RECEIVED + 1, opened=T0 + 4),
        # Host with a network request: attributed.
        tun("origin-a.test", opened=T0 + 1),
    ]
    snapshot = snap(tunnels)
    result = attribute(snapshot, [attach(ts=T0 + 0.5), req("origin-a.test")], CATALOGS)
    rows = {h.host: h for h in result.hosts}
    assert set(rows["optimizationguide-pa.googleapis.com"].buckets) == {"background:optimization-guide"}
    assert rows["optimizationguide-pa.googleapis.com"].background_id == "optimization-guide"
    assert set(rows["early.test"].buckets) == {"before_attach"}
    assert set(rows["origin-c.test"].buckets) == {"preconnect_idle"}
    assert rows["www.google.com"].buckets["unattributed"].tunnels == 2
    assert rows["www.google.com"].background_id is None
    assert set(rows["origin-a.test"].buckets) == {"attributed"}
    b = result.buckets
    assert b.background == {"optimization-guide": 1_503_000}
    assert b.before_attach == 20
    assert b.preconnect_idle == 517 + 5000 + 400 + 39
    assert b.unattributed == (PRECONNECT_IDLE_MAX_SENT + 1) + 100 + 10 + (PRECONNECT_IDLE_MAX_RECEIVED + 1)
    assert b.attributed == 10_000
    assert_buckets_sum(result, snapshot)
    assert result.hosts[0].host == "optimizationguide-pa.googleapis.com"  # sorted by bytes, descending


def test_uncatalogued_host_is_never_background() -> None:
    # A cross-site iframe host, a worker host and an idle preconnect host, none catalogued.
    tunnels = [tun("origin-b.test", opened=T0 + 5), tun("origin-c.test", sent=500, received=4000, opened=T0 + 5),
               tun("accounts.google.com", sent=5000, received=50000, opened=T0 + 5)]
    snapshot = snap(tunnels)
    result = attribute(snapshot, [attach()], CATALOGS)
    assert result.buckets.background == {}
    for row in result.hosts:
        assert not any(name.startswith("background:") for name in row.buckets)
        assert row.background_id is None


def test_catalogued_host_with_a_page_request_is_attributed_not_background() -> None:
    snapshot = snap([tun("update.googleapis.com")])
    result = attribute(snapshot, [attach(), req("update.googleapis.com", rtype="fetch")], CATALOGS)
    row = host_row(result, "update.googleapis.com")
    assert set(row.buckets) == {"attributed"}
    assert row.background_id == "component-updater"
    assert result.buckets.background == {}


def test_background_glob_and_no_events() -> None:
    snapshot = snap([tun("edgedl.me.gvt1.com"), tun("origin-a.test"), tun("origin-c.test", sent=1, received=1)])
    result = attribute(snapshot, [], CATALOGS)
    assert result.buckets.background == {"component-updater": 10_000}
    # Without any helper events every non-catalogued tunnel is unattributed (even a tiny one).
    assert result.buckets.unattributed == 10_002
    assert result.buckets.preconnect_idle == 0 and result.buckets.before_attach == 0
    assert result.types == [] and result.sources == []
    assert NO_EVENTS_WARNING in result.warnings
    assert any("background catalog (component-updater)" in w for w in result.warnings)
    assert_buckets_sum(result, snapshot)


def test_first_observation_falls_back_to_the_first_request_event() -> None:
    snapshot = snap([tun("early.test", sent=1, received=1, opened=T0 + 1), tun("origin-a.test", opened=T0 + 2)])
    result = attribute(snapshot, [req("origin-a.test", ts=T0 + 1.5)], CATALOGS)
    assert set(host_row(result, "early.test").buckets) == {"before_attach"}


def test_idle_limits_are_inclusive() -> None:
    at_limit = tun("idle.test", sent=PRECONNECT_IDLE_MAX_SENT, received=PRECONNECT_IDLE_MAX_RECEIVED, neg_sent=300,
                   neg_received=39, opened=T0 + 3)
    over = tun("busy.test", sent=PRECONNECT_IDLE_MAX_SENT + 1, received=10, opened=T0 + 3)
    snapshot = snap([at_limit, over])
    result = attribute(snapshot, [attach()], CATALOGS)
    assert result.buckets.preconnect_idle == at_limit.bytes_with_connect
    assert result.buckets.unattributed == over.bytes_with_connect


def test_refused_tunnels_of_hosts_without_requests_are_not_idle_preconnects() -> None:
    """meas3-8: a CONNECT the provider answered 502 or 407 leaves 0 payload bytes; it was a refusal,
    not a connection opened in advance, so it is unattributed (before_attach and background still
    apply first)."""
    refused = [tun("www.google.com", sent=0, received=0, neg_sent=180, neg_received=120, opened=T0 + 3,
                   status="failed:upstream_status") for _ in range(2)]
    denied_auth = tun("android.clients.google.com", sent=0, received=0, neg_sent=200, neg_received=300,
                      opened=T0 + 4, status="failed:upstream_status")
    early = tun("www.google.com", sent=0, received=0, neg_sent=180, neg_received=120, opened=T0 + 0.1,
                status="failed:upstream_status")
    idle = tun("origin-c.test", sent=517, received=5000, neg_sent=400, neg_received=39, opened=T0 + 3)
    snapshot = snap([*refused, denied_auth, early, idle])
    result = attribute(snapshot, [attach(ts=T0 + 0.5)], CATALOGS)
    rows = {h.host: h for h in result.hosts}
    assert rows["www.google.com"].buckets["unattributed"].tunnels == 2
    assert rows["www.google.com"].buckets["before_attach"].tunnels == 1
    assert "preconnect_idle" not in rows["www.google.com"].buckets
    assert set(rows["android.clients.google.com"].buckets) == {"unattributed"}
    assert set(rows["origin-c.test"].buckets) == {"preconnect_idle"}
    assert result.buckets.preconnect_idle == idle.bytes_with_connect
    assert result.buckets.unattributed == 2 * 300 + 500
    assert_buckets_sum(result, snapshot)


def test_failed_tunnels_count_and_are_bucketed() -> None:
    failed = tun("gone.test", sent=0, received=0, neg_sent=150, neg_received=120, status="failed:upstream_status",
                 opened=T0 + 3)
    snapshot = snap([failed])
    result = attribute(snapshot, [attach(), req("gone.test", status=None, failed=True, body=None, rh=None, qh=None)],
                       CATALOGS)
    row = host_row(result, "gone.test")
    assert row.failed_tunnels == 1 and row.tunnels == 1
    assert row.buckets["attributed"].bytes == 270
    assert_buckets_sum(result, snapshot)


# ---------------------------------------------------------------------------- network requests and dedup


def test_cache_hits_and_service_worker_answers_are_not_network_requests() -> None:
    snapshot = snap([tun("origin-a.test", opened=T0 + 3), tun("cdn.test", opened=T0 + 3)])
    events = [
        attach(),
        req("origin-a.test", rtype="fetch", frame="main", from_sw=True, body=0, rh=0, qh=0),  # page copy
        req("origin-a.test", rtype="fetch", frame="service_worker", body=68, rh=204, qh=433),  # worker copy
        req("cdn.test", rtype="image", from_cache=True, body=0, rh=0, qh=0),
    ]
    result = attribute(snapshot, events, CATALOGS)
    a = host_row(result, "origin-a.test")
    assert a.requests == 1  # the service-worker-handled request counts once
    assert a.allocated_by_type == {"fetch": 10_000}
    assert {t.type: t.requests for t in result.types} == {"fetch": 1}
    cdn = host_row(result, "cdn.test")
    assert cdn.requests == 0 and set(cdn.buckets) == {"unattributed"}
    assert result.status_histogram == {"200": 1}
    assert result.events.request == 3


def test_paths_top_twenty_by_reported_bytes() -> None:
    snapshot = snap([tun()])
    events = [attach()] + [req(path=f"/p/{i}", body=i * 10, rh=0, qh=0, qb=0) for i in range(25)]
    events.append(req(path="/p/24", body=5, rh=0, qh=0, qb=0))
    result = attribute(snapshot, events, CATALOGS)
    paths = host_row(result, "origin-a.test").paths
    assert len(paths) == 20
    assert paths[0].path == "/p/24" and paths[0].requests == 2 and paths[0].reported_bytes == 245
    assert [p.reported_bytes for p in paths] == sorted((p.reported_bytes for p in paths), reverse=True)


def test_no_paths_without_keep_urls_events() -> None:
    result = attribute(snap([tun()]), [attach(), req()], CATALOGS)
    assert host_row(result, "origin-a.test").paths == []


def test_types_fold_into_other_beyond_the_schema_limit() -> None:
    names = [("t" + "".join(chr(97 + (i // 26 ** k) % 26) for k in range(3))) for i in range(80)]
    events = [attach()] + [req(rtype=name, body=1000 + i, rh=0, qh=0) for i, name in enumerate(names)]
    result = attribute(snap([tun(sent=100_000, received=900_000)]), events, CATALOGS)
    assert len(result.types) == MAX_TYPES
    assert "other" in {t.type for t in result.types}
    assert sum(t.allocated_bytes for t in result.types) == result.buckets.attributed == 1_000_000
    assert sum(t.requests for t in result.types) == 80


# ---------------------------------------------------------------------------- units, success, timeline


def test_units_from_navigations_exclude_redirects_and_subframes() -> None:
    events = [attach()]
    events += [nav(T0 + 10 + i) for i in range(20)]
    events += [nav(T0 + 5, status=302), nav(T0 + 6, status=301)]  # redirect hops: not units
    events += [nav(T0 + 40, status=304)]  # revalidated page: a unit and a success
    events += [req(nav=True, frame="sub", ts=T0 + 11)]  # iframe navigation: not a unit
    events += [nav(T0 + 41, status=None, failed=True, body=None, rh=None, qh=None)]
    events += [nav(T0 + 42, status=500)]
    events += [req(source="requests", rtype="http_client", frame="other")]  # hooks lose to navigations
    result = attribute(snap([tun()]), events, CATALOGS)
    assert result.units.count == 23 and result.units.source == "navigations"
    assert result.units.low_sample_warning is False
    assert result.success is not None
    assert result.success.basis == "navigations" and result.success.count == 21
    assert result.success.rate == pytest.approx(21 / 23, abs=1e-6)
    assert not any("unreliable" in w for w in result.warnings)


def test_units_from_hooks_and_low_sample_warning() -> None:
    events = [AttachEvent(ts=T0, source="httpx", pid=1)]
    events += [req(source="httpx", rtype="http_client", frame="other", status=200, ts=T0 + i) for i in range(5)]
    events += [req(source="httpx", rtype="http_client", frame="other", status=307, ts=T0 + 9)]
    events += [req(source="requests", rtype="http_client", frame="other", status=None, failed=True, ts=T0 + 10)]
    result = attribute(snap([tun()]), events, CATALOGS)
    assert result.units.count == 6 and result.units.source == "requests"
    assert result.units.low_sample_warning is True
    assert result.success.basis == "requests" and result.success.count == 5
    assert result.sources == ["httpx", "requests"]
    assert any(w.startswith("only 6 units (requests)") for w in result.warnings)


def test_units_override_keeps_success_from_events() -> None:
    events = [attach(), nav(T0 + 1), nav(T0 + 2, status=404)]
    result = attribute(snap([tun()]), events, CATALOGS, units_override=500)
    assert result.units.count == 500 and result.units.source == "override"
    assert result.units.low_sample_warning is False
    assert result.success.count == 1 and result.success.rate == 0.5


def test_no_units() -> None:
    result = attribute(snap([tun()]), [attach(), req(rtype="image")], CATALOGS)
    assert result.units.source == "none" and result.units.count == 0 and result.units.low_sample_warning
    assert result.success is None and result.per_unit is None and result.bytes_before_first_navigation is None
    assert NO_UNITS_WARNING in result.warnings


def test_timeline_figures() -> None:
    timeline = [TimelinePoint(t=T0 + x, sent=10, received=90) for x in (0.0, 0.25, 1.0, 1.25, 2.0, 3.0, 3.5)]
    events = [attach(), nav(T0 + 1.0), nav(T0 + 2.0), nav(T0 + 3.0), LaunchEvent(ts=T0, source="playwright")]
    result = attribute(snap([tun()], timeline=timeline), events, CATALOGS)
    assert result.browser_launches == 1
    assert result.bytes_before_first_navigation == 200  # buckets starting before the first unit
    per = result.per_unit
    assert per is not None
    assert per.first_unit_bytes == 200 and per.rest_units == 2 and per.rest_bytes == 300
    assert per.rest_mean_bytes == 150 and per.resolution_s == 0.25


def test_timeline_bucket_straddling_the_first_unit_goes_to_that_unit() -> None:
    # A fast load fits inside one 0.25 s bucket that starts just before the first
    # navigation: it belongs to the first unit, not to "before the first navigation".
    timeline = [TimelinePoint(t=T0 + 0.75, sent=100, received=900), TimelinePoint(t=T0 + 1.25, sent=1, received=9)]
    events = [attach(), nav(T0 + 0.80), nav(T0 + 1.20)]
    result = attribute(snap([tun()], timeline=timeline), events, CATALOGS)
    assert result.bytes_before_first_navigation == 0
    assert result.per_unit is not None
    assert result.per_unit.first_unit_bytes == 1000 and result.per_unit.rest_bytes == 10
    assert not any(w.startswith(PER_UNIT_WITHHELD_PREFIX) for w in result.warnings)


def test_per_unit_withheld_when_units_start_within_one_timeline_step() -> None:
    # meas-12: five navigations in 0.12 s share one bucket; the first unit would absorb them all
    # (first 1,000 B, rest mean 2 B). The split is withheld and a warning says why.
    timeline = [TimelinePoint(t=T0 + 0.75, sent=100, received=900), TimelinePoint(t=T0 + 1.0, sent=1, received=9)]
    events = [attach(), *(nav(T0 + 0.80 + 0.03 * i) for i in range(5))]
    result = attribute(snap([tun()], timeline=timeline), events, CATALOGS)
    assert result.per_unit is None
    assert result.bytes_before_first_navigation == 0  # still reported
    (warning,) = [w for w in result.warnings if w.startswith(PER_UNIT_WITHHELD_PREFIX)]
    assert "0.030 s apart" in warning and "0.25 s" in warning


def test_timeline_bucket_straddling_the_second_unit_goes_to_the_rest() -> None:
    """meas3-4: the step that straddles the second unit's start holds that unit's first bytes (its
    handshakes and document). It went to the first unit, so a cache-warm second page that loads
    within one step left "rest" near zero (736,331 B first, 168 B rest in the reviewer's run)."""
    t1, t2 = T0 + 0.9, T0 + 4.0
    timeline = [
        TimelinePoint(t=T0 + 0.75, sent=31, received=700_000),   # straddles t1: the first unit
        TimelinePoint(t=T0 + 1.25, sent=100, received=36_200),   # the first unit
        TimelinePoint(t=t2 - 0.041, sent=2_675, received=10_000),  # straddles t2: the second unit
        TimelinePoint(t=t2 + 0.209, sent=100, received=68),
    ]
    result = attribute(snap([tun()], timeline=timeline), [attach(), nav(t1), nav(t2)], CATALOGS)
    per = result.per_unit
    assert per is not None
    assert per.first_unit_bytes == 700_031 + 36_300
    assert per.rest_units == 1 and per.rest_bytes == 12_675 + 168 and per.rest_mean_bytes == 12_843
    assert result.bytes_before_first_navigation == 0


def test_a_navigation_unit_starts_with_its_redirect_hops() -> None:
    """meas3-5: https://en.wikipedia.org/ answered 301 at +0.037 s and /wiki/Main_Page started at
    +0.504 s. The 301 hop and its tunnel's handshake (7,318 B) were reported as bytes before the
    first navigation; a later unit's hops went to the previous unit."""
    timeline = [
        TimelinePoint(t=T0 + 0.0, sent=2_318, received=5_000),   # the 301 hop and its TLS handshake
        TimelinePoint(t=T0 + 0.5, sent=900, received=90_000),    # the page it led to
        TimelinePoint(t=T0 + 4.75, sent=1_000, received=6_000),  # unit 2's redirect hop
        TimelinePoint(t=T0 + 5.5, sent=500, received=40_000),    # unit 2's page
    ]
    events = [
        attach(ts=T0 - 1),
        nav(T0 + 0.037, status=301), nav(T0 + 0.504),
        req(ts=T0 + 0.8, rtype="image"),  # a subresource between the units changes nothing
        nav(T0 + 4.9, status=302), nav(T0 + 5.1, status=307), nav(T0 + 5.6),
        # A redirect hop of another context does not move this context's units.
        nav(T0 + 3.5, status=301, context="1-2"),
    ]
    result = attribute(snap([tun()], timeline=timeline), events, CATALOGS)
    assert result.units.count == 2
    assert result.bytes_before_first_navigation == 0
    per = result.per_unit
    assert per is not None and per.first_unit_bytes == 7_318 + 90_900 and per.rest_bytes == 7_000 + 40_500
    # A hop whose chain end was never reported does not stretch a much later page back to it.
    orphan = attribute(snap([tun()], timeline=timeline),
                       [attach(ts=T0 - 1), nav(T0 + 0.037, status=301), nav(T0 + 0.037 + 31), nav(T0 + 40)],
                       CATALOGS)
    assert orphan.bytes_before_first_navigation == sum(p.sent + p.received for p in timeline)
    # Without the hops, the units start at their own events.
    plain = attribute(snap([tun()], timeline=timeline), [attach(ts=T0 - 1), nav(T0 + 0.504), nav(T0 + 5.6)],
                      CATALOGS)
    assert plain.bytes_before_first_navigation == 7_318


def test_timeline_single_unit() -> None:
    timeline = [TimelinePoint(t=T0 + x, sent=1, received=1) for x in (0.0, 5.0, 6.0)]
    result = attribute(snap([tun()], timeline=timeline), [nav(T0 + 4)], CATALOGS)
    assert result.bytes_before_first_navigation == 2
    assert result.per_unit.first_unit_bytes == 4
    assert result.per_unit.rest_units == 0 and result.per_unit.rest_mean_bytes is None


def test_multi_page_context() -> None:
    one_each = [nav(T0 + 1, context="1-1"), nav(T0 + 2, context="1-2")]
    assert attribute(snap([tun()]), one_each, CATALOGS).multi_page_context is False
    two = [*one_each, nav(T0 + 3, context="1-2")]
    assert attribute(snap([tun()]), two, CATALOGS).multi_page_context is True
    no_context = [nav(T0 + 1, context=None), nav(T0 + 2, context=None)]  # None counts as one context
    assert attribute(snap([tun()]), no_context, CATALOGS).multi_page_context is True


def test_status_histogram() -> None:
    events = [req(status=200), req(status=200), req(status=404), req(status=None, failed=True),
              req(status=503, failed=True), req(status=200, from_cache=True)]
    result = attribute(snap([tun()]), events, CATALOGS)
    assert result.status_histogram == {"200": 2, "404": 1, "503": 1, "failed": 1}
    assert list(result.status_histogram) == ["200", "404", "503", "failed"]


# ---------------------------------------------------------------------------- bypass detector


def test_bypass_detected_for_uncarried_host() -> None:
    snapshot = snap([tun("origin-a.test")])
    events = [attach(), req("origin-a.test"), req("sneaky.test"), req("sneaky.test"), req("other.test")]
    result = attribute(snapshot, events, CATALOGS)
    assert result.bypass.incomplete is True
    assert result.bypass.hosts == ["other.test", "sneaky.test"]
    assert result.bypass.requests == 3
    assert any(w.startswith("incomplete: helpers saw 3 network requests to 2 hosts") for w in result.warnings)


@pytest.mark.parametrize(
    "event",
    [
        req("localhost"),
        req("127.0.0.1"),
        req("127.8.9.10"),
        req("::1"),
        req("app.localhost"),
        req("cached.test", from_cache=True),
        req("sw.test", from_sw=True),
        req("blocked.test", status=None, failed=True, body=None, rh=None, qh=None),
    ],
    ids=["localhost", "127.0.0.1", "127/8", "ipv6-loopback", "sub.localhost", "cache", "service-worker",
         "failed-without-status"],
)
def test_bypass_exclusions(event: RequestEvent) -> None:
    result = attribute(snap([tun("origin-a.test")]), [attach(), event], CATALOGS)
    assert result.bypass.incomplete is False and result.bypass.requests == 0


def test_bypass_counts_failed_requests_that_have_a_status() -> None:
    result = attribute(snap([tun()]), [req("elsewhere.test", status=200, failed=True)], CATALOGS)
    assert result.bypass.incomplete is True


@pytest.mark.parametrize("route,status", [("non-target", "ok"), ("refused", "denied"), ("http-connect", "failed:dns")])
def test_hosts_in_any_tunnel_record_are_not_bypass(route: str, status: str) -> None:
    carried = tun("api.openai.com", route=route, status=status, rule="openai" if route == "non-target" else None)
    result = attribute(snap([carried]), [attach(), req("api.openai.com")], CATALOGS)
    assert result.bypass.incomplete is False


def test_bypass_hosts_are_capped() -> None:
    events = [req(f"h{i:03d}.test") for i in range(150)]
    result = attribute(snap([]), events, CATALOGS)
    assert result.bypass.requests == 150 and len(result.bypass.hosts) == 100
    assert result.bypass.hosts == sorted(result.bypass.hosts)


def test_ip_literal_hosts_match_their_tunnels_in_any_spelling() -> None:
    """meas4-1: the meter files tunnels under types.canonical_host; events from older helpers (or other
    writers) may carry another spelling of the same address. Each must still match its tunnel: no
    bypass, the tunnel attributed, per-type figures present."""
    snapshot = snap([
        tun("1.2.3.4", port=80, sent=600, received=20_000),
        tun("2001:db8::1", port=80, sent=600, received=20_000),
    ])
    events = [
        attach(),
        req("1.2.3.04", scheme="http", rtype="image", body=15_000, rh=300, qh=400),  # requests/httpx, legacy IPv4
        req("::ffff:102:304", scheme="http", rtype="script", body=2_000, rh=300, qh=400),  # Chromium, mapped IPv4
        req("2001:db8:0:0::1", scheme="http", rtype="image", body=18_000, rh=300, qh=400),  # uncompressed IPv6
    ]
    result = attribute(snapshot, events, CATALOGS)
    assert result.bypass.incomplete is False and result.bypass.requests == 0 and result.bypass.hosts == []
    assert not any(w.startswith("incomplete") for w in result.warnings)
    v4, v6 = host_row(result, "1.2.3.4"), host_row(result, "2001:db8::1")
    assert (v4.requests, v6.requests) == (2, 1)
    assert set(v4.buckets) == {"attributed"} and set(v6.buckets) == {"attributed"}
    assert set(v4.allocated_by_type) == {"image", "script"} and set(v6.allocated_by_type) == {"image"}
    assert result.buckets.preconnect_idle == 0 and result.buckets.unattributed == 0
    assert_buckets_sum(result, snapshot)


def test_bypass_hosts_are_named_in_the_meters_spelling() -> None:
    result = attribute(snap([tun("origin-a.test")]), [attach(), req("0x01020304", scheme="http")], CATALOGS)
    assert result.bypass.hosts == ["1.2.3.4"] and result.bypass.requests == 1
    # A loopback address in a legacy spelling is still the local machine, never bypass.
    result = attribute(snap([tun("origin-a.test")]), [attach(), req("127.1", scheme="http")], CATALOGS)
    assert result.bypass.incomplete is False


def test_is_loopback_host() -> None:
    assert is_loopback_host("localhost") and is_loopback_host("127.0.0.1") and is_loopback_host("::1")
    assert is_loopback_host("::ffff:127.0.0.1")
    assert not is_loopback_host("10.0.0.1") and not is_loopback_host("localhost.example.com")


# ---------------------------------------------------------------------------- non-target and denied


def test_non_target_hosts_are_listed_separately_and_excluded_from_hosts() -> None:
    tunnels = [
        tun("api.openai.com", route="non-target", rule="openai", sent=500, received=1500),
        tun("api.openai.com", route="non-target", rule="openai", sent=100, received=100),
        tun("s3.test", route="non-target", rule="not a catalog id", sent=1, received=1),
        tun("origin-a.test"),
    ]
    snapshot = snap(tunnels)
    result = attribute(snapshot, [attach(), req("origin-a.test"), req("api.openai.com", rtype="fetch")], CATALOGS)
    assert [h.host for h in result.hosts] == ["origin-a.test"]
    assert [(n.host, n.catalog_id, n.tunnels, n.bytes_sent, n.bytes_received) for n in result.non_target] == [
        ("api.openai.com", "openai", 2, 600, 1600),
        ("s3.test", "uncatalogued", 1, 1, 1),
    ]
    assert {t.type for t in result.types} == {"document"}
    assert_buckets_sum(result, snapshot)


def test_denied_hosts_appear_with_denied_counts_and_no_bytes() -> None:
    denied = tun("optimizationguide-pa.googleapis.com", route="refused", status="denied", sent=0, received=0,
                 rule="catalog:background:optimization-guide")
    snapshot = snap([denied, tun()])
    result = attribute(snapshot, [attach(), req()], CATALOGS)
    row = host_row(result, "optimizationguide-pa.googleapis.com")
    assert row.denied_tunnels == 1 and row.tunnels == 0 and row.bytes_with_connect == 0
    assert row.buckets == {} and row.allocated_by_type == {}
    assert_buckets_sum(result, snapshot)


# ---------------------------------------------------------------------------- warnings and counts


def test_warnings_for_dropped_events_and_internal_errors() -> None:
    result = attribute(snap([tun()], internal_errors=2), [attach()], CATALOGS, events_dropped=3)
    assert result.events.dropped == 3 and result.events.attach == 1
    assert any(w.startswith("3 helper event lines dropped") for w in result.warnings)
    assert any("2 internal errors" in w for w in result.warnings)
    one = attribute(snap([tun()]), [attach()], CATALOGS, events_dropped=1)
    assert any(w.startswith("1 helper event line dropped") for w in one.warnings)


def test_events_past_the_reader_cap_are_named_in_a_warning(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """sec4-5: lines past the reader's cap were reported only as "dropped (invalid, oversized or another
    events version)", which hid that the figures cover only the first events."""
    from scrapescope.attribution import core, read_events
    from scrapescope.types import event_to_json_line

    path = tmp_path / "events.jsonl"
    lines = [event_to_json_line(attach())] + [event_to_json_line(req(ts=T0 + 2 + i)) for i in range(24)]
    path.write_text("".join(lines) + "{broken\n")
    log = read_events(path, max_events=10)
    assert len(log.events) == 10 and log.capped == 16 and log.dropped == 16
    result = attribute(snap([tun()]), log.events, CATALOGS, events_dropped=log.dropped, events_capped=log.capped)
    (warning,) = [w for w in result.warnings if "not read" in w]
    assert warning.startswith("16 helper event lines were not read: the reader keeps at most 10 events")
    assert "cover only the events read" in warning and not any("dropped (invalid" in w for w in result.warnings)
    # Without the count (older callers) the cap is recognised by the number of events read.
    monkeypatch.setattr(core, "MAX_EVENTS", 10)
    inferred = attribute(snap([tun()]), log.events, CATALOGS, events_dropped=log.dropped)
    assert any(w.startswith("16 helper event lines were not read or were invalid") for w in inferred.warnings)
    # Invalid lines below the cap keep their own warning.
    log = read_events(path)
    assert log.capped == 0 and log.dropped == 1
    below = attribute(snap([tun()]), log.events, CATALOGS, events_dropped=log.dropped, events_capped=log.capped)
    assert any(w.startswith("1 helper event line dropped (invalid") for w in below.warnings)


def test_read_events_shares_repeated_strings(tmp_path) -> None:
    from scrapescope.attribution import read_events
    from scrapescope.types import event_to_json_line

    path = tmp_path / "events.jsonl"
    path.write_text("".join(event_to_json_line(req("cdn.example.test", ts=T0 + i)) for i in range(3)))
    events = read_events(path).events
    assert [e.host for e in events] == ["cdn.example.test"] * 3
    assert events[0].host is events[1].host is events[2].host  # one string object, not one per line
    assert events[0].resource_type is events[2].resource_type


def test_event_counts() -> None:
    events = [attach(), attach(context="1-2"), LaunchEvent(ts=T0, source="playwright"), req(), req()]
    result = attribute(snap([tun()]), events, CATALOGS)
    assert (result.events.attach, result.events.launch, result.events.request) == (2, 1, 2)
    assert result.browser_launches == 1


def test_attribute_is_deterministic() -> None:
    snapshot = snap([tun(), tun("origin-b.test"), tun("idle.test", sent=1, received=1, opened=T0 + 3)])
    events = [attach(), req(), req(rtype="image", body=777), req("origin-b.test", frame="sub")]
    first = attribute(snapshot, events, CATALOGS).to_dict()
    second = attribute(snapshot, list(events), CATALOGS).to_dict()
    assert first == second


# ---------------------------------------------------------------------------- schema conformance


def _schema() -> dict[str, Any]:
    return json.loads(resources.files("scrapescope.report").joinpath("schema.json").read_text(encoding="utf-8"))


def _check(instance: Any, schema: dict[str, Any], root: dict[str, Any], where: str = "$") -> list[str]:
    """Minimal validator for the keyword subset report/schema.json uses."""
    if "$ref" in schema:
        return _check(instance, root["$defs"][schema["$ref"].split("/")[-1]], root, where)
    errors: list[str] = []
    types = schema.get("type")
    if types is not None:
        types = [types] if isinstance(types, str) else types
        ok = {
            "object": isinstance(instance, dict),
            "array": isinstance(instance, list),
            "string": isinstance(instance, str),
            "integer": isinstance(instance, int) and not isinstance(instance, bool),
            "number": isinstance(instance, (int, float)) and not isinstance(instance, bool),
            "boolean": isinstance(instance, bool),
            "null": instance is None,
        }
        if not any(ok[t] for t in types):
            return [f"{where}: type {type(instance).__name__} not in {types}"]
    if "const" in schema and instance != schema["const"]:
        errors.append(f"{where}: const")
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{where}: enum {instance!r}")
    if isinstance(instance, dict):
        props = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in instance:
                errors.append(f"{where}: missing {key}")
        for key, value in instance.items():
            if "propertyNames" in schema:
                errors += _check(key, schema["propertyNames"], root, f"{where}.<{key}>")
            if key in props:
                errors += _check(value, props[key], root, f"{where}.{key}")
            else:
                extra = schema.get("additionalProperties", True)
                if extra is False:
                    errors.append(f"{where}: extra {key}")
                elif isinstance(extra, dict):
                    errors += _check(value, extra, root, f"{where}.{key}")
    if isinstance(instance, list):
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            errors.append(f"{where}: too many items")
        for i, item in enumerate(instance):
            if "items" in schema:
                errors += _check(item, schema["items"], root, f"{where}[{i}]")
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(f"{where}: below minimum")
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append(f"{where}: above maximum")
    if isinstance(instance, str):
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            errors.append(f"{where}: too long")
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append(f"{where}: too short")
        if "pattern" in schema:
            pattern = schema["pattern"]
            assert pattern.startswith("^") and pattern.endswith("$")
            if not re.fullmatch(pattern[1:-1], instance):
                errors.append(f"{where}: pattern {pattern} vs {instance!r}")
    return errors


def test_attribution_output_matches_report_schema_pieces() -> None:
    schema = _schema()
    props = schema["properties"]
    tunnels = [
        tun("optimizationguide-pa.googleapis.com", opened=T0 + 0.1),
        tun("origin-a.test"),
        tun("origin-c.test", sent=100, received=100, opened=T0 + 3),
        tun("api.openai.com", route="non-target", rule="openai"),
        tun("denied.test", route="refused", status="denied", sent=0, received=0),
        tun("[::1]".strip("[]"), port=8080),
    ]
    timeline = [TimelinePoint(t=T0 + i, sent=5, received=50) for i in range(10)]
    events = [attach(), LaunchEvent(ts=T0, source="playwright")]
    events += [nav(T0 + 2 + i, path=f"/product/{i}") for i in range(3)]
    events += [req(rtype="image", path="/static/img/hero-1.png"), req("bypass.test")]
    result = attribute(snap(tunnels, timeline=timeline), events, CATALOGS, events_dropped=1)
    data = result.to_dict()
    errors: list[str] = []
    for name in ("hosts", "types", "buckets", "non_target", "units", "per_unit", "status_histogram", "success",
                 "browser_launches", "bytes_before_first_navigation", "warnings"):
        errors += _check(data[name], props[name], schema, name)
    errors += _check({"hosts": data["bypass"]["hosts"], "requests": data["bypass"]["requests"]}, props["bypass"],
                     schema, "bypass")
    counts = data["events"]
    errors += _check(counts, props["helper_events"], schema, "helper_events")
    assert errors == []
    assert data["bypass"]["incomplete"] is True


# ---------------------------------------------------------------------------- bounded scale-up (meas-1)


def test_scale_up_is_bounded_and_the_rest_is_unreported() -> None:
    # meas-1 repro shape: an aborted 4 MB fetch left no event; the host's tunnel carried it anyway.
    # Before the fix, images were "allocated" about 4.15 MB against 0.63 MB reported.
    from scrapescope.model import compute_what_if
    from scrapescope.snippets import generate_fixes

    tunnel = tun(sent=20_000, received=4_557_944)
    snapshot = snap([tunnel])
    events = [
        attach(),
        nav(T0 + 2, body=9_000, rh=400, qh=600),
        *(req(rtype="image", body=210_000, rh=205, qh=0, qb=0) for _ in range(3)),
    ]
    result = attribute(snapshot, events, CATALOGS)
    row = host_row(result, "origin-a.test")
    reported = 10_000 + 3 * 210_205
    allowance = OVERHEAD_PER_TUNNEL_BYTES + reported // 4
    assert row.allocated_by_type[UNREPORTED_TYPE] == 4_577_944 - reported - allowance
    assert row.allocated_by_type["image"] <= 1.25 * 630_615 + OVERHEAD_PER_TUNNEL_BYTES
    types = {t.type: t for t in result.types}
    assert types[UNREPORTED_TYPE].requests == 0 and types[UNREPORTED_TYPE].reported_bytes == 0
    assert_buckets_sum(result, snapshot)
    assert any(f"type '{UNREPORTED_TYPE}'" in w and "origin-a.test" in w for w in result.warnings)
    # What-if and fixes leave the unreported bytes out: images are about a sixth of the run, not 97%.
    (block,) = [w for w in compute_what_if(result, snapshot.totals(), CATALOGS) if w.id == "block-images-media-fonts"]
    assert block.bytes_saved == row.allocated_by_type["image"] and block.share < 0.2
    (cdp,) = [f for f in generate_fixes(result, snapshot, CATALOGS) if f.id == "playwright-cdp-block"]
    assert int(re.search(r"were (\d+)% of the run", cdp.detection).group(1)) < 20


def test_a_record_that_continues_a_kept_connection_gets_no_setup_allowance() -> None:
    """meas4-6 (c): only a record that opened an upstream connection gets OVERHEAD_PER_TUNNEL_BYTES.

    On the HTTP CONNECT route a keep-alive plain-HTTP client that switches host keeps the provider
    connection; the new record (``continued_from``) set up no TLS or connection, so a second
    allowance would hide unreported bytes.
    """
    first = tun("origin-a.test", sent=500, received=1_500, neg_sent=146, neg_received=39, port=80)
    first.kind = "http"  # type: ignore[assignment]
    second = tun("origin-a.test", sent=500, received=80_000, port=80)
    second.kind, second.continued_from = "http", first.id  # type: ignore[assignment]
    assert first.opened_connection and not second.opened_connection
    snapshot = snap([first, second])
    events = [
        attach(),
        nav(T0 + 2, body=1_000, rh=300, qh=200, scheme="http"),
        req(ts=T0 + 3, rtype="xhr", body=1_000, rh=300, qh=200, scheme="http"),
    ]
    result = attribute(snapshot, events, CATALOGS)
    row = host_row(result, "origin-a.test")
    reported = 2 * 1_500
    total = first.bytes_with_connect + second.bytes_with_connect
    allowance = OVERHEAD_PER_TUNNEL_BYTES + 146 + 39 + reported // 4
    assert row.allocated_by_type[UNREPORTED_TYPE] == total - reported - allowance
    assert snapshot.totals().tunnels == 2 and snapshot.totals().connections == 1
    assert_buckets_sum(result, snapshot)


def test_small_overhead_is_shared_without_an_unreported_type() -> None:
    # A TLS handshake and a few percent of framing stay within the allowance.
    snapshot = snap([tun(sent=4_000, received=14_000)])
    events = [attach(), nav(T0 + 2, body=10_000, rh=300, qh=700)]
    result = attribute(snapshot, events, CATALOGS)
    assert host_row(result, "origin-a.test").allocated_by_type == {"document": 18_000}
    assert UNREPORTED_TYPE not in {t.type for t in result.types}
    assert not any(UNREPORTED_TYPE in w for w in result.warnings)


def test_unknown_headers_and_negotiation_extend_the_allowance() -> None:
    t = tun(sent=1_000, received=2_000, neg_sent=300, neg_received=39)
    events = [attach()] + [req(rtype="fetch", body=10, rh=None, qh=None, qb=1) for _ in range(40)]
    result = attribute(snap([t]), events, CATALOGS)
    row = host_row(result, "origin-a.test")
    # 440 reported + 40 x 512 unknown-header allowance + one tunnel's allowance covers 3,339 bytes.
    assert row.allocated_by_type == {"fetch": 3_339}


def test_scale_up_unbounded_when_a_successful_response_size_is_unknown() -> None:
    # A Requests hook on a chunked response reports no body size: nothing bounds what it carried.
    snapshot = snap([tun(sent=2_000, received=3_000_000)])
    events = [req(source="requests", rtype="http_client", frame="other", body=None, rh=300, qh=200)]
    result = attribute(snapshot, events, CATALOGS)
    assert host_row(result, "origin-a.test").allocated_by_type == {"http_client": 3_002_000}


def test_failed_requests_without_sizes_do_not_absorb_the_host_bytes() -> None:
    # A request flushed at context close (failed, sizes unknown) is bounded like any other.
    snapshot = snap([tun(sent=3_000, received=2_000_000)])
    events = [attach(), nav(T0 + 2, body=5_000, rh=300, qh=700),
              req(rtype="fetch", status=200, failed=True, body=None, rh=None, qh=None, qb=None)]
    result = attribute(snapshot, events, CATALOGS)
    row = host_row(result, "origin-a.test")
    assert row.allocated_by_type[UNREPORTED_TYPE] > 1_900_000
    assert_buckets_sum(result, snapshot)


def test_a_forged_unreported_resource_type_is_filed_as_other() -> None:
    result = attribute(snap([tun()]), [attach(), req(rtype=UNREPORTED_TYPE)], CATALOGS)
    assert {t.type for t in result.types} == {"other"}


def test_unreported_type_is_never_folded() -> None:
    events = [attach(), *(req(rtype=f"t{chr(97 + i // 26)}{chr(97 + i % 26)}", body=1) for i in range(80))]
    result = attribute(snap([tun(sent=10_000, received=2_000_000)]), events, CATALOGS)
    names = [t.type for t in result.types]
    assert len(names) == MAX_TYPES and UNREPORTED_TYPE in names and "other" in names


# ---------------------------------------------------------------------------- bypass by volume and time (meas-2)


def test_bypass_by_volume_one_request_through_the_meter_the_bulk_around_it() -> None:
    # meas-2 repro shape: one GET through the meter (6,268 B), then 5 x 2 MB through a Session with
    # its own proxies=; the hook reported 10 MB for the same host.
    snapshot = snap([tun(sent=1_268, received=5_000)])
    hook = {"source": "requests", "rtype": "http_client", "frame": "other"}
    events = [attach(), req(body=1_000, rh=200, qh=150, **hook),
              *(req(body=2_000_000, rh=200, qh=150, **hook) for _ in range(5))]
    result = attribute(snapshot, events, CATALOGS)
    assert result.bypass.incomplete is True
    assert result.bypass.hosts == ["origin-a.test"] and result.bypass.requests == 0
    (warning,) = [w for w in result.warnings if w.startswith("incomplete: helpers and hooks reported")]
    assert "10,003,100 B for origin-a.test" in warning and "only 6,268 B" in warning


@pytest.mark.parametrize("browser", ["firefox", "webkit"])
def test_firefox_and_webkit_sizes_are_flagged_unverified_and_kept_out_of_the_volume_check(browser: str) -> None:
    """meas3-2: Firefox/WebKit request sizes come without DevTools data; unrecognised cache hits
    made reported bytes exceed the tunnels (3.8 MB reported for 1.39 MB carried) and a false
    volume bypass. The run says the per-type figures are unverified and does not call it bypass."""
    snapshot = snap([tun(sent=10_000, received=500_000)])
    events = [attach(), LaunchEvent(ts=T0, source="playwright", browser=browser),  # type: ignore[arg-type]
              *(req(body=400_000, rtype="image") for _ in range(3))]
    result = attribute(snapshot, events, CATALOGS)
    assert result.bypass.incomplete is False
    (warning,) = [w for w in result.warnings if w.startswith(NON_CDP_WARNING_PREFIX)]
    assert {"firefox": "Firefox", "webkit": "WebKit"}[browser] in warning and "unverified" in warning
    # Hook traffic in the same run is still checked by volume, and a Chromium-only run gets no warning.
    hook = {"source": "requests", "rtype": "http_client", "frame": "other"}
    mixed = attribute(snapshot, [*events, *(req(body=2_000_000, **hook) for _ in range(5))], CATALOGS)
    assert mixed.bypass.incomplete is True and mixed.bypass.hosts == ["origin-a.test"]
    chromium = attribute(snapshot, [attach(), LaunchEvent(ts=T0, source="playwright"), req()], CATALOGS)
    assert not any(w.startswith(NON_CDP_WARNING_PREFIX) for w in chromium.warnings)
    assert all(t.allocated_bytes <= t.reported_bytes for t in result.types)


def test_no_volume_bypass_for_a_modest_scale_down() -> None:
    # HTTP/2 header estimates or compressed WebSocket frames can exceed the tunnel a little.
    snapshot = snap([tun(sent=10_000, received=90_000)])
    events = [attach(), req(body=140_000, rh=0, qh=0, rtype="image"),
              req(rtype="websocket", body=5_000_000, rh=None, qh=None, qb=100_000, status=101)]
    result = attribute(snapshot, events, CATALOGS)
    assert result.bypass.incomplete is False and result.bypass.hosts == []


def test_bypass_by_time_after_every_tunnel_closed() -> None:
    snapshot = snap([tun(opened=T0 + 1)])  # closed at T0 + 6
    within = attribute(snapshot, [attach(), req(ts=T0 + 7.5)], CATALOGS)
    assert within.bypass.incomplete is False
    late = attribute(snapshot, [attach(), req(ts=T0 + 3), req(ts=T0 + 30), req(ts=T0 + 40)], CATALOGS)
    assert late.bypass.incomplete is True and late.bypass.requests == 2 and late.bypass.hosts == ["origin-a.test"]
    assert any(w.startswith("incomplete: helpers saw 2 network requests to 1 host") for w in late.warnings)


def test_open_tunnels_count_until_the_snapshot() -> None:
    t = tun(opened=T0 + 1)
    t.closed_at = None
    t.status = "open"
    result = attribute(snap([t]), [attach(), req(ts=T0 + 90)], CATALOGS)  # snapshot taken at T0 + 100
    assert result.bypass.incomplete is False


# ---------------------------------------------------------------------------- round 2: no-network events,
# ---------------------------------------------------------------------------- budget refusals


def _no_network(kind: str, **kw: Any) -> RequestEvent:
    """A request event as read from a line with the helpers' no_network marker."""
    from dataclasses import fields

    from scrapescope.attribution import NoNetworkRequestEvent

    base = req(**kw)
    values = {f.name: getattr(base, f.name) for f in fields(RequestEvent) if f.init}
    return NoNetworkRequestEvent(**values, no_network=kind)


def test_requests_that_never_reached_the_network_are_not_network_requests() -> None:
    """meas2-1: route.fulfill stubs, route.abort and browser blocks carry no tunnel bytes.

    Before: a stub for a host no tunnel carried was bypass, a fulfilled font on a metered host took a
    share of its tunnel bytes, and aborted or mixed-content-blocked requests were "failed" in the
    status line and took a metered host's idle bytes by request count.
    """
    tunnels = [tun("origin-a.test", sent=2_000, received=20_000), tun("cdn.test", sent=1_500, received=4_000)]
    events = [
        attach(),
        nav(T0 + 2, body=10_000),
        _no_network("fulfilled", host="stub.invalid", rtype="script", body=0, rh=0, qh=0),
        _no_network("fulfilled", rtype="font", body=0, rh=0, qh=0),
        _no_network("aborted", host="cdn.test", rtype="image", status=None, failed=True, body=None, rh=None, qh=None),
        _no_network("blocked", host="ajax.googleapis.com", scheme="http", rtype="script", status=None,
                    failed=True, body=None, rh=None, qh=None),
    ]
    result = attribute(snap(tunnels), events, CATALOGS)
    assert result.bypass.incomplete is False and result.bypass.requests == 0
    assert result.status_histogram == {"200": 1}
    assert {t.type for t in result.types} == {"document"}
    rows = {h.host: h for h in result.hosts}
    assert rows["origin-a.test"].allocated_by_type == {"document": rows["origin-a.test"].bytes_with_connect}
    # A host whose only events never reached the network keeps its tunnel in the idle buckets.
    assert "attributed" not in rows["cdn.test"].buckets and rows["cdn.test"].requests == 0
    (warning,) = [w for w in result.warnings if "never reached the network" in w]
    assert warning.startswith("4 request events never reached the network: 2 answered by request interception")
    assert "1 aborted by route.abort" in warning and "1 blocked by the browser before sending" in warning
    assert result.events.request == 5
    assert_buckets_sum(result, snap(tunnels))


def _tripped(tunnels: list[TunnelRecord], at: float) -> MeterSnapshot:
    from scrapescope.types import BudgetEvent

    s = snap(tunnels)
    s.budget_bytes = 300_000
    s.budget_tripped = True
    s.budget_events = [BudgetEvent(ts=at - 1, kind="warn_80", counted_bytes=240_000, limit_bytes=300_000),
                       BudgetEvent(ts=at, kind="tripped", counted_bytes=300_100, limit_bytes=300_000)]
    s.refused = {"budget": 3}
    return s


def test_budget_refusals_after_the_trip_are_not_bypass() -> None:
    """meas2-8: after a trip the meter answers plain-HTTP requests itself with 403 and records no tunnel."""
    tunnels = [tun("origin-a.test", port=80)]
    trip = tunnels[0].closed_at
    assert trip is not None
    hooks = [attach()] + [
        req(ts=trip + 3 + i, status=403, source="requests", rtype="http_client", frame="other", scheme="http")
        for i in range(3)
    ]
    result = attribute(_tripped(tunnels, trip), hooks, CATALOGS)
    assert result.bypass.incomplete is False and result.bypass.requests == 0
    assert not any("no meter tunnel carried" in w for w in result.warnings)
    # A new host after the trip is refused the same way (no tunnel of any status).
    other = req("origin-b.test", ts=trip + 1, status=403, source="requests", rtype="http_client", scheme="http")
    assert attribute(_tripped(tunnels, trip), [attach(), other], CATALOGS).bypass.incomplete is False
    # Without a trip, or for a response the meter never sends after a trip, it is still bypass.
    assert attribute(snap(tunnels), hooks, CATALOGS).bypass.incomplete is True
    ok_after = req(ts=trip + 3, status=200, source="requests", rtype="http_client", scheme="http")
    assert attribute(_tripped(tunnels, trip), [attach(), ok_after], CATALOGS).bypass.incomplete is True
    # A 403 that started well before the trip is judged like any other request.
    early = req("origin-b.test", ts=trip - 10, status=403, source="requests", rtype="http_client", scheme="http")
    assert attribute(_tripped(tunnels, trip), [attach(), early], CATALOGS).bypass.incomplete is True
