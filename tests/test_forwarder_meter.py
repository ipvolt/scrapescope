"""Unit tests of scrapescope.forwarder.meter (no sockets)."""

from __future__ import annotations

import threading

import pytest

from scrapescope.config import synthetic_connect_sizes
from scrapescope.forwarder.meter import Meter, Tunnel
from scrapescope.types import BudgetEvent


class Clock:
    def __init__(self, t: float = 1_790_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def _meter(**kwargs: object) -> tuple[Meter, Clock]:
    clock = Clock()
    return Meter(mode="http-connect", clock=clock, **kwargs), clock  # type: ignore[arg-type]


def _tunnel(meter: Meter, host: str = "a.test", route: str = "http-connect", kind: str = "connect") -> Tunnel:
    return meter.open_tunnel(host=host, port=443, kind=kind, route=route)  # type: ignore[arg-type]


def test_counts_negotiation_and_totals() -> None:
    meter, _ = _meter()
    t = _tunnel(meter)
    meter.add_sent(t, 100, negotiation=100)
    meter.add_received(t, 39)
    meter.mark_negotiation_received(t, 39)
    meter.add_sent(t, 500)
    meter.add_received(t, 2000)
    meter.set_connect_sizes(t, 100, 60)
    meter.finish(t)
    snap = meter.snapshot()
    (rec,) = snap.tunnels
    assert (rec.upstream_bytes_sent, rec.upstream_bytes_received) == (600, 2039)
    assert (rec.negotiation_bytes_sent, rec.negotiation_bytes_received) == (100, 39)
    assert (rec.connect_request_bytes, rec.proxy_authorization_bytes) == (100, 60)
    totals = snap.totals()
    assert totals.with_connect == 2639 and totals.without_connect == 2500
    assert snap.counted_bytes == 2639
    assert rec.status == "ok" and rec.closed_at is not None


def test_negotiation_mark_never_exceeds_received() -> None:
    meter, _ = _meter()
    t = _tunnel(meter)
    meter.add_received(t, 10)
    meter.mark_negotiation_received(t, 50)
    assert meter.snapshot().tunnels[0].negotiation_bytes_received == 10


def test_mark_all_negotiation() -> None:
    meter, _ = _meter()
    t = _tunnel(meter)
    meter.add_sent(t, 120)
    meter.add_received(t, 80)
    meter.mark_all_negotiation(t)
    rec = meter.snapshot().tunnels[0]
    assert rec.negotiation_bytes_sent == 120 and rec.negotiation_bytes_received == 80
    assert rec.bytes_without_connect == 0


def test_warn_then_trip_counts_the_tripping_slice() -> None:
    meter, _ = _meter(budget_bytes=1000)
    events: list[BudgetEvent] = []
    meter.on_budget(events.append)
    aborted: list[str] = []
    a = _tunnel(meter, "a.test")
    b = _tunnel(meter, "b.test")
    a.add_aborter(lambda: aborted.append("a"))
    b.add_aborter(lambda: aborted.append("b"))
    meter.add_received(a, 700)
    assert events == []
    meter.add_received(b, 150)  # 850 >= 800: warn
    assert [e.kind for e in events] == ["warn_80"]
    meter.add_received(a, 400)  # 1250 >= 1000: trip, slice counted
    assert [e.kind for e in events] == ["warn_80", "tripped"]
    trip = events[1]
    assert trip.counted_bytes == 1250 and trip.limit_bytes == 1000 and trip.closed_tunnels == 2
    assert [(h.host, h.bytes) for h in trip.top_hosts] == [("a.test", 1100), ("b.test", 150)]
    assert sorted(aborted) == ["a", "b"]
    snap = meter.snapshot()
    assert snap.budget_tripped and meter.budget_tripped
    assert [t.status for t in snap.tunnels] == ["budget", "budget"]
    assert a.closing and b.closing
    # A later normal finish does not overwrite the budget status.
    assert meter.finish(a, "ok") is False
    assert meter.snapshot().tunnels[0].status == "budget"
    # Trip fires once.
    meter.add_received(a, 10_000)
    assert [e.kind for e in events] == ["warn_80", "tripped"]


def test_single_read_can_warn_and_trip() -> None:
    meter, _ = _meter(budget_bytes=100)
    events: list[BudgetEvent] = []
    meter.on_budget(events.append)
    meter.add_sent(_tunnel(meter), 500)
    assert [e.kind for e in events] == ["warn_80", "tripped"]


def test_sent_bytes_count_toward_budget() -> None:
    meter, _ = _meter(budget_bytes=1000)
    t = _tunnel(meter)
    meter.add_sent(t, 1000, negotiation=1000)
    assert meter.budget_tripped


def test_tunnel_cap_closes_only_that_tunnel() -> None:
    meter, _ = _meter(max_tunnel_bytes=1000)
    events: list[BudgetEvent] = []
    meter.on_budget(events.append)
    a, b = _tunnel(meter, "a.test"), _tunnel(meter, "b.test")
    hits: list[str] = []
    a.add_aborter(lambda: hits.append("a"))
    b.add_aborter(lambda: hits.append("b"))
    meter.add_received(b, 999)
    meter.add_received(a, 600)
    meter.add_sent(a, 600)
    assert hits == ["a"]
    (event,) = events
    assert event.kind == "tunnel_cap" and event.tunnel_id == a.id and event.host == "a.test"
    assert event.counted_bytes == 1200 and event.limit_bytes == 1000 and event.closed_tunnels == 1
    statuses = {t.host: t.status for t in meter.snapshot().tunnels}
    assert statuses == {"a.test": "tunnel_cap", "b.test": "open"}
    meter.add_received(a, 10)  # counted, no second event
    assert len(events) == 1


def test_non_target_tunnels_are_excluded() -> None:
    meter, _ = _meter(budget_bytes=100, max_tunnel_bytes=50)
    t = meter.open_tunnel(host="api.openai.com", port=443, kind="connect", route="non-target", rule="openai")
    meter.add_received(t, 10_000)
    snap = meter.snapshot()
    assert snap.counted_bytes == 0 and not snap.budget_tripped and snap.timeline == []
    assert snap.tunnels[0].upstream_bytes_received == 10_000 and snap.tunnels[0].status == "open"
    assert snap.totals().with_connect == 0


def test_denied_records_and_refusals() -> None:
    meter, _ = _meter()
    rec = meter.record_denied(host="x.test", port=443, kind="connect", listener="main", rule="deny-host:x.test")
    meter.refuse("origin_form")
    meter.refuse("origin_form")
    snap = meter.snapshot()
    assert snap.tunnels[0].status == "denied" and snap.tunnels[0].route == "refused" and rec.rule == "deny-host:x.test"
    assert snap.refused == {"origin_form": 2}
    assert snap.totals().denied_tunnels == 1 and snap.totals().tunnels == 0


def test_direct_mode_synthetic_sizes() -> None:
    meter = Meter(mode="direct", clock=Clock())
    t = meter.open_tunnel(host="origin-a.test", port=443, kind="connect", route="direct")
    h = meter.open_tunnel(host="origin-a.test", port=80, kind="http", route="direct")
    meter.add_received(t, 1000)
    rec, rec_http = meter.snapshot().tunnels
    assert (rec.synthetic_negotiation_bytes_sent, rec.synthetic_negotiation_bytes_received) == synthetic_connect_sizes(
        "origin-a.test", 443
    )
    assert rec_http.synthetic_negotiation_bytes_sent == 0
    snap = meter.snapshot()
    assert snap.counted_bytes == 1000
    assert snap.totals().with_connect_estimated
    assert snap.totals().with_connect == 1000 + sum(synthetic_connect_sizes("origin-a.test", 443))
    assert h.record.route == "direct"


def test_timeline_buckets_and_top_hosts_window() -> None:
    meter, clock = _meter(budget_bytes=10_000, timeline_resolution_s=0.25)
    old = _tunnel(meter, "old.test")
    new = _tunnel(meter, "new.test")
    meter.add_sent(old, 3000)
    clock.t += 0.1
    meter.add_received(old, 1000)
    clock.t += 0.2  # next 0.25 s bucket
    meter.add_received(old, 500)
    clock.t += 120  # the window only covers the final minute
    meter.add_received(new, 3000)
    meter.add_received(new, 3000)
    snap = meter.snapshot()
    base = 1_790_000_000.0
    assert [(p.t, p.sent, p.received) for p in snap.timeline] == [
        (base, 3000, 1000),
        (base + 0.25, 0, 500),
        (base + 120.25, 0, 6000),
    ]
    trip = [e for e in snap.budget_events if e.kind == "tripped"][0]
    assert [h.host for h in trip.top_hosts] == ["new.test"]


def test_top_hosts_limited_to_ten() -> None:
    meter, _ = _meter(budget_bytes=10**6)
    for i in range(15):
        meter.add_received(_tunnel(meter, f"h{i:02d}.test"), 1000 + i)
    meter.add_received(_tunnel(meter, "last.test"), 10**6)
    trip = meter.snapshot().budget_events[-1]
    assert len(trip.top_hosts) == 10
    assert trip.top_hosts[0].host == "last.test"
    assert [h.bytes for h in trip.top_hosts] == sorted((h.bytes for h in trip.top_hosts), reverse=True)


def test_callback_exception_counted_not_raised() -> None:
    meter, _ = _meter(budget_bytes=10)

    def boom(event: BudgetEvent) -> None:
        raise ValueError("bug")

    seen: list[str] = []
    meter.on_budget(boom)
    meter.on_budget(lambda e: seen.append(e.kind))
    meter.add_received(_tunnel(meter), 100)
    snap = meter.snapshot()
    assert snap.internal_errors == 2 and seen == ["warn_80", "tripped"]


def test_close_all_and_first_status_wins() -> None:
    meter, _ = _meter()
    a, _b = _tunnel(meter), _tunnel(meter)
    meter.finish(a, "failed:upstream_status")
    assert meter.close_all() == 1
    assert [t.status for t in meter.snapshot().tunnels] == ["failed:upstream_status", "ok"]
    assert meter.open_tunnels() == []


def test_snapshot_is_a_copy() -> None:
    meter, _ = _meter(budget_bytes=100)
    t = _tunnel(meter)
    meter.add_received(t, 200)
    snap = meter.snapshot()
    snap.tunnels[0].upstream_bytes_received = 1
    snap.budget_events[0].top_hosts.clear()
    snap.refused["x"] = 1
    again = meter.snapshot()
    assert again.tunnels[0].upstream_bytes_received == 200
    assert again.budget_events[1].top_hosts
    assert again.refused == {}


def test_snapshot_from_other_threads_while_counting() -> None:
    meter, _ = _meter()
    tunnels = [_tunnel(meter, f"h{i}.test") for i in range(20)]
    stop = threading.Event()
    errors: list[BaseException] = []

    def reader() -> None:
        try:
            while not stop.is_set():
                snap = meter.snapshot()
                assert snap.counted_bytes == sum(t.counted_bytes for t in snap.tunnels)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(3)]
    for th in threads:
        th.start()
    for _ in range(2000):
        for t in tunnels:
            meter.add_received(t, 7)
    stop.set()
    for th in threads:
        th.join()
    assert not errors
    assert meter.snapshot().counted_bytes == 2000 * 20 * 7


def test_invalid_limits_rejected() -> None:
    with pytest.raises(ValueError):
        Meter(mode="direct", budget_bytes=0)
    with pytest.raises(ValueError):
        Meter(mode="direct", max_tunnel_bytes=-1)
    with pytest.raises(ValueError):
        Meter(mode="direct", timeline_resolution_s=0)


def test_snapshot_holds_the_lock_only_for_open_and_changed_records(monkeypatch: pytest.MonkeyPatch) -> None:
    """sec-14: a snapshot must not copy every finished record while the loop thread waits for the lock."""
    from scrapescope.forwarder import meter as meter_module

    meter, _clock = _meter()
    tunnels = [_tunnel(meter, host=f"h{i}.test") for i in range(2000)]
    for tunnel in tunnels[:1990]:
        meter.add_received(tunnel, 10)
        meter.finish(tunnel)
    first = meter.snapshot()
    assert len(first.tunnels) == 2000
    under_lock: list[bool] = []
    real = meter_module._copy_record

    def spy(rec):  # noqa: ANN001, ANN202 - test spy
        under_lock.append(meter._lock.locked())
        return real(rec)

    monkeypatch.setattr(meter_module, "_copy_record", spy)
    meter.add_client(tunnels[5], sent=7)  # a late change to a finished record must still show up
    second = meter.snapshot()
    assert under_lock.count(True) == 10 + 1  # the 10 open tunnels and the 1 changed record
    assert len(second.tunnels) == 2000
    assert second.tunnels[5].client_bytes_sent == 7 and first.tunnels[5].client_bytes_sent == 0
    second.tunnels[0].host = "mutated.test"
    assert meter.snapshot().tunnels[0].host == "h0.test"  # callers get their own objects
    assert meter.open_count() == 10


# ---------------------------------------------------------------------------- bounded timeline (sec2-7)
def test_timeline_is_bounded_by_merging_slots_and_doubling_the_step() -> None:
    meter, clock = _meter(max_timeline_slots=64)
    t = _tunnel(meter)
    start = clock.t
    for i in range(1000):  # 1000 slots at 0.25 s, one count each
        clock.t = start + i * 0.25
        meter.add_received(t, 10)
        meter.add_sent(t, 1)
    snap = meter.snapshot()
    assert len(snap.timeline) <= 64
    assert snap.timeline_resolution_s == 0.25 * 16  # 1000 slots -> halved four times to 63
    assert sum(p.received for p in snap.timeline) == 10_000 and sum(p.sent for p in snap.timeline) == 1000
    assert snap.counted_bytes == 11_000
    step = snap.timeline_resolution_s
    assert all(p.t % step == 0 for p in snap.timeline)  # bucket starts on the (coarser) grid
    assert snap.timeline[0].t <= start < snap.timeline[0].t + step


def test_default_timeline_stays_bounded_for_a_long_session() -> None:
    from scrapescope.forwarder.meter import MAX_TIMELINE_SLOTS

    meter, clock = _meter()
    t = _tunnel(meter)
    start = clock.t
    for i in range(3 * MAX_TIMELINE_SLOTS):
        clock.t = start + i * 0.25
        meter.add_received(t, 1)
    snap = meter.snapshot()
    assert len(snap.timeline) <= MAX_TIMELINE_SLOTS
    assert sum(p.received for p in snap.timeline) == 3 * MAX_TIMELINE_SLOTS
    assert len(meter._timeline) <= MAX_TIMELINE_SLOTS  # the live structure, not just the copy


def test_record_timeline_off_keeps_no_slots() -> None:
    meter, clock = _meter(record_timeline=False)
    t = _tunnel(meter)
    for i in range(100):
        clock.t += 0.25
        meter.add_received(t, 5)
    snap = meter.snapshot()
    assert snap.timeline == [] and snap.counted_bytes == 500 and meter._timeline == {}


def test_snapshot_builds_timeline_points_outside_the_lock(monkeypatch: pytest.MonkeyPatch) -> None:
    """The loop thread must not wait while TimelinePoint objects are built."""
    import scrapescope.forwarder.meter as meter_module

    meter, clock = _meter()
    t = _tunnel(meter)
    for i in range(200):
        clock.t += 0.25
        meter.add_received(t, 1)
    held: list[bool] = []
    real_point = meter_module.TimelinePoint

    def point(**kwargs: object) -> object:
        held.append(meter._lock.locked())
        return real_point(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(meter_module, "TimelinePoint", point)
    snap = meter.snapshot()
    assert len(snap.timeline) == 200 and held and not any(held)


def test_forwarder_config_timeline_flag_reaches_the_meter() -> None:
    from scrapescope.config import ForwarderConfig
    from scrapescope.forwarder import Forwarder

    assert Forwarder(ForwarderConfig()).meter._record_timeline is True
    assert Forwarder(ForwarderConfig(record_timeline=False)).meter._record_timeline is False


# ---------------------------------------------------------------------------- discarded sends (meas2-7)
def test_discard_sent_uncounts_tunnel_budget_and_timeline() -> None:
    meter, clock = _meter(budget_bytes=10_000)
    t = _tunnel(meter)
    meter.add_sent(t, 100, negotiation=100)
    clock.t += 1.0
    meter.add_sent(t, 5_000)
    meter.discard_sent(t, 3_000)
    meter.discard_sent(t, 10**9)  # never below zero
    snap = meter.snapshot()
    (rec,) = snap.tunnels
    assert rec.upstream_bytes_sent == 0 and rec.negotiation_bytes_sent == 0
    assert snap.counted_bytes == 0 and sum(p.sent for p in snap.timeline) == 0


def test_discard_sent_keeps_a_trip_in_force() -> None:
    meter, _ = _meter(budget_bytes=1_000)
    t = _tunnel(meter)
    meter.add_sent(t, 1_500)
    assert meter.budget_tripped
    meter.discard_sent(t, 900)
    snap = meter.snapshot()
    assert snap.budget_tripped and snap.counted_bytes == 600
    assert [e.kind for e in snap.budget_events] == ["warn_80", "tripped"]
    assert snap.budget_events[-1].counted_bytes == 1_500  # what the meter decided on


def test_accept_limit_errors_reach_the_snapshot() -> None:
    meter, _ = _meter()
    meter.accept_limit_error()
    meter.accept_limit_error()
    assert meter.snapshot().accept_limit_errors == 2
