"""Budget guard, per-tunnel cap, deny rules, non-target carriage and concurrency."""

from __future__ import annotations

import asyncio
import threading
import time

import httpx
import pytest

from scrapescope.config import HostRule
from scrapescope.types import BudgetEvent
from tests.fixtures import TestWorld, site
from tests.test_forwarder_helpers import (
    Collected,
    connect_with_retry,
    deny,
    fetch,
    http_get_in_tunnel,
    make_config,
    open_connect,
    parse_response,
    raw_exchange,
    running,
    settle,
    wait_tunnels_closed,
    wait_until,
)

pytestmark = pytest.mark.timeout(60)

#: Largest single read the asyncio socket transport hands to the protocol.
MAX_READ = 256 * 1024


def _download(port: int, size: int, *, delay_ms: int = 0, host: str = "origin-a.test") -> bytes:
    """CONNECT host:80 through the meter and GET /big.bin?size=... inside the tunnel."""
    sock, reply, rest = open_connect(port, f"{host}:80", timeout=20)
    try:
        if reply.status != 200:
            return reply.raw
        query = f"/big.bin?size={size}&chunk=65536&delay_ms={delay_ms}"
        return rest + http_get_in_tunnel(sock, host, query)
    finally:
        sock.close()


def _open_count(fw) -> int:
    return len([t for t in fw.snapshot().tunnels if t.status == "open"])


def _start_staggered(target, n: int, *, with_index: bool = False) -> list[threading.Thread]:
    """Start n threads 5 ms apart (a burst of simultaneous SYNs stalls macOS loopback)."""
    threads = []
    for i in range(n):
        th = threading.Thread(target=target, args=(i,) if with_index else ())
        th.start()
        threads.append(th)
        time.sleep(0.005)
    return threads


# ---------------------------------------------------------------------------- budget
def test_budget_trip_mid_download(fresh_world: TestWorld) -> None:
    budget = 1_000_000
    events = Collected()
    config = make_config(fresh_world.http_upstream.url, budget_bytes=budget)
    with running(config) as fw:
        fw.on_budget(events)
        data = _download(fw.port, 20_000_000, delay_ms=2)
        assert fw.budget_tripped.wait(5)
        assert fw.forwarder.budget_tripped
        # New tunnels (and plain HTTP) are refused while the forwarder runs.
        refused = raw_exchange(fw.port, b"CONNECT origin-a.test:443 HTTP/1.1\r\nHost: origin-a.test:443\r\n\r\n")
        plain = raw_exchange(fw.port, b"GET http://origin-a.test/ HTTP/1.1\r\nHost: origin-a.test\r\n\r\n")
        snap = settle(fresh_world, fw)
    assert len(data) < 20_000_000
    for resp in (refused, plain):
        assert resp.status == 403
        assert resp.header("X-Scrapescope-Budget") == "tripped"
        assert resp.header("X-Scrapescope-Error") == "budget"
    assert snap.refused == {"budget": 2}
    assert snap.budget_tripped and snap.budget_bytes == budget
    kinds = [e.kind for e in snap.budget_events]
    assert kinds == ["warn_80", "tripped"]
    warn, trip = snap.budget_events
    assert warn.counted_bytes >= 0.8 * budget and warn.limit_bytes == budget
    # Count on read, including the slice that tripped it.
    assert budget <= trip.counted_bytes < budget + MAX_READ + 4096
    assert snap.counted_bytes == trip.counted_bytes
    assert trip.closed_tunnels == 1
    assert trip.top_hosts and trip.top_hosts[0].host == "origin-a.test"
    assert trip.top_hosts[0].bytes == trip.counted_bytes
    (tunnel,) = snap.target_tunnels()
    assert tunnel.status == "budget" and tunnel.counted_bytes == snap.counted_bytes
    # The meter never counts more than the upstream actually sent or read.
    (record,) = fresh_world.http_upstream.records()
    assert tunnel.upstream_bytes_received <= record.bytes_to_client
    assert tunnel.upstream_bytes_sent == record.bytes_from_client
    # The client received at most what the meter counted.
    assert len(data) <= tunnel.upstream_bytes_received
    assert [e.kind for e in events.snapshot()] == ["warn_80", "tripped"]
    assert all(isinstance(e, BudgetEvent) for e in events.snapshot())


def test_budget_trip_closes_50_concurrent_tunnels(fresh_world: TestWorld) -> None:
    budget = 6_000_000
    config = make_config(fresh_world.http_upstream.url, budget_bytes=budget)
    results: list[int] = []
    lock = threading.Lock()
    with running(config) as fw:
        barrier = threading.Barrier(51)  # 50 workers + this thread

        def worker() -> None:
            sock, _reply, rest = connect_with_retry(fw.port, "origin-a.test:80")
            try:
                barrier.wait(60)
                got = len(rest + http_get_in_tunnel(sock, "origin-a.test", "/big.bin?size=5000000&chunk=65536&delay_ms=20"))
            finally:
                sock.close()
            with lock:
                results.append(got)

        threads = _start_staggered(worker, 50)
        assert wait_until(lambda: _open_count(fw) == 50, 60), _open_count(fw)
        barrier.wait(10)  # all 50 tunnels are open at once; now download
        for t in threads:
            t.join(60)
        assert fw.budget_tripped.is_set()
        snap = settle(fresh_world, fw, timeout=20)
    assert len(results) == 50
    trip = [e for e in snap.budget_events if e.kind == "tripped"][0]
    target = snap.target_tunnels()
    budget_closed = [t for t in target if t.status == "budget"]
    # Every tunnel open at the trip was closed by it; any other one had closed before.
    assert trip.closed_tunnels == len(budget_closed) >= 1
    assert all(t.closed_at == trip.ts for t in budget_closed)
    assert all(t.closed_at is not None and t.closed_at <= trip.ts for t in target if t.status != "budget")
    # Normally all 50 are still downloading; kernel connect stalls in the fixture can let a few finish first.
    assert len(budget_closed) + len([t for t in target if t.status == "ok"]) >= 50
    assert budget <= trip.counted_bytes < budget + 50 * MAX_READ
    assert snap.counted_bytes >= trip.counted_bytes
    assert sum(results) < 50 * 5_000_000


def test_warn_only_below_budget(fresh_world: TestWorld) -> None:
    config = make_config(fresh_world.http_upstream.url, budget_bytes=1_000_000)
    with running(config) as fw:
        data = _download(fw.port, 850_000)
        snap = settle(fresh_world, fw)
    assert data.endswith(site.big_bytes(850_000 - 1000, 1000))
    assert [e.kind for e in snap.budget_events] == ["warn_80"]
    assert not snap.budget_tripped
    assert not fw.budget_tripped.is_set()


def test_budget_callback_exception_is_counted(fresh_world: TestWorld) -> None:
    def broken(event: BudgetEvent) -> None:
        raise RuntimeError("callback bug")

    config = make_config(fresh_world.http_upstream.url, budget_bytes=200_000)
    with running(config) as fw:
        fw.on_budget(broken)
        _download(fw.port, 2_000_000)
        assert fw.budget_tripped.wait(5)
        snap = settle(fresh_world, fw)
    assert snap.internal_errors == 2  # warn_80 and tripped
    assert snap.budget_tripped


# ---------------------------------------------------------------------------- tunnel cap
def test_max_tunnel_bytes_closes_only_that_tunnel(fresh_world: TestWorld) -> None:
    cap = 500_000
    events = Collected()
    config = make_config(fresh_world.http_upstream.url, max_tunnel_bytes=cap)
    with running(config) as fw:
        fw.on_budget(events)
        big = _download(fw.port, 5_000_000, delay_ms=2)
        small = _download(fw.port, 100_000)
        snap = settle(fresh_world, fw)
    assert len(big) < 5_000_000
    assert small.endswith(site.big_bytes(100_000 - 100, 100))
    first, second = snap.target_tunnels()
    assert first.status == "tunnel_cap" and second.status == "ok"
    assert cap <= first.counted_bytes < cap + MAX_READ + 4096
    (event,) = snap.budget_events
    assert event.kind == "tunnel_cap" and event.tunnel_id == first.id and event.host == "origin-a.test"
    assert event.limit_bytes == cap and event.counted_bytes == first.counted_bytes
    assert not snap.budget_tripped
    assert [e.kind for e in events.snapshot()] == ["tunnel_cap"]


def test_max_tunnel_bytes_follows_a_kept_provider_connection_across_authorities(fresh_world: TestWorld) -> None:
    """meas4-6 (a): continued records share their connection's count; the cap is per upstream connection."""
    import http.client

    cap = 100_000
    events = Collected()
    config = make_config(fresh_world.http_upstream.url, max_tunnel_bytes=cap)
    received = 0
    with running(config) as fw:
        fw.on_budget(events)
        conn = http.client.HTTPConnection("127.0.0.1", fw.port, timeout=20)
        with pytest.raises((http.client.HTTPException, OSError)):
            for _ in range(3):
                for host in ("origin-a.test", "origin-b.test"):
                    conn.request("GET", f"http://{host}/big.bin?size=60000")
                    received += len(conn.getresponse().read())
        conn.close()
        snap = settle(fresh_world, fw)
    assert received == 60_000  # before the fix all six responses (360,000 B) went through one connection
    first, second = snap.target_tunnels()
    assert second.continued_from == first.id and not second.opened_connection
    assert (first.status, second.status) == ("ok", "tunnel_cap")
    (event,) = snap.budget_events
    assert event.kind == "tunnel_cap" and event.tunnel_id == second.id and event.host == "origin-b.test"
    assert event.counted_bytes == first.counted_bytes + second.counted_bytes >= cap
    assert fresh_world.http_upstream.totals()["connections"] == 1
    totals = snap.totals()
    assert (totals.tunnels, totals.connections) == (2, 1)  # meas4-6 (b): records versus connections
    assert [e.kind for e in events.snapshot()] == ["tunnel_cap"]


# ---------------------------------------------------------------------------- deny and non-target
def test_deny_host_refuses_and_records(fresh_world: TestWorld) -> None:
    rules = (
        deny("*.googleapis.com"),
        HostRule("clients2.google.com", "catalog:background:component-updater"),
    )
    config = make_config(fresh_world.http_upstream.url, deny_rules=rules)
    with running(config) as fw:
        a = raw_exchange(fw.port, b"CONNECT update.googleapis.com:443 HTTP/1.1\r\nHost: update.googleapis.com:443\r\n\r\n")
        b = raw_exchange(
            fw.port, b"GET http://clients2.google.com/service HTTP/1.1\r\nHost: clients2.google.com\r\n\r\n"
        )
        ok = fetch(fresh_world, "httpx", fw.url, "https://origin-a.test/api/product.json")
        snap = settle(fresh_world, fw)
    for resp in (a, b):
        assert resp.status == 403 and resp.header("X-Scrapescope-Error") == "denied"
    assert ok[0] == 200
    denied = snap.denied_tunnels()
    assert [(t.host, t.port, t.kind, t.route, t.rule) for t in denied] == [
        ("update.googleapis.com", 443, "connect", "refused", "deny-host:*.googleapis.com"),
        ("clients2.google.com", 80, "http", "refused", "catalog:background:component-updater"),
    ]
    assert all(t.counted_bytes == 0 and t.closed_at is not None for t in denied)
    assert snap.totals().denied_tunnels == 2 and snap.totals().tunnels == 1
    assert {r.target for r in fresh_world.http_upstream.records()} == {"origin-a.test:443"}
    assert snap.refused == {}


@pytest.mark.parametrize(
    "target",
    ["1.2.3.4", "1.2.3.04", "0x01020304", "16909060", "1.2.772", "01.02.03.04", "[::ffff:1.2.3.4]"],
)
def test_deny_rule_on_an_address_covers_every_spelling(fresh_world: TestWorld, target: str) -> None:
    """sec3-5: legacy IPv4 spellings and mapped IPv6 name the same address, so the same rule applies."""
    config = make_config(fresh_world.http_upstream.url, deny_rules=(deny("1.2.3.4"), deny("2001:DB8:0::1")))
    with running(config) as fw:
        tunnel = raw_exchange(fw.port, f"CONNECT {target}:443 HTTP/1.1\r\nHost: {target}:443\r\n\r\n".encode())
        plain = raw_exchange(fw.port, f"GET http://{target}/ HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        snap = fw.snapshot()
    for resp in (tunnel, plain):
        assert resp.status == 403 and resp.header("X-Scrapescope-Error") == "denied", target
    assert [(t.host, t.status, t.rule) for t in snap.tunnels] == [("1.2.3.4", "denied", "deny-host:1.2.3.4")] * 2
    assert fresh_world.http_upstream.records() == []


def test_deny_rule_on_an_ipv6_address_covers_non_canonical_spellings(fresh_world: TestWorld) -> None:
    config = make_config(fresh_world.http_upstream.url, deny_rules=(deny("2001:DB8:0::1"),))
    assert config.deny_rules[0].pattern == "2001:db8::1"
    with running(config) as fw:
        for target in ("[2001:db8::1]", "[2001:DB8:0:0::1]", "[2001:0db8:0000:0000:0000:0000:0000:0001]"):
            resp = raw_exchange(fw.port, f"CONNECT {target}:443 HTTP/1.1\r\nHost: {target}:443\r\n\r\n".encode())
            assert resp.status == 403 and resp.header("X-Scrapescope-Error") == "denied", target
        snap = fw.snapshot()
    assert {t.host for t in snap.tunnels} == {"2001:db8::1"}
    assert fresh_world.http_upstream.records() == []


@pytest.mark.parametrize("target", ["[64:ff9b::a00:5]", "[::ffff:0:a00:5]", "[::a00:5]"])
def test_deny_rule_on_an_ipv4_address_covers_ipv6_forms_that_carry_it(fresh_world: TestWorld, target: str) -> None:
    """sec4-1: a NAT64 (or translated/compatible) spelling of 10.0.0.5 matches rules on 10.0.0.5 and 10.*."""
    for rule in ("10.0.0.5", "10.*"):
        config = make_config(fresh_world.http_upstream.url, deny_rules=(deny(rule),))
        with running(config) as fw:
            resp = raw_exchange(fw.port, f"CONNECT {target}:443 HTTP/1.1\r\nHost: {target}:443\r\n\r\n".encode())
            snap = fw.snapshot()
        assert resp.status == 403 and resp.header("X-Scrapescope-Error") == "denied", (target, rule)
        (record,) = snap.tunnels
        # The record keeps the address as the client spelled it (canonically); only the rule sees the IPv4 form.
        assert record.status == "denied" and record.host == target.strip("[]")
    assert fresh_world.http_upstream.records() == []


def test_ip_literal_spellings_are_recorded_once_and_forwarded_unchanged(fresh_world: TestWorld) -> None:
    """Records and reports use the canonical address; the HTTP CONNECT line stays the client's."""
    with running(make_config(fresh_world.http_upstream.url)) as fw:
        resp = raw_exchange(fw.port, b"CONNECT 1.2.3.04:443 HTTP/1.1\r\nHost: 1.2.3.04:443\r\n\r\n")
        snap = wait_tunnels_closed(fw)
    assert resp.status == 502  # the fixture upstream knows no such host
    (tunnel,) = snap.target_tunnels()
    assert tunnel.host == "1.2.3.4"
    assert [r.target for r in fresh_world.http_upstream.records()] == ["1.2.3.04:443"]


def test_deny_applies_in_direct_mode_before_routing(fresh_world: TestWorld) -> None:
    config = make_config(None, deny_rules=(deny("origin-b.test"),), direct_rules=(HostRule("origin-b.test", "x"),))
    with running(config, connect_map=fresh_world.hosts_map) as fw:
        resp = raw_exchange(fw.port, b"CONNECT origin-b.test:443 HTTP/1.1\r\nHost: origin-b.test:443\r\n\r\n")
        snap = fw.snapshot()
    assert resp.status == 403
    assert snap.tunnels[0].status == "denied"
    assert fresh_world.origin("origin-b.test").totals()["connections"] == 0


def test_direct_rules_carry_llm_hosts_direct_as_non_target(fresh_world: TestWorld) -> None:
    config = make_config(fresh_world.http_upstream.url, direct_rules=(HostRule("api.openai.com", "openai"),), budget_bytes=10**9)
    with running(config, connect_map=fresh_world.hosts_map) as fw:
        assert fetch(fresh_world, "httpx", fw.url, "https://api.openai.com/v1/models")[0] == 200
        assert fetch(fresh_world, "requests", fw.url, "http://api.openai.com/v1/models")[0] == 200
        assert fetch(fresh_world, "httpx", fw.url, "https://origin-a.test/api/product.json")[0] == 200
        snap = settle(fresh_world, fw)
    non_target = snap.non_target_tunnels()
    assert [(t.host, t.kind, t.rule, t.auth) for t in non_target] == [
        ("api.openai.com", "connect", "openai", "none"),
        ("api.openai.com", "http", "openai", "none"),
    ]
    assert all(t.upstream_bytes_received > 0 and t.status == "ok" for t in non_target)
    # Never sent to the upstream, excluded from totals, budget and timeline.
    assert {r.target for r in fresh_world.http_upstream.records()} == {"origin-a.test:443"}
    target = snap.target_tunnels()
    assert len(target) == 1
    assert snap.counted_bytes == target[0].counted_bytes == snap.totals().with_connect
    assert sum(p.sent + p.received for p in snap.timeline) == snap.counted_bytes
    https = fresh_world.origin("api.openai.com", "https").totals()
    assert non_target[0].upstream_bytes_sent == https["bytes_in"]
    assert non_target[0].upstream_bytes_received == https["bytes_out"]
    assert non_target[0].synthetic_negotiation_bytes_sent == 0  # only direct-mode target tunnels


# ---------------------------------------------------------------------------- concurrency
@pytest.mark.parametrize("kind", ["http", "socks"])
def test_50_concurrent_tunnels_counted_exactly(fresh_world: TestWorld, kind: str) -> None:
    upstream = fresh_world.http_upstream if kind == "http" else fresh_world.socks_upstream
    sizes = [50_000 + 1000 * i for i in range(50)]
    bodies: dict[int, bytes] = {}
    lock = threading.Lock()
    with running(make_config(upstream.url)) as fw:
        barrier = threading.Barrier(51)  # 50 workers + this thread

        def worker(i: int) -> None:
            sock, _reply, rest = connect_with_retry(fw.port, "origin-a.test:80")
            try:
                barrier.wait(60)
                raw = rest + http_get_in_tunnel(sock, "origin-a.test", f"/big.bin?size={sizes[i]}")
            finally:
                sock.close()
            with lock:
                bodies[i] = raw

        threads = _start_staggered(worker, 50, with_index=True)
        assert wait_until(lambda: _open_count(fw) == 50, 60), _open_count(fw)
        barrier.wait(10)  # all 50 tunnels are open at the same time
        for t in threads:
            t.join(60)
        snap = settle(fresh_world, fw, timeout=20)
    assert len(bodies) == 50
    for i, raw in bodies.items():
        resp = parse_response(raw)
        assert resp.status == 200 and resp.body == site.big_bytes(0, sizes[i])
    fixture = upstream.totals()
    target = snap.target_tunnels()
    # Failed setup attempts (kernel connect stalls, see connect_with_retry) are counted on both sides.
    assert len(target) == fixture["connections"]
    assert sum(t.upstream_bytes_sent for t in target) == fixture["bytes_from_client"]
    assert sum(t.upstream_bytes_received for t in target) == fixture["bytes_to_client"]
    assert sum(t.negotiation_bytes_sent for t in target) == fixture["negotiation_from_client"]
    assert sum(t.negotiation_bytes_received for t in target) == fixture["negotiation_to_client"]
    assert len([t for t in target if t.status == "ok" and t.upstream_bytes_received > 50_000]) == 50


def test_many_plain_http_clients_in_parallel(fresh_world: TestWorld) -> None:
    urls = [f"http://origin-a.test/big.bin?size={10_000 + i}" for i in range(20)]

    async def run(proxy: str) -> list[int]:
        limits = httpx.Limits(max_connections=10)
        async with httpx.AsyncClient(proxy=proxy, trust_env=False, limits=limits, timeout=30) as client:
            responses = await asyncio.gather(*(client.get(u) for u in urls))
            return [len(r.content) for r in responses]

    with running(make_config(fresh_world.http_upstream.url)) as fw:
        lengths = asyncio.run(run(fw.url))
        snap = settle(fresh_world, fw)
    assert sorted(lengths) == sorted(10_000 + i for i in range(20))
    fixture = fresh_world.http_upstream.totals()
    target = snap.target_tunnels()
    assert sum(t.requests for t in target) == 20
    assert sum(t.upstream_bytes_sent for t in target) == fixture["bytes_from_client"]
    assert sum(t.upstream_bytes_received for t in target) == fixture["bytes_to_client"]
    assert len(target) == fixture["connections"]


def test_raw_socket_helper_download_ok(fresh_world: TestWorld) -> None:
    with running(make_config(fresh_world.socks_upstream.url)) as fw:
        raw = _download(fw.port, 12345)
        settle(fresh_world, fw)
    resp = parse_response(raw)
    assert resp.status == 200 and resp.body == site.big_bytes(0, 12345)


# ---------------------------------------------------------------------------- sent bytes at an abort (meas2-7)
class _SlowSink:
    """Loopback origin that reads slowly (so the meter's send buffers fill) and counts every byte it got."""

    def __init__(self) -> None:
        import socket as _socket

        from tests.test_forwarder_helpers import LocalServer

        self.total = 0
        self.finished = threading.Event()
        self._lock = threading.Lock()

        def handler(sock: _socket.socket) -> None:
            try:
                time.sleep(0.5)
                while True:
                    try:
                        data = sock.recv(65536)
                    except OSError:
                        break
                    if not data:
                        break
                    with self._lock:
                        self.total += len(data)
                    time.sleep(0.01)
            finally:
                self.finished.set()

        self.server = LocalServer(handler)


def _push(port: int, total: int) -> None:
    """CONNECT sink.test:443 through the meter and push ``total`` bytes (stops when the meter closes)."""
    sock, reply, _rest = open_connect(port, "sink.test:443", timeout=20)
    assert reply.status == 200
    blob = b"x" * (256 * 1024)
    sock.settimeout(10)
    try:
        for _ in range(total // len(blob)):
            sock.sendall(blob)
    except OSError:
        pass
    finally:
        time.sleep(0.2)
        sock.close()


@pytest.mark.parametrize("limit", ["budget", "tunnel_cap"])
def test_sent_bytes_at_an_upload_trip_equal_what_left_the_meter(limit: str) -> None:
    """A trip during an upload uncounts what the abort discarded: sent == bytes the origin received."""
    sink = _SlowSink()
    kwargs = {"budget_bytes": 2_000_000} if limit == "budget" else {"max_tunnel_bytes": 2_000_000}
    connect_map = {("sink.test", 443): ("127.0.0.1", sink.server.port)}
    try:
        with running(make_config(None, **kwargs), connect_map=connect_map) as fw:
            _push(fw.port, 10_000_000)
            assert sink.finished.wait(20)
            snap = fw.snapshot()
    finally:
        sink.server.close()
    (tunnel,) = snap.target_tunnels()
    assert tunnel.status == limit
    # Before the fix the tripping 256 KiB slice (and whatever sat in the transport buffer)
    # was counted although it never left: about 263 kB more than the origin received.
    assert tunnel.upstream_bytes_sent == sink.total
    assert tunnel.negotiation_bytes_sent == 0
    if limit == "budget":
        assert snap.counted_bytes == tunnel.counted_bytes
        (trip,) = [e for e in snap.budget_events if e.kind == "tripped"]
        assert trip.counted_bytes >= 2_000_000  # the meter decided on its count at that moment
    assert sum(p.sent for p in snap.timeline) == tunnel.upstream_bytes_sent
