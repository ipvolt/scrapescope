"""The core counting contract: the meter's upstream-socket counts equal the fixture's.

The meter's upstream socket and the fixture upstream's client socket are the
two ends of one TCP connection, so once both have closed, the bytes the meter
wrote must equal the bytes the fixture read, and vice versa. The same holds for
the negotiation part (CONNECT exchange or SOCKS greeting/auth/request/reply).
In direct (sizing) mode the meter's upstream socket talks to the origin's
counting relay, which gives the same check against the origin.
"""

from __future__ import annotations

import pytest

from scrapescope.config import synthetic_connect_sizes
from scrapescope.types import MeterSnapshot
from tests.fixtures import TestWorld, site
from tests.test_forwarder_helpers import CLIENTS, fetch, make_config, open_connect, running, settle

pytestmark = pytest.mark.timeout(60)

HTTPS_URL = "https://origin-a.test/api/product.json"
HTTP_URL = "http://origin-a.test/plain.html"


def _upstream(world: TestWorld, kind: str):
    return world.http_upstream if kind == "http" else world.socks_upstream


def _assert_counts_equal(snap: MeterSnapshot, upstream) -> None:
    fixture = upstream.totals()
    target = snap.target_tunnels()
    assert len(target) == fixture["connections"]
    assert sum(t.upstream_bytes_sent for t in target) == fixture["bytes_from_client"]
    assert sum(t.upstream_bytes_received for t in target) == fixture["bytes_to_client"]
    assert sum(t.negotiation_bytes_sent for t in target) == fixture["negotiation_from_client"]
    assert sum(t.negotiation_bytes_received for t in target) == fixture["negotiation_to_client"]
    # Per connection too (sorted, since both sides number connections independently).
    meter_pairs = sorted((t.upstream_bytes_sent, t.upstream_bytes_received) for t in target)
    fixture_pairs = sorted((r.bytes_from_client, r.bytes_to_client) for r in upstream.records())
    assert meter_pairs == fixture_pairs
    totals = snap.totals()
    assert totals.bytes_sent == fixture["bytes_from_client"]
    assert totals.bytes_received == fixture["bytes_to_client"]
    assert totals.with_connect == fixture["bytes_from_client"] + fixture["bytes_to_client"]
    assert totals.without_connect == totals.with_connect - fixture["negotiation_from_client"] - fixture["negotiation_to_client"]
    assert not totals.with_connect_estimated
    assert snap.counted_bytes == totals.with_connect


@pytest.mark.parametrize("client", CLIENTS)
@pytest.mark.parametrize("kind", ["http", "socks"])
@pytest.mark.parametrize("url", [HTTPS_URL, HTTP_URL], ids=["connect", "plain-http"])
def test_counts_equal_fixture_upstream(fresh_world: TestWorld, client: str, kind: str, url: str) -> None:
    upstream = _upstream(fresh_world, kind)
    with running(make_config(upstream.url)) as fw:
        status, body = fetch(fresh_world, client, fw.url, url)
        assert status == 200
        assert site.PRODUCT_PRICE.encode() in body
        snap = settle(fresh_world, fw)
    _assert_counts_equal(snap, upstream)
    target = snap.target_tunnels()
    assert target, "no tunnel recorded"
    expected_kind = "connect" if url.startswith("https") else "http"
    expected_route = "http-connect" if kind == "http" else "socks5"
    for tunnel in target:
        assert tunnel.kind == expected_kind
        assert tunnel.route == expected_route
        assert tunnel.status == "ok"
        assert tunnel.host == "origin-a.test"
        assert tunnel.port == (443 if expected_kind == "connect" else 80)
        assert tunnel.auth == "injected"
        assert tunnel.closed_at is not None and tunnel.closed_at >= tunnel.opened_at
    # The upstream saw the hostname, never a locally resolved address.
    if kind == "socks":
        assert {r.atyp for r in upstream.records()} == {"domain"}
    else:
        assert {r.target for r in upstream.records()} == {f"origin-a.test:{target[0].port}"}


def test_connect_fields_http_upstream(fresh_world: TestWorld) -> None:
    upstream = fresh_world.http_upstream
    with running(make_config(upstream.url)) as fw:
        status, _ = fetch(fresh_world, "httpx", fw.url, HTTPS_URL)
        assert status == 200
        snap = settle(fresh_world, fw)
    (tunnel,) = snap.target_tunnels()
    (record,) = upstream.records()
    assert tunnel.upstream_status == 200
    assert tunnel.negotiation_bytes_received == len(b"HTTP/1.1 200 Connection established\r\n\r\n")
    assert tunnel.connect_request_bytes == record.negotiation_from_client == tunnel.negotiation_bytes_sent
    value = upstream.url.split("//", 1)[1].split("@", 1)[0]
    assert value  # credentials are configured
    # "Proxy-Authorization: Basic <b64>\r\n"
    assert tunnel.proxy_authorization_bytes > len("Proxy-Authorization: Basic \r\n")
    assert tunnel.client_bytes_received > 0 and tunnel.client_bytes_sent > 0
    assert tunnel.payload_bytes_sent == record.payload_from_client
    assert tunnel.payload_bytes_received == record.payload_to_client


def test_socks_negotiation_is_14_bytes_down(fresh_world: TestWorld) -> None:
    upstream = fresh_world.socks_upstream
    with running(make_config(upstream.url)) as fw:
        assert fetch(fresh_world, "requests", fw.url, HTTPS_URL)[0] == 200
        snap = settle(fresh_world, fw)
    (tunnel,) = snap.target_tunnels()
    assert tunnel.negotiation_bytes_received == 14  # method reply 2 + auth reply 2 + reply 10
    assert tunnel.socks_reply == 0
    assert tunnel.connect_request_bytes == 0
    (record,) = upstream.records()
    assert record.method_selected == 0x02 and record.auth_ok


def _forwarded_connect_head_size(world: TestWorld, client: str, url: str) -> int:
    """This client's CONNECT head as the meter forwards it to an HTTP CONNECT upstream, without Proxy-Authorization.

    Measured, not assumed: the head differs between clients and even between
    Python versions of the same client (3.12's ``http.client`` adds ``Host`` to
    CONNECT, 3.11's sends ``CONNECT host:port HTTP/1.0`` and a blank line, 38
    bytes for ``origin-a.test:443``, below the 63-byte minimal HTTP/1.1 head).
    """
    upstream = world.http_upstream
    with running(make_config(upstream.url)) as fw:
        assert fetch(world, client, fw.url, url)[0] == 200
        snap = settle(world, fw)
    (tunnel,) = snap.target_tunnels()
    assert tunnel.kind == "connect" and tunnel.route == "http-connect"
    assert tunnel.connect_request_bytes > tunnel.proxy_authorization_bytes > 0
    return tunnel.connect_request_bytes - tunnel.proxy_authorization_bytes


@pytest.mark.parametrize("client", CLIENTS)
@pytest.mark.parametrize("url", [HTTPS_URL, HTTP_URL], ids=["connect", "plain-http"])
def test_direct_mode_counts_equal_origin(fresh_world: TestWorld, client: str, url: str) -> None:
    scheme = "https" if url.startswith("https") else "http"
    origin = fresh_world.origin("origin-a.test", scheme)
    with running(make_config(None), connect_map=fresh_world.hosts_map) as fw:
        status, body = fetch(fresh_world, client, fw.url, url)
        assert status == 200 and site.PRODUCT_PRICE.encode() in body
        snap = settle(fresh_world, fw)
    assert snap.mode == "direct"
    target = snap.target_tunnels()
    totals = origin.totals()
    assert len(target) == totals["connections"]
    assert sum(t.upstream_bytes_sent for t in target) == totals["bytes_in"]
    assert sum(t.upstream_bytes_received for t in target) == totals["bytes_out"]
    # meas2-9: the request estimate is this client's own CONNECT head as it would reach an HTTP CONNECT
    # provider, without Proxy-Authorization. Measure that head by sending the same request through the
    # fixture upstream (after the origin totals above, which this second fetch would add to).
    forwarded_head = _forwarded_connect_head_size(fresh_world, client, url) if scheme == "https" else 0
    for tunnel in target:
        assert tunnel.route == "direct"
        assert tunnel.negotiation_bytes_sent == tunnel.negotiation_bytes_received == 0
        if tunnel.kind == "connect":
            assert tunnel.synthetic_negotiation_bytes_sent == forwarded_head > 0
            assert tunnel.synthetic_negotiation_bytes_received == synthetic_connect_sizes("origin-a.test", 443)[1]
        else:
            assert tunnel.synthetic_negotiation_bytes_sent == tunnel.synthetic_negotiation_bytes_received == 0
    t = snap.totals()
    assert t.with_connect_estimated == (scheme == "https")
    assert t.without_connect == totals["bytes_in"] + totals["bytes_out"]
    synthetic = sum(x.synthetic_negotiation_bytes_sent + x.synthetic_negotiation_bytes_received for x in target)
    assert t.with_connect == t.without_connect + synthetic
    # The budget never counts synthetic bytes.
    assert snap.counted_bytes == t.without_connect


def test_repeated_requests_stay_exact(fresh_world: TestWorld) -> None:
    """Several connections with keep-alive and mixed sizes still add up exactly."""
    upstream = fresh_world.http_upstream
    with running(make_config(upstream.url)) as fw:
        for _ in range(3):
            assert fetch(fresh_world, "httpx", fw.url, "https://origin-a.test/big.bin?size=300000")[0] == 200
            assert fetch(fresh_world, "requests", fw.url, "http://origin-a.test/chunked?n=3&size=5000")[0] == 200
        snap = settle(fresh_world, fw)
    _assert_counts_equal(snap, upstream)
    assert len(snap.target_tunnels()) == 6


def test_timeline_sums_to_counted(fresh_world: TestWorld) -> None:
    with running(make_config(fresh_world.http_upstream.url)) as fw:
        assert fetch(fresh_world, "httpx", fw.url, "https://origin-a.test/big.bin?size=500000")[0] == 200
        snap = settle(fresh_world, fw)
    assert snap.timeline, "no timeline points"
    assert sum(p.sent + p.received for p in snap.timeline) == snap.counted_bytes
    assert all(p.t % snap.timeline_resolution_s == 0 for p in snap.timeline)
    assert [p.t for p in snap.timeline] == sorted(p.t for p in snap.timeline)


def test_direct_mode_adds_no_estimate_for_plain_http(fresh_world: TestWorld) -> None:
    """meas3-9 (documented gap): sizing mode sends plain HTTP in origin form without Proxy-Authorization.

    A provider would receive the absolute-form target and the credentials line on every
    request; the meter adds no synthetic bytes for that, and the "estimated" mark on the
    with-CONNECT total reflects CONNECT tunnels only (docs/accuracy.md, "Sizing mode").
    """
    from tests.test_forwarder_helpers import meter_http

    with running(make_config(None), connect_map=fresh_world.hosts_map) as fw:
        conn = meter_http(fw.port)
        for _ in range(3):
            conn.request("GET", HTTP_URL, headers={"Proxy-Authorization": "Basic dXNlcjpwYXNz"})
            resp = conn.getresponse()
            resp.read()
            assert resp.status == 200
        conn.close()
        snap = settle(fresh_world, fw)
    (tunnel,) = snap.target_tunnels()
    assert tunnel.route == "direct" and tunnel.kind == "http" and tunnel.requests == 3
    assert tunnel.synthetic_negotiation_bytes_sent == tunnel.synthetic_negotiation_bytes_received == 0
    assert tunnel.proxy_authorization_bytes == 0  # client credentials are dropped in direct mode
    totals = snap.totals()
    assert totals.with_connect == totals.without_connect and totals.with_connect_estimated is False
    origin = fresh_world.origin("origin-a.test", "http")
    assert origin.totals()["requests"] == 3


def test_direct_mode_estimates_connect_from_the_clients_own_head(fresh_world: TestWorld) -> None:
    """meas2-9: the sizing-mode CONNECT estimate is the head the client sent, without Proxy-Authorization."""
    extra = (
        "Proxy-Connection: keep-alive\r\n"
        "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/153.0 Safari/537.36\r\n"
        "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"
    )
    authority = "origin-a.test:443"
    sent_head = f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n{extra}\r\n"
    expected = len(sent_head) - len("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n")
    with running(make_config(None), connect_map=fresh_world.hosts_map) as fw:
        sock, reply, _ = open_connect(fw.port, authority, extra=extra)
        assert reply.status == 200
        sock.close()
        snap = settle(fresh_world, fw)
    (tunnel,) = snap.target_tunnels()
    assert tunnel.route == "direct" and tunnel.kind == "connect"
    assert tunnel.synthetic_negotiation_bytes_sent == expected > synthetic_connect_sizes("origin-a.test", 443)[0] + 100
    assert tunnel.synthetic_negotiation_bytes_received == synthetic_connect_sizes("origin-a.test", 443)[1]
    assert tunnel.connect_request_bytes == 0 and tunnel.negotiation_bytes_sent == 0  # nothing was sent upstream
    assert snap.counted_bytes == tunnel.upstream_bytes_sent + tunnel.upstream_bytes_received  # never in the budget
