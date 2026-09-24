"""Refusals, upstream failures, verbatim relays and the credential-sentinel invariant."""

from __future__ import annotations

import base64
import json
import logging
import socket

import httpx
import pytest

from scrapescope.config import ForwarderConfig, parse_upstream_url
from scrapescope.forwarder import ForwarderThread
from tests.fixtures import (
    SESSION_PASSWORD,
    UPSTREAM_PASSWORD,
    UPSTREAM_USERNAME,
    VENDOR_ERROR_HEADER,
    TestWorld,
)
from tests.test_forwarder_helpers import (
    connect_map_with,
    fetch,
    make_config,
    raw_exchange,
    read_head,
    running,
    settle,
    wait_tunnels_closed,
)

pytestmark = pytest.mark.timeout(60)

CONNECT_A = b"CONNECT origin-a.test:443 HTTP/1.1\r\nHost: origin-a.test:443\r\n\r\n"


# ---------------------------------------------------------------------------- request forms
def test_origin_form_gets_bare_403(fresh_world: TestWorld) -> None:
    with running(make_config(fresh_world.http_upstream.url)) as fw:
        for request in (
            b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            b"GET /api/x HTTP/1.1\r\nHost: evil.example\r\nOrigin: http://evil.example\r\n\r\n",
            b"OPTIONS * HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            b"GET ftp://origin-a.test/ HTTP/1.1\r\nHost: origin-a.test\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 40\r\n\r\nCONNECT origin-a.test:443 HTTP/1.1\r\n\r\n",
        ):
            resp = raw_exchange(fw.port, request)
            assert resp.raw == b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            assert not any(name.startswith("x-scrapescope") for name in resp.header_names())
        snap = fw.snapshot()
    assert snap.refused == {"origin_form": 5}
    assert snap.tunnels == []
    assert fresh_world.http_upstream.records() == []


def test_absolute_https_gets_400(fresh_world: TestWorld) -> None:
    with running(make_config(fresh_world.http_upstream.url)) as fw:
        resp = raw_exchange(fw.port, b"GET https://origin-a.test/ HTTP/1.1\r\nHost: origin-a.test\r\n\r\n")
        assert resp.status == 400
        assert resp.header("X-Scrapescope-Error") == "https-absolute-form"
        assert resp.header("Content-Type") == "text/plain; charset=utf-8"
        assert resp.body.endswith(b"\n") and resp.body.count(b"\n") == 1
        assert int(resp.header("Content-Length") or -1) == len(resp.body)
        snap = fw.snapshot()
    assert snap.refused == {"https_absolute_form": 1}
    assert fresh_world.http_upstream.records() == []


@pytest.mark.parametrize(
    "request_bytes",
    [
        b"CONNECT origin-a.test HTTP/1.1\r\nHost: origin-a.test\r\n\r\n",  # no port
        b"CONNECT origin-a.test:99999 HTTP/1.1\r\nHost: x\r\n\r\n",
        b"CONNECT http://origin-a.test:443 HTTP/1.1\r\nHost: x\r\n\r\n",
        b"CONNECT bad_host$:443 HTTP/1.1\r\nHost: x\r\n\r\n",
        b"GET http://user:pw@origin-a.test/ HTTP/1.1\r\nHost: origin-a.test\r\n\r\n",
        b"GET http:///nohost HTTP/1.1\r\nHost: x\r\n\r\n",
        b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03garbage-tls-hello\r\n\r\n",
        b"NOT A REQUEST\r\n\r\n",
    ],
)
def test_malformed_requests_get_400(fresh_world: TestWorld, request_bytes: bytes) -> None:
    with running(make_config(fresh_world.http_upstream.url)) as fw:
        resp = raw_exchange(fw.port, request_bytes)
        assert resp.status == 400
        assert resp.header("X-Scrapescope-Error") == "bad-request"
        assert b"user" not in resp.raw and b"pw" not in resp.raw
        snap = fw.snapshot()
    assert snap.refused == {"bad_request": 1}
    assert fresh_world.http_upstream.records() == []


def test_self_loop_refused(fresh_world: TestWorld) -> None:
    config = make_config(fresh_world.http_upstream.url, auth_listener=True)
    with running(config) as fw:
        targets = [
            f"127.0.0.1:{fw.port}",
            f"localhost:{fw.port}",
            f"127.0.0.2:{fw.port}",
            f"[::1]:{fw.port}",
            f"0.0.0.0:{fw.port}",
            f"localhost:{fw.auth_port}",
            # Legacy IPv4 spellings that getaddrinfo (inet_aton) resolves to 127.0.0.1 (sec-4).
            f"127.1:{fw.port}",
            f"0x7f.0.0.1:{fw.port}",
            f"2130706433:{fw.port}",
            f"127.000.000.001:{fw.port}",
            f"0177.0.0.1:{fw.port}",
            f"[::ffff:127.0.0.1]:{fw.port}",
        ]
        for target in targets:
            resp = raw_exchange(fw.port, f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
            assert resp.status == 403, target
            assert resp.header("X-Scrapescope-Error") == "self-loop"
        for host in ("127.0.0.1", "127.1", "2130706433"):
            resp = raw_exchange(
                fw.port, f"GET http://{host}:{fw.port}/ HTTP/1.1\r\nHost: {host}:{fw.port}\r\n\r\n".encode()
            )
            assert resp.status == 403 and resp.header("X-Scrapescope-Error") == "self-loop", host
        snap = fw.snapshot()
    assert snap.refused == {"self_loop": len(targets) + 3}
    assert snap.tunnels == []
    assert fresh_world.http_upstream.records() == []


# ---------------------------------------------------------------------------- upstream failures
def test_upstream_407_relayed_verbatim(fresh_world: TestWorld) -> None:
    upstream = fresh_world.http_upstream
    with running(make_config(upstream.proxy_url(None))) as fw:  # no configured credentials
        resp = raw_exchange(fw.port, CONNECT_A)
        snap = settle(fresh_world, fw)
    assert resp.status == 407
    assert resp.header("Proxy-Authenticate") == 'Basic realm="fixture-upstream"'
    assert resp.header(VENDOR_ERROR_HEADER) == "auth_required"
    assert resp.body == b"407 auth_required\n"
    assert resp.header("X-Scrapescope-Error") is None  # the upstream's reply, not the meter's
    (tunnel,) = snap.target_tunnels()
    assert tunnel.status == "failed:upstream_status"
    assert tunnel.upstream_status == 407
    (record,) = upstream.records()
    # Verbatim: the client got exactly what the upstream sent.
    assert len(resp.raw) == record.bytes_to_client == tunnel.upstream_bytes_received
    assert tunnel.upstream_bytes_sent == record.bytes_from_client
    # A failed negotiation is all negotiation.
    assert tunnel.negotiation_bytes_received == tunnel.upstream_bytes_received
    assert tunnel.bytes_without_connect == 0
    assert snap.totals().failed_tunnels == 1


def test_wrong_password_407_relayed(fresh_world: TestWorld) -> None:
    upstream = fresh_world.http_upstream
    with running(make_config(upstream.proxy_url(UPSTREAM_USERNAME, "wrong-password"))) as fw:
        with pytest.raises(httpx.ProxyError):
            fetch(fresh_world, "httpx", fw.url, "https://origin-a.test/")
        resp = raw_exchange(fw.port, CONNECT_A)
        settle(fresh_world, fw)
    assert resp.status == 407 and resp.header(VENDOR_ERROR_HEADER) == "bad_auth"


def test_unknown_host_502_relayed_with_vendor_header(fresh_world: TestWorld) -> None:
    with running(make_config(fresh_world.http_upstream.url)) as fw:
        resp = raw_exchange(fw.port, b"CONNECT unknown-host.test:443 HTTP/1.1\r\nHost: unknown-host.test:443\r\n\r\n")
        plain = raw_exchange(
            fw.port, b"GET http://unknown-host.test/ HTTP/1.1\r\nHost: unknown-host.test\r\nConnection: close\r\n\r\n"
        )
        snap = settle(fresh_world, fw)
    assert resp.status == 502 and resp.header(VENDOR_ERROR_HEADER) == "host_unknown"
    assert resp.body == b"502 host_unknown\n"
    assert plain.status == 502 and plain.header(VENDOR_ERROR_HEADER) == "host_unknown"
    statuses = sorted(t.status for t in snap.target_tunnels())
    assert statuses == ["failed:upstream_status", "ok"]  # plain HTTP relays the reply as a response
    targets = [target for r in fresh_world.http_upstream.records() for target in r.targets]
    assert sorted(targets) == ["unknown-host.test:443", "unknown-host.test:80"]


@pytest.mark.parametrize("scheme", ["http", "socks5"])
def test_upstream_unreachable(fresh_world: TestWorld, closed_port: int, scheme: str) -> None:
    url = f"{scheme}://{UPSTREAM_USERNAME}:{UPSTREAM_PASSWORD}@127.0.0.1:{closed_port}"
    with running(make_config(url)) as fw:
        resp = raw_exchange(fw.port, CONNECT_A)
        plain = raw_exchange(fw.port, b"GET http://origin-a.test/ HTTP/1.1\r\nHost: origin-a.test\r\n\r\n")
        snap = fw.snapshot()
    for r in (resp, plain):
        assert r.status == 502
        assert r.header("X-Scrapescope-Error") == "upstream-unreachable"
        assert str(closed_port).encode() not in r.raw
    assert [t.status for t in snap.target_tunnels()] == ["failed:upstream_unreachable"] * 2
    assert snap.totals().failed_tunnels == 2 and snap.totals().with_connect == 0


def test_socks_auth_failure(fresh_world: TestWorld) -> None:
    upstream = fresh_world.socks_upstream
    with running(make_config(upstream.proxy_url(UPSTREAM_USERNAME, "wrong-password"))) as fw:
        resp = raw_exchange(fw.port, CONNECT_A)
        snap = settle(fresh_world, fw)
    assert resp.status == 502 and resp.header("X-Scrapescope-Error") == "socks-auth-failed"
    (tunnel,) = snap.target_tunnels()
    assert tunnel.status == "failed:socks_auth"
    (record,) = upstream.records()
    assert record.auth_ok is False
    assert tunnel.upstream_bytes_sent == record.bytes_from_client
    assert tunnel.upstream_bytes_received == record.bytes_to_client
    assert tunnel.negotiation_bytes_sent == tunnel.upstream_bytes_sent


def test_socks_no_acceptable_method(fresh_world: TestWorld) -> None:
    """No configured credentials against an auth-requiring SOCKS5 upstream."""
    with running(make_config(fresh_world.socks_upstream.proxy_url(None))) as fw:
        resp = raw_exchange(fw.port, CONNECT_A)
        snap = settle(fresh_world, fw)
    assert resp.status == 502 and resp.header("X-Scrapescope-Error") == "socks-no-method"
    assert snap.target_tunnels()[0].status == "failed:socks_method"


def test_socks_unknown_host_reply(fresh_world: TestWorld) -> None:
    with running(make_config(fresh_world.socks_upstream.url)) as fw:
        resp = raw_exchange(fw.port, b"CONNECT unknown-host.test:443 HTTP/1.1\r\nHost: unknown-host.test:443\r\n\r\n")
        snap = settle(fresh_world, fw)
    assert resp.status == 502 and resp.header("X-Scrapescope-Error") == "socks-reply-4"
    (tunnel,) = snap.target_tunnels()
    assert tunnel.status == "failed:socks_reply_4" and tunnel.socks_reply == 4
    (record,) = fresh_world.socks_upstream.records()
    assert record.atyp == "domain" and record.target == "unknown-host.test:443"
    assert tunnel.upstream_bytes_received == record.bytes_to_client


def test_direct_dns_failure_and_refused(fresh_world: TestWorld, closed_port: int) -> None:
    mapping = connect_map_with(fresh_world, {("refuses.test", 443): ("127.0.0.1", closed_port)})
    with running(make_config(None), connect_map=mapping) as fw:
        dns = raw_exchange(fw.port, b"CONNECT not-mapped.test:443 HTTP/1.1\r\nHost: not-mapped.test:443\r\n\r\n")
        refused = raw_exchange(fw.port, b"CONNECT refuses.test:443 HTTP/1.1\r\nHost: refuses.test:443\r\n\r\n")
        snap = fw.snapshot()
    assert dns.status == 502 and dns.header("X-Scrapescope-Error") == "dns-failed"
    assert refused.status == 502 and refused.header("X-Scrapescope-Error") == "connect-refused"
    assert [t.status for t in snap.target_tunnels()] == ["failed:dns", "failed:connect_refused"]


def test_tls_error_at_client_leaves_tunnel_ok(fresh_world: TestWorld) -> None:
    with running(make_config(fresh_world.http_upstream.url)) as fw:
        with pytest.raises(httpx.ConnectError):
            fetch(fresh_world, "httpx", fw.url, "https://badcert.test/")
        snap = settle(fresh_world, fw)
    (tunnel,) = snap.target_tunnels()
    assert tunnel.status == "ok" and tunnel.host == "badcert.test"
    totals = fresh_world.http_upstream.totals()
    assert tunnel.upstream_bytes_sent == totals["bytes_from_client"]
    assert tunnel.upstream_bytes_received == totals["bytes_to_client"]


def test_client_disconnect_during_negotiation(fresh_world: TestWorld) -> None:
    with running(make_config(fresh_world.http_upstream.url)) as fw:
        sock = socket.create_connection(("127.0.0.1", fw.port))
        sock.sendall(CONNECT_A)
        sock.close()
        snap = settle(fresh_world, fw)
    statuses = [t.status for t in snap.target_tunnels()]
    assert statuses in ([], ["ok"], ["failed:client_closed"])


# ---------------------------------------------------------------------------- sentinels
SENTINELS = [
    UPSTREAM_USERNAME,
    UPSTREAM_PASSWORD,
    SESSION_PASSWORD,
    base64.b64encode(f"{UPSTREAM_USERNAME}:{UPSTREAM_PASSWORD}".encode()).decode(),
    base64.b64encode(f"{UPSTREAM_USERNAME}:wrong-{UPSTREAM_PASSWORD}".encode()).decode(),
]


def _scan(text: str, where: str) -> None:
    for sentinel in SENTINELS:
        assert sentinel not in text, f"credential sentinel leaked into {where}"


@pytest.mark.timeout(90)
def test_credentials_never_logged_or_stored(fresh_world: TestWorld, caplog: pytest.LogCaptureFixture, capfd, closed_port: int) -> None:
    """Success and every error path: no credential in logs, stdout/stderr, snapshots or reprs."""
    caplog.set_level(logging.DEBUG)
    world = fresh_world
    good_http = world.http_upstream.url
    bad_http = world.http_upstream.proxy_url(UPSTREAM_USERNAME, "wrong-" + UPSTREAM_PASSWORD)
    good_socks = world.socks_upstream.url
    bad_socks = world.socks_upstream.proxy_url(UPSTREAM_USERNAME, "wrong-" + UPSTREAM_PASSWORD)
    unreachable = f"http://{UPSTREAM_USERNAME}:{UPSTREAM_PASSWORD}@127.0.0.1:{closed_port}"
    snapshots = []
    reprs = []
    for url in (good_http, bad_http, good_socks, bad_socks, unreachable):
        config = ForwarderConfig(upstream=parse_upstream_url(url), token="t0k", auth_listener=True)
        reprs += [repr(config), str(config), repr(config.upstream)]
        fw = ForwarderThread(config)
        reprs.append(repr(fw))
        fw.start()
        try:
            for target in ("https://origin-a.test/", "https://unknown-host.test/", "https://badcert.test/", "http://origin-a.test/plain.html"):
                try:
                    fetch(world, "httpx", fw.url, target)
                except (httpx.HTTPError, OSError):
                    pass
            # Pass-through of a session username with the sentinel password.
            try:
                fetch(world, "httpx", fw.url, "https://origin-a.test/", username="sess-9", password=SESSION_PASSWORD)
            except httpx.HTTPError:
                pass
            raw_exchange(fw.port, b"CONNECT unknown-host.test:443 HTTP/1.1\r\nHost: unknown-host.test:443\r\n\r\n")
            raw_exchange(fw.auth_port, CONNECT_A)  # local 407 challenge
            world.wait_idle()
        finally:
            snap = fw.stop()
        snapshots.append(json.dumps(snap.to_dict()))
        assert f":{closed_port}" not in snapshots[-1]
    records = [r for r in caplog.records if r.name.startswith(("scrapescope", "asyncio"))]
    assert any(r.name == "scrapescope.forwarder" for r in records), "expected DEBUG tunnel logs"
    _scan("\n".join(r.getMessage() for r in records), "logs")
    for record in records:
        if record.exc_info:
            _scan(logging.Formatter().formatException(record.exc_info), "logged tracebacks")
    out, err = capfd.readouterr()
    _scan(out + err, "stdout/stderr")
    for text in snapshots:
        _scan(text, "snapshot")
    for text in reprs:
        _scan(text, "repr")
    assert all("127.0.0.1" not in text or "hidden" in text for text in reprs if "UpstreamConfig" in text)


# ---------------------------------------------------------------------------- internal errors and resets
def test_internal_error_replies_502_and_forwarder_keeps_serving(fresh_world: TestWorld, monkeypatch: pytest.MonkeyPatch) -> None:
    from scrapescope.forwarder import upstream as upstream_module

    real = upstream_module.http_connect
    calls = {"n": 0}

    async def flaky(conn, head, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("injected bug")
        return await real(conn, head, **kwargs)

    monkeypatch.setattr(upstream_module, "http_connect", flaky)
    with running(make_config(fresh_world.http_upstream.url)) as fw:
        resp = raw_exchange(fw.port, CONNECT_A)
        assert resp.status == 502 and resp.header("X-Scrapescope-Error") == "internal-error"
        assert b"injected bug" not in resp.raw
        assert fetch(fresh_world, "httpx", fw.url, "https://origin-a.test/api/product.json")[0] == 200
        snap = settle(fresh_world, fw)
    assert snap.internal_errors == 1
    assert [t.status for t in snap.target_tunnels()] == ["failed:internal", "ok"]


def test_client_reset_mid_download_tears_down_upstream(fresh_world: TestWorld) -> None:
    import struct

    from tests.test_forwarder_helpers import open_connect, wait_until

    with running(make_config(fresh_world.http_upstream.url)) as fw:
        sock, reply, _ = open_connect(fw.port, "origin-a.test:80")
        assert reply.status == 200
        sock.sendall(b"GET /big.bin?size=200000000&chunk=65536&delay_ms=1 HTTP/1.1\r\nHost: origin-a.test\r\n\r\n")
        sock.recv(65536)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        sock.close()  # RST
        assert wait_until(lambda: all(t.status != "open" for t in fw.snapshot().tunnels), 10)
        assert fresh_world.wait_idle(10)
        snap = fw.snapshot()
    (tunnel,) = snap.target_tunnels()
    assert tunnel.status == "ok"
    assert tunnel.upstream_bytes_received < 50_000_000  # stopped long before the 200 MB body
    (record,) = fresh_world.http_upstream.records()
    assert tunnel.upstream_bytes_sent == record.bytes_from_client


def test_budget_trip_closes_idle_keep_alive_tunnels(fresh_world: TestWorld) -> None:
    """An idle keep-alive plain-HTTP tunnel is open, so the trip closes it too."""
    import http.client

    from tests.test_forwarder_helpers import meter_http, raw_exchange as exchange

    config = make_config(fresh_world.http_upstream.url, budget_bytes=300_000)
    with running(config) as fw:
        idle = meter_http(fw.port)
        idle.request("GET", "http://origin-a.test/big.bin?size=100000")
        assert len(idle.getresponse().read()) == 100_000
        busy = meter_http(fw.port)
        busy.request("GET", "http://origin-a.test/big.bin?size=1000000")
        with pytest.raises((ConnectionError, OSError, http.client.HTTPException)):
            busy.getresponse().read()  # reset mid-body by the trip
        assert fw.budget_tripped.wait(5)
        with pytest.raises((ConnectionError, OSError, http.client.HTTPException)):
            idle.request("GET", "http://origin-a.test/plain.html")
            idle.getresponse().read()
        refused = exchange(fw.port, b"GET http://origin-a.test/ HTTP/1.1\r\nHost: origin-a.test\r\n\r\n")
        idle.close()
        busy.close()
        snap = settle(fresh_world, fw)
    assert refused.status == 403 and refused.header("X-Scrapescope-Budget") == "tripped"
    trip = [e for e in snap.budget_events if e.kind == "tripped"][0]
    assert trip.closed_tunnels == 2
    assert [t.status for t in snap.target_tunnels()] == ["budget", "budget"]


# ---------------------------------------------------------------------------- local addresses (sec-3, sec-4)
def _fake_dns(monkeypatch: pytest.MonkeyPatch, names: dict[str, list[str]]) -> list[str]:
    """Replace getaddrinfo: ``names`` map to the given IPs, IP literals pass, anything else fails.

    Records every looked-up name (IP literals, such as the meter's own bind address, are not
    lookups); never touches real DNS.
    """
    import ipaddress

    real = socket.getaddrinfo
    lookups: list[str] = []

    def fake(host, port, family=0, type=0, proto=0, flags=0):  # noqa: A002 - socket's own signature
        text = host.decode() if isinstance(host, bytes) else host
        try:
            ipaddress.ip_address(text)
        except (ValueError, TypeError):
            lookups.append(text)
        if text in names:
            out = []
            for ip in names[text]:
                out.extend(real(ip, port, family, type, proto, socket.AI_NUMERICHOST))
            return out
        try:
            return real(text, port, family, type, proto, flags | socket.AI_NUMERICHOST)
        except socket.gaierror:
            raise socket.gaierror(socket.EAI_NONAME, "not in the fake DNS") from None

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    return lookups


def _secret_service(sock: socket.socket) -> None:
    sock.recv(65536)
    sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\nLOCAL-SECRET-DATA-42")


def test_direct_mode_refuses_private_destinations(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sizing mode: a name that (re)binds to loopback, or a private literal, is not relayed."""
    from tests.test_forwarder_helpers import LocalServer

    _fake_dns(monkeypatch, {"rebind.attacker.test": ["127.0.0.1"], "lan.attacker.test": ["10.1.2.3"]})
    with LocalServer(_secret_service) as svc, running(make_config(None, auth_listener=True)) as fw:
        requests = [
            f"GET http://rebind.attacker.test:{svc.port}/secret HTTP/1.1\r\nHost: rebind.attacker.test:{svc.port}\r\n\r\n",
            f"GET http://127.0.0.1:{svc.port}/secret HTTP/1.1\r\nHost: 127.0.0.1:{svc.port}\r\n\r\n",
            f"GET http://127.1:{svc.port}/secret HTTP/1.1\r\nHost: 127.1:{svc.port}\r\n\r\n",
            f"CONNECT rebind.attacker.test:{svc.port} HTTP/1.1\r\nHost: rebind.attacker.test:{svc.port}\r\n\r\n",
            "CONNECT lan.attacker.test:443 HTTP/1.1\r\nHost: lan.attacker.test:443\r\n\r\n",
            "CONNECT 169.254.169.254:80 HTTP/1.1\r\nHost: 169.254.169.254:80\r\n\r\n",
            "CONNECT 100.64.0.1:443 HTTP/1.1\r\nHost: 100.64.0.1:443\r\n\r\n",
            "CONNECT [fd00::1]:443 HTTP/1.1\r\nHost: [fd00::1]:443\r\n\r\n",
        ]
        for raw in requests:
            resp = raw_exchange(fw.port, raw.encode())
            assert resp.status == 403, raw
            assert resp.header("X-Scrapescope-Error") == "private-address", raw
            assert b"LOCAL-SECRET" not in resp.raw
        snap = fw.snapshot()
    assert [t.status for t in snap.target_tunnels()] == ["failed:private_address"] * len(requests)
    assert all(t.upstream_bytes_sent == 0 and t.upstream_bytes_received == 0 for t in snap.tunnels)


def test_private_destination_sees_ipv4_embedded_in_ipv6() -> None:
    """sec4-1: NAT64, IPv4-translated and IPv4-compatible spellings of a private IPv4 address are private."""
    import ipaddress

    from scrapescope.forwarder.upstream import is_private_destination, is_self_address

    private = [
        "64:ff9b::a00:5", "64:ff9b::a9fe:a9fe", "64:ff9b::7f00:1", "::ffff:0:a00:5", "::a9fe:a9fe",
        "::ffff:a9fe:a9fe", "fec0::1", "2002:a00:5::1", "64:ff9b:1::a00:5", "169.254.169.254", "fd00::1",
    ]
    public = ["64:ff9b::808:808", "::ffff:8.8.8.8", "8.8.8.8", "2606:4700:4700::1111"]
    for text in private:
        assert is_private_destination(ipaddress.ip_address(text)), text
    for text in public:
        assert not is_private_destination(ipaddress.ip_address(text)), text
    assert is_self_address(ipaddress.ip_address("64:ff9b::7f00:1"))
    assert not is_self_address(ipaddress.ip_address("64:ff9b::808:808"))


def test_direct_mode_refuses_private_ipv4_behind_ipv6_spellings() -> None:
    """sec4-1 repro: sizing mode never even tries to connect to these (no NAT64 needed to see it)."""
    targets = ["[64:ff9b::a9fe:a9fe]", "[64:ff9b::a00:5]", "[::a9fe:a9fe]", "[::ffff:0:a00:5]", "[fec0::1]"]
    with running(make_config(None, connect_timeout_s=3.0)) as fw:
        responses = [
            raw_exchange(fw.port, f"CONNECT {t}:80 HTTP/1.1\r\nHost: {t}:80\r\n\r\n".encode()) for t in targets
        ]
        snap = wait_tunnels_closed(fw)
    for target, resp in zip(targets, responses):
        assert resp.status == 403 and resp.header("X-Scrapescope-Error") == "private-address", target
    assert [t.status for t in snap.target_tunnels()] == ["failed:private_address"] * len(targets)
    assert all(t.upstream_bytes_sent == 0 and t.upstream_bytes_received == 0 for t in snap.tunnels)


def test_allow_private_targets_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    from tests.test_forwarder_helpers import LocalServer

    _fake_dns(monkeypatch, {"dev.local.test": ["127.0.0.1"]})
    with LocalServer(_secret_service) as svc, running(make_config(None, allow_private_targets=True)) as fw:
        resp = raw_exchange(
            fw.port, f"GET http://dev.local.test:{svc.port}/ HTTP/1.1\r\nHost: dev.local.test:{svc.port}\r\n\r\n".encode()
        )
        # Even with the opt-in, a name that resolves to the meter itself is a self-loop, not a relay.
        loop = raw_exchange(
            fw.port, f"CONNECT dev.local.test:{fw.port} HTTP/1.1\r\nHost: dev.local.test:{fw.port}\r\n\r\n".encode()
        )
        snap = fw.snapshot()
    assert resp.status == 200 and resp.body == b"LOCAL-SECRET-DATA-42"
    assert loop.status == 403 and loop.header("X-Scrapescope-Error") == "self-loop"
    assert [t.status for t in snap.target_tunnels()] == ["ok", "failed:self_loop"]


# ---------------------------------------------------------------------------- this machine's own addresses (sec3-1)
def _own_global_address() -> str | None:
    """A globally routable address of one of this machine's interfaces, or None.

    First the source address toward the internet (a UDP connect only looks up
    the route; no packet is sent), then the interface list from ``ifconfig`` or
    ``ip`` (a VPN can route around an interface's global address).
    """
    import ipaddress
    import re
    import shutil
    import subprocess

    def usable(text: str) -> bool:
        try:
            ip = ipaddress.ip_address(text.split("%", 1)[0])
        except ValueError:
            return False
        return ip.is_global and not ip.is_multicast

    for family, probe in ((socket.AF_INET6, "2001:4860:4860::8888"), (socket.AF_INET, "8.8.8.8")):
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.connect((probe, 53))
                address = str(sock.getsockname()[0]).split("%", 1)[0]
        except OSError:
            continue
        if usable(address):
            return address
    for command in (["ifconfig", "-a"], ["ip", "-o", "addr", "show"]):
        if shutil.which(command[0]) is None:
            continue
        try:
            out = subprocess.run(command, capture_output=True, text=True, timeout=5).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        for match in re.finditer(r"\binet6?\s+([0-9a-fA-F:.]+)", out):
            if usable(match.group(1)):
                return match.group(1)
    return None


class _AllInterfacesService:
    """A 'local only' service bound to every interface (``[::]`` or ``0.0.0.0``), like http.server."""

    def __init__(self, family: int) -> None:
        import threading

        self.sock = socket.socket(family, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            self.sock.bind(("::", 0))
        else:
            self.sock.bind(("0.0.0.0", 0))
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            with conn:
                conn.settimeout(2)
                try:
                    _secret_service(conn)
                except OSError:
                    pass

    def __enter__(self) -> _AllInterfacesService:
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop = True
        self._thread.join(2)
        self.sock.close()


def test_direct_mode_refuses_this_machines_own_global_address() -> None:
    """sec3-1: a service bound to all interfaces is not reachable at the machine's own global address."""
    address = _own_global_address()
    if address is None:
        pytest.skip("this machine has no globally routable address on an interface")
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    with _AllInterfacesService(family) as svc:
        authority = f"[{address}]:{svc.port}" if ":" in address else f"{address}:{svc.port}"
        get = f"GET http://{authority}/secret HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode()
        connect = f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode()
        with running(make_config(None, allow_private_targets=True)) as fw:
            control = raw_exchange(fw.port, get)  # the service really is reachable at that address
        with running(make_config(None)) as fw:
            refused = [raw_exchange(fw.port, get), raw_exchange(fw.port, connect)]
            snap = wait_tunnels_closed(fw)
    assert control.status == 200 and control.body == b"LOCAL-SECRET-DATA-42"
    for resp in refused:
        assert resp.status == 403 and resp.header("X-Scrapescope-Error") == "private-address"
        assert b"LOCAL-SECRET" not in resp.raw
    assert [t.status for t in snap.target_tunnels()] == ["failed:private_address"] * 2
    assert all(t.upstream_bytes_sent == 0 for t in snap.target_tunnels())


def test_direct_mode_refuses_a_routable_address_that_is_this_machine(monkeypatch: pytest.MonkeyPatch) -> None:
    """sec3-1, without depending on this machine's addresses: loopback stands in for a global own address.

    With the non-global check out of the way, the after-connect check must
    still refuse a connection whose peer is the meter's own source address,
    on the single-address path and on the Happy Eyeballs path.
    """
    from scrapescope.forwarder import upstream as up
    from tests.test_forwarder_helpers import LocalServer

    monkeypatch.setattr(up, "is_private_destination", lambda ip: False)
    _fake_dns(monkeypatch, {"own.attacker.test": ["127.0.0.1"], "own2.attacker.test": ["::ffff:127.0.0.1", "127.0.0.1"]})
    with LocalServer(_secret_service) as svc, running(make_config(None)) as fw:
        requests = [
            f"GET http://own.attacker.test:{svc.port}/ HTTP/1.1\r\nHost: own.attacker.test:{svc.port}\r\n\r\n",
            f"CONNECT own.attacker.test:{svc.port} HTTP/1.1\r\nHost: own.attacker.test:{svc.port}\r\n\r\n",
            f"GET http://127.0.0.1:{svc.port}/ HTTP/1.1\r\nHost: 127.0.0.1:{svc.port}\r\n\r\n",
            f"GET http://own2.attacker.test:{svc.port}/ HTTP/1.1\r\nHost: own2.attacker.test:{svc.port}\r\n\r\n",
        ]
        responses = [raw_exchange(fw.port, raw.encode()) for raw in requests]
        snap = wait_tunnels_closed(fw)
    for raw, resp in zip(requests, responses):
        assert resp.status == 403 and resp.header("X-Scrapescope-Error") == "private-address", raw
        assert b"LOCAL-SECRET" not in resp.raw
    assert [t.status for t in snap.target_tunnels()] == ["failed:private_address"] * len(requests)


def test_own_or_on_link_address_check() -> None:
    import ipaddress

    from scrapescope.forwarder.upstream import is_own_or_on_link

    ip = ipaddress.ip_address
    assert is_own_or_on_link(ip("203.0.113.5"), ip("203.0.113.5"))
    assert not is_own_or_on_link(ip("203.0.113.5"), ip("203.0.113.6"))  # IPv4 netmasks are not known
    assert is_own_or_on_link(ip("2a00:1eb8:c0e9:d7a1::5"), ip("2a00:1eb8:c0e9:d7a1::5"))
    assert is_own_or_on_link(ip("2a00:1eb8:c0e9:d7a1:1c64:306e:140:34f2"), ip("2a00:1eb8:c0e9:d7a1::1"))  # same /64
    assert not is_own_or_on_link(ip("2a00:1eb8:c0e9:d7a1::5"), ip("2a00:1eb8:c0e9:d7a2::5"))
    assert is_own_or_on_link(ip("::ffff:198.51.100.7"), ip("198.51.100.7"))  # mapped forms compare unmapped
    assert not is_own_or_on_link(ip("198.51.100.7"), ip("2001:db8::1"))
    assert not is_own_or_on_link(None, ip("198.51.100.7"))


def test_direct_connects_only_to_the_checked_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    """A mixed answer keeps only globally routable addresses; the meter connects to those literals."""
    import asyncio

    from scrapescope.forwarder import upstream as up

    lookups = _fake_dns(monkeypatch, {"mixed.test": ["127.0.0.1", "10.0.0.7", "93.184.215.14"]})

    async def candidates(**kwargs: object) -> list[tuple[str, int]]:
        return await up.direct_candidates("mixed.test", 443, connect_map=None, own_ports=frozenset({1}), timeout=5, **kwargs)

    assert asyncio.run(candidates(allow_private=False)) == [("93.184.215.14", 443)]
    assert asyncio.run(candidates(allow_private=True)) == [("127.0.0.1", 443), ("10.0.0.7", 443), ("93.184.215.14", 443)]
    assert lookups == ["mixed.test", "mixed.test"]  # one lookup per connection, never repeated by connect


@pytest.mark.parametrize(
    "host,expected",
    [
        ("127.1", "127.0.0.1"),
        ("0x7f.0.0.1", "127.0.0.1"),
        ("2130706433", "127.0.0.1"),
        ("127.000.000.001", "127.0.0.1"),
        ("::ffff:127.0.0.1", "127.0.0.1"),
        ("[::1]", "::1"),
        ("10.0.0.1", "10.0.0.1"),
        ("example.test", None),
        ("1e100.net", None),
        ("deadbeef", None),
    ],
)
def test_ip_literal_parses_like_getaddrinfo(host: str, expected: str | None) -> None:
    from scrapescope.forwarder.upstream import ip_literal

    ip = ip_literal(host)
    assert (str(ip) if ip is not None else None) == expected


def test_upstream_url_with_legacy_loopback_spelling_is_refused_at_start() -> None:
    from scrapescope.forwarder import ForwarderError

    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    for host in ("127.1", "2130706433", "0x7f.0.0.1"):
        fw = ForwarderThread(ForwarderConfig(upstream=parse_upstream_url(f"http://u:p@{host}:{port}"), port=port))
        with pytest.raises(ForwarderError, match="own listening port"):
            fw.start()


def test_upstream_name_resolving_to_the_meter_does_not_recurse(monkeypatch: pytest.MonkeyPatch) -> None:
    """The start check cannot see DNS; the connection check refuses after one hop (no FD exhaustion)."""
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    lookups = _fake_dns(monkeypatch, {"proxy-host.test": ["127.0.0.1"]})
    config = ForwarderConfig(upstream=parse_upstream_url(f"http://u:p@proxy-host.test:{port}"), port=port)
    with running(config) as fw:
        resp = raw_exchange(fw.port, CONNECT_A)
        snap = fw.snapshot()
    assert resp.status == 403 and resp.header("X-Scrapescope-Error") == "self-loop"
    assert [(t.host, t.status) for t in snap.tunnels] == [("origin-a.test", "failed:self_loop")]
    assert snap.tunnels[0].upstream_bytes_sent == 0
    assert set(lookups) == {"proxy-host.test"}


def test_upstream_route_never_resolves_target_names(monkeypatch: pytest.MonkeyPatch) -> None:
    """With a provider and no direct rules, the only local lookup is the provider's own name (sec-1)."""
    from tests.test_forwarder_helpers import LocalServer

    seen: list[bytes] = []

    def provider(sock: socket.socket) -> None:
        seen.append(sock.recv(4096).split(b"\r\n", 1)[0])
        sock.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

    lookups = _fake_dns(monkeypatch, {"proxy-host.test": ["127.0.0.1"]})
    with LocalServer(provider) as fake:
        config = ForwarderConfig(upstream=parse_upstream_url(f"http://u:p@proxy-host.test:{fake.port}"))
        with running(config) as fw:
            for target in ("my-private-bucket.s3.amazonaws.com:443", "target-site.test:443", "api.openai.com:443"):
                sock = socket.create_connection(("127.0.0.1", fw.port), timeout=5)
                sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
                assert sock.recv(200).startswith(b"HTTP/1.1 200")
                sock.close()
            snap = wait_tunnels_closed(fw)
    assert set(lookups) == {"proxy-host.test"}
    assert sorted(seen) == sorted(
        b"CONNECT " + t + b" HTTP/1.1"
        for t in (b"my-private-bucket.s3.amazonaws.com:443", b"target-site.test:443", b"api.openai.com:443")
    )
    assert {t.route for t in snap.tunnels} == {"http-connect"}


def test_env_all_direct_rules_resolve_locally_as_documented(monkeypatch: pytest.MonkeyPatch) -> None:
    """--env-all direct rules are the one exception: those names are resolved and connected locally."""
    from scrapescope.config import HostRule
    from tests.test_forwarder_helpers import LocalServer

    lookups = _fake_dns(monkeypatch, {"proxy-host.test": ["127.0.0.1"], "api.openai.com": ["127.0.0.1"]})
    with LocalServer(lambda s: s.close()) as fake_provider:
        config = ForwarderConfig(
            upstream=parse_upstream_url(f"http://u:p@proxy-host.test:{fake_provider.port}"),
            direct_rules=(HostRule("api.openai.com", "openai"),),
            # No --allow-private-targets: non-target hosts may resolve to private
            # addresses (cloud private endpoints); here the fake API is on loopback.
        )
        with running(config) as fw:
            resp = raw_exchange(fw.port, b"CONNECT api.openai.com:9 HTTP/1.1\r\nHost: api.openai.com:9\r\n\r\n")
            snap = fw.snapshot()
    assert lookups == ["api.openai.com"]
    (tunnel,) = snap.tunnels
    assert tunnel.route == "non-target" and tunnel.rule == "openai"
    assert resp.header("X-Scrapescope-Error") == "connect-refused"


# ---------------------------------------------------------------------------- Happy Eyeballs (meas2-10)
#: A documentation address (TEST-NET-1) that stands in for a blackholed path; never really dialled.
BLACKHOLE = "192.0.2.1"


def _blackhole_connects(monkeypatch: pytest.MonkeyPatch, dialled: list[str], hang: frozenset[str]) -> None:
    """Make connection attempts to the ``hang`` addresses wait forever (a dropped SYN) without sending anything."""
    import asyncio

    real = asyncio.base_events.BaseEventLoop.create_connection

    async def fake(self, protocol_factory, host=None, port=None, *args, **kwargs):  # noqa: ANN001
        dialled.append(str(host))
        if host in hang:
            await asyncio.sleep(3600)
        return await real(self, protocol_factory, host, port, *args, **kwargs)

    monkeypatch.setattr(asyncio.base_events.BaseEventLoop, "create_connection", fake)


def test_direct_route_falls_back_to_the_next_address_quickly(monkeypatch: pytest.MonkeyPatch) -> None:
    """A first address that never answers costs one attempt delay, not the whole connect timeout."""
    import time as _time

    from tests.test_forwarder_helpers import LocalServer

    dialled: list[str] = []
    _fake_dns(monkeypatch, {"dual.test": [BLACKHOLE, "127.0.0.1"]})
    _blackhole_connects(monkeypatch, dialled, frozenset({BLACKHOLE}))
    with LocalServer(_secret_service) as svc:
        config = make_config(None, allow_private_targets=True, connect_timeout_s=5.0)
        with running(config) as fw:
            started = _time.monotonic()
            resp = raw_exchange(fw.port, f"GET http://dual.test:{svc.port}/ HTTP/1.1\r\nHost: dual.test\r\n\r\n".encode())
            elapsed = _time.monotonic() - started
            snap = wait_tunnels_closed(fw, 5)
    assert resp.status == 200 and resp.body == b"LOCAL-SECRET-DATA-42"
    assert elapsed < 2.5, elapsed  # before the fix: 5 s, then 504 connect-timeout
    assert dialled[:2] == [BLACKHOLE, "127.0.0.1"]
    assert [t.status for t in snap.target_tunnels()] == ["ok"]


def test_direct_route_times_out_at_the_deadline_when_no_address_answers(monkeypatch: pytest.MonkeyPatch) -> None:
    import time as _time

    other = "192.0.2.2"
    dialled: list[str] = []
    _fake_dns(monkeypatch, {"dark.test": [BLACKHOLE, other]})
    _blackhole_connects(monkeypatch, dialled, frozenset({BLACKHOLE, other}))
    config = make_config(None, allow_private_targets=True, connect_timeout_s=1.0)
    with running(config) as fw:
        started = _time.monotonic()
        resp = raw_exchange(fw.port, b"CONNECT dark.test:443 HTTP/1.1\r\nHost: dark.test:443\r\n\r\n")
        elapsed = _time.monotonic() - started
        snap = wait_tunnels_closed(fw, 5)
    assert resp.status == 504 and resp.header("X-Scrapescope-Error") == "connect-timeout"
    assert 0.9 <= elapsed < 3.0, elapsed
    assert dialled == [BLACKHOLE, other]  # both tried, each once, within the one deadline
    assert [t.status for t in snap.target_tunnels()] == ["failed:connect_timeout"]


def test_interleave_families_alternates_starting_with_the_first() -> None:
    from scrapescope.forwarder.upstream import interleave_families

    cands = [("2001:db8::1", 443), ("2001:db8::2", 443), ("192.0.2.1", 443), ("192.0.2.2", 443), ("192.0.2.3", 443)]
    assert interleave_families(cands) == [
        ("2001:db8::1", 443),
        ("192.0.2.1", 443),
        ("2001:db8::2", 443),
        ("192.0.2.2", 443),
        ("192.0.2.3", 443),
    ]
    assert interleave_families([("192.0.2.1", 80)]) == [("192.0.2.1", 80)]


# ---------------------------------------------------------------------------- descriptor limit (meas2-4, sec2-6)
_LOW_LIMIT_METER = r"""
import json, resource, sys
resource.setrlimit(resource.RLIMIT_NOFILE, (int(sys.argv[1]), resource.getrlimit(resource.RLIMIT_NOFILE)[1]))
from scrapescope.config import ForwarderConfig
from scrapescope.forwarder import ForwarderThread
fw = ForwarderThread(ForwarderConfig(upstream=None), connect_map={("hold.test", 443): ("127.0.0.1", int(sys.argv[2]))})
fw.start()
print(fw.port, flush=True)
sys.stdin.readline()
snap = fw.stop()
statuses = {}
for t in snap.tunnels:
    statuses[t.status] = statuses.get(t.status, 0) + 1
print(json.dumps({"statuses": statuses, "accept": snap.accept_limit_errors}), flush=True)
"""


def _hold_open(sock: socket.socket) -> None:
    sock.settimeout(30)
    try:
        while sock.recv(65536):
            pass
    except OSError:
        pass


def test_out_of_descriptors_is_local_limit_not_the_target_refusing() -> None:
    """A meter at its open-file limit says so (503 local-limit), never "target refused the connection"."""
    import subprocess
    import sys
    import threading
    import time as _time

    from tests.test_forwarder_helpers import LocalServer

    with LocalServer(_hold_open) as hold:
        proc = subprocess.Popen(
            [sys.executable, "-c", _LOW_LIMIT_METER, "48", str(hold.port)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
        )
        try:
            port = int(proc.stdout.readline())
            socks: list[socket.socket] = []
            replies: list[bytes] = []
            lock = threading.Lock()

            def client() -> None:
                head = b""
                try:
                    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
                    with lock:
                        socks.append(sock)
                    sock.sendall(b"CONNECT hold.test:443 HTTP/1.1\r\nHost: hold.test:443\r\n\r\n")
                    head = read_head(sock)[0]
                except OSError:
                    pass  # accept paused (asyncio retries after 1 s), or reset: no reply
                with lock:
                    replies.append(head)

            # 40 held tunnels need 80+ descriptors in the meter; it has 48. Concurrent clients,
            # because a paused accept makes each waiting client take about a second.
            threads = [threading.Thread(target=client) for _ in range(40)]
            for th in threads:
                th.start()
                _time.sleep(0.005)
            for th in threads:
                th.join(15)
            for sock in socks:
                sock.close()
            proc.stdin.write("\n")
            proc.stdin.flush()
            result = json.loads(proc.stdout.readline())
        finally:
            proc.kill()
            proc.wait(10)
            proc.stdin.close()
            proc.stdout.close()
    statuses = result["statuses"]
    assert sum(r.startswith(b"HTTP/1.1 200") for r in replies) >= 5
    refused = [r for r in replies if r and not r.startswith(b"HTTP/1.1 200")]
    assert refused or result["accept"], (statuses, result)
    for head in refused:
        assert head.startswith(b"HTTP/1.1 503 Service Unavailable"), head
        assert b"X-Scrapescope-Error: local-limit" in head
    assert set(statuses) <= {"ok", "failed:local_limit", "failed:client_closed"}, statuses
    assert statuses.get("failed:local_limit", 0) == len(refused)


def test_raise_open_file_limit_raises_toward_the_hard_limit_and_never_lowers() -> None:
    import subprocess
    import sys

    code = (
        "import resource, sys\n"
        "from scrapescope.forwarder import raise_open_file_limit\n"
        "hard = resource.getrlimit(resource.RLIMIT_NOFILE)[1]\n"
        "resource.setrlimit(resource.RLIMIT_NOFILE, (256, hard))\n"
        "before, after = raise_open_file_limit()\n"
        "now = resource.getrlimit(resource.RLIMIT_NOFILE)[0]\n"
        "high = raise_open_file_limit(target=1000)\n"  # below the current soft limit: unchanged
        "print(before, after, now, resource.getrlimit(resource.RLIMIT_NOFILE)[0], high, hard)\n"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=30, check=True).stdout.split()
    before, after, now, again = (int(x) for x in out[:4])
    hard = int(out[-1])
    assert before == 256
    assert after == now == again
    assert after >= min(1024, hard) and after > 256
    assert after <= 65536
