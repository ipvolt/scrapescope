"""HTTP/1.1 framing through the meter (h11 on both sides) and raw-tunnel edge cases."""

from __future__ import annotations

import hashlib
import json
import socket
import threading

import pytest
import requests

from tests.fixtures import TestWorld, site
from tests.test_forwarder_helpers import (
    LocalServer,
    connect_map_with,
    make_config,
    meter_http,
    open_connect,
    parse_response,
    read_all,
    raw_exchange,
    read_head,
    running,
    settle,
    wait_tunnels_closed,
)

pytestmark = pytest.mark.timeout(60)

ROUTES = ["http", "socks", "direct"]


def _config(world: TestWorld, route: str):
    if route == "http":
        return make_config(world.http_upstream.url), None
    if route == "socks":
        return make_config(world.socks_upstream.url), None
    return make_config(None), world.hosts_map


@pytest.mark.parametrize("route", ROUTES)
def test_keep_alive_reuses_one_tunnel(fresh_world: TestWorld, route: str) -> None:
    config, cmap = _config(fresh_world, route)
    with running(config, connect_map=cmap) as fw:
        conn = meter_http(fw.port)
        bodies = []
        for _ in range(3):
            conn.request("GET", "http://origin-a.test/plain.html", headers={"Accept-Encoding": "identity"})
            resp = conn.getresponse()
            bodies.append(resp.read())
            assert resp.status == 200
        conn.close()
        snap = settle(fresh_world, fw)
    assert all(site.PRODUCT_PRICE.encode() in b for b in bodies)
    (tunnel,) = snap.target_tunnels()
    assert tunnel.kind == "http" and tunnel.requests == 3 and tunnel.upstream_status == 200
    origin = fresh_world.origin("origin-a.test", "http")
    assert origin.totals()["connections"] == 1 and origin.totals()["requests"] == 3


@pytest.mark.parametrize("route", ROUTES)
def test_authority_switch_opens_new_tunnel(fresh_world: TestWorld, route: str) -> None:
    config, cmap = _config(fresh_world, route)
    with running(config, connect_map=cmap) as fw:
        conn = meter_http(fw.port)
        for url in ("http://origin-a.test/plain.html", "http://origin-b.test/plain.html", "http://origin-a.test/plain.html"):
            conn.request("GET", url)
            resp = conn.getresponse()
            resp.read()
            assert resp.status == 200
        conn.close()
        snap = settle(fresh_world, fw)
    target = snap.target_tunnels()
    assert [(t.host, t.requests, t.status) for t in target] == [
        ("origin-a.test", 1, "ok"),
        ("origin-b.test", 1, "ok"),
        ("origin-a.test", 1, "ok"),
    ]
    if route == "http":
        # meas3-3: the provider serves every authority, so the meter keeps the one
        # upstream connection the client kept and only starts a new record.
        fixture = fresh_world.http_upstream.totals()
        assert fixture["connections"] == 1
        assert [t.continued_from for t in target] == [None, target[0].id, target[1].id]
        assert [t.opened_connection for t in target] == [True, False, False]
        assert sum(t.upstream_bytes_sent for t in target) == fixture["bytes_from_client"]
        assert sum(t.upstream_bytes_received for t in target) == fixture["bytes_to_client"]
        assert all(t.upstream_bytes_sent > 0 and t.upstream_bytes_received > 0 for t in target)
    else:
        # SOCKS5 and direct connections belong to one target: a switch needs a new one.
        assert [t.continued_from for t in target] == [None, None, None]
        assert all(t.opened_connection for t in target)


def _alternating_session(proxy: str, rounds: int = 3) -> list[int]:
    """A requests.Session doing http:// GETs to two hosts in turn through ``proxy``."""
    statuses = []
    with requests.Session() as session:
        session.trust_env = False
        for _ in range(rounds):
            for url in ("http://origin-a.test/plain.html", "http://origin-b.test/plain.html"):
                resp = session.get(url, proxies={"http": proxy}, timeout=20)
                statuses.append(resp.status_code)
    return statuses


def test_plain_http_connection_reuse_matches_the_client_without_the_meter(fresh_world: TestWorld) -> None:
    """meas3-3: the provider sees the same connections with and without the meter.

    requests keeps one proxy connection for http:// requests to any host.
    Providers that rotate the exit IP or bind sessions per connection would
    otherwise behave differently under the meter.
    """
    upstream = fresh_world.http_upstream
    assert _alternating_session(upstream.url) == [200] * 6
    assert fresh_world.wait_idle(10)
    baseline = [(len(r.targets), r.kind) for r in upstream.records()]
    assert baseline == [(6, "http")]
    fresh_world.reset()
    with running(make_config(upstream.url)) as fw:
        assert _alternating_session(fw.url) == [200] * 6
        snap = settle(fresh_world, fw)
    assert [(len(r.targets), r.kind) for r in upstream.records()] == baseline
    target = snap.target_tunnels()
    assert [t.host for t in target] == ["origin-a.test", "origin-b.test"] * 3
    assert [t.requests for t in target] == [1] * 6
    assert sum(t.opened_connection for t in target) == 1
    fixture = upstream.totals()
    assert sum(t.upstream_bytes_sent for t in target) == fixture["bytes_from_client"]
    assert sum(t.upstream_bytes_received for t in target) == fixture["bytes_to_client"]
    # Each record holds exactly its own exchange: the origin-b records match each other.
    b_records = [t for t in target if t.host == "origin-b.test"]
    assert len({(t.upstream_bytes_sent, t.upstream_bytes_received) for t in b_records}) == 1


def test_plain_http_same_host_after_switch_keeps_one_record_per_run(fresh_world: TestWorld) -> None:
    """Consecutive requests to one host stay on one record; only a switch starts a new one."""
    with running(make_config(fresh_world.http_upstream.url)) as fw:
        conn = meter_http(fw.port)
        for url in ("http://origin-a.test/plain.html",) * 2 + ("http://origin-b.test/plain.html",) * 2:
            conn.request("GET", url)
            resp = conn.getresponse()
            resp.read()
            assert resp.status == 200
        conn.close()
        snap = settle(fresh_world, fw)
    assert [(t.host, t.requests, t.status) for t in snap.target_tunnels()] == [
        ("origin-a.test", 2, "ok"),
        ("origin-b.test", 2, "ok"),
    ]
    assert fresh_world.http_upstream.totals()["connections"] == 1


@pytest.mark.parametrize("route", ROUTES)
def test_chunked_request_body(fresh_world: TestWorld, route: str) -> None:
    config, cmap = _config(fresh_world, route)
    parts = [b"a" * 1000, b"b" * 70_000, b"c" * 3]
    body = b"".join(parts)
    with running(config, connect_map=cmap) as fw:
        conn = meter_http(fw.port)
        conn.request("POST", "http://origin-a.test/echo", body=iter(parts), encode_chunked=True)
        resp = conn.getresponse()
        data = json.loads(resp.read())
        # Content-Length body on the same connection afterwards.
        conn.request("PUT", "http://origin-a.test/echo", body=b"xyz" * 1000)
        resp2 = conn.getresponse()
        data2 = json.loads(resp2.read())
        conn.close()
        settle(fresh_world, fw)
    assert data == {"method": "POST", "body_bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}
    assert data2["method"] == "PUT" and data2["body_bytes"] == 3000


@pytest.mark.parametrize("route", ROUTES)
def test_expect_100_continue_passthrough(fresh_world: TestWorld, route: str) -> None:
    config, cmap = _config(fresh_world, route)
    body = b"z" * 5000
    with running(config, connect_map=cmap) as fw:
        sock = socket.create_connection(("127.0.0.1", fw.port), timeout=5)
        sock.sendall(
            b"POST http://origin-a.test/echo HTTP/1.1\r\nHost: origin-a.test\r\n"
            b"Content-Length: 5000\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n"
        )
        head, rest = read_head(sock)  # must arrive before we send the body (5 s timeout)
        assert head.startswith(b"HTTP/1.1 100"), head
        sock.sendall(body)
        raw = rest + read_all(sock)
        sock.close()
        settle(fresh_world, fw)
    resp = parse_response(raw)
    assert resp.status == 200
    assert resp.header("Content-Length") is not None  # the origin's framing is kept
    assert json.loads(resp.body)["body_bytes"] == 5000


@pytest.mark.parametrize("route", ROUTES)
def test_head_204_304_keep_connection_usable(fresh_world: TestWorld, route: str) -> None:
    config, cmap = _config(fresh_world, route)
    with running(config, connect_map=cmap) as fw:
        conn = meter_http(fw.port)
        conn.request("HEAD", "http://origin-a.test/plain.html")
        head = conn.getresponse()
        assert head.status == 200 and head.read() == b""
        assert int(head.getheader("Content-Length")) > 0
        conn.request("GET", "http://origin-a.test/status/204")
        r204 = conn.getresponse()
        assert r204.status == 204 and r204.read() == b""
        conn.request("GET", "http://origin-a.test/static/style.css")
        css = conn.getresponse()
        etag = css.getheader("ETag")
        assert css.status == 200 and css.read()
        conn.request("GET", "http://origin-a.test/static/style.css", headers={"If-None-Match": etag})
        r304 = conn.getresponse()
        assert r304.status == 304 and r304.read() == b""
        conn.request("GET", "http://origin-a.test/status/418")
        r418 = conn.getresponse()
        assert r418.status == 418 and r418.read() == b"status 418\n"
        conn.close()
        snap = settle(fresh_world, fw)
    (tunnel,) = snap.target_tunnels()
    assert tunnel.requests == 5 and tunnel.upstream_status == 418


@pytest.mark.parametrize("route", ROUTES)
def test_close_delimited_and_chunked_responses(fresh_world: TestWorld, route: str) -> None:
    config, cmap = _config(fresh_world, route)
    with running(config, connect_map=cmap) as fw:
        conn = meter_http(fw.port)
        conn.request("GET", "http://origin-a.test/chunked?n=4&size=1000")
        chunked = conn.getresponse().read()
        conn.request("GET", "http://origin-a.test/close-delimited?size=5000")
        resp = conn.getresponse()
        closed = resp.read()
        conn.close()
        snap = settle(fresh_world, fw)
    assert chunked == b"".join(site.big_bytes(i * 1000, 1000) for i in range(4))
    assert closed == site.big_bytes(0, 5000)
    assert all(t.status == "ok" for t in snap.target_tunnels())


def test_pipelined_requests(fresh_world: TestWorld) -> None:
    with running(make_config(fresh_world.http_upstream.url)) as fw:
        sock = socket.create_connection(("127.0.0.1", fw.port), timeout=10)
        sock.sendall(
            b"GET http://origin-a.test/status/201 HTTP/1.1\r\nHost: origin-a.test\r\n\r\n"
            b"GET http://origin-a.test/status/202 HTTP/1.1\r\nHost: origin-a.test\r\nConnection: close\r\n\r\n"
        )
        raw = read_all(sock)
        sock.close()
        snap = settle(fresh_world, fw)
    assert raw.count(b"HTTP/1.1 201") == 1 and raw.count(b"HTTP/1.1 202") == 1
    assert raw.index(b"HTTP/1.1 201") < raw.index(b"HTTP/1.1 202")
    (tunnel,) = snap.target_tunnels()
    assert tunnel.requests == 2


def test_http10_client(fresh_world: TestWorld) -> None:
    """HTTP/1.0 without Host: the meter adds Host for the upstream and closes after the response."""
    with running(make_config(None), connect_map=fresh_world.hosts_map) as fw:
        sock = socket.create_connection(("127.0.0.1", fw.port), timeout=10)
        sock.sendall(b"GET http://origin-a.test/plain.html HTTP/1.0\r\n\r\n")
        raw = read_all(sock)
        sock.close()
        settle(fresh_world, fw)
    resp = parse_response(raw)
    assert resp.status == 200 and site.PRODUCT_PRICE.encode() in resp.body
    (req,) = fresh_world.origin("origin-a.test", "http").requests()
    assert req.header("Host") == "origin-a.test"


# ---------------------------------------------------------------------------- raw tunnels
def _echo_after_eof(sock: socket.socket) -> None:
    """Read until EOF, then answer with the byte count and a marker, then close."""
    total = 0
    while True:
        data = sock.recv(65536)
        if not data:
            break
        total += len(data)
    sock.sendall(f"received {total}\n".encode() + b"x" * 100_000)
    sock.shutdown(socket.SHUT_WR)


def test_half_close_propagates(fresh_world: TestWorld) -> None:
    with LocalServer(_echo_after_eof) as server:
        cmap = connect_map_with(fresh_world, {("halfclose.test", 7000): ("127.0.0.1", server.port)})
        with running(make_config(None), connect_map=cmap) as fw:
            sock, reply, rest = open_connect(fw.port, "halfclose.test:7000")
            assert reply.status == 200
            assert reply.raw == b"HTTP/1.1 200 Connection established\r\n\r\n"
            sock.sendall(b"q" * 123_456)
            sock.shutdown(socket.SHUT_WR)  # half-close: the reverse direction must keep flowing
            data = rest + read_all(sock)
            sock.close()
            snap = settle(fresh_world, fw)
    assert data.startswith(b"received 123456\n") and len(data) == len(b"received 123456\n") + 100_000
    (tunnel,) = snap.target_tunnels()
    assert tunnel.upstream_bytes_sent == 123_456
    assert tunnel.upstream_bytes_received == len(data)
    assert tunnel.status == "ok"


def _echo(sock: socket.socket) -> None:
    while True:
        data = sock.recv(65536)
        if not data:
            return
        sock.sendall(data)


def test_connect_early_data_is_forwarded(fresh_world: TestWorld) -> None:
    """Bytes the client pipelines right after the CONNECT head reach the target."""
    with LocalServer(_echo) as server:
        cmap = connect_map_with(fresh_world, {("echo.test", 7): ("127.0.0.1", server.port)})
        with running(make_config(None), connect_map=cmap) as fw:
            sock = socket.create_connection(("127.0.0.1", fw.port), timeout=10)
            sock.sendall(b"CONNECT echo.test:7 HTTP/1.1\r\nHost: echo.test:7\r\n\r\nEARLY-DATA")
            head, rest = read_head(sock)
            while len(rest) < len(b"EARLY-DATA"):
                rest += sock.recv(100)
            sock.close()
            settle(fresh_world, fw)
    assert head.startswith(b"HTTP/1.1 200")
    assert rest == b"EARLY-DATA"


def test_connect_without_host_header(fresh_world: TestWorld) -> None:
    """Python 3.11's http.client sends CONNECT without Host; the meter accepts it."""
    with LocalServer(_echo) as server:
        cmap = connect_map_with(fresh_world, {("echo.test", 7): ("127.0.0.1", server.port)})
        with running(make_config(None), connect_map=cmap) as fw:
            sock = socket.create_connection(("127.0.0.1", fw.port), timeout=10)
            sock.sendall(b"CONNECT echo.test:7 HTTP/1.1\r\nUser-Agent: x\r\n\r\n")
            head, _ = read_head(sock)
            sock.sendall(b"ping")
            assert sock.recv(10) == b"ping"
            sock.close()
            settle(fresh_world, fw)
    assert head.startswith(b"HTTP/1.1 200")


def test_connect_head_forwarded_unchanged(fresh_world: TestWorld) -> None:
    """Custom CONNECT headers reach the HTTP upstream; no Host is invented."""
    with running(make_config(fresh_world.http_upstream.url)) as fw:
        sock, reply, _ = open_connect(fw.port, "origin-a.test:443", extra="X-Provider-Session: s-17\r\n")
        sock.close()
        assert reply.status == 200
        sock = socket.create_connection(("127.0.0.1", fw.port), timeout=10)
        sock.sendall(b"CONNECT origin-a.test:443 HTTP/1.1\r\nUser-Agent: py311\r\n\r\n")
        head, _ = read_head(sock)
        sock.close()
        settle(fresh_world, fw)
    first, second = fresh_world.http_upstream.records()
    names = [n for n, _ in first.request_headers[0]]
    assert ("X-Provider-Session", "s-17") in first.request_headers[0]
    assert names.count("Host") == 1 and "Proxy-Authorization" in names
    # Without Host the fixture (like a strict provider) answers 400, which is relayed verbatim.
    assert head.startswith(b"HTTP/1.1 400")
    assert "bad_request" in second.errors


def _upgrade_server(sock: socket.socket) -> None:
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            return
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    assert head.startswith(b"GET /chat HTTP/1.1")
    sock.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\nWELCOME")
    if rest:
        sock.sendall(rest)
    _echo(sock)


def test_upgrade_switches_to_raw_relay(fresh_world: TestWorld) -> None:
    with LocalServer(_upgrade_server) as server:
        cmap = connect_map_with(fresh_world, {("ws.test", 80): ("127.0.0.1", server.port)})
        with running(make_config(None), connect_map=cmap) as fw:
            sock = socket.create_connection(("127.0.0.1", fw.port), timeout=10)
            sock.sendall(
                b"GET http://ws.test/chat HTTP/1.1\r\nHost: ws.test\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n"
            )
            head, rest = read_head(sock)
            while len(rest) < 7:
                rest += sock.recv(100)
            sock.sendall(b"hello over the upgraded connection")
            echoed = b""
            while len(echoed) < 34:
                echoed += sock.recv(100)
            sock.close()
            snap = settle(fresh_world, fw)
    assert head.startswith(b"HTTP/1.1 101")
    assert rest == b"WELCOME"
    assert echoed == b"hello over the upgraded connection"
    (tunnel,) = snap.target_tunnels()
    assert tunnel.upstream_status == 101 and tunnel.status == "ok"


def test_upstream_closes_mid_response(fresh_world: TestWorld) -> None:
    def truncated(sock: socket.socket) -> None:
        sock.recv(65536)
        sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n" + b"x" * 10)
        sock.close()

    def silent(sock: socket.socket) -> None:
        sock.recv(65536)
        sock.close()

    with LocalServer(truncated) as s1, LocalServer(silent) as s2:
        cmap = connect_map_with(
            fresh_world, {("trunc.test", 80): ("127.0.0.1", s1.port), ("silent.test", 80): ("127.0.0.1", s2.port)}
        )
        with running(make_config(None), connect_map=cmap) as fw:
            sock = socket.create_connection(("127.0.0.1", fw.port), timeout=10)
            sock.sendall(b"GET http://trunc.test/ HTTP/1.1\r\nHost: trunc.test\r\n\r\n")
            data = read_all(sock)
            sock.close()
            sock = socket.create_connection(("127.0.0.1", fw.port), timeout=10)
            sock.sendall(b"GET http://silent.test/ HTTP/1.1\r\nHost: silent.test\r\n\r\n")
            silent_resp = parse_response(read_all(sock))
            sock.close()
            snap = settle(fresh_world, fw)
    assert data.startswith(b"HTTP/1.1 200") and len(data) < 1000
    assert silent_resp.status == 502 and silent_resp.header("X-Scrapescope-Error") == "upstream-closed"
    assert [t.status for t in snap.target_tunnels()] == ["failed:upstream_closed", "failed:upstream_closed"]


def test_threads_share_one_forwarder(fresh_world: TestWorld) -> None:
    """http.client keep-alive connections from several threads at once."""
    errors: list[BaseException] = []
    with running(make_config(fresh_world.http_upstream.url)) as fw:

        def worker() -> None:
            try:
                conn = meter_http(fw.port)
                for _ in range(5):
                    conn.request("GET", "http://origin-a.test/big.bin?size=20000")
                    assert len(conn.getresponse().read()) == 20000
                conn.close()
            except BaseException as exc:  # noqa: BLE001 - reported below
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        snap = settle(fresh_world, fw)
    assert not errors
    target = snap.target_tunnels()
    assert len(target) == 10 and sum(t.requests for t in target) == 50
    fixture = fresh_world.http_upstream.totals()
    assert sum(t.upstream_bytes_received for t in target) == fixture["bytes_to_client"]


def test_upstream_closed_idle_keep_alive_is_replaced(fresh_world: TestWorld) -> None:
    """If the upstream closed an idle keep-alive connection, the next request opens a new tunnel."""
    import time as _time

    def one_shot(sock: socket.socket) -> None:
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                return
            buf += chunk
        sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        sock.close()  # closes the keep-alive connection right after the response

    with LocalServer(one_shot) as server:
        cmap = connect_map_with(fresh_world, {("oneshot.test", 80): ("127.0.0.1", server.port)})
        with running(make_config(None), connect_map=cmap) as fw:
            conn = meter_http(fw.port)
            conn.request("GET", "http://oneshot.test/a")
            assert conn.getresponse().read() == b"ok"
            _time.sleep(0.3)  # let the upstream's FIN arrive
            conn.request("GET", "http://oneshot.test/b")
            assert conn.getresponse().read() == b"ok"
            conn.close()
            snap = settle(fresh_world, fw)
    assert [(t.requests, t.status) for t in snap.target_tunnels()] == [(1, "ok"), (1, "ok")]


# ---------------------------------------------------------------------------- review fixes (meas-7/8/9, sec-6/7)
def _read_request_head(sock: socket.socket) -> bytes:
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buf += chunk
    return buf


def _recv_until_eof(sock: socket.socket, timeout: float) -> tuple[bytes, str]:
    """Read until EOF; returns (data, "eof" | "reset" | "timeout")."""
    sock.settimeout(timeout)
    data = b""
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                return data, "eof"
            data += chunk
    except ConnectionResetError:
        return data, "reset"
    except TimeoutError:
        return data, "timeout"


def _reject_before_body(close: bool):
    def handler(sock: socket.socket) -> None:
        _read_request_head(sock)
        if close:
            sock.sendall(b"HTTP/1.1 417 Expectation Failed\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnope")
            sock.close()  # without reading the body
            return
        sock.sendall(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
        while sock.recv(65536):  # keep-alive: hold the connection open
            pass

    return handler


@pytest.mark.parametrize("close", [True, False], ids=["417-close", "401-keep-alive"])
def test_final_response_before_100_continue_ends_the_connection(fresh_world: TestWorld, close: bool) -> None:
    """meas-7: the client never sends the body, so the meter must not wait for it (600 s idle timeout)."""
    with LocalServer(_reject_before_body(close)) as server:
        cmap = connect_map_with(fresh_world, {("expect.test", 80): ("127.0.0.1", server.port)})
        with running(make_config(None), connect_map=cmap) as fw:
            sock = socket.create_connection(("127.0.0.1", fw.port), timeout=5)
            sock.sendall(
                b"POST http://expect.test/upload HTTP/1.1\r\nHost: expect.test\r\n"
                b"Content-Length: 100000\r\nExpect: 100-continue\r\n\r\n"
            )
            data, how = _recv_until_eof(sock, 5)
            sock.close()
            snap = wait_tunnels_closed(fw, 5)
    assert how == "eof", (how, data[:80])
    assert data.startswith(b"HTTP/1.1 417" if close else b"HTTP/1.1 401")
    (tunnel,) = snap.target_tunnels()
    assert tunnel.status == "ok" and tunnel.upstream_status == (417 if close else 401)


def _data_then_reset(payload: bytes):
    def handler(sock: socket.socket) -> None:
        sock.recv(65536)
        sock.sendall(payload)
        import struct
        import time as _time

        _time.sleep(0.3)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        sock.close()  # RST

    return handler


def test_upstream_reset_in_tunnel_reaches_client_as_reset(fresh_world: TestWorld) -> None:
    """meas-8: an upstream RST is not turned into a clean close, and the tunnel is not "ok"."""
    with LocalServer(_data_then_reset(b"x" * 5000)) as server:
        cmap = connect_map_with(fresh_world, {("rst.test", 443): ("127.0.0.1", server.port)})
        with running(make_config(None), connect_map=cmap) as fw:
            sock, reply, rest = open_connect(fw.port, "rst.test:443")
            assert reply.status == 200
            sock.sendall(b"hello")
            data, how = _recv_until_eof(sock, 5)
            sock.close()
            snap = wait_tunnels_closed(fw, 5)
    assert how == "reset", (how, len(rest + data))
    (tunnel,) = snap.target_tunnels()
    assert tunnel.status == "failed:upstream_reset"
    assert tunnel.upstream_bytes_received == 5000


def test_upstream_reset_mid_close_delimited_body_is_not_a_complete_response(fresh_world: TestWorld) -> None:
    """meas-8 (plain HTTP): a reset during a close-delimited body must not look like its end."""
    payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n" + b"y" * 5000
    with LocalServer(_data_then_reset(payload)) as server:
        cmap = connect_map_with(fresh_world, {("rst.test", 80): ("127.0.0.1", server.port)})
        with running(make_config(None), connect_map=cmap) as fw:
            sock = socket.create_connection(("127.0.0.1", fw.port), timeout=5)
            sock.sendall(b"GET http://rst.test/ HTTP/1.1\r\nHost: rst.test\r\n\r\n")
            data, how = _recv_until_eof(sock, 5)
            sock.close()
            snap = wait_tunnels_closed(fw, 5)
    # The meter re-frames the close-delimited body as chunked; a reset must not end it with 0\r\n\r\n.
    assert how == "reset" or not data.endswith(b"0\r\n\r\n"), (how, data[-20:])
    (tunnel,) = snap.target_tunnels()
    assert tunnel.status == "failed:upstream_reset"


def test_client_reset_in_tunnel_is_passed_to_the_upstream(fresh_world: TestWorld) -> None:
    """meas-8 mirror: the upstream sees a reset, not a clean EOF, when the client resets."""
    import struct

    seen: list[str] = []
    ready = threading.Event()

    def origin(sock: socket.socket) -> None:
        try:
            sock.recv(65536)
            ready.set()
            while sock.recv(65536):
                pass
            seen.append("eof")
        except ConnectionResetError:
            seen.append("reset")

    with LocalServer(origin) as server:
        cmap = connect_map_with(fresh_world, {("crst.test", 443): ("127.0.0.1", server.port)})
        with running(make_config(None), connect_map=cmap) as fw:
            sock, reply, _ = open_connect(fw.port, "crst.test:443")
            assert reply.status == 200
            sock.sendall(b"hello")
            assert ready.wait(5)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            sock.close()
            snap = wait_tunnels_closed(fw, 5)
            deadline = __import__("time").monotonic() + 5
            while not seen and __import__("time").monotonic() < deadline:
                __import__("time").sleep(0.02)
    assert seen == ["reset"]
    (tunnel,) = snap.target_tunnels()
    assert tunnel.status == "ok"


def test_chunked_trailers_are_relayed_both_ways(fresh_world: TestWorld) -> None:
    """meas-9: trailers survive the h11 re-framing in both directions."""
    received: list[bytes] = []

    def origin(sock: socket.socket) -> None:
        buf = b""
        while not buf.endswith(b"0\r\nX-Request-Sum: r42\r\n\r\n"):
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
        received.append(buf)
        sock.sendall(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Checksum\r\n\r\n"
            b"5\r\nhello\r\n0\r\nX-Checksum: abc123\r\n\r\n"
        )
        while sock.recv(65536):
            pass

    with LocalServer(origin) as server:
        cmap = connect_map_with(fresh_world, {("trailer.test", 80): ("127.0.0.1", server.port)})
        with running(make_config(None), connect_map=cmap) as fw:
            sock = socket.create_connection(("127.0.0.1", fw.port), timeout=5)
            sock.sendall(
                b"POST http://trailer.test/ HTTP/1.1\r\nHost: trailer.test\r\nTE: trailers\r\n"
                b"Transfer-Encoding: chunked\r\nTrailer: X-Request-Sum\r\n\r\n"
                b"3\r\nabc\r\n0\r\nX-Request-Sum: r42\r\n\r\n"
            )
            buf = b""
            while not buf.endswith(b"\r\n\r\n") or b"0\r\n" not in buf:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buf += chunk
            sock.close()
            wait_tunnels_closed(fw, 5)
    assert b"X-Request-Sum: r42" in received[0]
    assert buf.endswith(b"5\r\nhello\r\n0\r\nX-Checksum: abc123\r\n\r\n"), buf


@pytest.mark.parametrize("route", ROUTES)
def test_content_length_with_transfer_encoding_is_refused(fresh_world: TestWorld, route: str) -> None:
    """sec-6: CL + TE is a smuggling vector; the meter refuses it before any upstream contact."""
    config, cmap = _config(fresh_world, route)
    with running(config, connect_map=cmap) as fw:
        resp = raw_exchange(
            fw.port,
            b"POST http://origin-a.test/echo HTTP/1.1\r\nHost: origin-a.test\r\nContent-Length: 4\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: origin-a.test\r\n\r\n",
        )
        snap = fw.snapshot()
    assert resp.status == 400 and resp.header("X-Scrapescope-Error") == "bad-request"
    assert snap.refused == {"bad_request": 1} and snap.tunnels == []
    assert fresh_world.origin("origin-a.test", "http").requests() == []
    assert fresh_world.http_upstream.records() == [] and fresh_world.socks_upstream.records() == []


@pytest.mark.parametrize("route", ROUTES)
def test_absolute_form_host_header_is_the_target_authority(fresh_world: TestWorld, route: str) -> None:
    """sec-7: a foreign Host cannot reach a denied host; the origin sees the routed authority."""
    from tests.test_forwarder_helpers import deny

    config, cmap = _config(fresh_world, route)
    config = type(config)(**{**config.__dict__, "deny_rules": (deny("origin-b.test"),)})
    with running(config, connect_map=cmap) as fw:
        denied = raw_exchange(fw.port, b"GET http://origin-b.test/plain.html HTTP/1.1\r\nHost: origin-b.test\r\n\r\n")
        resp = raw_exchange(
            fw.port,
            b"GET http://origin-a.test/plain.html HTTP/1.1\r\nHost: origin-b.test\r\nConnection: close\r\n\r\n",
        )
        snap = settle(fresh_world, fw)
    assert denied.status == 403 and denied.header("X-Scrapescope-Error") == "denied"
    assert resp.status == 200
    (req,) = fresh_world.origin("origin-a.test", "http").requests()
    assert req.header("Host") == "origin-a.test"
    assert fresh_world.origin("origin-b.test", "http").requests() == []
    assert [t.host for t in snap.target_tunnels()] == ["origin-a.test"]


def test_hop_by_hop_request_headers_are_not_forwarded(fresh_world: TestWorld) -> None:
    """RFC 9110 section 7.6.1: Connection-listed headers, Keep-Alive and Proxy-Connection stay at the meter."""
    with running(make_config(None), connect_map=fresh_world.hosts_map) as fw:
        resp = raw_exchange(
            fw.port,
            b"GET http://origin-a.test/plain.html HTTP/1.1\r\nHost: origin-a.test\r\n"
            b"Connection: close, X-Hop\r\nX-Hop: secret-hop\r\nKeep-Alive: timeout=5\r\n"
            b"Proxy-Connection: keep-alive\r\nX-End-To-End: kept\r\n\r\n",
        )
        settle(fresh_world, fw)
    assert resp.status == 200
    (req,) = fresh_world.origin("origin-a.test", "http").requests()
    assert req.header("X-Hop") is None and req.header("Keep-Alive") is None and req.header("Proxy-Connection") is None
    assert req.header("Connection") == "close" and req.header("X-End-To-End") == "kept"


# ---------------------------------------------------------------------------- keep-alive race (meas2-6)
def _answer_once_then(action: str):
    """Origin: answer request 1 with keep-alive, read request 2, then close or reset without a reply."""

    def handler(sock: socket.socket) -> None:
        import struct

        _read_request_head(sock)
        sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        _read_request_head(sock)  # the next request arrives just as the idle timeout fires
        if action == "reset":
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        sock.close()

    return handler


@pytest.mark.parametrize("action", ["close", "reset"])
def test_keep_alive_race_passes_the_close_on_instead_of_a_502(fresh_world: TestWorld, action: str) -> None:
    """A reused upstream connection that ends before any reply byte ends the client's connection the same way.

    Straight to the origin the client sees its reused connection close (or reset)
    and retries an idempotent request on a new one; a meter 502 would instead hand
    the job an error page.
    """
    with LocalServer(_answer_once_then(action)) as server:
        cmap = connect_map_with(fresh_world, {("race.test", 80): ("127.0.0.1", server.port)})
        with running(make_config(None), connect_map=cmap) as fw:
            sock = socket.create_connection(("127.0.0.1", fw.port), timeout=5)
            sock.sendall(b"GET http://race.test/1 HTTP/1.1\r\nHost: race.test\r\n\r\n")
            first, rest = read_head(sock)
            assert first.startswith(b"HTTP/1.1 200")
            if len(rest) < 2:
                rest += sock.recv(2 - len(rest))
            assert rest == b"ok"
            sock.sendall(b"GET http://race.test/2 HTTP/1.1\r\nHost: race.test\r\n\r\n")
            data, how = _recv_until_eof(sock, 5)
            sock.close()
            snap = wait_tunnels_closed(fw, 5)
    assert data == b"", data[:120]  # no meter reply: the client's own retry logic applies
    assert how == ("reset" if action == "reset" else "eof")
    (tunnel,) = snap.target_tunnels()
    assert tunnel.status == "ok" and tunnel.requests == 2


def test_fresh_upstream_connection_closing_before_a_reply_still_gets_a_502(fresh_world: TestWorld) -> None:
    """Only a reused connection gets the silent close; a first request that gets no reply is a real failure."""

    def silent(sock: socket.socket) -> None:
        _read_request_head(sock)
        sock.close()

    with LocalServer(silent) as server:
        cmap = connect_map_with(fresh_world, {("silent.test", 80): ("127.0.0.1", server.port)})
        with running(make_config(None), connect_map=cmap) as fw:
            resp = raw_exchange(fw.port, b"GET http://silent.test/ HTTP/1.1\r\nHost: silent.test\r\n\r\n")
            snap = wait_tunnels_closed(fw, 5)
    assert resp.status == 502 and resp.header("X-Scrapescope-Error") == "upstream-closed"
    assert [t.status for t in snap.target_tunnels()] == ["failed:upstream_closed"]


# ---------------------------------------------------------------------------- forwarded target (sec2-9)
def test_http_upstream_gets_the_routed_authority_not_the_raw_target() -> None:
    """A target whose fragment hides a second authority is forwarded rebuilt from the checked one."""
    from tests.test_forwarder_helpers import deny

    lines: list[bytes] = []

    def fake_upstream(sock: socket.socket) -> None:
        while True:
            head = _read_request_head(sock)
            if not head:
                return
            lines.append(head.split(b"\r\n", 1)[0])
            sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

    with LocalServer(fake_upstream) as upstream:
        config = make_config(f"http://127.0.0.1:{upstream.port}", deny_rules=(deny("denied.example"),))
        with running(config) as fw:
            hidden = raw_exchange(
                fw.port,
                b"GET http://allowed.example#@denied.example/secret HTTP/1.1\r\nHost: allowed.example\r\n"
                b"Connection: close\r\n\r\n",
            )
            query = raw_exchange(
                fw.port,
                b"GET http://Allowed.Example:8080/p/a?q=1&r=@x#frag HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            )
            denied = raw_exchange(fw.port, b"GET http://denied.example/ HTTP/1.1\r\nHost: denied.example\r\n\r\n")
            snap = wait_tunnels_closed(fw, 5)
    assert hidden.status == 200 and query.status == 200
    assert denied.status == 403 and denied.header("X-Scrapescope-Error") == "denied"
    assert lines == [
        b"GET http://allowed.example/ HTTP/1.1",
        b"GET http://Allowed.Example:8080/p/a?q=1&r=@x HTTP/1.1",  # host spelling kept, fragment dropped
    ]
    assert [t.host for t in snap.target_tunnels()] == ["allowed.example", "allowed.example"]


# ---------------------------------------------------------------------------- review fixes (round 3)
def _reset_after_head(sock: socket.socket) -> None:
    """Read the request head only, then reset the connection (SO_LINGER 0) mid-upload."""
    import struct

    _read_request_head(sock)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    sock.close()


def test_upstream_reset_during_the_request_body_is_a_failure(fresh_world: TestWorld) -> None:
    """meas3-6: a reset while the body is forwarded is failed:upstream_reset, not ok."""
    body_size = 8_000_000
    with LocalServer(_reset_after_head) as server:
        cmap = connect_map_with(fresh_world, {("upload.test", 80): ("127.0.0.1", server.port)})
        with running(make_config(None), connect_map=cmap) as fw:
            sock = socket.create_connection(("127.0.0.1", fw.port), timeout=10)
            sock.sendall(
                f"POST http://upload.test/up HTTP/1.1\r\nHost: upload.test\r\nContent-Length: {body_size}\r\n\r\n".encode()
            )

            def upload() -> None:
                chunk = b"u" * 65536
                sent = 0
                try:
                    while sent < body_size:
                        sock.sendall(chunk)
                        sent += len(chunk)
                except OSError:
                    pass

            sender = threading.Thread(target=upload, daemon=True)
            sender.start()
            data, _how = _recv_until_eof(sock, 10)
            sender.join(10)  # ends when the meter closes its side (a blocked send outlives a local close)
            sock.close()
            snap = wait_tunnels_closed(fw, 10)
    (tunnel,) = snap.target_tunnels()
    assert tunnel.status == "failed:upstream_reset", tunnel.status
    assert tunnel.upstream_bytes_sent > 0
    # Nothing of a response had reached the client: it gets the meter's 502 (or a reset if the
    # reply was lost to its own unfinished upload), never a normal end.
    assert data == b"" or data.startswith(b"HTTP/1.1 502")


def _reject_upload_then_reset(sock: socket.socket) -> None:
    """A complete keep-alive 413 without reading the body, then a reset (what a kernel sends for unread data)."""
    import struct
    import time as _time

    _read_request_head(sock)
    sock.sendall(b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 8\r\n\r\ntoo big!")
    _time.sleep(0.3)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    sock.close()


def test_reset_after_a_complete_response_does_not_fail_the_exchange(fresh_world: TestWorld) -> None:
    """The response arrived whole; the upstream only refused the rest of the upload.

    The client gets the whole 413 and then a (lingering) close; nothing it was
    owed was truncated, so the tunnel is ok.
    """
    body_size = 8_000_000
    with LocalServer(_reject_upload_then_reset) as server:
        cmap = connect_map_with(fresh_world, {("upload.test", 80): ("127.0.0.1", server.port)})
        with running(make_config(None), connect_map=cmap) as fw:
            sock = socket.create_connection(("127.0.0.1", fw.port), timeout=10)
            sock.sendall(
                f"POST http://upload.test/up HTTP/1.1\r\nHost: upload.test\r\nContent-Length: {body_size}\r\n\r\n".encode()
            )

            def upload() -> None:
                chunk = b"u" * 65536
                try:
                    for _ in range(body_size // len(chunk)):
                        sock.sendall(chunk)
                except OSError:
                    pass

            sender = threading.Thread(target=upload, daemon=True)
            sender.start()
            data, _how = _recv_until_eof(sock, 10)
            sender.join(10)  # ends when the meter closes its side (a blocked send outlives a local close)
            sock.close()
            snap = wait_tunnels_closed(fw, 10)
    assert data == b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 8\r\n\r\ntoo big!", data[:120]
    (tunnel,) = snap.target_tunnels()
    assert (tunnel.status, tunnel.upstream_status) == ("ok", 413)


def _early_hints_then_ok(sock: socket.socket) -> None:
    _read_request_head(sock)
    sock.sendall(
        b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n"
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
    )
    sock.close()


@pytest.mark.parametrize("version", ["1.0", "1.1"])
def test_informational_responses_never_reach_http10_clients(fresh_world: TestWorld, version: str) -> None:
    """meas3-10 (RFC 9110 section 15.2): 1xx go to HTTP/1.1 clients only."""
    with LocalServer(_early_hints_then_ok) as server:
        cmap = connect_map_with(fresh_world, {("hints.test", 80): ("127.0.0.1", server.port)})
        with running(make_config(None), connect_map=cmap) as fw:
            sock = socket.create_connection(("127.0.0.1", fw.port), timeout=10)
            extra = "Host: hints.test\r\nConnection: close\r\n" if version == "1.1" else ""
            sock.sendall(f"GET http://hints.test/ HTTP/{version}\r\n{extra}\r\n".encode())
            data, how = _recv_until_eof(sock, 10)
            sock.close()
            snap = wait_tunnels_closed(fw, 10)
    assert how == "eof"
    if version == "1.0":
        assert data.startswith(b"HTTP/1.1 200 OK\r\n"), data[:80]
        assert b"103" not in data.split(b"\r\n", 1)[0] and b"Early Hints" not in data
    else:
        assert data.startswith(b"HTTP/1.1 103 Early Hints\r\n"), data[:80]
        assert b"HTTP/1.1 200 OK\r\n" in data
    assert data.endswith(b"hello")
    (tunnel,) = snap.target_tunnels()
    assert tunnel.status == "ok" and tunnel.upstream_status == 200


def _raw_origin(*segments: bytes, pause: float = 0.05):
    """An origin that reads one request head, then sends ``segments`` with short pauses and closes."""

    def handler(sock: socket.socket) -> None:
        import time

        _read_request_head(sock)
        for segment in segments:
            sock.sendall(segment)
            time.sleep(pause)
        sock.close()

    return handler


def _get_through_meter(segments: tuple[bytes, ...], version: str = "1.1") -> tuple[bytes, object]:
    with LocalServer(_raw_origin(*segments)) as server:
        cmap = {("raw.test", 80): ("127.0.0.1", server.port)}
        with running(make_config(None), connect_map=cmap) as fw:
            sock = socket.create_connection(("127.0.0.1", fw.port), timeout=10)
            extra = "Host: raw.test\r\nConnection: close\r\n" if version == "1.1" else ""
            sock.sendall(f"GET http://raw.test/ HTTP/{version}\r\n{extra}\r\n".encode())
            data, how = _recv_until_eof(sock, 10)
            sock.close()
            snap = wait_tunnels_closed(fw, 10)
    assert how == "eof", how
    return data, snap


@pytest.mark.parametrize(
    "bad_line, fixed_line",
    [(b"X-Bad : v", b"X-Bad: v"), (b"X-A\t: b", b"X-A: b"), (b"X-Both \t : two words", b"X-Both: two words")],
)
def test_whitespace_before_a_response_colon_is_removed_not_refused(bad_line: bytes, fixed_line: bytes) -> None:
    """meas4-4 (RFC 9112 section 5.1): a proxy MUST remove it before forwarding; h11 alone would answer 502."""
    head = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n" + bad_line + b"\r\n\r\n"
    data, snap = _get_through_meter((head + b"hello",))
    resp = parse_response(data)
    assert resp.status == 200 and resp.body == b"hello", data[:200]
    assert fixed_line + b"\r\n" in data and bad_line not in data
    (tunnel,) = snap.target_tunnels()
    assert tunnel.status == "ok" and tunnel.upstream_status == 200


def test_response_heads_split_across_reads_and_after_1xx_are_normalised() -> None:
    """The fix holds when the head arrives in pieces and when a 103 precedes the final head in one segment."""
    segments = (
        b"HTTP/1.1 103 Early Hints\r\nLink : </a.css>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nX-Bad",
        b" : v\r\nContent-Length: 6\r\n\r\nhel",
        b"lo!",
    )
    data, snap = _get_through_meter(segments)
    assert data.startswith(b"HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\n"), data
    assert b"X-Bad: v\r\n" in data and data.endswith(b"\r\n\r\nhello!")
    (tunnel,) = snap.target_tunnels()
    assert tunnel.status == "ok" and tunnel.upstream_status == 200


def _chunked(payload: bytes, size: int = 7) -> bytes:
    out = b""
    for i in range(0, len(payload), size):
        part = payload[i : i + size]
        out += f"{len(part):x}\r\n".encode() + part + b"\r\n"
    return out + b"0\r\n\r\n"


def _dechunk(body: bytes) -> bytes:
    out = b""
    while True:
        line, _, body = body.partition(b"\r\n")
        size = int(line.split(b";")[0], 16)
        if size == 0:
            return out
        out, body = out + body[:size], body[size + 2 :]


def test_gzip_then_chunked_transfer_coding_is_relayed_with_its_coding() -> None:
    """meas4-4: 'Transfer-Encoding: gzip, chunked' is valid HTTP/1.1; the client gets the coding and the bytes."""
    import gzip

    payload = gzip.compress(b"hello transfer coding " * 20)
    head = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"
    data, snap = _get_through_meter((head + _chunked(payload),))
    resp = parse_response(data)
    assert resp.status == 200, data[:200]
    assert resp.header("Transfer-Encoding") == "gzip, chunked"
    assert gzip.decompress(_dechunk(resp.body)) == b"hello transfer coding " * 20
    (tunnel,) = snap.target_tunnels()
    assert tunnel.status == "ok"
    assert tunnel.upstream_bytes_received == len(head) + len(_chunked(payload))


def test_gzip_then_chunked_to_an_http10_client_is_still_refused() -> None:
    """An HTTP/1.0 client cannot receive a transfer coding, and the meter does not decode it: 502 as before."""
    import gzip

    head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"
    data, snap = _get_through_meter((head + _chunked(gzip.compress(b"x")),), version="1.0")
    resp = parse_response(data)
    assert resp.status == 502 and resp.header("X-Scrapescope-Error") == "upstream-protocol-error"
    (tunnel,) = snap.target_tunnels()
    assert tunnel.status == "failed:upstream_protocol"


def test_binary_reply_to_plain_http_still_fails_at_once() -> None:
    """The head buffering of meas4-4 does not wait for a blank line that a non-HTTP reply never sends."""
    import time

    def tls_alert_then_hold(sock: socket.socket) -> None:
        _read_request_head(sock)
        sock.sendall(b"\x15\x03\x01\x00\x02\x02\x28")  # a TLS alert: this port speaks TLS
        time.sleep(8)

    with LocalServer(tls_alert_then_hold) as server:
        cmap = {("tls.test", 80): ("127.0.0.1", server.port)}
        with running(make_config(None), connect_map=cmap) as fw:
            started = time.monotonic()
            resp = raw_exchange(fw.port, b"GET http://tls.test/ HTTP/1.1\r\nHost: tls.test\r\n\r\n")
            elapsed = time.monotonic() - started
            snap = wait_tunnels_closed(fw, 10)
    assert resp.status == 502 and resp.header("X-Scrapescope-Error") == "upstream-protocol-error"
    assert elapsed < 4
    (tunnel,) = snap.target_tunnels()
    assert tunnel.status == "failed:upstream_protocol"
