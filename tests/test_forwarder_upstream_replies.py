"""Upstream reply handling against scripted fake upstream proxies.

The fixture upstreams are well behaved; these tiny scripted proxies cover the
remaining rows of the failure table (contracts section 3.6) and the verbatim
relay of unusual replies: chunked and close-delimited error bodies, vendor
headers on a 200, payload in the same segment as the 200, garbage, silence.
"""

from __future__ import annotations

import socket
import threading
import time

import pytest

from tests.fixtures import UPSTREAM_PASSWORD, UPSTREAM_USERNAME, TestWorld
from tests.test_forwarder_helpers import (
    LocalServer,
    make_config,
    open_connect,
    raw_exchange,
    read_all,
    read_head,
    running,
    wait_tunnels_closed,
)

pytestmark = pytest.mark.timeout(60)

CONNECT = b"CONNECT target.test:443 HTTP/1.1\r\nHost: target.test:443\r\n\r\n"


class FakeProxy:
    """A scripted upstream: records the request head it received, then runs ``script``."""

    def __init__(self, script) -> None:
        self.heads: list[bytes] = []
        self._lock = threading.Lock()

        def handler(sock: socket.socket) -> None:
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = sock.recv(65536)
                if not chunk:
                    return
                buf += chunk
            with self._lock:
                self.heads.append(buf.split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n")
            script(sock)

        self.server = LocalServer(handler)

    @property
    def url(self) -> str:
        return f"http://{UPSTREAM_USERNAME}:{UPSTREAM_PASSWORD}@127.0.0.1:{self.server.port}"

    def __enter__(self) -> FakeProxy:
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.close()


def _hold(sock: socket.socket) -> None:
    """Keep the connection open until the meter closes it (like a provider after an error)."""
    sock.settimeout(10)
    try:
        while sock.recv(65536):
            pass
    except OSError:
        pass


def test_upstream_closes_before_replying() -> None:
    with FakeProxy(lambda sock: sock.close()) as proxy, running(make_config(proxy.url)) as fw:
        resp = raw_exchange(fw.port, CONNECT)
        snap = wait_tunnels_closed(fw)
    assert resp.status == 502 and resp.header("X-Scrapescope-Error") == "upstream-closed"
    (tunnel,) = snap.target_tunnels()
    assert tunnel.status == "failed:upstream_closed"
    assert tunnel.upstream_bytes_sent == tunnel.connect_request_bytes == len(proxy.heads[0])


def test_upstream_reply_timeout() -> None:
    """A provider that never answers CONNECT still ends in 504, after the reply timeout (the idle timeout)."""
    with FakeProxy(_hold) as proxy, running(make_config(proxy.url, connect_timeout_s=0.5)) as fw:
        assert fw.forwarder._reply_timeout_s == fw.config.idle_timeout_s >= 600  # meas4-3
        fw.forwarder._reply_timeout_s = 0.5  # the config itself refuses idle timeouts below 600 s
        started = time.monotonic()
        resp = raw_exchange(fw.port, CONNECT)
        elapsed = time.monotonic() - started
        snap = wait_tunnels_closed(fw)
    assert resp.status == 504 and resp.header("X-Scrapescope-Error") == "upstream-timeout"
    assert elapsed < 5
    assert snap.target_tunnels()[0].status == "failed:upstream_timeout"


def test_slow_connect_reply_is_not_cut_at_the_connect_timeout() -> None:
    """meas4-3: a provider may hold CONNECT longer than the 30 s TCP connect timeout (scaled down here)."""

    def script(sock: socket.socket) -> None:
        time.sleep(1.5)  # three times the connect timeout below
        sock.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        data = sock.recv(65536)
        sock.sendall(b"echo:" + data)
        _hold(sock)

    with FakeProxy(script) as proxy, running(make_config(proxy.url, connect_timeout_s=0.5)) as fw:
        sock, reply, rest = open_connect(fw.port, "target.test:443")
        with sock:
            assert reply.status == 200, reply.raw
            sock.sendall(b"ping")
            assert read_until(sock, rest, b"echo:ping")
        snap = wait_tunnels_closed(fw)
    (tunnel,) = snap.target_tunnels()
    assert tunnel.status == "ok" and tunnel.upstream_status == 200


def test_early_client_bytes_during_a_slow_connect_are_relayed_in_order() -> None:
    """Bytes a client sends before the 200 are kept and relayed first, after the reply (never lost)."""

    def script(sock: socket.socket) -> None:
        time.sleep(1.0)
        sock.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        sock.settimeout(5)
        buf = b""
        while b"END" not in buf:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
        sock.sendall(b"got:" + buf)
        _hold(sock)

    with FakeProxy(script) as proxy, running(make_config(proxy.url, connect_timeout_s=0.5)) as fw:
        sock = socket.create_connection(("127.0.0.1", fw.port), timeout=10)
        with sock:
            sock.sendall(CONNECT)
            time.sleep(0.3)
            sock.sendall(b"early-")  # before the provider answered
            head, rest = read_head(sock)
            assert head.startswith(b"HTTP/1.1 200 ")
            sock.sendall(b"late-END")
            assert read_until(sock, rest, b"got:early-late-END")
        snap = wait_tunnels_closed(fw)
    (tunnel,) = snap.target_tunnels()
    assert tunnel.status == "ok"
    assert tunnel.client_bytes_received == len(b"early-late-END")


def test_half_close_after_early_bytes_during_a_slow_connect_still_gets_the_tunnel() -> None:
    """A scripted client (a pipe) may send its payload and half-close before the 200; it still gets a tunnel."""

    def script(sock: socket.socket) -> None:
        time.sleep(1.0)
        sock.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        sock.settimeout(5)
        buf = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break  # the client's half-close arrived as our EOF
            buf += chunk
        sock.sendall(b"got:" + buf)
        sock.close()

    with FakeProxy(script) as proxy, running(make_config(proxy.url, connect_timeout_s=0.5)) as fw:
        sock = socket.create_connection(("127.0.0.1", fw.port), timeout=10)
        with sock:
            sock.sendall(CONNECT)
            time.sleep(0.2)
            sock.sendall(b"payload")
            sock.shutdown(socket.SHUT_WR)
            data = read_all(sock)
        snap = wait_tunnels_closed(fw)
    assert data.startswith(b"HTTP/1.1 200 ") and data.endswith(b"got:payload"), data
    (tunnel,) = snap.target_tunnels()
    assert tunnel.status == "ok"


def test_client_that_gives_up_during_a_slow_connect_closes_the_provider_connection() -> None:
    """With a long reply wait, a client that closes must not leave the CONNECT pending at the provider."""
    closed = threading.Event()

    def script(sock: socket.socket) -> None:
        sock.settimeout(20)
        try:
            while sock.recv(65536):
                pass
        except OSError:
            pass
        closed.set()

    with FakeProxy(script) as proxy, running(make_config(proxy.url)) as fw:
        sock = socket.create_connection(("127.0.0.1", fw.port), timeout=10)
        sock.sendall(CONNECT)
        time.sleep(0.3)
        sock.close()
        assert closed.wait(5), "the meter kept the provider connection after the client left"
        snap = wait_tunnels_closed(fw)
    (tunnel,) = snap.target_tunnels()
    assert tunnel.status == "failed:client_closed"
    assert tunnel.negotiation_bytes_sent == tunnel.upstream_bytes_sent == len(proxy.heads[0])


def test_slow_socks5_connect_reply_is_not_cut_at_the_connect_timeout() -> None:
    """meas4-3: the SOCKS5 CONNECT reply waits for the provider to reach the target, like HTTP CONNECT."""

    def socks(sock: socket.socket) -> None:
        sock.settimeout(10)
        sock.recv(3)  # greeting: 05 01 00
        sock.sendall(b"\x05\x00")
        request = sock.recv(512)
        assert request[:3] == b"\x05\x01\x00"
        time.sleep(1.5)  # three times the connect timeout below
        sock.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50")
        data = sock.recv(65536)
        sock.sendall(b"echo:" + data)
        _hold(sock)

    with LocalServer(socks) as server, running(
        make_config(f"socks5://127.0.0.1:{server.port}", connect_timeout_s=0.5)
    ) as fw:
        sock, reply, rest = open_connect(fw.port, "target.test:443")
        with sock:
            assert reply.status == 200, reply.raw
            sock.sendall(b"ping")
            assert read_until(sock, rest, b"echo:ping")
        snap = wait_tunnels_closed(fw)
    (tunnel,) = snap.target_tunnels()
    assert tunnel.status == "ok" and tunnel.socks_reply == 0


def read_until(sock: socket.socket, initial: bytes, needle: bytes, timeout: float = 10.0) -> bool:
    buf = initial
    deadline = time.monotonic() + timeout
    while needle not in buf and time.monotonic() < deadline:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buf += chunk
    return needle in buf


def test_garbage_reply_is_a_protocol_error() -> None:
    def script(sock: socket.socket) -> None:
        sock.sendall(b"SSH-2.0-OpenSSH_9.9\r\n\r\n")
        _hold(sock)

    with FakeProxy(script) as proxy, running(make_config(proxy.url)) as fw:
        resp = raw_exchange(fw.port, CONNECT)
        snap = wait_tunnels_closed(fw)
    assert resp.status == 502 and resp.header("X-Scrapescope-Error") == "upstream-protocol-error"
    assert snap.target_tunnels()[0].status == "failed:upstream_protocol"


def test_chunked_error_body_relayed_verbatim() -> None:
    reply = (
        b"HTTP/1.1 407 Proxy Authentication Required\r\n"
        b'Proxy-Authenticate: Basic realm="vendor"\r\n'
        b"X-Vendor-Error: E1001 zone disabled\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n"
        b"5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-Trailer: t\r\n\r\n"
    )

    def script(sock: socket.socket) -> None:
        sock.sendall(reply)
        _hold(sock)

    with FakeProxy(script) as proxy, running(make_config(proxy.url)) as fw:
        resp = raw_exchange(fw.port, CONNECT)
        snap = wait_tunnels_closed(fw)
    assert resp.raw == reply
    (tunnel,) = snap.target_tunnels()
    assert tunnel.status == "failed:upstream_status" and tunnel.upstream_status == 407
    assert tunnel.upstream_bytes_received == len(reply)
    assert tunnel.negotiation_bytes_received == len(reply)


def test_close_delimited_error_body_relayed_verbatim() -> None:
    reply = b"HTTP/1.1 502 Bad Gateway\r\nX-Vendor-Error: E2 target unreachable\r\n\r\nupstream said no, twice"

    def script(sock: socket.socket) -> None:
        sock.sendall(reply)
        sock.close()

    with FakeProxy(script) as proxy, running(make_config(proxy.url)) as fw:
        resp = raw_exchange(fw.port, CONNECT)
        snap = wait_tunnels_closed(fw)
    assert resp.raw == reply
    assert snap.target_tunnels()[0].upstream_status == 502


def test_success_reply_with_vendor_headers_and_same_segment_payload() -> None:
    head = b"HTTP/1.1 200 Connection established\r\nX-Vendor-Session: abc123\r\nX-Vendor-Exit: fr\r\n\r\n"

    def script(sock: socket.socket) -> None:
        sock.sendall(head + b"SERVER-FIRST")  # one segment: the reply head and tunnel payload
        data = sock.recv(100)
        sock.sendall(b"echo:" + data)
        sock.shutdown(socket.SHUT_WR)
        _hold(sock)

    with FakeProxy(script) as proxy, running(make_config(proxy.url)) as fw:
        sock, reply, rest = open_connect(fw.port, "target.test:443")
        while len(rest) < len(b"SERVER-FIRST"):
            rest += sock.recv(100)
        sock.sendall(b"ping")
        tail = read_all(sock)
        sock.close()
        snap = wait_tunnels_closed(fw)
    assert reply.raw == head  # relayed verbatim, vendor headers included
    assert rest == b"SERVER-FIRST" and tail == b"echo:ping"
    (tunnel,) = snap.target_tunnels()
    assert tunnel.status == "ok" and tunnel.upstream_status == 200
    assert tunnel.negotiation_bytes_received == len(head)
    assert tunnel.payload_bytes_received == len(b"SERVER-FIRST") + len(b"echo:ping")
    assert tunnel.payload_bytes_sent == len(b"ping")
    # The CONNECT head the fake received carries exactly one injected Proxy-Authorization.
    (received,) = proxy.heads
    assert received.lower().count(b"proxy-authorization: basic ") == 1
    assert tunnel.connect_request_bytes == len(received)


def test_request_head_on_upstream_is_the_clients(fresh_world: TestWorld) -> None:
    """Header order and custom headers of the client's CONNECT survive; only auth is rewritten."""

    def script(sock: socket.socket) -> None:
        sock.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
        _hold(sock)

    with FakeProxy(script) as proxy, running(make_config(proxy.url)) as fw:
        sock = socket.create_connection(("127.0.0.1", fw.port), timeout=10)
        sock.sendall(
            b"CONNECT target.test:443 HTTP/1.1\r\nHost: target.test:443\r\nUser-Agent: curl/8\r\n"
            b"Proxy-Authorization: Basic c3MtbWU6eA==\r\nX-Session: 42\r\nProxy-Connection: Keep-Alive\r\n\r\n"
        )
        read_head(sock)
        sock.close()
        wait_tunnels_closed(fw)
    lines = proxy.heads[0].split(b"\r\n")
    assert lines[0] == b"CONNECT target.test:443 HTTP/1.1"
    names = [line.split(b":", 1)[0] for line in lines[1:] if line]
    # ss-me is not the token (none configured), so the client's own Basic value passes through in place.
    assert names == [b"Host", b"User-Agent", b"Proxy-Authorization", b"X-Session", b"Proxy-Connection"]
    assert b"Proxy-Authorization: Basic c3MtbWU6eA==" in lines


@pytest.mark.parametrize("target,atyp", [("127.0.0.1", "ipv4"), ("[::1]", "ipv6"), ("origin-a.test", "domain")])
def test_socks_address_types(fresh_world: TestWorld, target: str, atyp: str) -> None:
    port = fresh_world.origin("origin-a.test", "http").port if target == "127.0.0.1" else 80
    with running(make_config(fresh_world.socks_upstream.url)) as fw:
        sock, reply, _ = open_connect(fw.port, f"{target}:{port}")
        sock.close()
        wait_tunnels_closed(fw)
    assert reply.status == (502 if atyp == "ipv6" else 200)  # the origin listens on IPv4 only
    (record,) = fresh_world.socks_upstream.records()
    assert record.atyp == atyp


# ---------------------------------------------------------------------------- round 3 (meas3-7)
def test_plain_http_407_from_the_provider_is_a_credential_failure(fresh_world: TestWorld) -> None:
    """meas3-7: plain http:// requests answered 407 by the provider end failed:upstream_status.

    The runner's credential hint and the report's tunnel_failures then cover
    them, as they cover a CONNECT answered 407.
    """
    import http.client

    from scrapescope.runner import _tunnel_failure_warnings

    wrong = fresh_world.http_upstream.proxy_url(password="wrong-password")
    with running(make_config(wrong)) as fw:
        conn = http.client.HTTPConnection("127.0.0.1", fw.port, timeout=10)
        statuses = []
        for host in ("origin-a.test", "origin-b.test", "origin-a.test", "origin-b.test"):
            conn.request("GET", f"http://{host}/plain.html")
            resp = conn.getresponse()
            resp.read()
            statuses.append(resp.status)
        conn.close()
        connect = raw_exchange(fw.port, b"CONNECT origin-a.test:443 HTTP/1.1\r\nHost: origin-a.test:443\r\n\r\n")
        snap = wait_tunnels_closed(fw)
    assert statuses == [407] * 4 and connect.status == 407
    target = snap.target_tunnels()
    assert [(t.kind, t.status, t.upstream_status) for t in target] == [
        ("http", "failed:upstream_status", 407)
    ] * 4 + [("connect", "failed:upstream_status", 407)]
    warnings = _tunnel_failure_warnings(snap, "HTTPS_PROXY", None)
    assert len(warnings) == 1
    assert "upstream_status 407 x5" in warnings[0]
    assert "the upstream proxy answered 407: check the credentials in $HTTPS_PROXY" in warnings[0]


def test_plain_http_407_then_success_on_one_record_stays_ok(fresh_world: TestWorld) -> None:
    """A challenge answered on the same connection (407, then 200) is a working tunnel."""
    import base64
    import http.client

    upstream = fresh_world.http_upstream
    good = base64.b64encode(f"{UPSTREAM_USERNAME}:{UPSTREAM_PASSWORD}".encode()).decode()
    bad = base64.b64encode(f"{UPSTREAM_USERNAME}:wrong".encode()).decode()
    with running(make_config(upstream.server)) as fw:  # no configured credentials: the client's pass through
        conn = http.client.HTTPConnection("127.0.0.1", fw.port, timeout=10)
        statuses = []
        for creds in (bad, good):
            conn.request("GET", "http://origin-a.test/plain.html", headers={"Proxy-Authorization": f"Basic {creds}"})
            resp = conn.getresponse()
            resp.read()
            statuses.append(resp.status)
        conn.close()
        snap = wait_tunnels_closed(fw)
    assert statuses == [407, 200]
    (tunnel,) = snap.target_tunnels()
    assert (tunnel.status, tunnel.upstream_status, tunnel.requests) == ("ok", 200, 2)


def test_plain_http_407_from_an_origin_on_a_direct_route_is_not_a_proxy_failure(fresh_world: TestWorld) -> None:
    """Only the HTTP CONNECT route has a provider in front: elsewhere a 407 is the origin's answer."""

    def origin_407(sock: socket.socket) -> None:
        sock.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        sock.close()

    with LocalServer(origin_407) as server:
        cmap = dict(fresh_world.hosts_map)
        cmap[("odd.test", 80)] = ("127.0.0.1", server.port)
        with running(make_config(None), connect_map=cmap) as fw:
            resp = raw_exchange(fw.port, b"GET http://odd.test/ HTTP/1.1\r\nHost: odd.test\r\n\r\n")
            snap = wait_tunnels_closed(fw)
    assert resp.status == 407
    (tunnel,) = snap.target_tunnels()
    assert (tunnel.status, tunnel.upstream_status) == ("ok", 407)
