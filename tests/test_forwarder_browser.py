"""Chromium through the meter: exact counts for a full page, and the auth-listener 407 flow.

Chromium sends proxy credentials only after a 407 challenge. The main listener
in run/find accepts tokenless connections (and injects configured
credentials), so per-context credentials only reach the upstream through the
auth listener, which challenges first (contracts sections 3.2 and 5.2).
"""

from __future__ import annotations

import pytest

from tests.fixtures import SESSION_PASSWORD, UPSTREAM_USERNAME, TestWorld
from tests.fixtures.browser import CONTEXT_KWARGS, PAGE_DONE_PREDICATE, chromium_launch_kwargs
from tests.test_forwarder_helpers import make_config, running, settle

pytestmark = [pytest.mark.browser, pytest.mark.timeout(120)]


def test_full_page_counts_equal_fixture(fresh_world: TestWorld) -> None:
    from playwright.sync_api import sync_playwright

    upstream = fresh_world.http_upstream
    with running(make_config(upstream.url)) as fw:
        with sync_playwright() as p:
            browser = p.chromium.launch(**chromium_launch_kwargs(fresh_world, server=fw.url))
            context = browser.new_context(**CONTEXT_KWARGS)
            page = context.new_page()
            response = page.goto("https://origin-a.test/", wait_until="load")
            assert response is not None and response.status == 200
            page.wait_for_function(PAGE_DONE_PREDICATE, timeout=30_000)
            context.close()
            browser.close()
        snap = settle(fresh_world, fw, timeout=20)
    fixture = upstream.totals()
    target = snap.target_tunnels()
    assert len(target) == fixture["connections"]
    assert sum(t.upstream_bytes_sent for t in target) == fixture["bytes_from_client"]
    assert sum(t.upstream_bytes_received for t in target) == fixture["bytes_to_client"]
    assert sum(t.negotiation_bytes_sent for t in target) == fixture["negotiation_from_client"]
    assert sum(t.negotiation_bytes_received for t in target) == fixture["negotiation_to_client"]
    hosts = {t.host for t in target}
    assert {"origin-a.test", "origin-b.test"} <= hosts
    assert all(t.auth == "injected" for t in target)
    assert {u for r in upstream.records() for u in r.usernames} == {UPSTREAM_USERNAME}
    # The meter does not change connection reuse: one upstream connection per tunnel.
    assert fixture["connections"] == len(snap.tunnels)


def test_launch_credentials_through_auth_listener(fresh_world: TestWorld) -> None:
    from playwright.sync_api import sync_playwright

    upstream = fresh_world.http_upstream
    config = make_config(upstream.proxy_url(None), auth_listener=True, token="tkn-Abcdefghijklmnopqrstu")
    with running(config) as fw:
        with sync_playwright() as p:
            kwargs = chromium_launch_kwargs(
                fresh_world, server=fw.auth_url, username="customer-ctx-session-1", password=SESSION_PASSWORD
            )
            browser = p.chromium.launch(**kwargs)
            page = browser.new_context(**CONTEXT_KWARGS).new_page()
            response = page.goto("https://origin-a.test/api/product.json")
            assert response is not None and response.status == 200
            browser.close()
        snap = settle(fresh_world, fw, timeout=20)
    assert snap.refused.get("auth_challenge", 0) >= 1
    names = {u for r in upstream.records() for u in r.usernames if u is not None}
    assert names == {"customer-ctx-session-1"}
    assert all(t.auth == "passthrough" and t.listener == "auth" for t in snap.target_tunnels())


def test_per_context_proxy_credentials(fresh_world: TestWorld) -> None:
    from playwright.sync_api import sync_playwright

    upstream = fresh_world.http_upstream
    config = make_config(upstream.proxy_url(None), auth_listener=True)
    with running(config) as fw:
        with sync_playwright() as p:
            browser = p.chromium.launch(**chromium_launch_kwargs(fresh_world, server=fw.url))
            for user in ("ctx-a-session", "ctx-b-session"):
                context = browser.new_context(
                    proxy={"server": fw.auth_url, "username": user, "password": SESSION_PASSWORD}, **CONTEXT_KWARGS
                )
                response = context.new_page().goto("https://origin-a.test/api/product.json")
                assert response is not None and response.status == 200
                context.close()
            browser.close()
        snap = settle(fresh_world, fw, timeout=20)
    names = sorted({u for r in upstream.records() for u in r.usernames if u is not None})
    assert names == ["ctx-a-session", "ctx-b-session"]
    assert {t.listener for t in snap.target_tunnels()} == {"auth"}


class _LatencyRelay:
    """A TCP relay in front of the fixture upstream that delays every chunk (a provider RTT stand-in).

    Each direction is pumped by its own thread: read a chunk, wait ``delay_s``,
    forward it. Used only to compare a browser's connection pattern with and
    without the meter when the provider is slower than loopback.
    """

    def __init__(self, target_port: int, delay_s: float) -> None:
        import socket
        import threading

        self._target = ("127.0.0.1", target_port)
        self._delay = delay_s
        self._listener = socket.create_server(("127.0.0.1", 0))
        self.port = self._listener.getsockname()[1]
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._accept = threading.Thread(target=self._serve, daemon=True)

    @property
    def server(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self) -> "_LatencyRelay":
        self._accept.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._listener.close()

    def _serve(self) -> None:
        import socket
        import threading

        while not self._stop.is_set():
            try:
                client, _ = self._listener.accept()
            except OSError:
                return
            try:
                upstream = socket.create_connection(self._target, timeout=10)
                upstream.settimeout(None)
            except OSError:
                client.close()
                continue
            for src, dst in ((client, upstream), (upstream, client)):
                t = threading.Thread(target=self._pump, args=(src, dst), daemon=True)
                t.start()
                self._threads.append(t)

    def _pump(self, src: "object", dst: "object") -> None:
        import socket
        import time

        assert isinstance(src, socket.socket) and isinstance(dst, socket.socket)
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                time.sleep(self._delay)
                dst.sendall(data)
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        finally:
            try:
                src.close()
            except OSError:
                pass


def _three_page_job(world: TestWorld, server: str) -> None:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(**chromium_launch_kwargs(world, server=server))
        context = browser.new_context(**CONTEXT_KWARGS)
        page = context.new_page()
        for path in ("/", "/product/2", "/product/3"):
            response = page.goto("https://origin-a.test" + path, wait_until="load")
            assert response is not None and response.status == 200
            page.wait_for_function(PAGE_DONE_PREDICATE, timeout=30_000)
        context.close()
        browser.close()


def _connection_pattern(world: TestWorld) -> tuple[int, int]:
    """(upstream connections, TLS handshakes at origin-a.test) since the last reset."""
    assert world.wait_idle(20), "fixture servers did not go idle"
    upstream = world.http_upstream_noauth.totals()["connections"]
    handshakes = sum(c.tls_handshakes for c in world.origin("origin-a.test").connections())
    return upstream, handshakes


@pytest.mark.timeout(240)
def test_connection_pattern_with_and_without_the_meter_under_provider_latency(fresh_world: TestWorld) -> None:
    """meas-10: the meter adds no connections of its own; its added latency may shift Chromium's scheduling.

    Chromium schedules HTTP/1.1 sockets by timing, so an extra hop can make it
    open another connection (on loopback, 7 instead of 6 upstream connections in
    5 of 8 trials). With a provider-like delay in front of the upstream, the
    meter's own latency is small against it. The meter is always 1:1 (tunnels ==
    upstream connections); the with/without difference is reported and bounded.
    """
    delay_s = 0.02
    observed: dict[str, list[tuple[int, int]]] = {"direct": [], "meter": []}
    with _LatencyRelay(fresh_world.http_upstream_noauth.port, delay_s) as relay:
        for _trial in range(2):
            fresh_world.reset()
            _three_page_job(fresh_world, relay.server)
            observed["direct"].append(_connection_pattern(fresh_world))
            fresh_world.reset()
            with running(make_config(relay.server)) as fw:
                _three_page_job(fresh_world, fw.url)
                snap = settle(fresh_world, fw, timeout=20)
            pattern = _connection_pattern(fresh_world)
            observed["meter"].append(pattern)
            # The meter itself never adds, pools or drops connections.
            assert len(snap.target_tunnels()) == pattern[0], (len(snap.target_tunnels()), pattern)
    direct_conn = min(c for c, _ in observed["direct"])
    direct_hs = min(h for _, h in observed["direct"])
    extra_conn = max(c for c, _ in observed["meter"]) - direct_conn
    extra_hs = max(h for _, h in observed["meter"]) - direct_hs
    # Tolerance: at most two extra connections and handshakes over three page loads.
    assert extra_conn <= 2 and extra_hs <= 2, observed
