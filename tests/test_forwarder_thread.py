"""ForwarderThread / Forwarder lifecycle, binding, idle timeout and relay throughput."""

from __future__ import annotations

import asyncio
import socket
import threading
import time
from collections.abc import Callable

import httpx
import pytest

from scrapescope.config import ForwarderConfig
from scrapescope.forwarder import Forwarder, ForwarderError, ForwarderThread
from scrapescope.types import BudgetEvent
from tests.fixtures import TestWorld, free_port
from tests.test_forwarder_helpers import (
    LocalServer,
    connect_map_with,
    fetch,
    make_config,
    open_connect,
    raw_exchange,
    read_all,
    running,
    settle,
    wait_until,
)

pytestmark = pytest.mark.timeout(60)


def test_start_stop_idempotent_and_final_snapshot(fresh_world: TestWorld) -> None:
    fw = ForwarderThread(make_config(fresh_world.http_upstream.url))
    fw.start()
    assert fw.url == f"http://127.0.0.1:{fw.port}" and fw.auth_port is None and fw.auth_url is None
    assert fetch(fresh_world, "httpx", fw.url, "https://origin-a.test/api/product.json")[0] == 200
    settle(fresh_world, fw)
    first = fw.stop()
    second = fw.stop()
    assert first is second and fw.snapshot() is first
    assert len(first.target_tunnels()) == 1 and first.mode == "http-connect"
    assert first.port == fw.port and first.taken_at >= first.started_at
    assert fw.error is None
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", fw.port), timeout=1).close()


def test_context_manager_and_repr_hide_upstream(fresh_world: TestWorld) -> None:
    config = make_config(fresh_world.http_upstream.url)
    with ForwarderThread(config) as fw:
        assert str(fresh_world.http_upstream.port) not in repr(fw)
        assert "sentinel" not in repr(fw) and "sentinel" not in repr(fw.forwarder)
    assert fw.snapshot().tunnels == []


def test_stop_without_start() -> None:
    fw = ForwarderThread(ForwarderConfig())
    snap = fw.stop()
    assert snap.tunnels == [] and snap.mode == "direct"


def test_port_in_use_raises_forwarder_error() -> None:
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    port = blocker.getsockname()[1]
    try:
        fw = ForwarderThread(ForwarderConfig(port=port))
        with pytest.raises(ForwarderError) as info:
            fw.start()
        assert "127.0.0.1" in str(info.value)
        fw.stop()
    finally:
        blocker.close()


def test_fixed_port_and_loopback_only_binding() -> None:
    port = free_port()
    with running(ForwarderConfig(port=port, auth_listener=True)) as fw:
        assert fw.port == port
        servers = fw.forwarder._servers
        assert len(servers) == 2
        for server in servers:
            for sock in server.sockets:
                assert sock.getsockname()[0] == "127.0.0.1"
                assert sock.family == socket.AF_INET


def test_double_start_rejected() -> None:
    fw = ForwarderThread(ForwarderConfig())
    fw.start()
    try:
        with pytest.raises(ForwarderError):
            fw.start()
    finally:
        fw.stop()


def test_stop_closes_open_tunnels_as_ok(fresh_world: TestWorld) -> None:
    fw = ForwarderThread(make_config(fresh_world.http_upstream.url))
    fw.start()
    sock, reply, _ = open_connect(fw.port, "origin-a.test:80")
    assert reply.status == 200
    assert wait_until(lambda: any(t.status == "open" for t in fw.snapshot().tunnels))
    snap = fw.stop()
    sock.settimeout(5)
    assert read_all(sock) == b""
    sock.close()
    assert [t.status for t in snap.tunnels] == ["ok"]
    assert snap.tunnels[0].closed_at is not None


def test_budget_callback_runs_on_forwarder_thread(fresh_world: TestWorld) -> None:
    seen: list[tuple[str, str]] = []

    def callback(event: BudgetEvent) -> None:
        seen.append((event.kind, threading.current_thread().name))

    config = make_config(fresh_world.http_upstream.url, budget_bytes=50_000)
    with running(config) as fw:
        fw.on_budget(callback)
        try:
            fetch(fresh_world, "httpx", fw.url, "https://origin-a.test/big.bin?size=1000000")
        except httpx.HTTPError:
            pass
        assert fw.budget_tripped.wait(5)
        settle(fresh_world, fw)
    assert [k for k, _ in seen] == ["warn_80", "tripped"]
    assert {name for _, name in seen} == {"scrapescope-forwarder"}


def test_idle_timeout_closes_quiet_tunnels(fresh_world: TestWorld) -> None:
    fw = ForwarderThread(make_config(fresh_world.http_upstream.url))
    fw.forwarder._idle_timeout_s = 0.4  # the config itself refuses anything below 600 s
    fw.forwarder._watchdog_interval_s = 0.1
    fw.start()
    try:
        sock, reply, _ = open_connect(fw.port, "origin-a.test:80")
        assert reply.status == 200
        idle = socket.create_connection(("127.0.0.1", fw.port))  # never sends a request
        sock.settimeout(5)
        assert read_all(sock) == b""
        idle.settimeout(5)
        assert read_all(idle) == b""
        sock.close()
        idle.close()
        snap = settle(fresh_world, fw)
    finally:
        fw.stop()
    assert [t.status for t in snap.tunnels] == ["ok"]


def test_connections_without_a_first_request_head_are_closed_early(fresh_world: TestWorld) -> None:
    """sec2-6: a connection that never completes a request head is closed at the first-request deadline."""
    fw = ForwarderThread(make_config(fresh_world.http_upstream.url))
    fw.forwarder._first_request_timeout_s = 0.5  # FIRST_REQUEST_TIMEOUT_S is 60 s; the idle timeout stays 600 s
    fw.forwarder._watchdog_interval_s = 0.1
    fw.start()
    try:
        sock, reply, _ = open_connect(fw.port, "origin-a.test:80")
        assert reply.status == 200
        silent = socket.create_connection(("127.0.0.1", fw.port))  # never sends anything
        dribble = socket.create_connection(("127.0.0.1", fw.port))
        dribble.sendall(b"CONNECT origin-a.test:80 HTTP/1.1\r\n")  # a head that never completes
        silent.settimeout(5)
        dribble.settimeout(5)
        started = time.monotonic()
        assert read_all(silent) == b""
        assert read_all(dribble) == b""
        assert time.monotonic() - started < 4
        # the established tunnel is still open: it delivered its request head
        sock.sendall(b"GET /plain.html HTTP/1.1\r\nHost: origin-a.test\r\nConnection: close\r\n\r\n")
        sock.settimeout(5)
        assert read_all(sock).startswith(b"HTTP/1.1 200")
        sock.close()
        silent.close()
        dribble.close()
        snap = settle(fresh_world, fw)
    finally:
        fw.stop()
    assert [t.status for t in snap.tunnels] == ["ok"]


def test_config_refuses_idle_timeout_below_ten_minutes() -> None:
    with pytest.raises(ValueError):
        ForwarderConfig(idle_timeout_s=599)


def test_forwarder_on_callers_event_loop(fresh_world: TestWorld) -> None:
    """The asyncio Forwarder can run on the caller's own loop."""

    async def main() -> tuple[int, int]:
        fw = Forwarder(make_config(None), connect_map=fresh_world.hosts_map, clock=lambda: 1_790_000_000.0)
        await fw.start()
        try:
            assert fw.url.startswith("http://127.0.0.1:")
            assert fw.budget_tripped is False
            async with httpx.AsyncClient(proxy=fw.url, verify=fresh_world.tls.client_context(), trust_env=False) as c:
                resp = await c.get("https://origin-a.test/api/product.json")
            for _ in range(200):
                if all(t.status != "open" for t in fw.snapshot().tunnels):
                    break
                await asyncio.sleep(0.02)
            snap = fw.snapshot()
            return resp.status_code, len(snap.target_tunnels())
        finally:
            await fw.stop()
            await fw.stop()

    status, tunnels = asyncio.run(main())
    assert (status, tunnels) == (200, 1)


def test_snapshot_timestamps_use_injected_clock(fresh_world: TestWorld) -> None:
    async def main():
        fw = Forwarder(make_config(None), connect_map=fresh_world.hosts_map, clock=lambda: 1_790_000_123.4)
        await fw.start()
        try:
            await asyncio.to_thread(raw_exchange, fw.port, b"CONNECT nowhere.test:1 HTTP/1.1\r\nHost: x\r\n\r\n")
            return fw.snapshot()
        finally:
            await fw.stop()

    snap = asyncio.run(main())
    assert snap.started_at == snap.taken_at == 1_790_000_123.4
    assert snap.tunnels[0].opened_at == 1_790_000_123.4


# ---------------------------------------------------------------------------- throughput
def _blaster(total: int) -> Callable[[socket.socket], None]:
    block = b"\x5a" * (1 << 20)

    def handler(sock: socket.socket) -> None:
        sent = 0
        while sent < total:
            n = min(len(block), total - sent)
            sock.sendall(block[:n])
            sent += n
        sock.shutdown(socket.SHUT_WR)
        sock.recv(1)

    return handler


def _sink(sock: socket.socket) -> None:
    total = 0
    while True:
        data = sock.recv(1 << 20)
        if not data:
            break
        total += len(data)
    sock.sendall(str(total).encode())


@pytest.mark.timeout(120)
def test_relay_throughput_at_least_50_mb_per_s(fresh_world: TestWorld) -> None:
    total = 200 * 10**6
    with LocalServer(_blaster(total)) as down, LocalServer(_sink) as up:
        cmap = connect_map_with(
            fresh_world, {("blast.test", 9000): ("127.0.0.1", down.port), ("sink.test", 9001): ("127.0.0.1", up.port)}
        )
        with running(make_config(None), connect_map=cmap) as fw:
            # Download
            sock, reply, rest = open_connect(fw.port, "blast.test:9000", timeout=30)
            assert reply.status == 200
            received = len(rest)
            start = time.perf_counter()
            buf = bytearray(1 << 20)
            while received < total:
                n = sock.recv_into(buf)
                if not n:
                    break
                received += n
            down_s = time.perf_counter() - start
            sock.close()
            # Upload
            sock, reply, _ = open_connect(fw.port, "sink.test:9001", timeout=30)
            chunk = b"\xa5" * (1 << 20)
            start = time.perf_counter()
            for _ in range(total // len(chunk)):
                sock.sendall(chunk)
            sock.shutdown(socket.SHUT_WR)
            ack = read_all(sock)
            up_s = time.perf_counter() - start
            sock.close()
            snap = settle(fresh_world, fw, timeout=30)
    assert received == total
    assert int(ack) == (total // (1 << 20)) * (1 << 20)
    down_rate = total / down_s / 1e6
    up_rate = (total // (1 << 20)) * (1 << 20) / up_s / 1e6
    assert down_rate >= 50, f"download relay {down_rate:.0f} MB/s"
    assert up_rate >= 50, f"upload relay {up_rate:.0f} MB/s"
    first, second = snap.target_tunnels()
    assert first.upstream_bytes_received == total
    assert second.upstream_bytes_sent == int(ack)


def test_upstream_pointing_at_the_meter_itself_is_refused() -> None:
    port = free_port()
    config = make_config(f"http://sentinel-user:sentinel-pass@127.0.0.1:{port}", port=port)
    fw = ForwarderThread(config)
    with pytest.raises(ForwarderError) as info:
        fw.start()
    assert "sentinel" not in str(info.value)
    fw.stop()
    # The port was released.
    with running(ForwarderConfig(port=port)) as again:
        assert again.port == port
