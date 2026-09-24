"""Shared helpers for the forwarder tests (tests/test_forwarder_*.py).

This module holds no product logic: it starts forwarders against the fixture
world, drives clients (curl, requests, httpx, raw sockets, http.client) through
them, and waits until counters are final. The few tests at the bottom check the
helpers themselves.
"""

from __future__ import annotations

import contextlib
import http.client
import shutil
import socket
import socketserver
import subprocess
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from urllib.parse import quote

import httpx
import pytest
import requests

from scrapescope.config import ForwarderConfig, HostRule, parse_upstream_url
from scrapescope.forwarder import ForwarderThread
from scrapescope.types import MeterSnapshot
from tests.fixtures import TestWorld

CLIENTS = ("curl", "requests", "httpx")


# ---------------------------------------------------------------------------- forwarders
def make_config(upstream_url: str | None = None, **kwargs: object) -> ForwarderConfig:
    """ForwarderConfig for an upstream URL (None = direct/sizing mode)."""
    upstream = parse_upstream_url(upstream_url) if upstream_url is not None else None
    return ForwarderConfig(upstream=upstream, **kwargs)  # type: ignore[arg-type]


@contextlib.contextmanager
def running(config: ForwarderConfig, connect_map: dict | None = None) -> Iterator[ForwarderThread]:
    """A started ForwarderThread, stopped on exit."""
    fw = ForwarderThread(config, connect_map=connect_map)
    fw.start()
    try:
        yield fw
    finally:
        fw.stop()


def wait_until(predicate: Callable[[], bool], timeout: float = 10.0, interval: float = 0.02) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        if predicate():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval)


def wait_tunnels_closed(fw: ForwarderThread, timeout: float = 10.0) -> MeterSnapshot:
    """Wait until the meter has no open tunnel, then return a snapshot."""
    assert wait_until(lambda: all(t.status != "open" for t in fw.snapshot().tunnels), timeout), [
        (t.id, t.host, t.status) for t in fw.snapshot().tunnels if t.status == "open"
    ]
    return fw.snapshot()


def settle(world: TestWorld, fw: ForwarderThread, timeout: float = 10.0) -> MeterSnapshot:
    """Wait for the fixture servers to go idle and the meter to close every tunnel."""
    wait_tunnels_closed(fw, timeout)
    assert world.wait_idle(timeout), "fixture servers did not go idle"
    return wait_tunnels_closed(fw, timeout)


def with_credentials(url: str, username: str | None, password: str | None) -> str:
    if username is None:
        return url
    scheme, rest = url.split("://", 1)
    userinfo = quote(username, safe="")
    if password is not None:
        userinfo += ":" + quote(password, safe="")
    return f"{scheme}://{userinfo}@{rest}"


# ---------------------------------------------------------------------------- clients
def curl(world: TestWorld, *args: str, timeout: float = 30) -> subprocess.CompletedProcess[bytes]:
    if shutil.which("curl") is None:
        pytest.skip("curl is not installed")
    env = world.subprocess_env()
    return subprocess.run(
        ["curl", "-q", "-sS", "--max-time", "20", *args], capture_output=True, env=env, timeout=timeout
    )


def fetch(
    world: TestWorld,
    client: str,
    proxy: str,
    url: str,
    *,
    username: str | None = None,
    password: str | None = None,
) -> tuple[int, bytes]:
    """GET ``url`` through the meter at ``proxy`` (http://127.0.0.1:PORT) with ``client``."""
    if client == "curl":
        args = ["--proxy", proxy]
        if username is not None:
            args += ["--proxy-user", f"{username}:{password or ''}"]
        proc = curl(world, *args, "--cacert", world.ca_pem, "-o", "-", "-w", "\n%{http_code}", url)
        if proc.returncode != 0:
            raise RuntimeError(f"curl exit {proc.returncode}")
        body, _, code = proc.stdout.rpartition(b"\n")
        return int(code), body
    proxy_url = with_credentials(proxy, username, password)
    if client == "requests":
        with requests.Session() as session:
            session.trust_env = False
            resp = session.get(url, proxies={"http": proxy_url, "https": proxy_url}, verify=world.ca_pem, timeout=20)
            return resp.status_code, resp.content
    if client == "httpx":
        assert world.tls is not None
        with httpx.Client(proxy=proxy_url, verify=world.tls.client_context(), trust_env=False, timeout=20) as c:
            resp = c.get(url)
            return resp.status_code, resp.content
    raise AssertionError(client)


@dataclass
class RawResponse:
    status: int
    reason: str
    headers: list[tuple[str, str]]
    body: bytes
    raw: bytes

    def header(self, name: str) -> str | None:
        for key, value in self.headers:
            if key.lower() == name.lower():
                return value
        return None

    def header_names(self) -> list[str]:
        return [key.lower() for key, _ in self.headers]


def parse_response(raw: bytes) -> RawResponse:
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ", 2)
    headers = []
    for line in lines[1:]:
        key, _, value = line.partition(":")
        headers.append((key.strip(), value.strip()))
    return RawResponse(int(parts[1]), parts[2] if len(parts) > 2 else "", headers, body, raw)


def read_head(sock: socket.socket) -> tuple[bytes, bytes]:
    """Read one response head; returns (head incl. blank line, bytes read after it)."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buf += chunk
    head, sep, rest = buf.partition(b"\r\n\r\n")
    return head + sep, rest


def read_all(sock: socket.socket) -> bytes:
    out = bytearray()
    while True:
        try:
            chunk = sock.recv(1 << 20)
        except (ConnectionResetError, TimeoutError):
            break
        if not chunk:
            break
        out += chunk
    return bytes(out)


def raw_exchange(port: int, data: bytes, *, timeout: float = 10.0) -> RawResponse:
    """Send ``data`` to the meter and read until it closes the connection."""
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        sock.sendall(data)
        return parse_response(read_all(sock))


def open_connect(port: int, authority: str, *, extra: str = "", timeout: float = 10.0) -> tuple[socket.socket, RawResponse, bytes]:
    """Raw CONNECT through the meter; returns (socket, reply, bytes after the reply head)."""
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    sock.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n{extra}\r\n".encode("latin-1"))
    head, rest = read_head(sock)
    return sock, parse_response(head), rest


def connect_with_retry(port: int, authority: str, *, attempts: int = 4, timeout: float = 30.0) -> tuple[socket.socket, RawResponse, bytes]:
    """:func:`open_connect` that retries when the tunnel could not be set up.

    On macOS, bursts of dozens of simultaneous loopback connects occasionally
    stall in the kernel (SYN retransmits of 1-4 s, sometimes ETIMEDOUT after
    about 7.8 s) with a plain asyncio listener too, so concurrency tests retry
    setup. A failed attempt is still counted identically by the meter and the
    fixture, so byte-equality checks stay valid.
    """
    last: BaseException | None = None
    for _ in range(attempts):
        try:
            sock, reply, rest = open_connect(port, authority, timeout=timeout)
        except OSError as exc:
            last = exc
            continue
        if reply.status == 200:
            return sock, reply, rest
        sock.close()
        last = AssertionError(f"tunnel setup failed: {reply.status} {reply.header('X-Scrapescope-Error')}")
    assert last is not None
    raise last


def http_get_in_tunnel(sock: socket.socket, host: str, path: str) -> bytes:
    """Plain HTTP/1.1 GET inside an established tunnel with Connection: close; returns the raw response."""
    sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("ascii"))
    return read_all(sock)


def meter_http(port: int, timeout: float = 20.0) -> http.client.HTTPConnection:
    """http.client connection to the meter (absolute-form URLs set Host from the URL)."""
    return http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)


# ---------------------------------------------------------------------------- tiny local servers
class LocalServer:
    """A threaded TCP server on 127.0.0.1 running ``handler(sock)`` per connection."""

    def __init__(self, handler: Callable[[socket.socket], None]) -> None:
        outer = self

        class _Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                with contextlib.suppress(OSError):
                    handler(self.request)

        class _Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True

        self._server = _Server(("127.0.0.1", 0), _Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
        self._thread.start()
        self._outer = outer

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def __enter__(self) -> LocalServer:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def connect_map_with(world: TestWorld, extra: dict[tuple[str, int], tuple[str, int]] | None = None) -> dict:
    """The world's connect map plus extra ``(host, port) -> (ip, port)`` entries."""
    mapping = dict(world.hosts_map)
    if extra:
        mapping.update(extra)
    return mapping


@dataclass
class Collected:
    """Thread-safe list for budget callbacks."""

    items: list = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def __call__(self, item: object) -> None:
        with self.lock:
            self.items.append(item)

    def snapshot(self) -> list:
        with self.lock:
            return list(self.items)


def deny(pattern: str, label: str | None = None) -> HostRule:
    return HostRule(pattern, label or f"deny-host:{pattern}")


# ---------------------------------------------------------------------------- helper self-tests
def test_parse_response_and_credentials_helper() -> None:
    resp = parse_response(b"HTTP/1.1 407 Proxy Authentication Required\r\nA: b\r\nX-Y: z\r\n\r\nbody")
    assert resp.status == 407 and resp.header("x-y") == "z" and resp.body == b"body"
    assert with_credentials("http://127.0.0.1:1", "u@x", "p:w") == "http://u%40x:p%3Aw@127.0.0.1:1"
