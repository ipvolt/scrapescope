"""The whole local test world: origins, upstream proxies, CA and hosts map.

``TestWorld.start()`` starts, on free loopback ports:
- an HTTPS origin for every name in :data:`HTTPS_HOSTS` (``badcert.test`` uses
  an untrusted certificate) and a plain HTTP origin for :data:`HTTP_HOSTS`;
- four upstream proxies: HTTP CONNECT with auth, HTTP without auth, SOCKS5 with
  RFC 1929 auth and SOCKS5 without auth.

The hosts map ``{(name, port): ("127.0.0.1", real_port)}`` is the "remote DNS"
of the upstream fixtures and, serialised by :meth:`TestWorld.connect_map_json`,
the value of ``SCRAPESCOPE_TEST_CONNECT_MAP`` for the forwarder's direct mode.
"""

from __future__ import annotations

import os
import socket
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ._aio import BackgroundLoop, wait_until
from .common import AuthPolicy, HostsMap, connect_map_json
from .origin import OriginServer
from .tls import BAD_CERT_NAME, TestCA
from .upstream_http import UpstreamHTTPProxy
from .upstream_socks import UpstreamSocks5Proxy

#: Chromium background hosts (well documented; see the README) served locally so
#: a real browser's background fetches through a fixture upstream stay on this
#: machine. Other Google hosts Chromium contacts (www.google.com,
#: accounts.google.com, ...) are deliberately NOT mapped: the upstreams refuse
#: them (502 / SOCKS 0x04), which models "uncatalogued, never background".
BACKGROUND_HOSTS: tuple[str, ...] = (
    "optimizationguide-pa.googleapis.com",
    "update.googleapis.com",
    "clients2.google.com",
    "clients2.googleusercontent.com",
    "edgedl.me.gvt1.com",
    "safebrowsing.googleapis.com",
)
HTTPS_HOSTS: tuple[str, ...] = (
    "origin-a.test",
    "origin-b.test",
    "origin-c.test",
    "api.openai.com",
    *BACKGROUND_HOSTS,
    BAD_CERT_NAME,
)
HTTP_HOSTS: tuple[str, ...] = (
    "origin-a.test",
    "origin-b.test",
    "origin-c.test",
    "api.openai.com",
    "update.googleapis.com",
    "clients2.google.com",
    "edgedl.me.gvt1.com",
)

#: Environment variables removed from subprocess environments built by the world.
PROXY_ENV_VARS: tuple[str, ...] = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "NODE_USE_ENV_PROXY",
    "SCRAPESCOPE_PROXY_URL",
    "SCRAPESCOPE_AUTH_PROXY_URL",
    "SCRAPESCOPE_EVENTS",
)


def free_port() -> int:
    """A loopback TCP port that nothing listens on (at the time of the call)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class TestWorld:
    """Starts and owns every fixture server."""

    __test__ = False  # not a pytest test class

    def __init__(self, workdir: str | os.PathLike[str] | None = None) -> None:
        self._own_workdir = workdir is None
        self.workdir = Path(workdir) if workdir is not None else Path(tempfile.mkdtemp(prefix="scrapescope-world-"))
        self.hosts_map: HostsMap = {}
        self.origins: dict[tuple[str, str], OriginServer] = {}
        self.tls: TestCA | None = None
        self.http_upstream: UpstreamHTTPProxy
        self.http_upstream_noauth: UpstreamHTTPProxy
        self.socks_upstream: UpstreamSocks5Proxy
        self.socks_upstream_noauth: UpstreamSocks5Proxy
        self._origin_loop: BackgroundLoop | None = None
        self._started = False

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> TestWorld:
        if self._started:
            return self
        self.tls = TestCA(self.workdir / "tls")
        self._origin_loop = BackgroundLoop("origins")
        for host in HTTPS_HOSTS:
            ctx = self.tls.server_context(bad=host == BAD_CERT_NAME)
            origin = OriginServer(host, "https", ctx, loop=self._origin_loop).start()
            self.origins[(host, "https")] = origin
            self.hosts_map[(host, 443)] = origin.address
        for host in HTTP_HOSTS:
            origin = OriginServer(host, "http", loop=self._origin_loop).start()
            self.origins[(host, "http")] = origin
            self.hosts_map[(host, 80)] = origin.address
        self.http_upstream = UpstreamHTTPProxy(self.hosts_map, AuthPolicy.default(), "http-upstream").start()
        self.http_upstream_noauth = UpstreamHTTPProxy(self.hosts_map, AuthPolicy.open(), "http-upstream-noauth").start()
        self.socks_upstream = UpstreamSocks5Proxy(self.hosts_map, AuthPolicy.default(), "socks-upstream").start()
        self.socks_upstream_noauth = UpstreamSocks5Proxy(self.hosts_map, AuthPolicy.open(), "socks-upstream-noauth").start()
        self._started = True
        return self

    def stop(self) -> None:
        if not self._started:
            return
        servers = [*self.upstreams, *self.origins.values()]
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda server: server.stop(), servers))
        if self._origin_loop is not None:
            self._origin_loop.stop()
        self._started = False

    def __enter__(self) -> TestWorld:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # ------------------------------------------------------------------ accessors
    @property
    def ca_pem(self) -> str:
        """Path of the fixture CA certificate (PEM)."""
        assert self.tls is not None
        return self.tls.ca_pem

    def origin(self, host: str, scheme: str = "https") -> OriginServer:
        return self.origins[(host, scheme)]

    @property
    def upstreams(self) -> list[UpstreamHTTPProxy | UpstreamSocks5Proxy]:
        return [self.http_upstream, self.http_upstream_noauth, self.socks_upstream, self.socks_upstream_noauth]

    def connect_map(self) -> dict[str, str]:
        """``{"host:port": "127.0.0.1:real_port"}`` for every fake name."""
        return {f"{h}:{p}": f"{ip}:{rp}" for (h, p), (ip, rp) in sorted(self.hosts_map.items())}

    def connect_map_json(self) -> str:
        """The ``SCRAPESCOPE_TEST_CONNECT_MAP`` value (see :func:`common.connect_map_json`)."""
        return connect_map_json(self.hosts_map)

    def chromium_args(self) -> list[str]:
        """Extra Chromium launch args that make the fixture certificate valid.

        With this SPKI allow-list, Chromium treats the fixture certificate as
        trusted (service workers need that); ``ignore_https_errors=True`` on the
        context is still recommended as a fallback.
        """
        assert self.tls is not None
        return [f"--ignore-certificate-errors-spki-list={self.tls.leaf_spki_sha256_b64()}"]

    def subprocess_env(self, extra: dict[str, str] | None = None, *, trust_ca: bool = True) -> dict[str, str]:
        """A copy of ``os.environ`` for child processes in tests.

        Removes proxy variables (so nothing inherits a real proxy), sets
        ``SCRAPESCOPE_TESTING=1``, ``SCRAPESCOPE_TEST_CONNECT_MAP`` and
        ``SCRAPESCOPE_TEST_CA``, and, with ``trust_ca``, points
        ``SSL_CERT_FILE``, ``REQUESTS_CA_BUNDLE`` and ``CURL_CA_BUNDLE`` at the
        fixture CA.
        """
        env = {k: v for k, v in os.environ.items() if k not in PROXY_ENV_VARS}
        env["SCRAPESCOPE_TESTING"] = "1"
        env["SCRAPESCOPE_TEST_CONNECT_MAP"] = self.connect_map_json()
        env["SCRAPESCOPE_TEST_CA"] = self.ca_pem
        if trust_ca:
            env["SSL_CERT_FILE"] = self.ca_pem
            env["REQUESTS_CA_BUNDLE"] = self.ca_pem
            env["CURL_CA_BUNDLE"] = self.ca_pem
        if extra:
            env.update(extra)
        return env

    # ------------------------------------------------------------------ counters
    def reset(self, wait: bool = True, timeout: float = 5.0) -> None:
        """Forget every record on every server (waiting for idle first if asked)."""
        if wait:
            self.wait_idle(timeout)
        for proxy in self.upstreams:
            proxy.reset(wait=False)
        for origin in self.origins.values():
            origin.reset(wait=False)

    def open_connections(self) -> int:
        return sum(p.open_connections() for p in self.upstreams) + sum(o.open_connections() for o in self.origins.values())

    def wait_idle(self, timeout: float = 5.0) -> bool:
        """Wait until no fixture server has an open client connection."""
        return wait_until(lambda: self.open_connections() == 0, timeout)

    def origin_totals(self) -> dict[str, dict[str, int]]:
        return {f"{scheme}://{host}": o.totals() for (host, scheme), o in self.origins.items()}

    @staticmethod
    def closed_port() -> int:
        """A loopback port with no listener, for "upstream unreachable" tests."""
        return free_port()
