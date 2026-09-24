"""Shared pytest fixtures: the local test world (see tests/fixtures/README.md).

Everything here is local: fake hostnames resolve only through the fixture
hosts map and the fixture upstreams refuse every other name. Proxy variables
inherited from the developer's shell are removed for the whole session so no
test (or child process) can pick up a real proxy by accident.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:  # pyproject sets pythonpath=["."]; this keeps direct runs working
    sys.path.insert(0, str(_ROOT))

from tests.fixtures import (  # noqa: E402
    PROXY_ENV_VARS,
    HostsMap,
    OriginServer,
    TestWorld,
    UpstreamHTTPProxy,
    UpstreamSocks5Proxy,
    free_port,
)
from tests.fixtures.browser import chromium_unavailable_reason  # noqa: E402


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "browser: needs Playwright with Chromium; skipped cleanly when unavailable")


@pytest.fixture(scope="session", autouse=True)
def _no_inherited_proxy_env() -> Iterator[None]:
    """Remove proxy and scrapescope child variables from os.environ for the session."""
    saved = {name: os.environ.pop(name) for name in PROXY_ENV_VARS if name in os.environ}
    yield
    os.environ.update(saved)


@pytest.fixture(autouse=True)
def _skip_browser_tests_without_chromium(request: pytest.FixtureRequest) -> None:
    """Skip tests marked ``browser`` when Playwright cannot launch Chromium."""
    if request.node.get_closest_marker("browser") is not None:
        reason = chromium_unavailable_reason()
        if reason is not None:
            pytest.skip(reason)


# ---------------------------------------------------------------------------- world
@pytest.fixture(scope="session")
def world(tmp_path_factory: pytest.TempPathFactory) -> Iterator[TestWorld]:
    """The running test world (session-scoped; counters shared across tests)."""
    test_world = TestWorld(tmp_path_factory.mktemp("scrapescope-world"))
    test_world.start()
    try:
        yield test_world
    finally:
        test_world.stop()


@pytest.fixture
def fresh_world(world: TestWorld) -> TestWorld:
    """The world with every counter reset (waits up to 5 s for idle first)."""
    world.reset()
    return world


@pytest.fixture(scope="session")
def ca_pem(world: TestWorld) -> str:
    """Path of the fixture CA certificate (PEM)."""
    return world.ca_pem


@pytest.fixture(scope="session")
def hosts_map(world: TestWorld) -> HostsMap:
    """{(fake host, port): ("127.0.0.1", real port)}."""
    return world.hosts_map


@pytest.fixture(scope="session")
def connect_map_json(world: TestWorld) -> str:
    """Value for SCRAPESCOPE_TEST_CONNECT_MAP: {"host:port": "ip:port"}."""
    return world.connect_map_json()


@pytest.fixture
def subprocess_env(world: TestWorld) -> dict[str, str]:
    """Environment for child processes: no proxy variables, testing hooks and CA set."""
    return world.subprocess_env()


@pytest.fixture(scope="session")
def chromium_args(world: TestWorld) -> list[str]:
    """Chromium launch args that make the fixture certificate valid (see browser.py)."""
    return world.chromium_args()


@pytest.fixture(scope="session")
def http_upstream(world: TestWorld) -> UpstreamHTTPProxy:
    """HTTP CONNECT upstream requiring Basic auth (fixture or session credentials)."""
    return world.http_upstream


@pytest.fixture(scope="session")
def http_upstream_noauth(world: TestWorld) -> UpstreamHTTPProxy:
    return world.http_upstream_noauth


@pytest.fixture(scope="session")
def socks_upstream(world: TestWorld) -> UpstreamSocks5Proxy:
    """SOCKS5 upstream requiring RFC 1929 auth."""
    return world.socks_upstream


@pytest.fixture(scope="session")
def socks_upstream_noauth(world: TestWorld) -> UpstreamSocks5Proxy:
    return world.socks_upstream_noauth


@pytest.fixture(scope="session")
def origin_a(world: TestWorld) -> OriginServer:
    """https://origin-a.test (the product shop)."""
    return world.origin("origin-a.test", "https")


@pytest.fixture
def closed_port() -> int:
    """A loopback port with nothing listening (upstream-unreachable tests)."""
    return free_port()
