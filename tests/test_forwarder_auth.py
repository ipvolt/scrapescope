"""Credential handling (contracts section 3.3): injection, pass-through, tokens, auth listener."""

from __future__ import annotations

import base64

import pytest

from scrapescope.config import token_username
from tests.fixtures import SESSION_PASSWORD, UPSTREAM_PASSWORD, UPSTREAM_USERNAME, TestWorld
from tests.test_forwarder_helpers import (
    CLIENTS,
    fetch,
    make_config,
    raw_exchange,
    running,
    settle,
)

pytestmark = pytest.mark.timeout(60)

URL = "https://origin-a.test/api/product.json"
PLAIN = "http://origin-a.test/plain.html"
TOKEN = "tok3n-Abc_123-xyz0987654"


def _usernames(world: TestWorld, kind: str) -> list[str | None]:
    if kind == "http":
        return [name for r in world.http_upstream.records() for name in r.usernames]
    return [r.username for r in world.socks_upstream.records()]


def _url(world: TestWorld, kind: str, *, with_creds: bool = True) -> str:
    upstream = world.http_upstream if kind == "http" else world.socks_upstream
    return upstream.url if with_creds else upstream.proxy_url(None)


@pytest.mark.parametrize("kind", ["http", "socks"])
@pytest.mark.parametrize("url", [URL, PLAIN], ids=["connect", "plain-http"])
def test_configured_credentials_are_injected(fresh_world: TestWorld, kind: str, url: str) -> None:
    with running(make_config(_url(fresh_world, kind))) as fw:
        assert fetch(fresh_world, "httpx", fw.url, url)[0] == 200
        snap = settle(fresh_world, fw)
    assert _usernames(fresh_world, kind) == [UPSTREAM_USERNAME]
    assert [t.auth for t in snap.target_tunnels()] == ["injected"]


@pytest.mark.parametrize("client", CLIENTS)
@pytest.mark.parametrize("kind", ["http", "socks"])
def test_session_usernames_pass_through_unchanged(fresh_world: TestWorld, client: str, kind: str) -> None:
    """Two different provider session usernames arrive at the upstream exactly as sent."""
    users = ["customer-acme-session-1111", "customer-acme-session-2222"]
    with running(make_config(_url(fresh_world, kind))) as fw:
        for user in users:
            status, _ = fetch(fresh_world, client, fw.url, URL, username=user, password=SESSION_PASSWORD)
            assert status == 200
        snap = settle(fresh_world, fw)
    assert sorted(u for u in _usernames(fresh_world, kind) if u) == users
    assert [t.auth for t in snap.target_tunnels()] == ["passthrough", "passthrough"]


@pytest.mark.parametrize("kind", ["http", "socks"])
def test_passthrough_without_configured_credentials(fresh_world: TestWorld, kind: str) -> None:
    with running(make_config(_url(fresh_world, kind, with_creds=False))) as fw:
        status, _ = fetch(fresh_world, "requests", fw.url, URL, username="sess-a", password=SESSION_PASSWORD)
        assert status == 200
        settle(fresh_world, fw)
    assert _usernames(fresh_world, kind) == ["sess-a"]


@pytest.mark.parametrize("kind", ["http", "socks"])
@pytest.mark.parametrize("url", [URL, PLAIN], ids=["connect", "plain-http"])
def test_token_username_is_stripped_and_credentials_injected(fresh_world: TestWorld, kind: str, url: str) -> None:
    config = make_config(_url(fresh_world, kind), token=TOKEN, require_token=True)
    with running(config) as fw:
        status, _ = fetch(fresh_world, "httpx", fw.url, url, username=token_username(TOKEN), password="ignored")
        assert status == 200
        snap = settle(fresh_world, fw)
    names = _usernames(fresh_world, kind)
    assert names == [UPSTREAM_USERNAME]
    assert not any(n and n.startswith("ss-") for n in names)
    assert [t.auth for t in snap.target_tunnels()] == ["injected"]


@pytest.mark.parametrize("kind", ["http", "socks"])
def test_token_mapped_upstream_user(fresh_world: TestWorld, kind: str) -> None:
    config = make_config(_url(fresh_world, kind), token=TOKEN, require_token=True)
    with running(config) as fw:
        user = token_username(TOKEN, "customer-zed-session-42")
        status, _ = fetch(fresh_world, "curl", fw.url, URL, username=user, password=SESSION_PASSWORD)
        assert status == 200
        snap = settle(fresh_world, fw)
    assert _usernames(fresh_world, kind) == ["customer-zed-session-42"]
    assert [t.auth for t in snap.target_tunnels()] == ["token-mapped"]


def test_token_required_refusals(fresh_world: TestWorld) -> None:
    config = make_config(fresh_world.http_upstream.url, token=TOKEN, require_token=True)
    with running(config) as fw:
        # No credentials at all.
        resp = raw_exchange(fw.port, b"CONNECT origin-a.test:443 HTTP/1.1\r\nHost: origin-a.test:443\r\n\r\n")
        assert resp.status == 407
        assert resp.header("Proxy-Authenticate") == 'Basic realm="scrapescope"'
        assert resp.header("X-Scrapescope-Error") == "token-required"
        assert resp.header("Connection") == "close"
        # Other credentials without the token.
        with pytest.raises(Exception):
            fetch(fresh_world, "httpx", fw.url, URL, username=UPSTREAM_USERNAME, password=UPSTREAM_PASSWORD)
        # Wrong token.
        status = None
        try:
            status, _ = fetch(fresh_world, "requests", fw.url, PLAIN, username="ss-wrong", password="x")
        except Exception:
            status = 407
        assert status == 407
        snap = fw.snapshot()
    assert snap.refused.get("token_required", 0) >= 2
    assert snap.refused.get("bad_token", 0) == 1
    assert snap.tunnels == []
    assert fresh_world.http_upstream.records() == []  # nothing reached the upstream


def test_bad_token_prefix_refused_even_when_tokenless(fresh_world: TestWorld) -> None:
    """run/find accept tokenless connections, but a wrong ss- token is still a local 407."""
    config = make_config(fresh_world.http_upstream.url, token=TOKEN, require_token=False)
    with running(config) as fw:
        resp = raw_exchange(
            fw.port,
            b"CONNECT origin-a.test:443 HTTP/1.1\r\nHost: origin-a.test:443\r\n"
            b"Proxy-Authorization: Basic c3Mtbm9wZTp4\r\n\r\n",  # ss-nope:x
        )
        assert resp.status == 407 and resp.header("X-Scrapescope-Error") == "bad-token"
        # Tokenless works in this mode.
        assert fetch(fresh_world, "httpx", fw.url, URL)[0] == 200
        snap = settle(fresh_world, fw)
    assert snap.refused == {"bad_token": 1}
    assert len(snap.target_tunnels()) == 1


def test_ss_prefix_passes_through_when_no_token_configured(fresh_world: TestWorld) -> None:
    with running(make_config(fresh_world.http_upstream.url)) as fw:
        status, _ = fetch(fresh_world, "httpx", fw.url, URL, username="ss-provider-user", password=SESSION_PASSWORD)
        assert status == 200
        settle(fresh_world, fw)
    assert _usernames(fresh_world, "http") == ["ss-provider-user"]


def test_auth_listener_challenges_then_passes_through(fresh_world: TestWorld) -> None:
    config = make_config(fresh_world.http_upstream.url, token=TOKEN, auth_listener=True)
    with running(config) as fw:
        assert fw.auth_port is not None and fw.auth_port != fw.port
        assert fw.auth_url == f"http://127.0.0.1:{fw.auth_port}"
        resp = raw_exchange(fw.auth_port, b"CONNECT origin-a.test:443 HTTP/1.1\r\nHost: origin-a.test:443\r\n\r\n")
        assert resp.status == 407
        assert resp.header("X-Scrapescope-Error") == "auth-challenge"
        assert resp.header("Proxy-Authenticate") == 'Basic realm="scrapescope"'
        status, _ = fetch(fresh_world, "httpx", fw.auth_url, URL, username="ctx-session-7", password=SESSION_PASSWORD)
        assert status == 200
        # The main listener still accepts tokenless connections and injects.
        assert fetch(fresh_world, "httpx", fw.url, URL)[0] == 200
        snap = settle(fresh_world, fw)
    assert snap.auth_port == fw.auth_port
    assert snap.refused == {"auth_challenge": 1}
    by_listener = {t.listener: t for t in snap.target_tunnels()}
    assert by_listener["auth"].auth == "passthrough"
    assert by_listener["main"].auth == "injected"
    assert sorted(_usernames(fresh_world, "http")) == sorted([UPSTREAM_USERNAME, "ctx-session-7"])


def test_non_basic_proxy_authorization(fresh_world: TestWorld) -> None:
    """HTTP upstream: passed through unchanged. SOCKS5: 502 socks-auth-unsupported."""
    request = (
        b"CONNECT origin-a.test:443 HTTP/1.1\r\nHost: origin-a.test:443\r\n"
        b"Proxy-Authorization: Bearer opaque-token-value\r\n\r\n"
    )
    with running(make_config(fresh_world.http_upstream.url)) as fw:
        resp = raw_exchange(fw.port, request)
        # The fixture does not accept Bearer: its own 407 comes back verbatim.
        assert resp.status == 407
        assert resp.header("X-Fixture-Proxy-Error") == "bad_auth"
        snap = settle(fresh_world, fw)
    (record,) = fresh_world.http_upstream.records()
    assert record.usernames == [None]  # the Bearer header arrived, not replaced by injected Basic
    assert ("Proxy-Authorization", "<redacted>") in record.request_headers[0]
    (tunnel,) = snap.target_tunnels()
    assert tunnel.auth == "passthrough" and tunnel.status == "failed:upstream_status"

    with running(make_config(fresh_world.socks_upstream.url)) as fw:
        resp = raw_exchange(fw.port, request)
        assert resp.status == 502 and resp.header("X-Scrapescope-Error") == "socks-auth-unsupported"
        snap = settle(fresh_world, fw)
    assert snap.target_tunnels()[0].status == "failed:socks_auth_unsupported"
    assert fresh_world.socks_upstream.records() == []


def test_direct_mode_drops_client_credentials(fresh_world: TestWorld) -> None:
    origin = fresh_world.origin("origin-a.test", "http")
    with running(make_config(None), connect_map=fresh_world.hosts_map) as fw:
        status, _ = fetch(fresh_world, "requests", fw.url, PLAIN, username=UPSTREAM_USERNAME, password=UPSTREAM_PASSWORD)
        assert status == 200
        snap = settle(fresh_world, fw)
    (req,) = origin.requests()
    assert req.header("Proxy-Authorization") is None
    assert req.header("Proxy-Connection") is None
    assert req.path == "/plain.html"
    assert [t.auth for t in snap.target_tunnels()] == ["none"]


def test_plain_http_proxy_authorization_rewritten_not_duplicated(fresh_world: TestWorld) -> None:
    """Token username stripped on plain HTTP: exactly one Proxy-Authorization reaches the upstream."""
    config = make_config(fresh_world.http_upstream.url, token=TOKEN)
    with running(config) as fw:
        request = (
            b"GET http://origin-a.test/plain.html HTTP/1.1\r\nHost: origin-a.test\r\n"
            b"Proxy-Authorization: Basic " + base64.b64encode(f"ss-{TOKEN}:".encode()) + b"\r\n"
            b"Connection: close\r\n\r\n"
        )
        resp = raw_exchange(fw.port, request)
        assert resp.status == 200
        snap = settle(fresh_world, fw)
    (record,) = fresh_world.http_upstream.records()
    names = [n for n, _ in record.request_headers[0]]
    assert [n.lower() for n in names].count("proxy-authorization") == 1
    assert record.usernames == [UPSTREAM_USERNAME]
    (tunnel,) = snap.target_tunnels()
    assert tunnel.requests == 1 and tunnel.proxy_authorization_bytes > 0
