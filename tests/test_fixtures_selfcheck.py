"""Self-check of the local test world (tests/fixtures).

Proves that real clients (curl, requests, httpx, Playwright Chromium) reach the
fake origins through both fixture upstreams, that wrong credentials fail the
way a provider's would, and that the byte counters are non-zero and agree with
each other. Nothing here touches the internet or imports scrapescope.
"""

from __future__ import annotations

import base64
import gzip
import json
import shutil
import socket
import struct
import subprocess
import time

import httpx
import pytest
import requests

from tests.fixtures import (
    BACKGROUND_HOSTS,
    CONNECT_OK,
    HTTP_HOSTS,
    HTTPS_HOSTS,
    SESSION_PASSWORD,
    UPSTREAM_PASSWORD,
    UPSTREAM_USERNAME,
    VENDOR_ERROR_HEADER,
    TestWorld,
    site,
)
from tests.fixtures.browser import CONTEXT_KWARGS, PAGE_DONE_PREDICATE, chromium_launch_kwargs, chromium_unavailable_reason
from tests.fixtures.upstream_socks import REP_HOST_UNREACHABLE

PRODUCT_URL = "https://origin-a.test/api/product.json"
CLIENTS = ("curl", "requests", "httpx")
KINDS = ("http", "socks")

pytestmark = pytest.mark.timeout(60)


# ---------------------------------------------------------------------------- client helpers
def _curl(world: TestWorld, *args: str) -> subprocess.CompletedProcess[bytes]:
    if shutil.which("curl") is None:
        pytest.skip("curl is not installed")
    return subprocess.run(
        ["curl", "-q", "-sS", "--max-time", "20", *args],
        capture_output=True,
        env=world.subprocess_env(),
        timeout=30,
    )


def fetch(
    world: TestWorld,
    client: str,
    kind: str,
    url: str = PRODUCT_URL,
    *,
    username: str = UPSTREAM_USERNAME,
    password: str = UPSTREAM_PASSWORD,
) -> tuple[int, bytes]:
    """GET ``url`` with ``client`` through the authenticated ``kind`` upstream."""
    if client == "curl":
        if kind == "http":
            proxy = world.http_upstream.server
        else:
            proxy = f"socks5h://127.0.0.1:{world.socks_upstream.port}"
        proc = _curl(
            world,
            "--proxy", proxy,
            "--proxy-user", f"{username}:{password}",
            "--cacert", world.ca_pem,
            "-o", "-", "-w", "\n%{http_code}",
            url,
        )  # fmt: skip
        if proc.returncode != 0:
            raise RuntimeError(f"curl exit {proc.returncode}: {proc.stderr.decode(errors='replace')[:300]}")
        body, _, code = proc.stdout.rpartition(b"\n")
        return int(code), body
    if client == "requests":
        if kind == "http":
            proxy_url = world.http_upstream.proxy_url(username, password)
        else:
            proxy_url = world.socks_upstream.proxy_url(username, password, scheme="socks5h")
        with requests.Session() as session:
            session.trust_env = False
            resp = session.get(url, proxies={"http": proxy_url, "https": proxy_url}, verify=world.ca_pem, timeout=20)
            return resp.status_code, resp.content
    if client == "httpx":
        if kind == "http":
            proxy_url = world.http_upstream.proxy_url(username, password)
        else:
            proxy_url = world.socks_upstream.proxy_url(username, password)
        assert world.tls is not None
        with httpx.Client(proxy=proxy_url, verify=world.tls.client_context(), trust_env=False, timeout=20) as client_:
            resp = client_.get(url)
            return resp.status_code, resp.content
    raise AssertionError(client)


def _raw_proxy_exchange(port: int, data: bytes, *, read_until_close: bool = False) -> bytes:
    """Send raw bytes to a local proxy and read one response head (+ small body)."""
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        sock.sendall(data)
        return _read_response(sock, read_until_close=read_until_close)


def _read_response(sock: socket.socket, *, read_until_close: bool = False) -> bytes:
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            return buf
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value.strip())
    while len(rest) < length or read_until_close:
        chunk = sock.recv(65536)
        if not chunk:
            break
        rest += chunk
    return head + b"\r\n\r\n" + rest


def _basic(username: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()


def _assert_counters_consistent(world: TestWorld, kind: str, rec, host: str = "origin-a.test") -> None:  # noqa: ANN001
    """Upstream and origin agree byte for byte on one tunnel."""
    origin = world.origin(host)
    conns = origin.connections()
    assert len(conns) == 1, conns
    conn = conns[0]
    assert rec.closed and conn.closed
    assert rec.tunnel_established
    assert rec.bytes_from_client > rec.negotiation_from_client > 0
    assert rec.bytes_to_client > rec.negotiation_to_client > 0
    # Everything after negotiation is carried verbatim to and from the origin.
    assert rec.payload_from_client == rec.bytes_to_origin == conn.bytes_in > 0
    assert rec.payload_to_client == rec.bytes_from_origin == conn.bytes_out > 0
    assert conn.tls_handshakes == 1 and conn.tls_failures == 0
    assert conn.sni == host
    if kind == "http":
        assert rec.negotiation_to_client == len(CONNECT_OK)
        assert rec.kind == "connect" and rec.target == f"{host}:443"
    else:
        assert rec.atyp == "domain"
        assert rec.target == f"{host}:443"
        assert rec.negotiation_to_client == 2 + 2 + 10
        expected_from = (
            2 + len(rec.methods_offered)
            + 3 + len(rec.username.encode()) + len(UPSTREAM_PASSWORD.encode())
            + 4 + 1 + len(host) + 2
        )  # fmt: skip
        assert rec.negotiation_from_client == expected_from


def _records(world: TestWorld, kind: str) -> list:
    return world.http_upstream.records() if kind == "http" else world.socks_upstream.records()


# ---------------------------------------------------------------------------- world basics
def test_hosts_map_and_connect_map(world: TestWorld) -> None:
    for host in HTTPS_HOSTS:
        assert (host, 443) in world.hosts_map
    for host in HTTP_HOSTS:
        assert (host, 80) in world.hosts_map
    cmap = json.loads(world.connect_map_json())
    assert cmap["origin-a.test:443"] == f"127.0.0.1:{world.origin('origin-a.test').port}"
    assert cmap["origin-a.test:80"] == f"127.0.0.1:{world.origin('origin-a.test', 'http').port}"
    for value in cmap.values():
        ip, port = value.rsplit(":", 1)
        socket.create_connection((ip, int(port)), timeout=5).close()
    env = world.subprocess_env()
    assert env["SCRAPESCOPE_TESTING"] == "1"
    assert json.loads(env["SCRAPESCOPE_TEST_CONNECT_MAP"]) == cmap
    assert "HTTPS_PROXY" not in env and "https_proxy" not in env


def test_direct_tls_via_connect_map(fresh_world: TestWorld) -> None:
    """Direct mode's view: dial the mapped address, SNI = the fake hostname."""
    assert fresh_world.tls is not None
    ip, port = fresh_world.hosts_map[("origin-a.test", 443)]
    ctx = fresh_world.tls.client_context()
    with socket.create_connection((ip, port), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname="origin-a.test") as tls:
            tls.sendall(b"GET /api/product.json HTTP/1.1\r\nHost: origin-a.test\r\nConnection: close\r\n\r\n")
            data = _read_response(tls, read_until_close=True)
    assert data.startswith(b"HTTP/1.1 200")
    assert site.PRODUCT_PRICE.encode() in data
    fresh_world.wait_idle()
    (conn,) = fresh_world.origin("origin-a.test").connections()
    assert conn.sni == "origin-a.test" and conn.tls_handshakes == 1
    assert conn.bytes_in > 0 and conn.bytes_out > len(site.PRODUCT_JSON)


# ---------------------------------------------------------------------------- clients x upstreams
@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("client", CLIENTS)
def test_client_reaches_origin_through_upstream(fresh_world: TestWorld, client: str, kind: str) -> None:
    status, body = fetch(fresh_world, client, kind)
    assert status == 200
    data = json.loads(body)
    assert data["name"] == site.PRODUCT_NAME and data["price"] == site.PRODUCT_PRICE
    assert fresh_world.wait_idle(10)
    (rec,) = _records(fresh_world, kind)
    assert rec.username == UPSTREAM_USERNAME
    _assert_counters_consistent(fresh_world, kind, rec)
    (req,) = fresh_world.origin("origin-a.test").requests()
    assert req.path == "/api/product.json" and req.status == 200
    assert req.header("Host") == "origin-a.test"


@pytest.mark.parametrize("client", CLIENTS)
def test_wrong_password_gets_407(fresh_world: TestWorld, client: str) -> None:
    with pytest.raises(Exception) as excinfo:
        status, _ = fetch(fresh_world, client, "http", password="wrong-password")
        raise AssertionError(f"unexpected success with status {status}")
    assert not isinstance(excinfo.value, AssertionError), excinfo.value
    assert fresh_world.wait_idle(10)
    recs = fresh_world.http_upstream.records()
    assert recs and all(r.statuses and set(r.statuses) == {407} for r in recs)
    assert all(r.errors[0] == "bad_auth" and not r.tunnel_established for r in recs)
    assert all(r.usernames[0] == UPSTREAM_USERNAME for r in recs)
    assert fresh_world.origin("origin-a.test").connections() == []


@pytest.mark.parametrize("client", CLIENTS)
def test_socks_auth_failure(fresh_world: TestWorld, client: str) -> None:
    with pytest.raises(Exception) as excinfo:
        status, _ = fetch(fresh_world, client, "socks", password="wrong-password")
        raise AssertionError(f"unexpected success with status {status}")
    assert not isinstance(excinfo.value, AssertionError), excinfo.value
    assert fresh_world.wait_idle(10)
    recs = fresh_world.socks_upstream.records()
    assert recs and all(r.auth_ok is False and r.error == "auth_failed" for r in recs)
    assert all(r.auth_reply_bytes == 2 and not r.tunnel_established for r in recs)
    assert fresh_world.origin("origin-a.test").connections() == []


def test_407_challenge_then_retry_on_same_connection(fresh_world: TestWorld) -> None:
    """Chromium's pattern: CONNECT without credentials, 407, CONNECT again on the same socket."""
    port = fresh_world.http_upstream.port
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        sock.sendall(b"CONNECT origin-a.test:443 HTTP/1.1\r\nHost: origin-a.test:443\r\n\r\n")
        first = _read_response(sock)
        head = first.split(b"\r\n\r\n")[0].decode()
        assert head.startswith("HTTP/1.1 407 ")
        assert 'Proxy-Authenticate: Basic realm="fixture-upstream"' in head
        assert f"{VENDOR_ERROR_HEADER}: auth_required" in head
        auth = _basic(UPSTREAM_USERNAME, UPSTREAM_PASSWORD)
        sock.sendall(f"CONNECT origin-a.test:443 HTTP/1.1\r\nHost: origin-a.test:443\r\nProxy-Authorization: {auth}\r\n\r\n".encode())
        second = sock.recv(len(CONNECT_OK))
        assert second == CONNECT_OK
    assert fresh_world.wait_idle(10)
    (rec,) = fresh_world.http_upstream.records()
    assert rec.statuses == [407, 200]
    assert rec.usernames == [None, UPSTREAM_USERNAME]
    assert rec.negotiation_to_client == len(first) + len(CONNECT_OK)
    assert all(v == "<redacted>" for h in rec.request_headers for n, v in h if n.lower() == "proxy-authorization")


def test_unknown_host_gets_502_with_vendor_header(fresh_world: TestWorld) -> None:
    auth = _basic(UPSTREAM_USERNAME, UPSTREAM_PASSWORD)
    resp = _raw_proxy_exchange(
        fresh_world.http_upstream.port,
        f"CONNECT no-such-host.test:443 HTTP/1.1\r\nHost: no-such-host.test:443\r\nProxy-Authorization: {auth}\r\n\r\n".encode(),
    )
    head = resp.split(b"\r\n\r\n")[0].decode()
    assert head.startswith("HTTP/1.1 502 ")
    assert f"{VENDOR_ERROR_HEADER}: host_unknown" in head
    assert fresh_world.wait_idle(10)
    (rec,) = fresh_world.http_upstream.records()
    assert rec.errors == ["host_unknown"] and rec.target == "no-such-host.test:443"


def test_socks_unknown_host_is_unreachable(fresh_world: TestWorld) -> None:
    with pytest.raises(httpx.ProxyError):
        with httpx.Client(proxy=fresh_world.socks_upstream.url, trust_env=False, timeout=10) as client:
            client.get("https://no-such-host.test/")
    assert fresh_world.wait_idle(10)
    (rec,) = fresh_world.socks_upstream.records()
    assert rec.reply_code == REP_HOST_UNREACHABLE and rec.atyp == "domain" and rec.target == "no-such-host.test:443"


def test_session_usernames_pass_through(fresh_world: TestWorld) -> None:
    """Any username is accepted with SESSION_PASSWORD; usernames are recorded unchanged."""
    names = ["customer-a-session-1", "customer-a-session-2"]
    for name in names:
        status, _ = fetch(fresh_world, "httpx", "http", username=name, password=SESSION_PASSWORD)
        assert status == 200
        status, _ = fetch(fresh_world, "httpx", "socks", username=name, password=SESSION_PASSWORD)
        assert status == 200
    assert fresh_world.wait_idle(10)
    assert [r.username for r in fresh_world.http_upstream.records()] == names
    assert [r.username for r in fresh_world.socks_upstream.records()] == names


def test_noauth_upstreams(fresh_world: TestWorld) -> None:
    assert fresh_world.tls is not None
    for proxy in (fresh_world.http_upstream_noauth.url, fresh_world.socks_upstream_noauth.url):
        with httpx.Client(proxy=proxy, verify=fresh_world.tls.client_context(), trust_env=False, timeout=10) as client:
            assert client.get(PRODUCT_URL).status_code == 200
    assert fresh_world.wait_idle(10)
    (http_rec,) = fresh_world.http_upstream_noauth.records()
    (socks_rec,) = fresh_world.socks_upstream_noauth.records()
    assert http_rec.usernames == [None] and http_rec.statuses == [200]
    assert socks_rec.method_selected == 0 and socks_rec.username is None and socks_rec.tunnel_established


def test_plain_http_absolute_form_keep_alive(fresh_world: TestWorld) -> None:
    """Two plain-HTTP requests on one client connection -> one upstream record."""
    proxy = fresh_world.http_upstream.url

    def run() -> tuple[tuple[int, str], tuple[int, int], tuple[int, bytes]]:
        # Response objects keep requests' socket open (via makefile references)
        # until they are garbage collected, so only plain values leave here.
        with requests.Session() as session:
            session.trust_env = False
            first = session.get("http://origin-a.test/plain.html", proxies={"http": proxy})
            second = session.post("http://origin-a.test/echo", data=b"x" * 3000, proxies={"http": proxy})
            head = session.head("http://origin-a.test/plain.html", proxies={"http": proxy})
            return (first.status_code, first.text), (second.status_code, second.json()["body_bytes"]), (head.status_code, head.content)

    (first_status, first_text), (second_status, echoed), (head_status, head_body) = run()
    assert first_status == 200 and site.PRODUCT_PRICE in first_text
    assert second_status == 200 and echoed == 3000
    assert head_status == 200 and head_body == b""
    assert fresh_world.wait_idle(10)
    (rec,) = fresh_world.http_upstream.records()
    assert rec.kind == "http" and rec.methods == ["GET", "POST", "HEAD"]
    assert rec.statuses == [200, 200, 200] and rec.origin_connections == 1
    assert rec.negotiation_from_client == 0 and rec.negotiation_to_client == 0
    (conn,) = fresh_world.origin("origin-a.test", "http").connections()
    assert [r.method for r in conn.requests] == ["GET", "POST", "HEAD"]
    assert conn.bytes_in == rec.bytes_to_origin and conn.bytes_out == rec.bytes_from_origin


def test_absolute_https_and_origin_form_are_rejected(fresh_world: TestWorld) -> None:
    auth = _basic(UPSTREAM_USERNAME, UPSTREAM_PASSWORD)
    port = fresh_world.http_upstream.port
    https_abs = _raw_proxy_exchange(
        port, f"GET https://origin-a.test/ HTTP/1.1\r\nHost: origin-a.test\r\nProxy-Authorization: {auth}\r\n\r\n".encode()
    )
    assert https_abs.startswith(b"HTTP/1.1 400 ")
    origin_form = _raw_proxy_exchange(port, f"GET / HTTP/1.1\r\nHost: origin-a.test\r\nProxy-Authorization: {auth}\r\n\r\n".encode())
    assert origin_form.startswith(b"HTTP/1.1 400 ")


def test_tls_error_on_untrusted_certificate(fresh_world: TestWorld) -> None:
    assert fresh_world.tls is not None
    with pytest.raises(httpx.ConnectError):
        with httpx.Client(proxy=fresh_world.http_upstream.url, verify=fresh_world.tls.client_context(), trust_env=False) as c:
            c.get("https://badcert.test/")
    assert fresh_world.wait_idle(10)
    (conn,) = fresh_world.origin("badcert.test").connections()
    assert conn.tls_failures == 1 and conn.tls_handshakes == 0


# ---------------------------------------------------------------------------- site content
@pytest.fixture
def https_client(world: TestWorld):  # noqa: ANN201
    assert world.tls is not None
    with httpx.Client(proxy=world.http_upstream.url, verify=world.tls.client_context(), trust_env=False, timeout=20) as client:
        yield client


def test_site_assets_are_deterministic_and_sized(https_client: httpx.Client) -> None:
    for path in site.IMAGES:
        first = https_client.get(f"https://origin-a.test{path}")
        second = https_client.get(f"https://origin-a.test{path}")
        assert first.status_code == 200 and first.headers["content-type"] == "image/png"
        assert first.content == second.content and first.content.startswith(b"\x89PNG\r\n\x1a\n")
        assert 150_000 <= len(first.content) <= 250_000, (path, len(first.content))
        assert "content-encoding" not in first.headers
        width, height = struct.unpack(">II", first.content[16:24])
        assert (width, height) == site.IMAGES[path][:2]
    font = https_client.get("https://origin-a.test/static/font.woff2")
    assert font.headers["content-type"] == "font/woff2" and 40_000 <= len(font.content) <= 60_000
    css = https_client.get("https://origin-a.test/static/style.css")
    assert "@font-face" in css.text and site.FONT_PATH in css.text


def test_gzip_only_when_accepted(https_client: httpx.Client) -> None:
    gz = https_client.get(PRODUCT_URL, headers={"Accept-Encoding": "gzip"})
    assert gz.headers["content-encoding"] == "gzip" and gz.json()["price"] == site.PRODUCT_PRICE
    plain = https_client.get(PRODUCT_URL, headers={"Accept-Encoding": "identity"})
    assert "content-encoding" not in plain.headers and plain.content == site.PRODUCT_JSON
    assert gzip.decompress(site.gzip_body(site.PRODUCT_JSON)) == site.PRODUCT_JSON


def test_product_page_markup(https_client: httpx.Client) -> None:
    resp = https_client.get("https://origin-a.test/")
    html = resp.text
    assert resp.headers["content-encoding"] == "gzip"
    for needle in (
        '<link rel="preconnect" href="https://origin-c.test">',
        'application/ld+json',
        f'"name":"{site.PRODUCT_NAME}"',
        '__NEXT_DATA__',
        site.NEXT_DATA_MARKER,
        site.PRICE_NNBSP_TEXT,
        'https://origin-b.test/embed',
        '/static/app.js',
        '<span class="int">129</span>.<span class="dec">99</span>',
    ):
        assert needle in html, needle
    assert site.PRODUCT_PRICE not in html  # only variants in the document; exact value comes from the API
    cookie = resp.headers["set-cookie"]
    assert cookie.startswith(f"{site.SESSION_COOKIE_NAME}=") and "Path=/api/session-product.json" in cookie


def test_session_and_token_endpoints(https_client: httpx.Client) -> None:
    assert https_client.get("https://origin-a.test/api/session-product.json").status_code == 401
    cookie = {"Cookie": f"{site.SESSION_COOKIE_NAME}={site.SESSION_COOKIE_VALUE}"}
    ok = https_client.get("https://origin-a.test/api/session-product.json", headers=cookie)
    assert ok.status_code == 200 and ok.json()["price"] == site.PRODUCT_PRICE
    assert https_client.get("https://origin-a.test/api/offer.json").status_code == 403
    offer = https_client.get(f"https://origin-a.test/api/offer.json?sig={site.SIGNED_QUERY_TOKEN}")
    assert offer.json()["price"] == site.PRODUCT_PRICE
    beacon = https_client.post("https://origin-a.test/api/collect", json={"event": "view"})
    assert beacon.json() == {"ok": True, "seq": site.BEACON_SEQ}


def test_challenge_pages(https_client: httpx.Client) -> None:
    cf = https_client.get("https://origin-a.test/challenge-cf")
    assert cf.status_code == 403 and cf.headers["cf-mitigated"] == "challenge"
    assert "Just a moment..." in cf.text and "/cdn-cgi/challenge-platform/" in cf.text
    assert cf.headers["server"] == "cloudflare"
    aws = https_client.get("https://origin-a.test/challenge-aws")
    assert aws.status_code == 202 and aws.headers["x-amzn-waf-action"] == "challenge"
    captcha = https_client.get("https://origin-a.test/challenge-aws-captcha")
    assert captcha.status_code == 405 and captcha.headers["x-amzn-waf-action"] == "captcha"


def test_big_bin_and_openai(fresh_world: TestWorld, https_client: httpx.Client) -> None:
    size = 300_000
    resp = https_client.get(f"https://origin-a.test/big.bin?size={size}")
    assert resp.status_code == 200 and len(resp.content) == size
    assert resp.content[:1000] == site.big_bytes(0, 1000)
    models = https_client.get("https://api.openai.com/v1/models")
    assert models.json()["object"] == "list"
    https_client.close()
    assert fresh_world.wait_idle(10)
    (big_conn,) = fresh_world.origin("origin-a.test").connections()
    assert big_conn.bytes_out > size
    assert fresh_world.origin("api.openai.com").requests()[0].path == "/v1/models"
    for host in BACKGROUND_HOSTS:
        assert (host, 443) in fresh_world.hosts_map


def test_big_bin_stall_after_sends_exactly_that_much_then_waits_for_the_client(fresh_world: TestWorld) -> None:
    """``stall_after=S``: S body bytes arrive, nothing more until the client closes, and the origin records S."""
    ip, port = fresh_world.hosts_map[("origin-a.test", 80)]
    size, stall_after = 500_000, 150_000
    with socket.create_connection((ip, port), timeout=10) as sock:
        sock.sendall(f"GET /big.bin?size={size}&stall_after={stall_after} HTTP/1.1\r\nHost: origin-a.test\r\n\r\n".encode())
        data = b""
        while b"\r\n\r\n" not in data or len(data) - data.index(b"\r\n\r\n") - 4 < stall_after:
            chunk = sock.recv(65536)
            assert chunk, "the origin closed before sending stall_after bytes"
            data += chunk
        head, _, body = data.partition(b"\r\n\r\n")
        assert f"Content-Length: {size}".encode() in head
        assert body == b"".join(site.big_stream(stall_after))  # exactly stall_after bytes, the stream's own
        sock.settimeout(1.0)
        with pytest.raises(TimeoutError):  # the origin stalls: not one byte more while the client stays
            sock.recv(1)
    assert fresh_world.wait_idle(10)  # the client's close ends the stall and the connection
    origin = fresh_world.origin("origin-a.test", "http")
    (record,) = origin.requests()
    assert record.path == "/big.bin" and record.response_body_bytes == stall_after
    (conn,) = origin.connections()
    assert conn.closed and conn.bytes_out >= stall_after
    ip, port = fresh_world.hosts_map[("origin-a.test", 80)]
    assert requests.get(f"http://{ip}:{port}/big.bin?size=10&stall_after=10", headers={"Host": "origin-a.test"},
                        timeout=10).status_code == 400  # stall_after must leave something unsent


def test_http_origin_edge_cases(world: TestWorld) -> None:
    """Chunked, close-delimited, ETag/304 and Expect: 100-continue on the plain origin."""
    ip, port = world.hosts_map[("origin-a.test", 80)]
    with socket.create_connection((ip, port), timeout=10) as sock:
        sock.sendall(b"GET /chunked?n=3&size=10 HTTP/1.1\r\nHost: origin-a.test\r\n\r\n")
        data = b""
        while not data.endswith(b"0\r\n\r\n"):
            data += sock.recv(65536)
        head, _, body = data.partition(b"\r\n\r\n")
        assert b"Transfer-Encoding: chunked" in head
        sizes = []
        while True:
            line, _, body = body.partition(b"\r\n")
            size = int(line, 16)
            sizes.append(size)
            if size == 0:
                break
            body = body[size + 2 :]
        assert sizes == [10, 10, 10, 0]
        sock.sendall(b"POST /echo HTTP/1.1\r\nHost: origin-a.test\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n")
        interim = sock.recv(65536)
        assert interim.startswith(b"HTTP/1.1 100 Continue")
        sock.sendall(b"hello")
        final = _read_response(sock)
        assert b'"body_bytes":5' in final
    with socket.create_connection((ip, port), timeout=10) as sock:
        sock.sendall(b"GET /close-delimited?size=1234 HTTP/1.1\r\nHost: origin-a.test\r\n\r\n")
        data = _read_response(sock, read_until_close=True)
        head, _, body = data.partition(b"\r\n\r\n")
        assert b"Content-Length" not in head and b"Connection: close" in head and len(body) == 1234
    with httpx.Client(trust_env=False) as client:
        first = client.get(f"http://{ip}:{port}/static/app.js", headers={"Host": "origin-a.test"})
        etag = first.headers["etag"]
        again = client.get(f"http://{ip}:{port}/static/app.js", headers={"Host": "origin-a.test", "If-None-Match": etag})
        assert again.status_code == 304 and again.content == b""


def test_hostile_page_paths(https_client: httpx.Client) -> None:
    page = https_client.get("https://origin-a.test/hostile").text
    for path in site.HOSTILE_PATHS:
        assert path in page
        assert https_client.get(f"https://origin-a.test{path}").status_code == 200


# ---------------------------------------------------------------------------- browser
@pytest.mark.browser
@pytest.mark.timeout(120)
def test_chromium_loads_page_with_worker_sw_and_iframe(fresh_world: TestWorld) -> None:
    from playwright.sync_api import sync_playwright

    kwargs = chromium_launch_kwargs(
        fresh_world, server=fresh_world.http_upstream.server, username=UPSTREAM_USERNAME, password=UPSTREAM_PASSWORD
    )
    with sync_playwright() as p:
        browser = p.chromium.launch(**kwargs)
        try:
            context = browser.new_context(**CONTEXT_KWARGS)
            page = context.new_page()
            page.goto("https://origin-a.test/", wait_until="load")
            page.wait_for_function(PAGE_DONE_PREDICATE, timeout=30_000)
            state = page.evaluate("window.__fixture")
            price_text = page.inner_text("#price")
            frame_texts = [f.content() for f in page.frames if f.url.startswith("https://origin-b.test/")]
            context.close()
        finally:
            browser.close()

    assert state["price"] == site.PRODUCT_PRICE and price_text == f"{site.PRODUCT_PRICE} {site.PRODUCT_CURRENCY}"
    assert state["session"] == site.PRODUCT_PRICE  # the page's cookie reached the session endpoint
    assert state["offer"] == site.PRODUCT_PRICE and state["beacon"] == site.BEACON_SEQ
    assert state["worker"] == site.WORKER_MARKER
    assert state["sw"] == f"{site.SW_MARKER}:service-worker"
    assert any(site.EMBED_MARKER in text for text in frame_texts)

    assert fresh_world.wait_idle(15)
    a_paths = fresh_world.origin("origin-a.test").paths()
    for path in (
        "/",
        "/static/app.js",
        "/static/style.css",
        site.FONT_PATH,
        *site.IMAGES,
        "/api/product.json",
        "/static/worker.js",
        "/api/worker.json",
        "/sw.js",
        "/api/sw-backend.json",
    ):
        assert path in a_paths, path
    assert "/api/sw.json" not in a_paths  # served by the service worker, never by the network
    session_req = next(r for r in fresh_world.origin("origin-a.test").requests() if r.path == "/api/session-product.json")
    assert site.SESSION_COOKIE_VALUE in (session_req.header("Cookie") or "")
    product_req = next(r for r in fresh_world.origin("origin-a.test").requests() if r.path == "/api/product.json")
    assert product_req.header("Cookie") is None  # the cookie is path-scoped
    assert set(fresh_world.origin("origin-b.test").paths()) >= {"/embed", site.EMBED_IMAGE}

    recs = fresh_world.http_upstream.records()
    assert recs and {r.target for r in recs} >= {"origin-a.test:443", "origin-b.test:443"}
    assert {r.username for r in recs} == {UPSTREAM_USERNAME}
    assert any(r.statuses[:2] == [407, 200] for r in recs)  # Chromium answers the challenge on the same socket
    upstream_payload = sum(r.payload_to_client for r in recs if r.target and r.target.startswith("origin-"))
    origin_out = sum(
        c.bytes_out for host in ("origin-a.test", "origin-b.test", "origin-c.test") for c in fresh_world.origin(host).connections()
    )
    assert upstream_payload == origin_out > 3 * 150_000


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_full_chromium_idle_preconnect(fresh_world: TestWorld) -> None:
    """The preconnect hint opens an idle tunnel (full Chromium build, persistent context)."""
    reason = chromium_unavailable_reason(full_chromium=True)
    if reason is not None:
        pytest.skip(reason)
    from playwright.sync_api import sync_playwright

    kwargs = chromium_launch_kwargs(fresh_world, server=fresh_world.http_upstream_noauth.server, full_chromium=True)
    user_data_dir = fresh_world.workdir / f"chromium-profile-{time.monotonic_ns()}"
    with sync_playwright() as p:
        context = p.chromium.launch_persistent_context(str(user_data_dir), **kwargs, **CONTEXT_KWARGS)
        try:
            page = context.new_page()
            page.goto("https://origin-a.test/", wait_until="load")
            page.wait_for_function(PAGE_DONE_PREDICATE, timeout=30_000)
            origin_c = fresh_world.origin("origin-c.test")
            deadline = time.monotonic() + 10
            while not origin_c.connections() and time.monotonic() < deadline:
                time.sleep(0.1)
        finally:
            context.close()
    assert fresh_world.wait_idle(15)
    conns = fresh_world.origin("origin-c.test").connections()
    assert conns, "no preconnect to origin-c.test"
    assert all(c.requests == [] for c in conns) and sum(c.tls_handshakes for c in conns) >= 1
    targets = [r.target for r in fresh_world.http_upstream_noauth.records()]
    assert "origin-c.test:443" in targets
    # Uncatalogued Google hosts are refused by the upstream, never served.
    refused = {r.target for r in fresh_world.http_upstream_noauth.records() if "host_unknown" in r.errors}
    assert not any(t.startswith(("origin-", "update.googleapis.com")) for t in refused)
