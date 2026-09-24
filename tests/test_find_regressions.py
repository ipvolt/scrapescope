"""find regressions from the 2026-09-23 review, in real headless Chromium against a local page set.

The pages are served by a tiny loopback HTTP server started here (the fixture
upstreams reach loopback IP literals, and Playwright proxies loopback too), so
the shared fixture site stays untouched. Each page reproduces one review
finding: escaped embedded JSON (find-1), a currency value whose API carries
the bare number (find-2), a JSON fetched twice from the HTTP cache (find-3),
a request id in the query (find-5) and a challenged XHR (find-7).
"""

from __future__ import annotations

import asyncio
import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from scrapescope.find import render_find_text, run_find
from scrapescope.types import FindMatch, FindResult
from tests.fixtures import TestWorld
from tests.test_find_support import make_test_catalogs, validate_find_entry

PRICE = "£51.77"
UUID = "550e8400-e29b-41d4-a716-446655440000"


def _next_escape(obj: object) -> str:
    text = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    for ch, esc in (("&", "\\u0026"), (">", "\\u003e"), ("<", "\\u003c")):
        text = text.replace(ch, esc)
    return text


_DONE = "document.documentElement.dataset.done = '1';"

PAGES: dict[str, tuple[int, list[tuple[str, str]], bytes]] = {
    "/next.html": (
        200,
        [("Content-Type", "text/html; charset=utf-8")],
        (
            "<!doctype html><html><head><title>Mill</title>"
            '<script id="__NEXT_DATA__" type="application/json">'
            + _next_escape({"props": {"pageProps": {"name": "Salt & Pepper Mill", "price": "1 299,00 €"}}})
            + '</script><script type="application/ld+json">'
            + _next_escape({"@type": "Product", "name": "Tom & Jerry Mug"})  # Rails escapes & < > the same way
            + "</script></head><body><div id=root></div></body></html>"
        ).encode("utf-8"),
    ),
    "/currency.html": (
        200,
        [("Content-Type", "text/html; charset=utf-8")],
        (
            f"<!doctype html><html><body><p class=price>{PRICE}</p>"
            f"<script>fetch('/api/price.json').then(r => r.json()).then(() => {{ {_DONE} }});</script>"
            "</body></html>"
        ).encode("utf-8"),
    ),
    "/api/price.json": (200, [("Content-Type", "application/json")], json.dumps({"price": 51.77}).encode()),
    "/cache.html": (
        200,
        [("Content-Type", "text/html; charset=utf-8")],
        (
            "<!doctype html><html><body><p>loading</p><script>"
            "fetch('/data.json').then(r => r.text()).then(() => fetch('/data.json')).then(r => r.text())"
            f".then(() => {{ {_DONE} }});</script></body></html>"
        ).encode("utf-8"),
    ),
    "/data.json": (
        200,
        [("Content-Type", "application/json"), ("Cache-Control", "public, max-age=600")],
        json.dumps({"price": PRICE, "note": "x" * 1000}, ensure_ascii=False).encode("utf-8"),
    ),
    "/api.html": (
        200,
        [("Content-Type", "text/html; charset=utf-8")],
        (
            "<!doctype html><html><body><script>"
            f"fetch('/api/item?rid={UUID}').then(r => r.json()).then(() => {{ {_DONE} }});"
            "</script></body></html>"
        ).encode("utf-8"),
    ),
    "/api/item": (200, [("Content-Type", "application/json")], json.dumps({"price": PRICE}, ensure_ascii=False).encode()),
    "/xhrblock.html": (
        200,
        [("Content-Type", "text/html; charset=utf-8")],
        (
            "<!doctype html><html><body><p>price below</p><script>"
            f"fetch('/api/blocked-price').then(r => r.text()).then(() => {{ {_DONE} }});"
            "</script></body></html>"
        ).encode("utf-8"),
    ),
    # sec2-1: a page that opens an RTCPeerConnection to the STUN server named in its query
    "/webrtc.html": (
        200,
        [("Content-Type", "text/html; charset=utf-8")],
        (
            "<!doctype html><html><body><p>price hello-webrtc-123</p><script>"
            "const stun = new URLSearchParams(location.search).get('stun');"
            "const pc = new RTCPeerConnection({iceServers: [{urls: 'stun:' + stun}]});"
            "pc.createDataChannel('x');"
            "pc.createOffer().then(o => pc.setLocalDescription(o))"
            f".then(() => new Promise(r => setTimeout(r, 1500))).then(() => {{ {_DONE} }});"
            "</script></body></html>"
        ).encode("utf-8"),
    ),
    "/api/blocked-price": (
        403,
        [("Content-Type", "text/html; charset=UTF-8"), ("cf-mitigated", "challenge"), ("Server", "cloudflare")],
        b"<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>"
        b"<script>window._cf_chl_opt={cvId: '3'};</script></body></html>",
    ),
}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - quiet test server
        return

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        page = PAGES.get(self.path.split("?", 1)[0])
        if page is None:
            status, headers, body = 404, [("Content-Type", "text/plain")], b"not found\n"
        else:
            status, headers, body = page
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        if not any(n.lower() == "cache-control" for n, _ in headers):
            self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def local_site() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def run(world: TestWorld, url: str, values: list[str], **kwargs: Any) -> FindResult:
    kwargs.setdefault("catalogs", make_test_catalogs())
    kwargs.setdefault("timeout_s", 30.0)
    return asyncio.run(
        run_find(
            url,
            values,
            proxy_url=world.http_upstream_noauth.server,
            ca_file=world.ca_pem,
            browser_args=world.chromium_args(),
            **kwargs,
        )
    )


def matches_for(result: FindResult, path: str) -> list[FindMatch]:
    return [m for m in result.matches if result.match_urls[str(m.rank)].split("?")[0].endswith(path)]


def assert_private(result: FindResult, values: list[str]) -> None:
    dumped = json.dumps(result.to_dict(), ensure_ascii=False)
    for value in values:
        assert value not in dumped and value.casefold() not in dumped.casefold()
    assert validate_find_entry(result) == []


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_escaped_next_data_and_ld_json_values_are_found(world: TestWorld, local_site: str) -> None:
    """find-1: HTML-safe escaped __NEXT_DATA__ and ensure_ascii JSON-LD are searched, not "not found"."""
    values = ["Salt & Pepper Mill", "Tom & Jerry Mug", "1 299,00 €"]
    result = run(world, f"{local_site}/next.html", values)
    assert result.status == "found", render_find_text(result)
    (doc,) = matches_for(result, "/next.html")
    assert doc.all_values
    assert doc.match_kinds == ["variant:json-escape", "variant:json-escape", "variant:space-normalized"]
    assert "embedded:next-data" in doc.locations and "embedded:ld-json" in doc.locations
    assert_private(result, values)


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_currency_value_finds_the_bare_number_in_the_api(world: TestWorld, local_site: str) -> None:
    """find-2: '£51.77' as displayed also matches {"price": 51.77}, labelled number-format."""
    result = run(world, f"{local_site}/currency.html", [PRICE])
    assert result.status == "found"
    (api,) = matches_for(result, "/api/price.json")
    (doc,) = matches_for(result, "/currency.html")
    assert api.match_kinds == ["variant:number-format"] and doc.match_kinds == ["exact"]
    assert "json-key:price" in api.locations
    assert api.rank < doc.rank  # the JSON is smaller than the page
    assert result.short_value_warning is True
    assert_private(result, [PRICE, "51.77"])


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_http_cache_hit_is_not_ranked_as_its_own_smaller_response(world: TestWorld, local_site: str) -> None:
    """find-3: a JSON fetched twice is listed once, with the network copy's sizes."""
    result = run(world, f"{local_site}/cache.html", [PRICE])
    assert result.status == "found"
    data = matches_for(result, "/data.json")
    assert len(data) == 1, [(m.rank, m.encoded_body_bytes, m.locations) for m in data]
    assert data[0].encoded_body_bytes > 1000 and "served-from-cache" not in data[0].locations
    assert any("served from the browser's HTTP cache and not listed" in w for w in result.warnings), result.warnings
    assert_private(result, [PRICE])


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_uuid_request_id_withholds_code_and_verify(world: TestWorld, local_site: str) -> None:
    """find-5: a UUID request id in the query is a random-looking token: no starter code, no replay."""
    result = run(world, f"{local_site}/api.html", [PRICE], verify=True)
    (api,) = matches_for(result, "/api/item")
    assert api.flags.random_query_token is True
    assert api.code_eligible is False and api.code_ineligible_reason == "random-looking query token"
    assert result.starter_code == []
    assert result.verify.replays == "not_tested" and result.verify.reason == "no eligible match"
    assert UUID not in json.dumps(result.to_dict())


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_challenged_xhr_is_not_counted_as_inspected(world: TestWorld, local_site: str) -> None:
    """find-7: a challenged data request is reported, so "not found" is not the whole story."""
    result = run(world, f"{local_site}/xhrblock.html", [PRICE])
    assert result.status == "not_found"
    assert result.challenge.blocked is False  # the page itself loaded
    assert result.coverage.skipped.get("challenge", 0) >= 1 and "other" not in result.coverage.skipped
    warning = next((w for w in result.warnings if "challenge page" in w), None)
    assert warning is not None and "Cloudflare" in warning
    text = render_find_text(result)
    assert "challenge page (Cloudflare)" in text
    assert "skipped: 1 challenge page (not searched; see warnings)" in text
    assert "replays without a browser" not in text  # nothing found, --verify not requested
    assert_private(result, [PRICE])


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_unsafe_port_is_not_retried(world: TestWorld) -> None:
    """find-13: a deterministic navigation error fails once, without the retry."""
    result = run(world, "http://127.0.0.1:1/x", ["Widget Pro"], timeout_s=20.0)
    assert result.status == "error"
    assert "page load failed: net::ERR_UNSAFE_PORT; cannot search" in result.warnings
    assert not any("retried" in w for w in result.warnings)


# --------------------------------------------------------------------------- round 2 review


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_webrtc_sends_no_udp_around_the_proxy(world: TestWorld, local_site: str) -> None:
    """sec2-1: a page's RTCPeerConnection must not send STUN over UDP from this machine."""
    import socket

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    udp.settimeout(0.2)
    port = udp.getsockname()[1]
    got: list[object] = []
    stop = threading.Event()

    def listen() -> None:
        while not stop.is_set():
            try:
                _data, addr = udp.recvfrom(4096)
                got.append(addr)
            except OSError:
                continue

    thread = threading.Thread(target=listen, daemon=True)
    thread.start()
    try:
        result = run(world, f"{local_site}/webrtc.html?stun=127.0.0.1:{port}", ["hello-webrtc-123"])
    finally:
        stop.set()
        thread.join(2)
        udp.close()
    assert result.status == "found", render_find_text(result)
    assert got == [], f"{len(got)} STUN packets reached a local UDP port directly from find's browser"


def _meter(**kwargs: Any):  # noqa: ANN202 - test helper
    from scrapescope.config import ForwarderConfig
    from scrapescope.forwarder import ForwarderThread

    fw = ForwarderThread(ForwarderConfig(**kwargs))
    fw.start()
    return fw


def _run_through(fw: Any, url: str, values: list[str], **kwargs: Any) -> FindResult:
    kwargs.setdefault("catalogs", make_test_catalogs())
    kwargs.setdefault("timeout_s", 30.0)
    return asyncio.run(run_find(url, values, proxy_url=fw.url, **kwargs))


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_meter_refusal_of_an_http_target_is_a_load_error_not_not_found(local_site: str) -> None:
    """find-x1 / honest-2: the meter's 403 private-address reply is never searched as the page."""
    fw = _meter()  # sizing mode, private targets refused
    try:
        result = _run_through(fw, f"{local_site}/currency.html", [PRICE])
    finally:
        fw.stop()
    assert result.status == "error", render_find_text(result)
    assert result.coverage.inspected == 0 and result.matches == []
    assert result.verify.reason == "page load failed"
    warning = next(w for w in result.warnings if w.startswith("page load failed"))
    assert "X-Scrapescope-Error: private-address" in warning and "--allow-private-targets" in warning
    text = render_find_text(result)
    assert "cannot search: the page did not load" in text and "not found" not in text
    assert_private(result, [PRICE])


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_meter_refusal_of_an_https_target_names_the_cause_without_a_retry() -> None:
    """honest-2: a refused CONNECT to a private literal is not retried and says why."""
    import socket

    with socket.socket() as s:  # a free port: nothing listens there, and the meter refuses it first
        s.bind(("127.0.0.1", 0))
        target = f"https://127.0.0.1:{s.getsockname()[1]}/"
    fw = _meter()
    try:
        plain = _run_through(fw, target, ["12.34"], timeout_s=20.0)

        def check() -> str | None:  # what the CLI's abort check reports for this tunnel status
            for tunnel in fw.snapshot().tunnels:
                if tunnel.status == "failed:private_address":
                    return "the meter refused a private address (--allow-private-targets)"
            return None

        explained = _run_through(fw, target, ["12.34"], timeout_s=20.0, abort_check=check)
    finally:
        fw.stop()
    assert plain.status == "error"
    assert "page load failed: net::ERR_TUNNEL_CONNECTION_FAILED; cannot search" in plain.warnings
    assert any("--allow-private-targets" in w for w in plain.warnings), plain.warnings
    assert not any("retried" in w for w in plain.warnings)
    assert explained.status == "error"
    assert (
        "page load failed: the meter refused a private address (--allow-private-targets) "
        "(net::ERR_TUNNEL_CONNECTION_FAILED); cannot search"
    ) in explained.warnings, explained.warnings
    assert not any("retried" in w for w in explained.warnings)


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_meter_refused_sub_request_is_skipped_and_named(local_site: str) -> None:
    """find-x1: a sub-request the meter answered itself is not searched and is reported."""
    from scrapescope.config import HostRule

    port = local_site.rsplit(":", 1)[1]
    page = (
        "<!doctype html><html><body><p>Widget Pro</p>"
        # an iframe document: Chromium hands its 403 reply over (a cross-origin script would be blocked by ORB)
        f"<iframe src='http://localhost:{port}/api/price.json'></iframe></body></html>"
    ).encode()
    PAGES["/denied-sub.html"] = (200, [("Content-Type", "text/html; charset=utf-8")], page)
    fw = _meter(allow_private_targets=True, deny_rules=(HostRule("localhost", "deny-host:localhost"),))
    try:
        result = _run_through(fw, f"{local_site}/denied-sub.html", ["51.77"])
    finally:
        fw.stop()
    assert result.status == "not_found", render_find_text(result)
    assert result.coverage.skipped.get("failed", 0) >= 1
    warning = next((w for w in result.warnings if "answered by the meter itself" in w), None)
    assert warning is not None and "denied x1" in warning, result.warnings
    assert any(w.startswith("not found: the value;") for w in result.warnings)
    text = render_find_text(result)
    lines = text.splitlines()
    # find3-14: the coverage line says "not found" once; its explanation follows
    assert lines[1].startswith("not found in ") and "not found: the value" not in text
    assert lines[2].startswith("only responses of the initial page load were inspected")


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_value_only_inside_a_longer_number_is_not_found(world: TestWorld, local_site: str) -> None:
    """find-r2-7: '51.7' only occurs inside '£51.77' and '51.77': not found (exit 1), with a note."""
    result = run(world, f"{local_site}/currency.html", ["51.7"])
    assert result.status == "not_found", render_find_text(result)
    assert result.matches == [] and result.starter_code == []
    assert any("never on its own" in w and "value 1" in w for w in result.warnings), result.warnings


# --------------------------------------------------------------------------- round 3 review

API_KEY = "k9J2mQ7xL4pZ8vB3nR6tY1wE5"
VALUE = "Z9Q-UNIQ-4417"
_FILLER = "<p>" + "catalogue text " * 40 + "</p>"

PAGES.update(
    {
        # sec3-3: a charset Python cannot decode with errors="replace"
        "/undefined-charset.html": (
            200,
            [("Content-Type", "text/html; charset=undefined")],
            f"<!doctype html><html><body><p>{VALUE}</p></body></html>".encode(),
        ),
        # find3-2: a time series as compact JSON arrays
        "/arr.html": (
            200,
            [("Content-Type", "text/html; charset=utf-8")],
            (
                "<!doctype html><html><body><p>chart</p><script>"
                f"fetch('/api/history.json').then(r => r.json()).then(() => {{ {_DONE} }});"
                "</script></body></html>"
            ).encode(),
        ),
        "/api/history.json": (
            200,
            [("Content-Type", "application/json")],
            b'{"history":[[1690000000,49.99],[1690086400,51.77]]}',
        ),
        # find3-6: the data request carries an API key header
        "/hdr.html": (
            200,
            [("Content-Type", "text/html; charset=utf-8")],
            (
                "<!doctype html><html><body><p>price below</p><script>"
                f"fetch('/api/keyed.json', {{headers: {{'x-api-key': '{API_KEY}'}}}}).then(r => r.json())"
                f".then(() => {{ {_DONE} }});</script></body></html>"
            ).encode(),
        ),
        # find3-7: an analytics cookie is set before the data request; the page itself is large
        "/ck.html": (
            200,
            [("Content-Type", "text/html; charset=utf-8")],
            (
                "<!doctype html><html><body><p>Widget Pro 51.77</p>" + _FILLER * 60 + "<script>"
                "document.cookie = '_ga=GA1.1.123.456; path=/';"
                f"fetch('/api/p2.json').then(r => r.json()).then(() => {{ {_DONE} }});"
                "</script></body></html>"
            ).encode(),
        ),
        "/api/p2.json": (200, [("Content-Type", "application/json")], b'{"name":"Widget Pro","price":51.77}'),
        "/api/keyed.json": (200, [("Content-Type", "application/json")], b'{"price":"51.77"}'),
        # sec3-4: an http site imitating the meter's private-address refusal
        "/forged.html": (
            403,
            [("Content-Type", "text/plain; charset=utf-8"), ("X-Scrapescope-Error", "private-address")],
            b"scrapescope: refusing a direct connection to a loopback, private or link-local address "
            b"(--allow-private-targets permits it)\n",
        ),
        "/forged-sub.html": (
            200,
            [("Content-Type", "text/html; charset=utf-8")],
            b"<!doctype html><html><body><p>Widget Pro</p><iframe src='/forged.html'></iframe></body></html>",
        ),
        # find3-5: the value is in the page; a large download after load trips a small budget
        "/late.html": (
            200,
            [("Content-Type", "text/html; charset=utf-8")],
            (
                "<!doctype html><html><body><p>51.77</p><script>"
                "window.addEventListener('load', () => setTimeout(() => fetch('/big.bin').then(r => r.arrayBuffer())"
                f".catch(() => null).then(() => {{ {_DONE} }}), 100));</script></body></html>"
            ).encode(),
        ),
        "/big.bin": (200, [("Content-Type", "application/octet-stream")], b"\0" * 400_000),
    }
)


class _KeyedHandler(_Handler):
    """The keyed API answers 401 without its header, like a real key-protected endpoint."""

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        if self.path.split("?", 1)[0] == "/api/keyed.json" and self.headers.get("x-api-key") != API_KEY:
            body = b'{"error":"api key required"}'
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()


@pytest.fixture(scope="module")
def keyed_site() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _KeyedHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_undefined_charset_on_the_main_document_is_searched(world: TestWorld, local_site: str) -> None:
    """sec3-3: charset=undefined made find raise ValueError (a usage error, no report); now it is UTF-8."""
    result = run(world, f"{local_site}/undefined-charset.html", [VALUE])
    assert result.status == "found", render_find_text(result)
    assert_private(result, [VALUE])


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_time_series_array_values_are_found(world: TestWorld, local_site: str) -> None:
    """find3-2: 51.77 and 49.99 inside [[t,49.99],[t,51.77]] are values, not parts of longer numbers."""
    result = run(world, f"{local_site}/arr.html", ["51.77", "49.99"])
    assert result.status == "found", render_find_text(result)
    (api,) = matches_for(result, "/api/history.json")
    assert api.all_values and api.match_kinds == ["exact", "exact"]
    assert api.locations_by_value == [["json-key:history[1][1]"], ["json-key:history[0][1]"]]
    assert not any("never on its own" in w for w in result.warnings)


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_api_key_header_withholds_code_and_verify_says_no(world: TestWorld, keyed_site: str) -> None:
    """find3-6: a fetch that sent x-api-key gets no starter code; the header-less replay gets 401."""
    result = run(world, f"{keyed_site}/hdr.html", ["51.77"], verify=True)
    (api,) = matches_for(result, "/api/keyed.json")
    assert api.code_eligible is False and api.code_ineligible_reason == "sent a token header"
    assert result.starter_code == []
    assert (result.verify.replays, result.verify.status) == ("no", 401), result.verify
    text = render_find_text(result)
    assert "token-header" in text and "starter code" not in text
    assert API_KEY not in json.dumps(result.to_dict()) and API_KEY not in text


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_analytics_cookie_does_not_keep_the_json_from_verify(world: TestWorld, local_site: str) -> None:
    """find3-7: the small JSON sent only an analytics cookie; --verify replays it and it gets code."""
    result = run(world, f"{local_site}/ck.html", ["Widget Pro", "51.77"], verify=True)
    (api,) = matches_for(result, "/api/p2.json")
    (doc,) = matches_for(result, "/ck.html")
    assert api.rank < doc.rank and api.flags.sent_cookies is True
    assert result.verify.replays == "yes", result.verify
    assert api.code_eligible is True
    assert api.rank in {c.rank for c in result.starter_code}
    text = render_find_text(result)
    assert f"replays without a browser: yes (rank {api.rank}," in text
    assert "a saving: --verify replayed it without a browser" in text
    assert validate_find_entry(result) == []


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_forged_meter_reply_is_the_sites_when_the_meter_did_not_send_it(world: TestWorld, local_site: str) -> None:
    """sec3-4: a hostile http page imitating the meter must not steer the user to --allow-private-targets."""
    asked: list[tuple[str, str, int]] = []

    def meter_records(code: str, host: str, port: int) -> bool:
        asked.append((code, host, port))
        return False  # what the meter's snapshot says: no refusal for this host:port

    result = run(world, f"{local_site}/forged.html", ["abc"], meter_reply_check=meter_records)
    assert asked and asked[0][0] == "private-address"
    assert result.status == "not_found", render_find_text(result)
    text = render_find_text(result)
    assert "--allow-private-targets" not in text
    assert any("the site sent the header itself" in w for w in result.warnings)
    # a sub-response imitating the meter is searched as the site's, named, and gets no meter advice
    sub = run(world, f"{local_site}/forged-sub.html", ["Widget Pro"], meter_reply_check=meter_records)
    warning = next((w for w in sub.warnings if "X-Scrapescope-Error (private-address x1)" in w), None)
    assert warning is not None and "searched as the site's responses" in warning, sub.warnings
    assert "failed" not in sub.coverage.skipped
    assert "--allow-private-targets" not in render_find_text(sub)


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_no_replay_once_the_budget_tripped(local_site: str) -> None:
    """find3-5: after a budget trip the meter refuses the replay; it is not sent and not reported as 'no'."""
    fw = _meter(allow_private_targets=True, budget_bytes=100_000)

    def budget() -> str | None:  # the CLI's check (runner._find_abort_check) says the same
        return "the byte budget tripped" if fw.snapshot().budget_tripped else None

    try:
        result = _run_through(fw, f"{local_site}/late.html", ["51.77"], verify=True, abort_check=budget)
        tripped = fw.snapshot().budget_tripped
    finally:
        fw.stop()
    assert tripped, "the fixture download did not trip the budget"
    assert result.status == "found", render_find_text(result)
    assert (result.verify.replays, result.verify.reason) == ("not_tested", "not sent: the byte budget tripped")
    assert result.verify.replay_billed_basis_bytes is None


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_forged_meter_reply_through_the_real_meter_and_its_records(local_site: str) -> None:
    """sec3-4 end to end: the meter's records (meter_reply_check_from_snapshot) tell a forged reply from a real one."""
    from scrapescope.find import meter_reply_check_from_snapshot

    # --allow-private-targets given: the page's own 403 + X-Scrapescope-Error is the site's, and no advice follows
    fw = _meter(allow_private_targets=True)
    try:
        forged = _run_through(fw, f"{local_site}/forged.html", ["abc"],
                              meter_reply_check=meter_reply_check_from_snapshot(fw.snapshot))
    finally:
        fw.stop()
    assert forged.status == "not_found", render_find_text(forged)
    assert "--allow-private-targets" not in render_find_text(forged)
    assert any("the site sent the header itself" in w for w in forged.warnings), forged.warnings
    # sizing mode: the meter itself refuses the loopback target, which its records confirm
    fw = _meter()
    try:
        real = _run_through(fw, f"{local_site}/forged.html", ["abc"],
                            meter_reply_check=meter_reply_check_from_snapshot(fw.snapshot))
    finally:
        fw.stop()
    assert real.status == "error", render_find_text(real)
    warning = next(w for w in real.warnings if w.startswith("page load failed"))
    assert "is the meter's own reply" in warning and "--allow-private-targets" in warning
