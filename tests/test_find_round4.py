"""find, round 4 review: private-address advice, IPv4-mapped records, number formats, the saving claim.

Most tests run without a browser: ``run_find`` is driven through the fake
``load_page`` of ``tests.test_find_round3`` (prepared responses searched with
the real search code). The meter-record tests use a real meter and HTTPX; one
test loads a page in real Chromium.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

import scrapescope.find.core as core
from scrapescope.find import meter_reply_check_from_snapshot, render_find_text, run_find
from scrapescope.find.render import share_line
from scrapescope.find.browser import MainDocument, ObservedResponse
from scrapescope.find.search import number_pattern, prepare_values, search_body
from scrapescope.types import FindResult, VerifyResult
from tests.test_find_round3 import _fake_load, _m, _obs, _result, _run, _snapshot
from tests.test_find_support import make_test_catalogs, validate_find_entry

# --------------------------------------------------------------------------- sec4-2: --allow-private-targets advice


def _refused(seq: int, url: str, **kw: Any) -> ObservedResponse:
    kw.setdefault("resource_type", "document")
    kw.setdefault("frame", "sub")
    obs = _obs(seq, url, meter_error="private-address", **kw)
    obs.skip, obs.status = "failed", 403
    return obs


def _page(url: str, html: str = "<p>Widget Pro</p>") -> tuple[ObservedResponse, str]:
    return _obs(1, url, body=html, kind="html", resource_type="document", frame="main"), html


def test_a_sub_request_refused_as_private_never_recommends_the_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    """sec4-2: an iframe to a router address is the page's choice, not the user's target."""
    page = _page("https://site.test/")
    _fake_load(monkeypatch, [page, (_refused(2, "http://192.168.1.1/"), "")],
               main=MainDocument(200, [], page[1], "https", "site.test", 443))
    result = _run("https://site.test/", ["Widget Pro"])
    warning = next(w for w in result.warnings if "answered by the meter itself" in w)
    assert "private-address x1" in warning
    assert "pass --allow-private-targets" not in warning
    assert "the page asked for a private or local address" in warning
    assert "to protect this machine's network" in warning and "only for a page you trust" in warning
    assert "pass --allow-private-targets" not in render_find_text(result)
    assert validate_find_entry(result) == []


def test_the_targets_own_name_refused_later_is_named_as_rebinding(monkeypatch: pytest.MonkeyPatch) -> None:
    """sec4-2: the page loaded from rebind.test, then a request to rebind.test was refused as private."""
    page = _page("http://rebind.test/")
    own = _refused(2, "http://rebind.test/admin", resource_type="fetch", frame="main")
    _fake_load(monkeypatch, [page, (own, "")], main=MainDocument(200, [], page[1], "http", "rebind.test", 80))
    result = _run("http://rebind.test/", ["Widget Pro"])
    warning = next(w for w in result.warnings if "answered by the meter itself" in w)
    assert "pass --allow-private-targets" not in warning
    assert "DNS rebinding" in warning and "only for a site you trust" in warning


def test_a_redirect_of_the_target_to_a_private_address_does_not_recommend_the_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """sec4-2: http://site.test/ redirected to http://192.168.1.1/, which the meter refused."""
    refusal = MainDocument(403, [("X-Scrapescope-Error", "private-address")], "scrapescope: refusing ...\n",
                           "http", "192.168.1.1", 80)
    _fake_load(monkeypatch, [], main=refusal)
    result = _run("http://site.test/", ["abc"], meter_reply_check=lambda c, h, p: True)
    assert result.status == "error"
    warning = next(w for w in result.warnings if w.startswith("page load failed"))
    assert "is the meter's own reply" in warning
    assert "pass --allow-private-targets" not in warning
    assert "the target redirected to a private or local address" in warning
    # not checked against the records either: still no recommendation for someone else's address
    unchecked = _run("http://site.test/", ["abc"])
    warning = next(w for w in unchecked.warnings if w.startswith("page load failed"))
    assert "not checked against the meter's records" in warning and "pass --allow-private-targets" not in warning
    # the typed target itself (any spelling of it) still gets the advice
    own = MainDocument(403, [("X-Scrapescope-Error", "private-address")], "scrapescope: refusing ...\n",
                       "http", "127.0.0.1", 8080)
    _fake_load(monkeypatch, [], main=own)
    mine = _run("http://[::ffff:127.0.0.1]:8080/", ["abc"], meter_reply_check=lambda c, h, p: True)
    warning = next(w for w in mine.warnings if w.startswith("page load failed"))
    assert "pass --allow-private-targets to load such a target" in warning
    assert "DNS-rebinding" not in warning  # an address the user typed
    # a typed name that resolved to a private address: the advice carries the rebinding caution
    named = MainDocument(403, [("X-Scrapescope-Error", "private-address")], "scrapescope: refusing ...\n",
                         "http", "nas.example", 80)
    _fake_load(monkeypatch, [], main=named)
    name = _run("http://nas.example/", ["abc"], meter_reply_check=lambda c, h, p: True)
    warning = next(w for w in name.warnings if w.startswith("page load failed"))
    assert "pass --allow-private-targets to load such a target, only if you expect this name on your own network" in warning
    assert "DNS-rebinding attack" in warning


def test_meter_warning_unit() -> None:
    """sec4-2: the reviewer's unit repro, with and without the target's endpoint."""
    obs = _refused(3, "http://rebind.example/x", frame="main")
    other = core._meter_warning([obs], ("site.example", 80))
    assert other is not None and "pass --allow-private-targets" not in other
    assert "the page asked for a private or local address" in other
    unknown = core._meter_warning([obs])
    assert unknown is not None and "pass --allow-private-targets" not in unknown
    budget = _refused(4, "http://a.test/")
    budget.meter_error = "budget"
    plain = core._meter_warning([budget], ("a.test", 80))
    assert plain is not None and "allow-private-targets" not in plain


# --------------------------------------------------------------------------- ux4-3: one warning per forged main document


def test_a_forged_main_document_is_warned_about_once(monkeypatch: pytest.MonkeyPatch) -> None:
    forged = MainDocument(403, [("Content-Type", "text/plain"), ("X-Scrapescope-Error", "private-address")],
                          "scrapescope: refused\n", "http", "127.0.0.1", 18933)
    doc = _obs(1, "http://127.0.0.1:18933/", body="scrapescope: refused", kind="text", resource_type="document",
               frame="main", imitated_meter_error="private-address")
    doc.status = 403
    sub = _obs(2, "http://127.0.0.1:18933/api", body='{"n":"refused"}', imitated_meter_error="private-address")
    _fake_load(monkeypatch, [(doc, "scrapescope: refused"), (sub, '{"n":"refused"}')], main=forged)
    result = _run("http://127.0.0.1:18933/", ["refused"], meter_reply_check=lambda c, h, p: False)
    forged_warnings = [w for w in result.warnings if "X-Scrapescope-Error" in w]
    assert len(forged_warnings) == 2, forged_warnings
    assert forged_warnings[0].startswith("the main document carried X-Scrapescope-Error: private-address")
    # the other warning counts only the sub-response
    assert "a response carried X-Scrapescope-Error (private-address x1)" in forged_warnings[1]
    # without the sub-response the main document is named once
    _fake_load(monkeypatch, [(doc, "scrapescope: refused")], main=forged)
    alone = _run("http://127.0.0.1:18933/", ["refused"], meter_reply_check=lambda c, h, p: False)
    assert sum("X-Scrapescope-Error" in w for w in alone.warnings) == 1, alone.warnings


# --------------------------------------------------------------------------- sec4-3: IPv4-mapped literals


def test_meter_reply_check_matches_ipv4_mapped_spellings() -> None:
    """sec4-3: the meter records 127.0.0.1; Chromium and HTTPX keep [::ffff:7f00:1] in the URL."""
    check = meter_reply_check_from_snapshot(lambda: _snapshot([("127.0.0.1", 8080, "failed:private_address")]))
    assert check("private-address", "127.0.0.1", 8080) is True
    assert check("private-address", "::ffff:7f00:1", 8080) is True
    assert check("private-address", "[::ffff:127.0.0.1]", 8080) is True
    assert check("private-address", "::ffff:7f00:1", 8081) is False
    assert check("private-address", "::1", 8080) is False


class _Secret(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - quiet test server
        return

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        if self.path.startswith("/secret"):
            body = b"router admin: s3cr3t-token"
            ctype = "text/plain"
        else:
            port = self.server.server_address[1]
            body = (
                "<!doctype html><html><body><p>Widget Pro</p>"
                f"<iframe src='http://[::ffff:127.0.0.1]:{port}/secret'></iframe></body></html>"
            ).encode()
            ctype = "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def secret_site() -> Iterator[int]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Secret)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()


def test_a_real_refusal_of_an_ipv4_mapped_url_is_confirmed(secret_site: int) -> None:
    """sec4-3: a request for http://[::ffff:7f00:1]:P/ through a real meter; its record says 127.0.0.1.

    Sent on a raw socket as Chromium sends it (HTTPX writes an IPv6 absolute-form target without
    brackets, which the meter rejects as malformed).
    """
    import socket
    import urllib.parse

    from scrapescope.config import ForwarderConfig
    from scrapescope.forwarder import ForwarderThread

    fw = ForwarderThread(ForwarderConfig())
    fw.start()
    try:
        meter = urllib.parse.urlsplit(fw.url)
        for spelling in ("[::ffff:7f00:1]", "[::ffff:127.0.0.1]"):
            url = f"http://{spelling}:{secret_site}/secret"
            with socket.create_connection((meter.hostname, meter.port), timeout=10) as sock:
                sock.sendall(f"GET {url} HTTP/1.1\r\nHost: {spelling}:{secret_site}\r\nConnection: close\r\n\r\n".encode())
                reply = b""
                while chunk := sock.recv(4096):
                    reply += chunk
            assert b"X-Scrapescope-Error: private-address" in reply, reply[:200]
            check = meter_reply_check_from_snapshot(fw.snapshot)
            host = urllib.parse.urlsplit(url).hostname or ""
            assert check("private-address", host, secret_site) is True, host
        records = [(t.host, t.port, t.status) for t in fw.snapshot().tunnels]
        assert records and all(r == ("127.0.0.1", secret_site, "failed:private_address") for r in records), records
    finally:
        fw.stop()


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_an_iframe_to_an_ipv4_mapped_literal_is_the_meters_refusal(secret_site: int) -> None:
    """sec4-3 / sec4-2 live repro: site.test embeds http://[::ffff:127.0.0.1]:P/secret; the meter refuses it."""
    from scrapescope.config import ForwarderConfig
    from scrapescope.forwarder import ForwarderThread

    fw = ForwarderThread(ForwarderConfig(), connect_map={("site.test", 80): ("127.0.0.1", secret_site)})
    fw.start()
    try:
        result = asyncio.run(
            run_find("http://site.test/", ["Widget Pro", "s3cr3t-token"], proxy_url=fw.url,
                     catalogs=make_test_catalogs(), timeout_s=30.0,
                     meter_reply_check=meter_reply_check_from_snapshot(fw.snapshot))
        )
        tunnels = [(t.host, t.port, t.status) for t in fw.snapshot().tunnels]
    finally:
        fw.stop()
    text = render_find_text(result)
    assert ("127.0.0.1", secret_site, "failed:private_address") in tunnels, tunnels
    assert result.status == "found", text
    assert "the site sent the header itself" not in text
    assert "private-address x1" in text and "the page asked for a private or local address" in text
    assert "pass --allow-private-targets" not in text
    assert result.missing_values == [1]  # the meter's refusal body is never searched as the site's
    assert result.coverage.skipped.get("failed") == 1


# --------------------------------------------------------------------------- hon4-1: never a different number


@pytest.mark.parametrize(
    ("value", "body", "kind"),
    [
        ("1994", '{"a": 1.994}', "json"),  # a JSON number: "." is a decimal point
        ("5000", '{"r": 5.000}', "json"),
        ("1994", '{"a": [1,994]}', "json"),  # an array, not a thousands group
        ("1234567", '{"a": [1,234,567]}', "json"),
        ("2024", "h1{font-size:2.024rem}", "css"),
        ("1994", '<svg><path d="M3 2-1.668-1.994a4 4 0 0 1 2 2"/></svg>', "xml"),
        ("1994", "<p>version 1.994</p>", "html"),
        ("1994", "<p>-1.994</p>", "html"),
        ("1234567", "<p>1,234.567</p>", "html"),  # mixed separators: 1234.567
        ("42", '{"t": -42}', "json"),
        ("42", "<p>delta: -42</p>", "html"),
        ("42", "<p>delta −42</p>", "html"),
        ("42", "x=1e-42", "js"),
        ("1994", "<p>(-1994)</p>", "html"),
        ("5,000", "h1{width:5.000rem}", "css"),  # a whole number typed with a comma: still not 5.0
        ("1994.00", "<p>1.994</p>", "html"),
        ("-1994", "<p>-1.994</p>", "html"),
    ],
)
def test_number_format_never_reads_a_different_number(value: str, body: str, kind: str) -> None:
    hits = search_body(body, kind, prepare_values([value]))
    assert hits.values_matched == 0, (value, body, hits.kinds)


@pytest.mark.parametrize(
    ("value", "body", "kind", "expected"),
    [
        ("1299", "<p>1.299 €</p>", "html", "variant:number-format"),  # currency: a thousands dot
        ("1299", "<p>€1.299</p>", "html", "variant:number-format"),
        ("1299", "<p>EUR 1.299</p>", "html", "variant:number-format"),
        ("1299", "<p>1.299,- kr</p>", "html", "variant:number-format"),
        ("1299", "total 1.299,00", "text", "variant:number-format"),  # decimal comma after the group
        ("1234567", "<p>1.234.567</p>", "html", "variant:number-format"),  # two dot groups
        ("1994", "<p>1,994 reviews</p>", "html", "variant:number-format"),
        ("1994", "<p>1 994 reviews</p>", "html", "variant:number-format"),
        ("1994", '{"a": 1994.0}', "json", "variant:number-format"),
        ("1994", '{"a": "1,994"}', "json", "variant:number-format"),
        ("1994", '{"a": "1.994 €"}', "json", "variant:number-format"),
        ("1.994", '{"a": 1.994}', "json", "exact"),
        ("1,994", '{"a": 1.994}', "json", "variant:number-format"),  # the user's decimal-comma reading
        ("1,994", '{"a": 1994}', "json", "variant:number-format"),
        ("£1994", '{"a": 1994}', "json", "variant:number-format"),
        ("42", "<p>SKU ABC-42</p>", "html", "exact"),  # a hyphen after a letter is not a minus sign
        ("2024", "<p>2020-2024</p>", "html", "exact"),  # a range
        ("42", "<p>- 42 items</p>", "html", "exact"),  # a dash with a space
        ("-42", '{"t": -42}', "json", "exact"),
        ("-42", "<p>−42</p>", "html", "variant:number-format"),
        ("1,299", "<p>1.299</p>", "html", "variant:number-format"),  # the value itself may mean 1.299
        ("5,000", "<p>5.000 \u20ac</p>", "html", "variant:number-format"),
        ("-1994", "<p>-1.994 \u20ac</p>", "html", "variant:number-format"),
        ("1994.00", "<p>1.994,00</p>", "html", "variant:number-format"),
        ("1000000000000000000000", '{"v": 1e21}', "json", "variant:number-format"),
    ],
)
def test_number_format_still_matches_the_same_number(value: str, body: str, kind: str, expected: str) -> None:
    assert search_body(body, kind, prepare_values([value])).kinds == [expected], (value, body)


def test_json_numbers_are_read_from_the_whole_body() -> None:
    """hon4-1: number tokens are compared as numbers everywhere, not only within the bounded leaf walk."""
    import json

    from scrapescope.find import search as search_mod

    body = json.dumps({"filler": [0] * (search_mod.MAX_JSON_NODES + 10), "price": 51.77})
    assert search_body(body, "json", prepare_values(["\u00a351.77"])).kinds == ["variant:number-format"]
    assert search_body(body, "json", prepare_values(["5177"])).kinds == ["none"]


def test_json_number_leaves_are_decimal_numbers() -> None:
    """hon4-1: a JSON number leaf is located only where it equals the value."""
    hits = search_body('{"a": 1.994, "b": 1994, "c": -1994, "d": 19940}', "json", prepare_values(["1994"]))
    assert hits.kinds == ["exact"] and hits.by_value[0] == ["json-key:b"]
    hits = search_body('{"a": 1.994, "b": 1994.0}', "json", prepare_values(["1994"]))
    assert hits.kinds == ["variant:number-format"] and hits.by_value[0] == ["json-key:b"]


def test_the_privacy_matcher_stays_loose() -> None:
    """Paths are still dropped for any spelling of the digits (errs on dropping)."""
    from scrapescope.find.search import contains_any_value

    assert contains_any_value("/v/1.994", ["1994"])
    assert contains_any_value("/delta/-42", ["42"])
    loose = number_pattern("1994", loose=True)
    assert loose is not None and loose.search("1.994")


# --------------------------------------------------------------------------- hon4-2: a saving only when the replay moved less


def _replayed(moved: int, *, page: int, billed: int = 9_792) -> FindResult:
    verify = VerifyResult(replays="yes", status=200, received_bytes=moved - 500, replay_billed_basis_bytes=moved)
    return _result([_m(1, billed=billed)], page=page, verify=verify)


def test_a_replay_that_moved_more_than_the_page_load_is_no_saving() -> None:
    """hon4-2: the reviewer's repro: 20,000 B br copy, 97,200 B replayed, 30,000 B page load."""
    from scrapescope.config import TLS_HANDSHAKE_ESTIMATE_BYTES as TLS

    result = _replayed(97_200, page=30_000, billed=27_200)
    line = share_line(result)
    assert line is not None
    assert "a saving" not in line.replace("no saving", "")
    assert line.endswith(
        f"; no saving for a client that accepts only gzip or deflate: the --verify replay moved about "
        f"{97_200 - TLS:,} B body and headers, more than this page load (see warnings)"
    ), line
    # the terminal prints the same line
    assert line in render_find_text(result)


def test_a_replay_that_moved_more_than_the_browser_copy_shows_its_own_share() -> None:
    """hon4-2: the README demo: 1.4% for the br copy, about 5.3% for what the replay moved."""
    from scrapescope.config import TLS_HANDSHAKE_ESTIMATE_BYTES as TLS

    result = _replayed(16_953, page=184_119)
    line = share_line(result)
    assert line is not None and line.startswith("share: 1.4% of this page load (2,592 B")
    own = 16_953 - TLS
    assert line.endswith(
        f"; a saving: --verify replayed it without a browser, moving about {own:,} B body and headers "
        f"({100.0 * own / 184_119:.1f}% of this page load; see warnings)"
    ), line
    # a replay that moved about the same as the browser's copy keeps the short form
    same = share_line(_replayed(9_900, page=184_119))
    assert same is not None and same.endswith("; a saving: --verify replayed it without a browser"), same


class _Forged(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - quiet test server
        return

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        body = b"scrapescope: refused\n"
        self.send_response(403)
        self.send_header("Content-Type", "text/plain")
        self.send_header("X-Scrapescope-Error", "private-address")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_a_forged_main_document_in_chromium_is_warned_about_once() -> None:
    """ux4-3 in real Chromium: the collector's copy of the main document is matched and left out."""
    from scrapescope.config import ForwarderConfig
    from scrapescope.forwarder import ForwarderThread

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Forged)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    fw = ForwarderThread(ForwarderConfig(allow_private_targets=True))
    fw.start()
    try:
        result = asyncio.run(
            run_find(f"http://127.0.0.1:{server.server_address[1]}/", ["refused"], proxy_url=fw.url,
                     catalogs=make_test_catalogs(), timeout_s=30.0,
                     meter_reply_check=meter_reply_check_from_snapshot(fw.snapshot))
        )
    finally:
        fw.stop()
        server.shutdown()
        server.server_close()
    assert result.status == "found", render_find_text(result)
    forged = [w for w in result.warnings if "X-Scrapescope-Error" in w]
    assert len(forged) == 1 and forged[0].startswith("the main document carried"), forged


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_find_leaves_the_proxy_hop_out_of_plain_http_request_heads(fresh_world: Any, hosts_map: Any) -> None:
    """meas4-5, find side: on a plain http:// page Chromium sends the meter ``Proxy-Connection``, which
    DevTools counts in ``requestHeadersSize``; the meter never passes it on. find's billed basis leaves
    it out, as the helper does, so the request head is at most what the origin received."""
    from tests.fixtures import site
    from tests.test_forwarder_helpers import make_config, running
    from tests.test_helpers_playwright import _origin_head_size

    origin = fresh_world.origin("origin-a.test", "http")
    with running(make_config(None), connect_map=dict(hosts_map)) as fw:
        result = asyncio.run(
            run_find("http://origin-a.test/plain.html", [site.PRODUCT_PRICE], proxy_url=fw.url,
                     catalogs=make_test_catalogs(), timeout_s=40.0, browser_args=fresh_world.chromium_args())
        )
    (doc,) = [m for m in result.matches if result.match_urls[str(m.rank)].endswith("/plain.html")]
    received = [_origin_head_size(r) for r in origin.requests() if r.path == "/plain.html"]
    assert received and not doc.multiplexed
    assert 0 < doc.request_header_bytes <= min(received), (doc.request_header_bytes, received)
