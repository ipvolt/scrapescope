"""find against the fixture site in real headless Chromium, plus --verify and error paths.

The forwarder is built in parallel, so these tests point find's browser-wide
proxy straight at a FIXTURE upstream (remote DNS through the hosts map). The
end-to-end path through the meter is the integrator's test.
"""

from __future__ import annotations

import asyncio
import base64
import json
import sys
import time
from typing import Any

import pytest

from scrapescope.config import TLS_HANDSHAKE_ESTIMATE_BYTES, USER_AGENT
from scrapescope.find import BrowserUnavailableError, render_find_text, run_find
from scrapescope.find.heuristics import NOT_EMITTED_TEXT
from scrapescope.find.search import prepare_values
from scrapescope.find.verify import verify_replay
from scrapescope.types import FindMatch, FindResult, safe_text
from tests.fixtures import SESSION_PASSWORD, UPSTREAM_PASSWORD, UPSTREAM_USERNAME, TestWorld, site
from tests.test_find_support import make_test_catalogs, shipped_catalogs_or_none, validate_find_entry


def find(world: TestWorld, path: str, values: list[str], *, proxy_url: str | None = None, host: str = "origin-a.test",
         scheme: str = "https", **kwargs: Any) -> FindResult:
    """Run find synchronously through the no-auth HTTP fixture upstream by default."""
    kwargs.setdefault("catalogs", make_test_catalogs())
    kwargs.setdefault("timeout_s", 40.0)
    return asyncio.run(
        run_find(
            f"{scheme}://{host}{path}",
            values,
            proxy_url=proxy_url or world.http_upstream_noauth.server,
            ca_file=world.ca_pem,
            browser_args=world.chromium_args(),
            **kwargs,
        )
    )


def by_path(result: FindResult, path: str, host: str = "origin-a.test") -> FindMatch:
    for match in result.matches:
        if match.host == host and result.match_urls[str(match.rank)].split("?")[0].endswith(path) and (
            match.path in (path, None)
        ):
            return match
    raise AssertionError(f"no match for {host}{path}: {[(m.host, m.path) for m in result.matches]}")


def assert_private(result: FindResult, values: list[str]) -> None:
    """The report half of the result never holds a value, and fits the schema."""
    dumped = json.dumps(result.to_dict(), ensure_ascii=False)
    for value in values:
        assert value not in dumped, value
        assert value.casefold() not in dumped.casefold(), value
    assert validate_find_entry(result) == []


# --------------------------------------------------------------------------- the product page


@pytest.fixture(scope="module")
def price_result(world: TestWorld) -> FindResult:
    """One load for the single-value price assertions (read-only in the tests below)."""
    if not _browser_ok():
        pytest.skip("Chromium unavailable")
    return find(world, "/", [site.PRODUCT_PRICE])


def _browser_ok() -> bool:
    from tests.fixtures.browser import chromium_unavailable_reason

    return chromium_unavailable_reason() is None


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_price_found_in_product_json_and_ranked_above_the_html(price_result: FindResult) -> None:
    result = price_result
    assert result.status == "found"
    assert result.challenge.blocked is False and result.challenge.status == 200
    product = by_path(result, "/api/product.json")
    document = by_path(result, "/")
    assert product.rank < document.rank
    assert product.match_kinds == ["exact"]
    assert "json-key:price" in product.locations and product.locations[0] == "fetch"
    assert product.all_values and product.values_matched == 1
    assert product.mime_type == "application/json"
    # "129.99" occurs in the HTML only split across tags
    assert document.match_kinds == ["variant:tag-stripped"]
    assert "html-text" in document.locations
    # billed basis = encoded body + response headers + request headers + one TLS handshake estimate
    for m in result.matches:
        assert m.tls_handshake_estimate == TLS_HANDSHAKE_ESTIMATE_BYTES
        assert m.billed_basis_bytes == (
            m.encoded_body_bytes + m.response_header_bytes + m.request_header_bytes + TLS_HANDSHAKE_ESTIMATE_BYTES
        )
    all_first = [m.all_values for m in result.matches]
    assert all_first == sorted(all_first, reverse=True)
    billed = [m.billed_basis_bytes for m in result.matches if m.all_values and "served-by-service-worker" not in m.locations]
    assert billed == sorted(billed)
    # starter code for the product JSON, curl --compressed and httpx
    codes = {c.rank: c for c in result.starter_code}
    assert product.code_eligible and product.rank in codes
    assert codes[product.rank].curl == "curl --compressed 'https://origin-a.test/api/product.json'"
    assert "httpx.get('https://origin-a.test/api/product.json'" in codes[product.rank].httpx
    assert result.short_value_warning is True
    assert result.verify.replays == "not_tested" and result.verify.reason == "not requested"
    assert_private(result, [site.PRODUCT_PRICE])


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_session_product_flagged_sent_cookies_and_not_code_eligible(price_result: FindResult) -> None:
    session = by_path(price_result, "/api/session-product.json")
    assert session.flags.sent_cookies is True
    assert session.code_eligible is False
    assert session.code_ineligible_reason == "sent cookies"
    assert session.rank not in {c.rank for c in price_result.starter_code}
    text = render_find_text(price_result)
    # find3-7: a match ineligible only for its cookies is untested, not "depends on session state"
    assert (
        f"rank {session.rank} (sent cookies): not emitted: the browser sent cookies with it and it was not tested "
        "without them (--verify replays it once without them)"
    ) in text
    assert f"rank {session.rank} (sent cookies): {NOT_EMITTED_TEXT}" not in text


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_signed_offer_flagged_random_token(price_result: FindResult) -> None:
    offer = by_path(price_result, "/api/offer.json")
    assert offer.flags.random_query_token is True
    assert offer.code_eligible is False
    assert offer.code_ineligible_reason == "random-looking query token"
    # the query string (and the token) is terminal-only
    assert site.SIGNED_QUERY_TOKEN in price_result.match_urls[str(offer.rank)]
    assert site.SIGNED_QUERY_TOKEN not in json.dumps(price_result.to_dict())
    assert offer.path == "/api/offer.json"


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_coverage_counts_every_response(price_result: FindResult) -> None:
    cov = price_result.coverage
    assert cov.inspected >= 10
    # 3 hero images + the font + the iframe's image are binary
    assert cov.skipped.get("binary", 0) >= 5
    assert price_result.responses_total == cov.inspected + sum(cov.skipped.values())
    assert price_result.page_reported_bytes > sum(len(site.image(p)) for p in site.IMAGES)
    assert price_result.coverage.summary(True).startswith(f"searched {cov.inspected} inspected responses; skipped: ")


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_render_of_a_real_result(price_result: FindResult) -> None:
    text = render_find_text(price_result)
    assert "searched" in text and "origin-a.test/api/product.json" in text
    assert "curl --compressed 'https://origin-a.test/api/product.json'" in text
    assert "computed" not in text
    assert not [c for c in text if (ord(c) < 0x20 and c != "\n") or 0x7F <= ord(c) <= 0x9F]


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_name_and_price_rank_responses_with_all_values_first(world: TestWorld) -> None:
    result = find(world, "/", [site.PRODUCT_NAME, site.PRODUCT_PRICE])
    assert result.status == "found"
    product = by_path(result, "/api/product.json")
    document = by_path(result, "/")
    offer = by_path(result, "/api/offer.json")
    assert product.all_values and product.match_kinds == ["exact", "exact"]
    assert document.all_values and document.match_kinds[0] == "exact"
    assert document.match_kinds[1].startswith("variant:")
    assert "embedded:ld-json" in document.locations
    # offer.json is the smallest response but holds only the price
    assert not offer.all_values and offer.match_kinds == ["none", "exact"]
    assert offer.billed_basis_bytes < product.billed_basis_bytes
    assert offer.rank > document.rank > product.rank
    first_partial = min(m.rank for m in result.matches if not m.all_values)
    assert all(m.all_values for m in result.matches if m.rank < first_partial)
    assert_private(result, [site.PRODUCT_NAME, site.PRODUCT_PRICE])


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_narrow_nbsp_price_matched_as_variant(world: TestWorld) -> None:
    typed = site.PRICE_NNBSP_TEXT.replace("\u202f", " ")
    result = find(world, "/", [typed])
    assert result.status == "found"
    document = by_path(result, "/")
    assert document.match_kinds == ["variant:space-normalized"]
    assert "html-text" in document.locations
    assert_private(result, [typed])


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_embedded_next_data_and_ld_json(world: TestWorld) -> None:
    result = find(world, "/", [site.NEXT_DATA_MARKER])
    document = by_path(result, "/")
    assert "embedded:next-data" in document.locations
    assert "json-key:props.pageProps.marker" in document.locations
    sku = find(world, "/", [site.PRODUCT_SKU])
    locations = by_path(sku, "/").locations
    assert "embedded:ld-json" in locations and "embedded:next-data" in locations
    assert "json-key:sku" in by_path(sku, "/api/product.json").locations


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_iframe_worker_and_service_worker_responses_are_inspected(world: TestWorld) -> None:
    result = find(world, "/", [site.EMBED_MARKER, site.WORKER_MARKER, site.SW_MARKER])
    embed = by_path(result, "/embed", host="origin-b.test")
    assert embed.match_kinds[0] == "exact"
    assert "iframe" in embed.locations and embed.resource_type == "document"
    assert embed.flags.third_party is True
    assert embed.code_eligible  # third party alone does not withhold code
    worker = by_path(result, "/api/worker.json")
    assert worker.match_kinds[1] == "exact"
    backend = by_path(result, "/api/sw-backend.json")
    assert backend.match_kinds[2] == "exact"
    assert "service-worker" in backend.locations
    served = by_path(result, "/api/sw.json")
    assert "served-by-service-worker" in served.locations
    assert served.code_eligible is False and served.code_ineligible_reason == "served by a service worker"
    # service-worker-served responses rank after network responses of the same all-values status
    assert served.rank > backend.rank


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_coincidental_beacon_match_is_flagged(world: TestWorld) -> None:
    value = str(site.BEACON_SEQ)
    result = find(world, "/", [value])
    assert result.short_value_warning is True
    assert any("short or numeric-only" in w for w in result.warnings)
    beacon = by_path(result, "/api/collect")
    assert beacon.method == "POST" and beacon.flags.non_get is True
    assert beacon.code_eligible is False and beacon.code_ineligible_reason == "not a GET"
    assert "json-key:seq" in beacon.locations


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_value_nowhere_reports_not_found_with_coverage(world: TestWorld) -> None:
    value = "absent-value-7c1e"
    result = find(world, "/", [value], verify=True)
    assert result.status == "not_found"
    assert result.matches == []
    line = result.coverage.summary(False)
    assert line.startswith(f"not found in {result.coverage.inspected} inspected responses; skipped: ")
    assert "binary" in line
    # find-r4-8: nothing matched at all, which "no eligible match" would misstate
    assert result.verify.replays == "not_tested" and result.verify.reason == "nothing matched"
    text = render_find_text(result)
    assert line in text and "computed" not in text
    assert_private(result, [value])


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_body_cap_skips_large_bodies(world: TestWorld) -> None:
    result = find(world, "/", [site.PRODUCT_NAME], body_cap_bytes=3000)
    assert result.coverage.skipped.get("over_cap", 0) >= 1
    assert all(m.path != "/" for m in result.matches)  # the 6 KB document was not read
    assert by_path(result, "/api/product.json").match_kinds == ["exact"]


# --------------------------------------------------------------------------- challenges


@pytest.mark.browser
@pytest.mark.timeout(120)
@pytest.mark.parametrize(
    ("path", "vendor", "status"),
    [("/challenge-cf", "cloudflare", 403), ("/challenge-aws", "aws-waf", 202), ("/challenge-aws-captcha", "aws-waf", 405)],
)
def test_challenge_pages_are_blocked_not_not_found(world: TestWorld, path: str, vendor: str, status: int) -> None:
    catalogs = [make_test_catalogs()]
    shipped = shipped_catalogs_or_none()
    if shipped is not None:
        catalogs.append(shipped)
    for cat in catalogs:
        result = find(world, path, ["Widget Pro"], catalogs=cat, verify=True)
        assert result.status == "blocked"
        assert result.challenge.blocked is True
        assert result.challenge.vendor_id == vendor
        assert result.challenge.status == status
        assert result.matches == [] and result.coverage.inspected == 0
        assert result.verify.replays == "not_tested" and result.verify.reason == "blocked"
        text = render_find_text(result)
        assert f"blocked; cannot search (challenge: {result.challenge.vendor_name})" in text
        assert "not found" not in text
        assert_private(result, ["Widget Pro"])


# --------------------------------------------------------------------------- verify


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_verify_replays_product_json_through_the_same_proxy(fresh_world: TestWorld) -> None:
    world = fresh_world
    result = find(world, "/", [site.PRODUCT_PRICE], verify=True)
    if result.verify.reason and result.verify.reason.startswith("request failed ("):
        # transport flake on a loaded shared host (see test_verify_replay_outcomes): redo once from scratch
        world.reset()
        result = find(world, "/", [site.PRODUCT_PRICE], verify=True)
    assert result.verify.replays == "yes", result.verify
    assert result.verify.status == 200
    assert result.verify.received_bytes and result.verify.received_bytes > 0
    top = next(m for m in result.matches if m.code_eligible)
    assert top.path == "/api/product.json"
    world.wait_idle()
    replays = [
        r for r in world.origin("origin-a.test").requests()
        if r.path == "/api/product.json" and r.header("user-agent") == USER_AGENT
    ]
    assert len(replays) == 1, "exactly one verify request"
    replay = replays[0]
    assert replay.header("cookie") is None and replay.header("authorization") is None
    assert replay.method == "GET"
    # it went through the upstream (remote DNS), not directly
    assert any(rec.target == "origin-a.test:443" for rec in world.http_upstream_noauth.records())
    assert "replays without a browser: yes" in render_find_text(result)


def test_verify_replay_outcomes(world: TestWorld) -> None:
    values = prepare_values([site.PRODUCT_PRICE, site.PRODUCT_NAME])

    def replay(url: str, needed: list[int], proxy: str | None = None, *, tolerate_flake: bool = True):
        def once():
            return asyncio.run(
                verify_replay(
                    url, values, needed, proxy_url=proxy or world.http_upstream_noauth.server,
                    ca_file=world.ca_pem, timeout_s=30, body_cap_bytes=1_000_000,
                )
            )

        result = once()
        # A transport failure says nothing about replay semantics; on a loaded
        # shared host a loopback connect can fail transiently, so try once more.
        if tolerate_flake and result.reason and result.reason.startswith("request failed ("):
            result = once()
        return result

    yes = replay("https://origin-a.test/api/product.json", [0, 1])
    assert (yes.replays, yes.status, yes.reason) == ("yes", 200, None)
    missing = replay("https://origin-a.test/api/worker.json", [0])
    assert (missing.replays, missing.reason) == ("no", "value missing")
    # the session endpoint needs the browser's cookie: a cookie-less replay gets 401
    no = replay("https://origin-a.test/api/session-product.json", [0])
    assert (no.replays, no.status, no.reason) == ("no", 401, "status 401")
    redirect = replay("https://origin-a.test/redirect", [0])
    assert (redirect.replays, redirect.reason) == ("no", "status 302")
    dead = replay(
        "https://origin-a.test/api/product.json", [0], proxy=f"http://127.0.0.1:{world.closed_port()}", tolerate_flake=False
    )
    assert dead.replays == "not_tested"
    assert dead.reason is not None and dead.reason.startswith("request failed (ConnectError")
    tiny = asyncio.run(
        verify_replay(
            "https://origin-a.test/api/product.json", values, [0], proxy_url=world.http_upstream_noauth.server,
            ca_file=world.ca_pem, body_cap_bytes=10,
        )
    )
    assert tiny.replays == "not_tested" and tiny.reason == "response over the size cap"


# --------------------------------------------------------------------------- other upstreams and credentials


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_find_through_socks5_upstream(world: TestWorld) -> None:
    result = find(world, "/", [site.PRODUCT_PRICE], proxy_url=world.socks_upstream_noauth.url, verify=True)
    assert result.status == "found"
    assert by_path(result, "/api/product.json").match_kinds == ["exact"]
    assert result.verify.replays == "yes"


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_credentials_in_proxy_url_never_reach_output(world: TestWorld) -> None:
    proxy = world.http_upstream.proxy_url(UPSTREAM_USERNAME, UPSTREAM_PASSWORD)
    result = find(world, "/", [site.PRODUCT_PRICE], proxy_url=proxy, verify=True)
    assert result.status == "found"
    assert result.verify.replays == "yes"
    sentinels = [UPSTREAM_USERNAME, UPSTREAM_PASSWORD, base64.b64encode(f"{UPSTREAM_USERNAME}:{UPSTREAM_PASSWORD}".encode()).decode()]
    outputs = [render_find_text(result), json.dumps(result.to_dict()), repr(result)]
    for out in outputs:
        for sentinel in sentinels:
            assert sentinel not in out


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_wrong_proxy_credentials_end_early_through_abort_check(fresh_world: TestWorld) -> None:
    """Chromium waits for credentials after a 407; the caller's abort_check ends the load."""
    world = fresh_world
    bad_password = "wrong-" + SESSION_PASSWORD[::-1]
    proxy = world.http_upstream.proxy_url(UPSTREAM_USERNAME, bad_password)

    def saw_407() -> str | None:
        rejected = any(407 in rec.statuses for rec in world.http_upstream.records())
        return "the upstream proxy answered 407 (credentials rejected)" if rejected else None

    started = time.monotonic()
    result = find(world, "/", ["Widget Pro"], proxy_url=proxy, timeout_s=40.0, abort_check=saw_407, verify=True)
    assert time.monotonic() - started < 20.0
    assert result.status == "error"
    assert "page load failed: the upstream proxy answered 407 (credentials rejected); cannot search" in result.warnings
    assert not any("retried" in w for w in result.warnings)
    assert result.verify.reason == "page load failed"
    text = render_find_text(result) + json.dumps(result.to_dict()) + repr(result)
    assert UPSTREAM_USERNAME not in text and bad_password not in text


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_proxy_407_without_abort_check_times_out_once_without_retry(world: TestWorld) -> None:
    started = time.monotonic()
    result = find(world, "/", ["Widget Pro"], proxy_url=world.http_upstream.server, timeout_s=6.0)
    assert time.monotonic() - started < 20.0
    assert result.status == "error"
    assert "page load failed: timeout; cannot search" in result.warnings
    assert not any("retried" in w for w in result.warnings)


def test_abort_check_errors_are_ignored() -> None:
    from scrapescope.find.browser import _abort_reason

    def broken() -> str:
        raise RuntimeError("boom")

    assert _abort_reason(broken) is None
    assert _abort_reason(None) is None
    assert _abort_reason(lambda: "") is None
    from scrapescope.find.browser import ABORT_REASON_MAX

    long_reason = "x\x1b[31m" + "y" * 400
    reason = _abort_reason(lambda: long_reason)
    assert reason == safe_text(long_reason, ABORT_REASON_MAX)
    assert reason is not None and len(reason) == ABORT_REASON_MAX and "\x1b" not in reason


# --------------------------------------------------------------------------- errors


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_navigation_failure_retries_once_then_reports_error(world: TestWorld) -> None:
    result = find(world, "/secret-path?token=abc123", ["Widget Pro"], host="unmapped-host.test", verify=True)
    assert result.status == "error"
    assert result.matches == [] and result.coverage.inspected == 0
    assert result.verify.replays == "not_tested" and result.verify.reason == "page load failed"
    assert any(w.startswith("page load failed: net::ERR_") for w in result.warnings)
    assert any(w.startswith("the page load was retried once after: net::ERR_") for w in result.warnings)
    joined = " ".join(result.warnings)
    assert "unmapped-host" not in joined and "token" not in joined and "secret-path" not in joined
    assert "cannot search" in render_find_text(result)
    assert validate_find_entry(result) == []


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_value_in_the_url_path_is_kept_out_of_the_report(world: TestWorld) -> None:
    value = "product.json"
    result = find(world, "/", [value])
    assert result.status == "found"
    # the product JSON path contains the value, so its path is dropped from the report half
    for m in result.matches:
        url_path = result.match_urls[str(m.rank)].split("?")[0]
        if value in url_path:
            assert m.path is None
    assert_private(result, [value])
    # the terminal still shows where the match is
    assert "origin-a.test/static/app.js" in render_find_text(result)


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_page_reported_bytes_stay_below_tunnel_bytes(fresh_world: TestWorld) -> None:
    """Fake 'tunnel bytes' input: the fixture upstream's per-connection byte counts."""
    world = fresh_world
    result = find(world, "/", [site.PRODUCT_PRICE])
    world.wait_idle()
    tunnel_bytes = sum(rec.bytes_from_client + rec.bytes_to_client for rec in world.http_upstream_noauth.records())
    assert result.page_reported_bytes > 0
    # DevTools sizes exclude TLS records and CONNECT, so they are below the tunnel-measured bytes
    assert result.page_reported_bytes < tunnel_bytes


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_plain_http_target_has_no_tls_estimate(world: TestWorld) -> None:
    result = find(world, "/plain.html", [site.PRODUCT_PRICE], scheme="http")
    doc = by_path(result, "/plain.html")
    assert doc.scheme == "http" and doc.port == 80
    assert doc.tls_handshake_estimate == 0
    assert doc.billed_basis_bytes == doc.encoded_body_bytes + doc.response_header_bytes + doc.request_header_bytes


# --------------------------------------------------------------------------- argument validation (no browser)


@pytest.mark.parametrize(
    ("url", "values"),
    [
        ("ftp://origin-a.test/", ["x"]),
        ("origin-a.test/", ["x"]),
        ("https://", ["x"]),
        ("https://origin-a.test:99999/", ["x"]),
        ("https://origin-a.test/", []),
        ("https://origin-a.test/", ["   "]),
        ("https://origin-a.test/", ["v"] * 51),
    ],
)
def test_invalid_arguments_raise_value_error(url: str, values: list[str]) -> None:
    with pytest.raises(ValueError) as info:
        asyncio.run(run_find(url, values, proxy_url="http://127.0.0.1:9", catalogs=make_test_catalogs()))
    assert "origin-a" not in str(info.value)


def test_missing_playwright_raises_browser_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "playwright.async_api", None)
    with pytest.raises(BrowserUnavailableError) as info:
        asyncio.run(
            run_find("https://origin-a.test/", ["x"], proxy_url="http://127.0.0.1:9", catalogs=make_test_catalogs())
        )
    assert "playwright install chromium" in str(info.value)


def test_import_is_cheap() -> None:
    import subprocess

    code = (
        "import sys, scrapescope.find; "
        "print(any(m.startswith(('playwright', 'httpx')) for m in sys.modules))"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "False"


@pytest.mark.browser
@pytest.mark.timeout(120)
def test_redirect_hop_counts_as_no_body(world: TestWorld) -> None:
    result = find(world, "/redirect", [site.PRODUCT_PRICE])
    assert result.status == "found"
    assert result.target_path == "/redirect"
    assert result.coverage.skipped.get("no_body", 0) >= 1
    assert "no body (redirect, 204 or 304)" in result.coverage.summary(True)


class _FakeResponse:
    def __init__(self, headers: list[tuple[str, str]], body: bytes) -> None:
        self.status = 200
        self._headers = headers
        self._body = body
        self.body_reads = 0

    async def headers_array(self) -> list[dict[str, str]]:
        return [{"name": n, "value": v} for n, v in self._headers]

    async def body(self) -> bytes:
        self.body_reads += 1
        return self._body


def test_main_document_window_and_cap() -> None:
    from scrapescope.find.browser import MAIN_BODY_WINDOW_BYTES, _main_document

    big = b"<title>Just a moment...</title>" + b"x" * (2 * MAIN_BODY_WINDOW_BYTES)
    ok = _FakeResponse([("Content-Type", "text/html; charset=utf-8")], big)
    doc = asyncio.run(_main_document(ok, RuntimeError, 10**9))
    assert doc.status == 200 and doc.headers[0] == ("Content-Type", "text/html; charset=utf-8")
    assert doc.body_text is not None and len(doc.body_text) == MAIN_BODY_WINDOW_BYTES
    assert doc.body_text.startswith("<title>Just a moment")
    capped = _FakeResponse([("Content-Length", str(len(big)))], big)
    doc = asyncio.run(_main_document(capped, RuntimeError, 1000))
    assert doc.body_text is None and capped.body_reads == 0


# --------------------------------------------------------------------------- OS sandbox
@pytest.mark.browser
@pytest.mark.timeout(120)
def test_find_asks_for_the_sandbox_and_falls_back_with_a_warning(world: TestWorld, monkeypatch: pytest.MonkeyPatch) -> None:
    from playwright.async_api import BrowserType
    from playwright.async_api import Error as PlaywrightError

    from scrapescope.find.core import SANDBOX_WARNING

    original = BrowserType.launch
    calls: list[bool | None] = []

    async def launch(self: Any, **kwargs: Any) -> Any:
        calls.append(kwargs.get("chromium_sandbox"))
        if kwargs.get("chromium_sandbox"):
            raise PlaywrightError("No usable sandbox!")  # what a container without user namespaces gives
        return await original(self, **kwargs)

    monkeypatch.setattr(BrowserType, "launch", launch)
    result = find(world, "/plain.html", [site.PRODUCT_PRICE], scheme="http")
    assert calls == [True, False]
    assert result.status == "found"
    assert SANDBOX_WARNING in result.warnings
