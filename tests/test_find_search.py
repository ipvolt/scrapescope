"""find without a browser: variants, locations, heuristics, starter code and rendering."""

from __future__ import annotations

import json

import pytest

from scrapescope.config import TLS_HANDSHAKE_ESTIMATE_BYTES
from scrapescope.find import render_find_text
from scrapescope.find.browser import body_error_reason, navigation_error_reason, playwright_proxy
from scrapescope.find.heuristics import (
    NOT_EMITTED_TEXT,
    body_kind,
    code_eligibility,
    decode_body,
    has_random_query_token,
    is_third_party,
    looks_binary,
    looks_random,
    mime_of,
)
from scrapescope.find.search import (
    contains_any_value,
    is_short_value,
    match_kind,
    normalize_space,
    number_pattern,
    parse_json_text,
    prepare_values,
    search_body,
    SearchText,
)
from scrapescope.find.starter import curl_command, httpx_snippet, starter_code
from scrapescope.types import (
    ChallengeResult,
    Coverage,
    FindFlags,
    FindMatch,
    FindResult,
    StarterCode,
    VerifyResult,
)
from tests.fixtures import site
from tests.test_find_support import validate_find_entry


def kind_of(body: str, kind: str, value: str) -> str:
    return match_kind(SearchText(body, kind), prepare_values([value])[0])


# --------------------------------------------------------------------------- variants


def test_exact_match_wins() -> None:
    assert kind_of(site.PRODUCT_JSON.decode(), "json", site.PRODUCT_PRICE) == "exact"


def test_value_absent_is_none() -> None:
    assert kind_of(site.PRODUCT_JSON.decode(), "json", "not-there-42") == "none"


def test_json_escape_variant() -> None:
    body = json.dumps({"title": "Caf\u00e9 \u201cnoir\u201d / 1/2"})  # ensure_ascii escapes
    assert "\\u00e9" in body
    assert kind_of(body, "json", "Caf\u00e9 \u201cnoir\u201d / 1/2") == "variant:json-escape"
    js = 'var x = "a\\/b\\u202Fc";'
    assert kind_of(js, "js", "a/b\u202fc") == "variant:json-escape"


def test_json_decoded_strings_count_as_json_escape() -> None:
    body = '{"q": "say \\"hi\\""}'
    assert kind_of(body, "json", 'say "hi"') == "variant:json-escape"


def test_html_entity_variant() -> None:
    body = "<p>Fish &amp; Chips &#8364;5</p>"
    assert kind_of(body, "html", "Fish & Chips \u20ac5") == "variant:html-entity"


def test_space_normalized_variants() -> None:
    html_body = site.product_html("https")
    typed = site.PRICE_NNBSP_TEXT.replace("\u202f", " ")
    assert typed != site.PRICE_NNBSP_TEXT
    assert kind_of(html_body, "html", typed) == "variant:space-normalized"
    assert kind_of(html_body, "html", site.PRICE_NNBSP_TEXT.replace("\u202f", "\u00a0")) == "variant:space-normalized"
    # the exact NNBSP form is an exact match
    assert kind_of(html_body, "html", site.PRICE_NNBSP_TEXT) == "exact"
    # value typed with a no-break space against a plain-space body
    assert kind_of("price: 1 299 kr", "text", "1\u00a0299 kr") == "variant:space-normalized"
    # zero-width characters and soft hyphens are ignored
    assert kind_of("Wid\u00adget\u200b Pro", "text", "Widget Pro") == "variant:space-normalized"


def test_tag_stripped_variant_for_split_price() -> None:
    html_body = site.product_html("https")
    assert site.PRODUCT_PRICE not in html_body
    assert kind_of(html_body, "html", site.PRODUCT_PRICE) == "variant:tag-stripped"


def test_tag_stripped_separates_block_elements() -> None:
    body = "<table><tr><td>12</td><td>9.99</td></tr></table>"
    assert kind_of(body, "html", "129.99") == "none"
    assert kind_of("<b>12</b><i>9.99</i>", "html", "129.99") == "variant:tag-stripped"


def test_script_and_style_are_not_visible_text() -> None:
    body = "<style>.x{content:'secret-token'}</style><script>var s='hidden'+'value';</script><p>shown</p>"
    text = SearchText(body, "html")
    assert "secret-token" not in text.visible
    assert "hidden" not in text.visible
    assert text.visible == "shown"


@pytest.mark.parametrize(
    ("value", "body", "expected"),
    [
        ("129.99", "Preis: 129,99 EUR", "variant:number-format"),
        ("129,99", "price 129.99", "variant:number-format"),
        ("1299", "total 1,299.00", "variant:number-format"),
        ("1299.5", "total 1.299,50", "variant:number-format"),
        ("1,299.00", "total 1\u202f299,00", "variant:number-format"),
        ("129.9", "129,90", "variant:number-format"),
        ("129.9", "129.90", "variant:number-format"),  # trailing zero: not the exact string on its own
        ("129.99", "1129.99", "variant:substring"),  # numeric values respect digit boundaries
        ("129.99", "129.995", "variant:substring"),
        ("129.99", "price 129.99.", "exact"),  # a sentence full stop does not continue the number
        ("129.99", "129,995", "none"),  # digits continue the number
        ("129.99", "12999", "none"),
        ("129", '{"seq":129}', "exact"),
    ],
)
def test_number_format_variants(value: str, body: str, expected: str) -> None:
    assert kind_of(body, "text", value) == expected


def test_number_pattern_readings() -> None:
    assert number_pattern("Widget Pro") is None
    assert number_pattern("WP-1000") is None
    rx = number_pattern("1,299")  # ambiguous: 1299 or 1.299
    assert rx is not None
    assert rx.search("1299") and rx.search("1.299") and rx.search("1,299")
    assert number_pattern("1,2,3") is None
    assert number_pattern("-42").search("x -42 y") and not number_pattern("-42").search("x 42 y")


def test_case_insensitive_variant() -> None:
    assert kind_of("<h2>WIDGET PRO</h2>", "html", "widget pro") == "variant:case-insensitive"
    assert kind_of('{"n":"WIDGET PRO"}', "json", "Widget Pro") == "variant:case-insensitive"


def test_normalize_space() -> None:
    assert normalize_space("  a\u00a0\u202f b\n\tc\u200b ") == "a b c"


def test_prepare_values_rejects_empty() -> None:
    with pytest.raises(ValueError):
        prepare_values(["   "])


# --------------------------------------------------------------------------- locations


def test_json_key_locations() -> None:
    values = prepare_values([site.PRODUCT_PRICE, site.PRODUCT_NAME])
    hits = search_body(site.PRODUCT_JSON.decode(), "json", values, base_locations=["fetch"])
    assert hits.kinds == ["exact", "exact"]
    assert hits.all
    assert hits.locations[0] == "fetch"
    assert "json-key:price" in hits.locations and "json-key:name" in hits.locations


def test_nested_json_key_paths_and_arrays() -> None:
    body = json.dumps({"data": {"items": [{"offer": {"price": 5}}, {"offer": {"price": 129.99}}]}})
    hits = search_body(body, "json", prepare_values(["129.99"]))
    assert "json-key:data.items[1].offer.price" in hits.locations
    root_list = json.dumps([{"sku": "WP-1000"}])
    assert "json-key:[0].sku" in search_body(root_list, "json", prepare_values(["WP-1000"])).locations


def test_json_key_paths_containing_a_value_or_odd_characters_are_dropped() -> None:
    body = json.dumps({"price-129.99": "129.99", "weird key!": "129.99", "ok": "129.99"})
    locs = search_body(body, "json", prepare_values(["129.99"])).locations
    assert "json-key:ok" in locs
    assert not any("weird" in loc or "price-129" in loc for loc in locs)


def test_anti_xssi_prefix_is_tolerated() -> None:
    assert parse_json_text(")]}'\n{\"a\": 1}") == {"a": 1}
    assert parse_json_text("not json") is None


def test_html_locations_embedded_blocks_text_and_markup() -> None:
    html_body = site.product_html("https")
    values = prepare_values([site.NEXT_DATA_MARKER, site.PRODUCT_SKU, site.PRODUCT_NAME])
    hits = search_body(html_body, "html", values, base_locations=["document"])
    assert hits.kinds == ["exact", "exact", "exact"]
    assert "embedded:next-data" in hits.locations
    assert "json-key:props.pageProps.marker" in hits.locations
    assert "embedded:ld-json" in hits.locations
    assert "json-key:sku" in hits.locations
    assert "html-text" in hits.locations
    markup = search_body('<img src="/x.png" alt="hidden-alt-text">', "html", prepare_values(["hidden-alt-text"]))
    assert markup.locations == ["html-markup"]


def test_locations_fit_report_pattern() -> None:
    import re

    rx = re.compile(r"[a-z][a-z0-9+_-]{0,31}(:[A-Za-z0-9_.$@\[\]-]{1,128})?")
    body = json.dumps({"a b": {"\u00fcber": "X"}, "long": {"k" * 200: "X"}, "fine": "X"})
    hits = search_body(body, "json", prepare_values(["X"]), base_locations=["fetch", "Bad Type"])
    assert all(rx.fullmatch(loc) for loc in hits.locations), hits.locations


# --------------------------------------------------------------------------- heuristics


@pytest.mark.parametrize(
    ("value", "random"),
    [
        (site.SIGNED_QUERY_TOKEN, True),
        ("5d41402abc4b2a765d41402abc4b2a76", True),  # hex
        ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig", True),  # JWT shape
        ("Ab3_Zz9-Qq1_Yy2-Ww3_Xx", True),  # base64url
        ("spring2026collection", False),
        ("this-is-a-long-slug-for-product", False),
        ("1234567890123456", False),
        ("page", False),
        ("2", False),
        ("", False),
    ],
)
def test_looks_random(value: str, random: bool) -> None:
    assert looks_random(value) is random


def test_random_query_token_detection() -> None:
    assert has_random_query_token(f"https://origin-a.test/api/offer.json?sig={site.SIGNED_QUERY_TOKEN}")
    assert has_random_query_token("https://x.test/a?sig=short")  # signature-like name
    assert has_random_query_token("https://x.test/a?X-Amz-Signature=abc")
    assert not has_random_query_token("https://x.test/a?page=2&sort=price")
    assert not has_random_query_token("https://x.test/a")


def test_third_party() -> None:
    assert is_third_party("origin-b.test", "origin-a.test")
    assert not is_third_party("cdn.origin-a.test", "origin-a.test")
    assert not is_third_party("origin-a.test", "origin-a.test")
    assert is_third_party("127.0.0.2", "127.0.0.1")


def test_code_eligibility_reasons() -> None:
    ok = code_eligibility(method="GET", status=200, flags=FindFlags())
    assert ok.eligible and ok.reason is None
    cases = [
        (dict(method="GET", status=200, flags=FindFlags(sent_cookies=True)), "sent cookies"),
        (dict(method="GET", status=200, flags=FindFlags(sent_authorization=True)), "sent authorization"),
        (dict(method="GET", status=200, flags=FindFlags(random_query_token=True)), "random-looking query token"),
        (dict(method="POST", status=200, flags=FindFlags(non_get=True)), "not a GET"),
        (dict(method="GET", status=404, flags=FindFlags()), "status 404"),
        (dict(method="GET", status=None, flags=FindFlags()), "status unknown"),
        (dict(method="GET", status=200, flags=FindFlags(), served_by_service_worker=True), "served by a service worker"),
    ]
    for kwargs, reason in cases:
        result = code_eligibility(**kwargs)
        assert not result.eligible and result.reason == reason
    # third party alone does not block code
    assert code_eligibility(method="GET", status=200, flags=FindFlags(third_party=True)).eligible


def test_mime_and_body_kind() -> None:
    assert mime_of("Application/JSON; charset=utf-8") == "application/json"
    assert mime_of("garbage") is None
    assert mime_of(None) is None
    assert body_kind("text/html", "document") == "html"
    assert body_kind("application/ld+json", "fetch") == "json"
    assert body_kind("application/javascript", "script") == "js"
    assert body_kind("image/svg+xml", "image") == "xml"
    assert body_kind("text/css", "stylesheet") == "css"
    assert body_kind("text/plain", "fetch") == "text"
    for binary in ("image/png", "font/woff2", "application/octet-stream", "video/mp4", "application/pdf"):
        assert body_kind(binary, "other") is None
    assert body_kind(None, "document") == "html"
    assert body_kind(None, "image") is None


def test_decode_body_and_binary_sniff() -> None:
    assert decode_body("caf\u00e9".encode("latin-1"), "text/html; charset=ISO-8859-1", "html") == "caf\u00e9"
    assert decode_body(b'<meta charset="latin-1"><p>\xe9</p>', None, "html").endswith("\u00e9</p>")
    assert decode_body(b"\xef\xbb\xbfhi", None, "text") == "hi"
    assert decode_body(b"x", "text/plain; charset=nonsense-cs", "text") == "x"
    assert looks_binary(b"\x89PNG\x00\x00") and not looks_binary(b"{}")


def test_short_value_rule() -> None:
    assert is_short_value("129")
    assert is_short_value("129.99")
    assert is_short_value("1 299,00")
    assert is_short_value(" abc ")
    assert not is_short_value("Widget Pro")
    assert not is_short_value("WP-1000")


def test_contains_any_value() -> None:
    assert contains_any_value("/p/Widget%20Pro", ["widget pro"])
    assert contains_any_value("/p/widget+pro", ["Widget Pro"])
    assert not contains_any_value("/api/product.json", ["Widget Pro"])
    assert not contains_any_value("", ["x"])


def test_error_reason_mapping() -> None:
    assert body_error_reason("Protocol error (Network.getResponseBody): No resource with given identifier found") == "evicted"
    assert body_error_reason("Response.body: Worker closed") == "no_session"
    assert body_error_reason("Response body is unavailable for redirect responses") == "no_body"
    assert body_error_reason("something odd") == "other"

    class TimeoutError(Exception):  # noqa: A001 - mimics playwright's class name
        pass

    err = Exception("Page.goto: net::ERR_TUNNEL_CONNECTION_FAILED at https://secret.test/path?token=abc\nCall log: ...")
    assert navigation_error_reason(err) == "net::ERR_TUNNEL_CONNECTION_FAILED"
    assert navigation_error_reason(TimeoutError("Page.goto: Timeout 3000ms exceeded.")) == "timeout"
    assert navigation_error_reason(Exception("Target crashed https://secret.test/")) == "browser error"


def test_playwright_proxy_splits_credentials() -> None:
    assert playwright_proxy("http://127.0.0.1:8080") == {"server": "http://127.0.0.1:8080"}
    proxy = playwright_proxy("http://us%40er:p%3Ass@127.0.0.1:9")
    assert proxy == {"server": "http://127.0.0.1:9", "username": "us@er", "password": "p:ss"}
    assert playwright_proxy("socks5://[::1]:1080") == {"server": "socks5://[::1]:1080"}


# --------------------------------------------------------------------------- starter code


def test_starter_code_quotes_and_contains_no_state() -> None:
    url = "https://origin-a.test/api/it's.json?page=2"
    curl = curl_command(url)
    assert curl == "curl --compressed 'https://origin-a.test/api/it'\\''s.json?page=2'"
    code = httpx_snippet(url, json_body=True)
    assert repr(url) in code
    assert "response.json()" in code
    for forbidden in ("Cookie:", "Authorization:", "cookies=", "headers=", "auth=", "Mozilla", "-H ", "-b "):
        assert forbidden not in code and forbidden not in curl
    compile(code, "<starter>", "exec")
    sc = starter_code(3, "https://origin-a.test/", json_body=False)
    assert sc.rank == 3 and "response.text" in sc.httpx


def test_starter_code_neutralises_control_characters() -> None:
    code = httpx_snippet("https://x.test/\x1b[31m\u202e", json_body=False)
    assert "\x1b" not in code and "\u202e" not in code


# --------------------------------------------------------------------------- rendering


def _match(rank: int, **kw) -> FindMatch:
    base = dict(
        rank=rank,
        host="origin-a.test",
        port=443,
        scheme="https",
        path="/api/product.json",
        method="GET",
        resource_type="fetch",
        status=200,
        mime_type="application/json",
        all_values=True,
        values_matched=1,
        match_kinds=["exact"],
        locations=["fetch", "json-key:price"],
        encoded_body_bytes=149,
        response_header_bytes=205,
        request_header_bytes=511,
        tls_handshake_estimate=TLS_HANDSHAKE_ESTIMATE_BYTES,
        billed_basis_bytes=149 + 205 + 511 + TLS_HANDSHAKE_ESTIMATE_BYTES,
        flags=FindFlags(),
        code_eligible=True,
        code_ineligible_reason=None,
    )
    base.update(kw)
    return FindMatch(**base)


def _found_result() -> FindResult:
    m1 = _match(
        1,
        path="/api/session-product.json",
        # cookies and Authorization: not a replay candidate (find3-7), so the plan's not-emitted text
        flags=FindFlags(sent_cookies=True, sent_authorization=True),
        code_eligible=False,
        code_ineligible_reason="sent cookies",
    )
    m2 = _match(2)
    return FindResult(
        status="found",
        target_host="origin-a.test",
        target_path="/",
        values_count=1,
        short_value_warning=True,
        challenge=ChallengeResult(blocked=False, status=200),
        matches=[m1, m2],
        coverage=Coverage(inspected=13, skipped={"binary": 5}),
        verify=VerifyResult(replays="yes", status=200, received_bytes=149),
        responses_total=18,
        page_reported_bytes=692_000,
        warnings=["short or numeric-only value: check the match location"],
        target_url="https://origin-a.test/",
        starter_code=[StarterCode(rank=2, curl=curl_command("https://origin-a.test/api/product.json"), httpx="import httpx\n")],
        match_urls={"1": "https://origin-a.test/api/session-product.json", "2": "https://origin-a.test/api/product.json"},
    )


def test_short_value_warning_names_the_value_and_is_left_out_when_it_cannot_mislead() -> None:
    """ux-1: the warning names the short value; not when nothing was searched or a long value shares the top match."""
    from scrapescope.find.core import _short_value_warning

    def result(status: str, kinds: list[list[str]]) -> FindResult:
        return FindResult(
            status=status, target_host="origin-a.test", target_path="/", values_count=2, short_value_warning=False,  # type: ignore[arg-type]
            challenge=ChallengeResult(blocked=status == "blocked"),
            matches=[_match(i + 1, match_kinds=k) for i, k in enumerate(kinds)],
        )

    values = ["Widget Pro", "129"]
    alone = _short_value_warning(result("found", [["none", "exact"], ["exact", "exact"]]), values)
    assert alone is not None and alone.startswith("value 2 is short or numeric-only")
    # the top match also holds the long value: it is not a coincidental beacon
    assert _short_value_warning(result("found", [["exact", "exact"]]), values) is None
    # a weak hit of the long value does not count
    assert _short_value_warning(result("found", [["variant:substring", "exact"]]), values) is not None
    assert _short_value_warning(result("blocked", []), values) is None
    assert _short_value_warning(result("error", []), values) is None
    assert _short_value_warning(result("found", [["exact", "exact"]]), ["Widget Pro", "Blue Edition"]) is None
    both = _short_value_warning(result("not_found", []), ["12", "\u00a34"])
    assert both is not None and both.startswith("values 1, 2 are short or numeric-only")


def test_render_found() -> None:
    text = render_find_text(_found_result())
    assert "searched 13 inspected responses; skipped: 5 binary" in text
    assert "origin-a.test/api/product.json" in text
    assert "curl --compressed 'https://origin-a.test/api/product.json'" in text
    assert f"rank 1 (sent cookies): {NOT_EMITTED_TEXT}" in text
    assert "replays without a browser: yes (rank 2, status 200, 149 body bytes received)" in text
    assert "7,200 bytes" in text
    assert "\x1b" not in text
    assert "computed" not in text
    no_code = render_find_text(_found_result(), show_code=False)
    assert "curl --compressed" not in no_code


def test_render_escapes_hostile_urls_and_names() -> None:
    result = _found_result()
    result.match_urls["2"] = "https://origin-a.test/\x1b]8;;evil\x07/\u202eabc?x=1"
    result.challenge = ChallengeResult(blocked=True, vendor_id="cloudflare", vendor_name="Cloud\x1bflare", status=403)
    for status in ("found", "blocked", "not_found", "error"):
        result.status = status
        text = render_find_text(result)
        assert "\x1b" not in text and "\x07" not in text and "\u202e" not in text


def test_render_blocked_and_not_found_and_error() -> None:
    blocked = FindResult(
        status="blocked",
        target_host="origin-a.test",
        target_path="/challenge-cf",
        values_count=1,
        short_value_warning=False,
        challenge=ChallengeResult(blocked=True, vendor_id="cloudflare", vendor_name="Cloudflare", status=403),
        verify=VerifyResult(replays="not_tested", reason="blocked"),
    )
    text = render_find_text(blocked)
    assert "blocked; cannot search (challenge: Cloudflare)" in text
    assert "not found" not in text
    not_found = FindResult(
        status="not_found",
        target_host="origin-a.test",
        target_path=None,
        values_count=2,
        short_value_warning=False,
        challenge=ChallengeResult(blocked=False, status=200),
        coverage=Coverage(inspected=4, skipped={"binary": 2, "over_cap": 1}),
        verify=VerifyResult(replays="not_tested", reason="no eligible match"),
    )
    text = render_find_text(not_found)
    assert "not found in 4 inspected responses; skipped: 2 binary, 1 over the size cap" in text
    assert "replays without a browser: not tested (no eligible match)" in text
    error = FindResult(
        status="error",
        target_host="origin-a.test",
        target_path="/",
        values_count=1,
        short_value_warning=False,
        challenge=ChallengeResult(blocked=False),
        verify=VerifyResult(replays="not_tested", reason="page load failed"),
        warnings=["page load failed: net::ERR_TUNNEL_CONNECTION_FAILED; cannot search"],
    )
    text = render_find_text(error)
    assert "cannot search" in text and "net::ERR_TUNNEL_CONNECTION_FAILED" in text


def test_render_works_on_a_result_rebuilt_from_report_json() -> None:
    data = _found_result().to_dict()
    assert "match_urls" not in data and "starter_code" not in data and "target_url" not in data
    rebuilt = FindResult.from_dict(data)
    text = render_find_text(rebuilt)
    assert "origin-a.test/api/product.json" in text
    assert "curl" not in text  # starter code is terminal-only and not in the report


def test_synthetic_result_fits_schema() -> None:
    assert validate_find_entry(_found_result()) == []


def test_verify_failure_detail_names_classes_and_errno_only() -> None:
    import errno
    import ssl

    from scrapescope.find.verify import failure_detail

    class ConnectError(Exception):
        pass

    try:
        try:
            raise ConnectionRefusedError(errno.ECONNREFUSED, "refused https://secret.test/?token=abc")
        except OSError as inner:
            raise ConnectError("https://secret.test/?token=abc") from inner
    except ConnectError as exc:
        assert failure_detail(exc) == "ConnectError, ECONNREFUSED"
    tls = ConnectError("handshake with secret.test")
    tls.__cause__ = ssl.SSLError(1, "certificate verify failed for secret.test")
    assert failure_detail(tls) == "ConnectError, SSL"
    assert failure_detail(TimeoutError()) == "TimeoutError"


# --------------------------------------------------------------------------- review fixes (2026-09-23)
# find-1: values inside embedded JSON/JS with HTML-safe or JS escapes are found, never "none".


def _next_escape(obj: object) -> str:
    """JSON.stringify + Next.js htmlEscapeJsonString (& < > U+2028 U+2029 as \\uXXXX)."""
    text = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    for ch, esc in (("&", "\\u0026"), (">", "\\u003e"), ("<", "\\u003c"), ("\u2028", "\\u2028"), ("\u2029", "\\u2029")):
        text = text.replace(ch, esc)
    return text


def _rails_escape(obj: object) -> str:
    """ActiveSupport JSON with escape_html_entities_in_json (the Rails default)."""
    return _next_escape(obj)


def _php_hex_escape(obj: object) -> str:
    """PHP json_encode with JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT (uppercase hex, \\/ and \\uXXXX)."""
    text = json.dumps(obj).replace("/", "\\/")
    return text.replace("&", "\\u0026").replace("<", "\\u003C").replace(">", "\\u003E").replace("'", "\\u0027")


EMBED_VALUES = ["Salt & Pepper Mill", "Tom & Jerry Mug <3", "Chef's Knife", "Crème brûlée", "Rock & Roll"]


def _embedded_pages(value: str) -> dict[str, str]:
    data = {"props": {"pageProps": {"product": {"name": value, "price": "1 299,00 €"}}}}
    flight_line = "1:" + json.dumps(["$", "div", None, {"children": value}], ensure_ascii=False)
    js_hex = value.replace("&", "\\x26").replace("'", "\\'").replace("<", "\\x3c")
    return {
        "next-data": f'<html><body><script id="__NEXT_DATA__" type="application/json">{_next_escape(data)}</script></body></html>',
        "ld-json-ascii": f'<script type="application/ld+json">{json.dumps({"@type": "Product", "name": value})}</script>',
        "ld-json-rails": f'<script type="application/ld+json">{_rails_escape({"name": value})}</script>',
        "json-script-php": f'<script type="application/json" id="state">{_php_hex_escape({"item": {"title": value}})}</script>',
        "inline-hex": f"<script>window.__STATE__ = {{name: '{js_hex}'}};</script>",
        "inline-unicode": f"<script>window.__S = {json.dumps({'n': value})};</script>",
        "rsc-flight": f"<script>self.__next_f.push([1,{json.dumps(flight_line)}])</script>",
        "rsc-flight-ascii": f"<script>self.__next_f.push([1,{json.dumps(json.dumps({'t': value}))}])</script>",
    }


@pytest.mark.parametrize("value", EMBED_VALUES)
def test_escaped_embedded_values_are_never_not_found(value: str) -> None:
    for name, page in _embedded_pages(value).items():
        hits = search_body(page, "html", prepare_values([value]), base_locations=["document"])
        assert hits.kinds != ["none"], name
        assert hits.kinds[0] in ("exact", "variant:json-escape", "variant:html-entity"), (name, hits.kinds)
        assert any(loc.startswith("embedded:") for loc in hits.locations), (name, hits.locations)


def test_escaped_embedded_value_labels_and_json_key_locations() -> None:
    page = _embedded_pages("Salt & Pepper Mill")["next-data"]
    assert "Salt & Pepper Mill" not in page and "\\u0026" in page
    hits = search_body(page, "html", prepare_values(["Salt & Pepper Mill"]), base_locations=["document"])
    assert hits.kinds == ["variant:json-escape"]
    assert "embedded:next-data" in hits.locations
    assert "json-key:props.pageProps.product.name" in hits.locations
    # a price with a no-break space, typed with a plain space
    price = search_body(page, "html", prepare_values(["1 299,00 €"]))
    assert price.kinds == ["variant:space-normalized"]
    assert "json-key:props.pageProps.product.price" in price.locations


def test_js_and_json_bodies_decode_escapes_including_double_escaping() -> None:
    assert kind_of("var s = 'A \\x26 B';", "js", "A & B") == "variant:json-escape"
    assert kind_of('var s = "Don\\\'t";', "js", "Don't") == "variant:json-escape"
    assert kind_of('var s = "\\u{1F600} ok";', "js", "\U0001F600 ok") == "variant:json-escape"
    assert kind_of('var s = "\\ud83d\\ude00 ok";', "js", "\U0001F600 ok") == "variant:json-escape"
    double = json.dumps({"payload": _next_escape({"name": "Salt & Pepper <Mill>"})})
    assert "\\\\u0026" in double
    assert kind_of(double, "json", "Salt & Pepper <Mill>") == "variant:json-escape"
    # HTML entities inside a JSON string (rich text) are decoded too
    assert kind_of('{"body_html":"\\u003cp\\u003eTom \\u0026amp; Jerry\\u003c/p\\u003e"}', "json", "Tom & Jerry") == (
        "variant:html-entity"
    )
    # nothing to decode stays "none"
    assert kind_of('{"a": "b"}', "json", "Salt & Pepper") == "none"


def test_html_entity_label_is_not_taken_by_unrelated_backslashes() -> None:
    body = "<p>Fish &amp; Chips</p><script>var re = /\\d+/;</script>"
    assert kind_of(body, "html", "Fish & Chips") == "variant:html-entity"


def test_value_forms_include_html_safe_escapes() -> None:
    pv = prepare_values(["Tom & Jerry <3"])[0]
    assert "Tom \\u0026 Jerry \\u003c3" in pv.json_forms
    assert "Tom \\u0026 Jerry \\u003C3" in pv.json_forms


# find-9: matching is not limited by the JSON walk's node cap.


def test_large_json_is_searched_to_the_end() -> None:
    from scrapescope.find.search import MAX_JSON_NODES

    items = [{"i": i, "n": "x"} for i in range(MAX_JSON_NODES // 2)] + [{"price": "1 299,00 EUR"}]
    body = json.dumps(items)  # ensure_ascii: the no-break space is  
    hits = search_body(body, "json", prepare_values(["1 299,00 EUR"]))
    assert hits.kinds == ["variant:space-normalized"]
    assert search_body(body, "json", prepare_values(["1299 EUR"])).kinds == ["variant:number-format"]


# find-2: a currency symbol or code does not switch off number matching.


@pytest.mark.parametrize(
    ("value", "body", "expected"),
    [
        ("£51.77", '{"price": 51.77}', "variant:number-format"),
        ("$1,299.00", '{"price":1299}', "variant:number-format"),
        ("€129.99", '{"price":"129.99"}', "variant:number-format"),
        ("129,99 €", '{"price":"129.99"}', "variant:number-format"),
        ("129,99 €", '{"price":129.99}', "variant:number-format"),
        ("USD 1,299.00", '{"amount":"1299.00"}', "variant:number-format"),
        ("1.299,00 EUR", '{"amount":1299}', "variant:number-format"),
        ("R$ 1.299,90", '{"p":1299.9}', "variant:number-format"),
        ("US$10", '{"p":10}', "variant:number-format"),
        ("-$5.00", '{"delta":-5}', "variant:number-format"),
        ("£51.77", "<p>£51.77</p>", "exact"),  # the form as typed is still exact
        ("£51.77", "<p>£51.775</p>", "variant:substring"),
        ("£51.77", '{"price": 151.77}', "none"),
        ("£51.77", '{"price": 51.775}', "none"),
    ],
)
def test_currency_values_match_bare_numbers(value: str, body: str, expected: str) -> None:
    kind = "json" if body.startswith("{") else "html"
    assert kind_of(body, kind, value) == expected


def test_strip_currency() -> None:
    from scrapescope.find.search import strip_currency

    assert strip_currency("£51.77") == "51.77"
    assert strip_currency("129,99 €") == "129,99"
    assert strip_currency("129,99 €") == "129,99"
    assert strip_currency("US$ 10") == "10"
    assert strip_currency("EUR 1.299,00") == "1.299,00"
    assert strip_currency("1,299.00 USD") == "1,299.00"
    assert strip_currency("-$5.00") == "-5.00"
    assert strip_currency("¥ 1,299") == "1,299"
    for plain in ("51.77", "WP-1000", "Widget Pro", "In stock (22 available)", "SKU 1000"):
        assert strip_currency(plain) is None, plain


def test_currency_values_count_as_numeric_only() -> None:
    assert is_short_value("£51.77")
    assert is_short_value("1.299,00 EUR")
    assert not is_short_value("Widget Pro 2")


# find-8: numeric values respect digit boundaries; substring hits are labelled and rank last.


def test_numeric_exact_respects_digit_boundaries() -> None:
    assert search_body("<p>£151.77</p>", "html", prepare_values(["51.77"])).kinds == ["variant:substring"]
    assert search_body('{"x":51.775}', "json", prepare_values(["51.77"])).kinds == ["variant:substring"]
    assert search_body("<p>Copyright 2012</p>", "html", prepare_values(["12"])).kinds == ["variant:substring"]
    assert search_body("<p>Only 12 left</p>", "html", prepare_values(["12"])).kinds == ["exact"]
    assert search_body("<p>19.99</p>", "html", prepare_values(["9.99"])).kinds == ["variant:substring"]
    # round 2 (find-r2-3): any value ending in a digit gets the boundary, so a longer SKU is only a weak hit
    assert search_body("<p>WP-10000</p>", "html", prepare_values(["WP-1000"])).kinds == ["variant:substring"]
    # values without a digit at either edge keep substring semantics
    assert search_body("<p>Widget Pros</p>", "html", prepare_values(["Widget Pro"])).kinds == ["exact"]


def _obs(seq: int, kinds: list[str], billed: int, **kw):  # noqa: ANN202 - test helper
    from scrapescope.find.browser import ObservedResponse
    from scrapescope.find.search import BodyHits

    obs = ObservedResponse(
        seq=seq, url=kw.pop("url", f"https://origin-a.test/r{seq}"), host="origin-a.test", port=443,
        scheme="https", method="GET", resource_type="fetch", status=200, **kw,
    )
    obs.encoded_body_bytes = billed
    obs.hits = BodyHits(kinds)
    return obs


def test_ranking_puts_substring_hits_after_boundary_matches_and_more_values_first() -> None:
    from scrapescope.find.core import _ranked_matches

    # round 2 (find-r2-7): a response with only a weak hit is not a match at all
    substring_small = _obs(1, ["variant:substring"], 10)
    exact_big = _obs(2, ["exact"], 5000)
    ranked, dropped = _ranked_matches([substring_small, exact_big])
    assert [o.seq for o in ranked] == [2] and dropped == 0
    # among responses with the same counted values, weak hits rank later
    weak_small = _obs(6, ["exact", "variant:substring"], 10)
    none_big = _obs(7, ["exact", "none"], 5000)
    ranked, _ = _ranked_matches([weak_small, none_big])
    assert [o.seq for o in ranked] == [7, 6]
    # within the "some values" group, more matched values rank first
    one_of_three = _obs(3, ["exact", "none", "none"], 10)
    two_of_three = _obs(4, ["exact", "exact", "none"], 9000)
    all_three = _obs(5, ["exact", "exact", "exact"], 20000)
    ranked, _ = _ranked_matches([one_of_three, two_of_three, all_three])
    assert [o.seq for o in ranked] == [5, 4, 3]


# find-3: HTTP-cache hits.


def test_http_cache_hits_are_recognised_from_sizes() -> None:
    from scrapescope.find.browser import served_from_http_cache

    cached = {"responseBodySize": -207, "responseHeadersSize": 207, "requestHeadersSize": 341, "requestBodySize": 0}
    assert served_from_http_cache(cached, served_by_service_worker=False)
    assert not served_from_http_cache(cached, served_by_service_worker=True)
    network = {"responseBodySize": 1061, "responseHeadersSize": 207}
    assert not served_from_http_cache(network, served_by_service_worker=False)
    assert not served_from_http_cache({}, served_by_service_worker=False)
    assert not served_from_http_cache({"responseBodySize": None, "responseHeadersSize": 5}, served_by_service_worker=False)


def test_cached_copy_is_dropped_when_the_network_copy_matched() -> None:
    from scrapescope.find.core import _ranked_matches

    network = _obs(1, ["exact"], 1061, url="https://origin-a.test/data.json")
    cached = _obs(2, ["exact"], 0, url="https://origin-a.test/data.json", served_from_cache=True)
    ranked, dropped = _ranked_matches([network, cached])
    assert [o.seq for o in ranked] == [1] and dropped == 1
    # a cache-only copy stays, after network responses
    lonely = _obs(3, ["exact"], 0, url="https://origin-a.test/other.json", served_from_cache=True)
    bigger = _obs(4, ["exact"], 9000)
    ranked, dropped = _ranked_matches([lonely, bigger])
    assert [o.seq for o in ranked] == [4, 3] and dropped == 0


# sec-2: paths and JSON key paths never carry a searched value in any searched form.


def test_json_key_paths_drop_number_format_and_digit_run_forms() -> None:
    from scrapescope.find.search import json_key_paths

    hits = search_body(
        json.dumps({"variants": {"48213": {"id": 48213}}}), "json", prepare_values(["48,213"]),
        base_locations=["xhr"], raw_values=["48,213"],
    )
    assert hits.kinds == ["variant:number-format"]
    assert not any("48213" in loc for loc in hits.locations), hits.locations
    assert json_key_paths({"prices": {"1299": "$1,299.00"}}, prepare_values(["$1,299.00"]), ["$1,299.00"]) == [[]]
    big_list = [0] * 3 + [{"sku": "x"}]
    assert json_key_paths(big_list, prepare_values(["x"]), ["3"]) == [[]]  # index [3] is the value "3"
    # unrelated keys stay
    assert json_key_paths({"offers": {"price": "1299.00"}}, prepare_values(["$1,299.00"]), ["$1,299.00"]) == [
        ["offers.price"]
    ]


def test_safe_path_drops_number_format_and_multiply_encoded_forms() -> None:
    from scrapescope.find.core import _safe_path

    assert _safe_path("/item/1299.00/buy", ["1,299.00"]) is None
    assert _safe_path("/item/1.299,00/buy", ["$1,299.00"]) is None
    assert _safe_path("/v1.1299/buy", ["1,299"]) is None
    assert _safe_path("/search/caf%25C3%25A9", ["café"]) is None
    assert _safe_path("/search/caf%2525C3%2525A9", ["café"]) is None
    assert _safe_path("/p/Tom%20%26amp%3B%20Jerry", ["Tom & Jerry"]) is None
    assert _safe_path("/api/product.json", ["£51.77", "Widget Pro"]) == "/api/product.json"


def test_contains_any_value_forms() -> None:
    assert contains_any_value("/p/widget%2520pro", ["Widget Pro"])
    assert contains_any_value("prices.1299", ["$1,299.00"])
    assert contains_any_value("items[48213]", ["48,213"])
    assert not contains_any_value("items[4821]", ["48,213"])
    assert not contains_any_value("offers.price", ["$1,299.00", "Widget Pro"])


def test_no_searched_form_reaches_locations_or_paths_d8() -> None:
    """D8 regression: number-format and double-encoded forms of a value stay out of the report half."""
    from scrapescope.find.core import _safe_path

    values = ["$1,299.00", "café"]
    body = json.dumps({"by_price": {"1299": {"name": "café"}}, "by_name": {"café": 1299}})
    hits = search_body(body, "json", prepare_values(values), base_locations=["fetch"], raw_values=values)
    assert hits.all
    leaked = [loc for loc in hits.locations if contains_any_value(loc, values)]
    assert leaked == [] and not any("1299" in loc for loc in hits.locations), hits.locations
    for path in ("/p/1299", "/p/1.299,00", "/q/caf%25C3%25A9"):
        assert _safe_path(path, values) is None


# find-5: UUIDs, lowercase tokens and path tokens.


@pytest.mark.parametrize(
    ("value", "random"),
    [
        ("550e8400-e29b-41d4-a716-446655440000", True),
        ("550E8400-E29B-41D4-A716-446655440000", True),
        ("cart_550e8400-e29b-41d4-a716-446655440000", True),
        ("k3j4h5g6f7d8s9a0q1w2", True),  # lowercase random id
        ("summer-sale-2026-v2-collection", False),  # slug with a year and a version
        ("product-2024-spring-edition", False),
    ],
)
def test_looks_random_uuids_and_lowercase_ids(value: str, random: bool) -> None:
    assert looks_random(value) is random


def test_random_path_token_detection() -> None:
    from scrapescope.find.heuristics import has_random_path_token, has_random_token

    uuid = "550e8400-e29b-41d4-a716-446655440000"
    assert has_random_query_token(f"https://x.test/api/item?requestId={uuid}")
    assert has_random_query_token(f"https://x.test/api/item?rid={uuid.upper()}")
    assert has_random_path_token("https://x.test/s/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefg/data.json")
    assert has_random_path_token("https://x.test/api/5d41402abc4b2a765d41402abc4b2a76/items.json")
    assert has_random_path_token(f"https://x.test/cart/{uuid}.json")
    assert has_random_token(f"https://x.test/cart/{uuid}.json")
    # slugs, SKUs and short content hashes in file names are allowed
    assert not has_random_path_token("https://x.test/static/js/main.5d41402a.js")
    assert not has_random_path_token("https://x.test/products/widget-pro-2026/wp-1000.json")
    assert not has_random_path_token("https://x.test/")


def test_find_and_reports_share_one_path_token_heuristic() -> None:
    """sec2-12: find flags exactly the path segments that clean_path replaces with {token}."""
    from scrapescope.find.heuristics import has_random_path_token, looks_random_path_segment
    from scrapescope.types import clean_path, is_path_token_segment

    b64 = "aZ3kQ9mX2pL7vB4nR8tY1wE6uI0oP5sD"  # 32 base64url characters, both cases, digits
    segments = [
        b64, b64 + ".json", "5d41402abc4b2a765d41402abc4b2a76", "550e8400-e29b-41d4-a716-446655440000.json",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefg", "main.5d41402a.js", "Galaxy_S24_Ultra_512GB_Titanium_Black",
        "wp-1000.json", "index.html",
    ]
    for seg in segments:
        replaced = "{token}" in (clean_path("/" + seg) or "")
        assert is_path_token_segment(seg) is replaced, seg
        assert looks_random_path_segment(seg) is replaced, seg
        assert has_random_path_token(f"https://x.test/{seg}") is replaced, seg
    assert has_random_path_token(f"https://x.test/s/{b64}/data.json")  # long base64 now counts in find too


def test_path_token_reason() -> None:
    result = code_eligibility(method="GET", status=200, flags=FindFlags(random_query_token=True), token_in_path=True)
    assert not result.eligible and result.reason == "random-looking token in the path"


# find-11 / find-4: starter code names the right proxy variable and warns about br/zstd.


def test_starter_code_proxy_comment_follows_the_scheme() -> None:
    https_code = httpx_snippet("https://origin-a.test/api/product.json", json_body=True)
    assert "HTTPS_PROXY" in https_code and "HTTP_PROXY " not in https_code
    http_code = httpx_snippet("http://quotes.toscrape.com/api/quotes?page=1", json_body=True)
    assert "HTTP_PROXY (not HTTPS_PROXY)" in http_code and "http_proxy" in http_code
    compile(http_code, "<starter>", "exec")


def test_starter_code_mentions_brotli_when_the_browser_got_br() -> None:
    br = httpx_snippet("https://books.toscrape.com/", json_body=False, content_encoding="br")
    assert "br-compressed" in br and "httpx[brotli,zstd]" in br
    compile(br, "<starter>", "exec")
    assert "compressed" not in httpx_snippet("https://books.toscrape.com/", json_body=False, content_encoding="gzip")
    sc = starter_code(1, "https://books.toscrape.com/", json_body=False, content_encoding="zstd")
    assert "zstd-compressed" in sc.httpx


def test_encoding_and_replay_warnings() -> None:
    from scrapescope.find.core import _encoding_warning, _replay_warning
    from scrapescope.find.verify import ReplayDetail

    m = _match(1, encoded_body_bytes=2588, response_header_bytes=0, request_header_bytes=781,
               billed_basis_bytes=2588 + 781 + TLS_HANDSHAKE_ESTIMATE_BYTES)
    obs = _obs(1, ["exact"], 2588, content_encoding="br")
    warning = _encoding_warning([(m, obs)])
    assert warning is not None and "rank 1 (br)" in warning and "gzip or deflate" in warning
    assert _encoding_warning([(m, _obs(2, ["exact"], 10, content_encoding="gzip"))]) is None
    detail = ReplayDetail(received_body_bytes=9279, response_header_bytes=250, request_header_bytes=180,
                          content_encoding="", accept_encoding="gzip, deflate")
    replay = _replay_warning(m, obs, detail)
    assert replay is not None and "9,279 body bytes" in replay and "gzip, deflate" in replay and "(2,588 body bytes, br)" in replay
    close = ReplayDetail(received_body_bytes=2600, response_header_bytes=250, request_header_bytes=180,
                         content_encoding="br", accept_encoding="gzip, deflate, br")
    assert _replay_warning(m, obs, close) is None


# sec-8: --verify never crashes find.


def test_verify_replay_rejects_overlong_urls_as_not_tested() -> None:
    import asyncio

    from scrapescope.find.heuristics import has_random_query_token as token_check
    from scrapescope.find.verify import verify_replay

    url = "https://shop.test/api/item?" + "page=1&" * 12000
    assert not token_check(url)
    result = asyncio.run(verify_replay(url, prepare_values(["x"]), [0], proxy_url="http://127.0.0.1:9", body_cap_bytes=1000))
    assert result.replays == "not_tested"
    assert result.reason == "request failed (InvalidURL)"


def test_verify_top_turns_unexpected_errors_into_not_tested(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    import scrapescope.find.core as core

    async def broken(*_a, **_k):  # noqa: ANN002, ANN003, ANN202
        raise RuntimeError("boom https://secret.test/?token=abc")

    monkeypatch.setattr(core, "verify_replay_detail", broken)
    result, detail = asyncio.run(
        core._verify_top(_obs(1, ["exact"], 10), _match(1), prepare_values(["x"]), proxy_url="http://127.0.0.1:9",
                         ca_file=None, timeout_s=5, body_cap_bytes=100)
    )
    assert (result.replays, result.reason, detail) == ("not_tested", "request failed (RuntimeError)", None)


# find-13: deterministic navigation errors are not retried.


def test_navigation_retry_rule() -> None:
    from scrapescope.find.browser import navigation_retryable

    assert navigation_retryable("net::ERR_TUNNEL_CONNECTION_FAILED")
    assert navigation_retryable("net::ERR_CONNECTION_RESET")
    for reason in ("timeout", "net::ERR_UNSAFE_PORT", "net::ERR_NAME_NOT_RESOLVED", "net::ERR_CERT_AUTHORITY_INVALID",
                   "net::ERR_CERT_COMMON_NAME_INVALID", "net::ERR_TOO_MANY_REDIRECTS"):
        assert not navigation_retryable(reason), reason


# find-7: which sub-responses are classified.


def test_sub_response_classification_scope() -> None:
    from scrapescope.find.browser import ObservedResponse, should_classify

    def obs(resource_type: str, status: int, frame: str = "main") -> ObservedResponse:
        return ObservedResponse(seq=1, url="https://x.test/", host="x.test", port=443, scheme="https", method="GET",
                                resource_type=resource_type, frame=frame, status=status)

    assert not should_classify(obs("document", 403))  # the main document is classified before the search
    assert should_classify(obs("document", 200, frame="sub"))
    assert should_classify(obs("xhr", 200)) and should_classify(obs("fetch", 403))
    assert should_classify(obs("script", 403)) and should_classify(obs("script", 202))
    assert not should_classify(obs("script", 200)) and not should_classify(obs("stylesheet", 200))


# find-12: readable output.


def test_render_middle_truncation_keeps_the_file_name() -> None:
    from scrapescope.find.render import _cell

    css = "books.toscrape.com/static/oscar/js/bootstrap-datetimepicker/bootstrap-datetimepicker.css"
    js = "books.toscrape.com/static/oscar/js/bootstrap-datetimepicker/bootstrap-datetimepicker.min.js"
    assert _cell(css, 60) != _cell(js, 60)
    assert _cell(js, 60).endswith("/bootstrap-datetimepicker.min.js") and len(_cell(js, 60)) == 60
    assert _cell("short/path", 60) == "short/path"


def test_render_is_narrow_lists_kinds_per_value_and_summarises() -> None:
    result = _found_result()
    result.values_count = 2
    result.matches[0].match_kinds = ["exact", "variant:tag-stripped"]
    result.matches[0].values_matched = 2
    result.matches[1].match_kinds = ["exact", "variant:json-escape"]
    result.matches[1].values_matched = 2
    text = render_find_text(result)
    assert "        value 1: exact\n" in text and "        value 2: variant:tag-stripped\n" in text
    first = result.matches[0]
    assert f"smallest with all values: rank 1, {first.billed_basis_bytes:,} B billed-basis\n" in text
    # honest-r3-1: an ineligible top match gets no page-load share
    assert "share of this page load: not shown for rank 1 (no starter code: sent cookies)" in text
    table_lines = [line for line in text.splitlines() if line.startswith("  ") and "billed-basis bytes =" not in line
                   and not line.startswith("  import") and "curl" not in line]
    assert max(len(line) for line in table_lines) <= 100, max(table_lines, key=len)


def test_render_not_found_without_verify_has_no_verify_line() -> None:
    not_found = FindResult(
        status="not_found", target_host="origin-a.test", target_path="/", values_count=1, short_value_warning=False,
        challenge=ChallengeResult(blocked=False, status=200), coverage=Coverage(inspected=2),
        verify=VerifyResult(replays="not_tested", reason="not requested"),
    )
    assert "replays without a browser" not in render_find_text(not_found)
    not_found.verify = VerifyResult(replays="not_tested", reason="no eligible match")
    assert "replays without a browser: not tested (no eligible match)" in render_find_text(not_found)


# find-12: locations per value.


def test_locations_are_recorded_per_value() -> None:
    values = prepare_values(["Widget Pro", "51.77"])
    html = (
        '<html><body><h1>Widget Pro</h1><script type="application/ld+json">'
        '{"offers": {"price": "51.77"}}</script></body></html>'
    )
    hits = search_body(html, "html", values, base_locations=["document"])
    assert hits.kinds[0] != "none" and hits.kinds[1] != "none"
    assert hits.by_value[0] == ["html-text"]
    assert "embedded:ld-json" in hits.by_value[1] and "json-key:offers.price" in hits.by_value[1]
    assert "html-text" not in hits.by_value[1]
    assert hits.locations[0] == "document"  # response-level labels stay in the merged list only
    doc = search_body('{"a": {"name": "Widget Pro"}, "b": [1, 51.77]}', "json", values)
    assert doc.by_value == [["json-key:a.name"], ["json-key:b[1]"]]
    none = search_body("nothing here", "text", values)
    assert none.by_value == [[], []]


def test_render_prints_locations_per_value_and_response_labels() -> None:
    result = _found_result()
    result.values_count = 2
    m = result.matches[1]
    m.match_kinds = ["exact", "variant:number-format"]
    m.values_matched = 2
    m.locations = ["fetch", "iframe", "json-key:name", "json-key:offers.price"]
    m.locations_by_value = [["json-key:name"], ["json-key:offers.price"]]
    m.content_encoding = "br"
    text = render_find_text(result)
    assert "        value 1: exact in json-key:name\n" in text
    assert "        value 2: variant:number-format in json-key:offers.price\n" in text
    assert "        response: iframe\n" in text
    assert "        content-encoding: br\n" in text
    assert validate_find_entry(result) == []


# --------------------------------------------------------------------------- round 2 review (2026-09-23)

# find-r2-1: number-format must not turn round thousands into small numbers or swallow thousands groups.


@pytest.mark.parametrize(
    ("value", "body", "kind"),
    [
        ("1,000", "<p>Page 1 of 3</p>", "html"),
        ("$1,000", '{"v":1}', "json"),
        ("$10,000", "a{width:10px}", "css"),
        ("US$10,000", "<p>Top 10 peaks</p>", "html"),
        ("£2,000", '{"qty": 2}', "json"),
        ("1000", "population 1,000,000", "text"),
        ("1,000", "population 1,000,000", "text"),
        ("1.000", "Einwohner 1.000.000", "text"),
        ("12345", "id 12 345 678", "text"),
        ("345678", "id 12 345 678", "text"),
        ("02134", "zip 2134", "text"),
        ("007", "agent 7", "text"),
        ("4.5", "4,500 reviews", "text"),
        ("-42", "x 42 y", "text"),
    ],
)
def test_number_format_has_no_round_thousands_false_positives(value: str, body: str, kind: str) -> None:
    hits = search_body(body, kind, prepare_values([value]))
    # at most a weak hit (the value inside a longer number), which never counts as found
    assert hits.kinds[0] in ("none", "variant:substring") and hits.values_matched == 0, (value, body, hits.kinds)


@pytest.mark.parametrize(
    ("value", "body"),
    [
        ("1,000", '{"price":1000}'),
        ("1,000", "total 1.000,00 EUR"),
        ("$10,000", '{"amount":"10000.00"}'),
        ("1000", "total 1,000.00"),
        ("1000", "total 1 000"),
        ("007", "agent 007.00"),  # leading zeros kept
        ("-42", "delta −42"),
        ("4.5", "rating 4,50"),
        ("129.9", "129,90"),
    ],
)
def test_number_format_still_matches_real_reformattings(value: str, body: str) -> None:
    assert search_body(body, "text", prepare_values([value])).kinds == ["variant:number-format"], (value, body)


def test_number_pattern_keeps_sign_and_leading_zeros() -> None:
    rx = number_pattern("-42")
    assert rx is not None and rx.search("x -42 y") and not rx.search("x 42 y")
    assert number_pattern("007").search("agent 007") and not number_pattern("007").search("agent 7")
    rx = number_pattern("1,000")
    assert rx is not None and not rx.search("1") and not rx.search("1,000,000") and rx.search("1000")


def test_paths_holding_the_magnitude_of_a_value_are_still_dropped() -> None:
    # the privacy check stays loose: a path with 2134 is dropped for the value 02134, 42 for -42
    assert contains_any_value("/zip/2134", ["02134"])
    assert contains_any_value("/delta/42", ["-42"])
    # ...but a round-thousands value no longer drops every path with a bare 1
    assert not contains_any_value("/v1/items", ["1,000"])


# find-r2-3: any value starting or ending with a digit gets digit boundaries.


@pytest.mark.parametrize(
    ("value", "body"),
    [
        ("22 available", "In stock (122 available)"),
        ("4.5 stars", "Rated 14.5 stars"),
        ("ABC-12", "part ABC-123"),
        ("8,848 m", "height 18,848 m"),
        ("15%", "up 115%"),
        ("2 GB", "12 GB RAM"),
    ],
)
def test_values_with_digit_edges_are_not_exact_inside_longer_numbers(value: str, body: str) -> None:
    hits = search_body(body, "html", prepare_values([value]))
    assert hits.kinds == ["variant:substring"], (value, body)
    assert not hits.any and not hits.all and hits.values_matched == 0


def test_values_with_digit_edges_still_match_on_their_own() -> None:
    for value, body in [("22 available", "In stock (22 available)"), ("ABC-12", "part ABC-12, ABC-13"), ("15%", "up 15%")]:
        assert search_body(body, "html", prepare_values([value])).kinds == ["exact"], (value, body)


# find-r2-4: entities inside JSON and JavaScript bodies without any backslash.


def test_entities_in_json_without_backslashes_are_found_with_a_location() -> None:
    hits = search_body('{"id":7,"title":{"rendered":"Tom &amp; Jerry Mug"}}', "json", prepare_values(["Tom & Jerry Mug"]))
    assert hits.kinds == ["variant:html-entity"]
    assert hits.by_value == [["json-key:title.rendered"]]
    js = search_body('var t = "It&#8217;s here";', "js", prepare_values(["It’s here"]))
    assert js.kinds == ["variant:html-entity"]


# find-r2-7: a value only inside a longer number is not a match.


def test_weak_hits_do_not_count_as_matched() -> None:
    from scrapescope.find.search import BodyHits

    hits = BodyHits(["variant:substring"])
    assert hits.values_matched == 0 and not hits.any and not hits.all and hits.weak_matches == 1
    mixed = BodyHits(["exact", "variant:substring"])
    assert mixed.values_matched == 1 and mixed.any and not mixed.all
    assert BodyHits(["exact", "variant:case-insensitive"]).all


def test_weak_only_responses_are_not_ranked_and_the_result_says_why() -> None:
    from scrapescope.find.core import _ranked_matches, _weak_only_warning

    weak = _obs(1, ["variant:substring"], 10)
    ranked, _ = _ranked_matches([weak])
    assert ranked == []
    warning = _weak_only_warning([weak], 1)
    assert warning is not None and "value 1" in warning and "longer number" in warning


def test_verify_needs_a_non_weak_match_in_the_replay() -> None:
    import asyncio
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from scrapescope.find.verify import verify_replay

    class H(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            body = b"<p>price 122</p>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a) -> None:  # noqa: ANN002
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        from scrapescope.config import ForwarderConfig
        from scrapescope.forwarder import ForwarderThread

        fw = ForwarderThread(ForwarderConfig(allow_private_targets=True))
        fw.start()
        try:
            result = asyncio.run(
                verify_replay(
                    f"http://127.0.0.1:{server.server_address[1]}/p", prepare_values(["12"]), [0],
                    proxy_url=fw.url, body_cap_bytes=1_000_000,
                )
            )
        finally:
            fw.stop()
    finally:
        server.shutdown()
        server.server_close()
    assert result.replays == "no" and result.reason == "value missing"


# sec2-3: --verify decodes with a bounded output, so a compression bomb stops at the cap.


def _gzip_zeros(n: int) -> bytes:
    import zlib

    c = zlib.compressobj(9, zlib.DEFLATED, 31)
    block = b"\0" * (1 << 20)
    out = []
    while n > 0:
        out.append(c.compress(block[: min(n, len(block))]))
        n -= len(block)
    out.append(c.flush())
    return b"".join(out)


def test_bounded_decoder_stops_at_the_cap_and_refuses_stacked_codings() -> None:
    import gzip
    import zlib

    from scrapescope.find.verify import BoundedDecoder, OverCap, UnsupportedEncoding

    bomb = _gzip_zeros(50_000_000)
    assert len(bomb) < 100_000
    dec = BoundedDecoder("gzip", 1_000_000)
    with pytest.raises(OverCap):
        for i in range(0, len(bomb), 16_384):
            dec.feed(bomb[i : i + 16_384])
    assert dec.total <= 1_000_001
    for stacked in ("gzip, gzip", "br", "zstd", "gzip, br", "compress"):
        with pytest.raises(UnsupportedEncoding):
            BoundedDecoder(stacked, 1_000_000)
    # ordinary bodies decode exactly: gzip, zlib deflate, raw deflate and identity
    text = b"<p>Widget Pro 51.77</p>" * 100
    for encoding, data in (
        ("gzip", gzip.compress(text)),
        ("x-gzip", gzip.compress(text)),
        ("deflate", zlib.compress(text)),
        ("deflate", zlib.compress(text)[2:-4]),  # raw deflate, as some servers send it
        ("", text),
        ("identity", text),
    ):
        dec = BoundedDecoder(encoding, 1_000_000)
        for i in range(0, len(data), 7):
            dec.feed(data[i : i + 7])
        assert dec.body() == text, encoding


class _BombHandler:
    """Serve one body with a given Content-Encoding (built per test)."""

    @staticmethod
    def serve(body: bytes, encoding: str):  # noqa: ANN205 - test helper
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        seen: list[str] = []

        class H(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                seen.append(self.headers.get("Accept-Encoding", ""))
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Encoding", encoding)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a) -> None:  # noqa: ANN002
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server, seen


@pytest.mark.parametrize("stacked", [False, True])
def test_verify_survives_a_compression_bomb(stacked: bool) -> None:
    import asyncio
    import gzip
    import tracemalloc

    from scrapescope.config import ForwarderConfig
    from scrapescope.forwarder import ForwarderThread
    from scrapescope.find.verify import REPLAY_ACCEPT_ENCODING, verify_replay_detail

    inner = _gzip_zeros(60_000_000)
    body, encoding = (gzip.compress(inner, 9), "gzip, gzip") if stacked else (inner, "gzip")
    server, seen = _BombHandler.serve(body, encoding)
    fw = ForwarderThread(ForwarderConfig(allow_private_targets=True))
    fw.start()
    try:
        tracemalloc.start()
        try:
            result, detail = asyncio.run(
                verify_replay_detail(
                    f"http://127.0.0.1:{server.server_address[1]}/x", prepare_values(["hello"]), [0],
                    proxy_url=fw.url, body_cap_bytes=1_000_000,
                )
            )
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
    finally:
        fw.stop()
        server.shutdown()
        server.server_close()
    assert result.replays == "not_tested"
    if stacked:
        assert result.reason == "unsupported content encoding (gzip, gzip)"
    else:
        assert result.reason == "response over the size cap"
    assert peak < 15_000_000, peak  # the unbounded decoder allocated the whole 60 MB
    assert seen == [REPLAY_ACCEPT_ENCODING]
    assert detail is not None and detail.accept_encoding == REPLAY_ACCEPT_ENCODING


# find-r2-5: session ids in path parameters, compound signed values and session-like parameter names.


@pytest.mark.parametrize(
    "url",
    [
        "https://x.test/api/stock.json;jsessionid=1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D",
        "https://x.test/shop;jsessionid=abc123/item.json",
        "https://x.test/a/b;PHPSESSID=abcdefghij0123456789/c.json",
        "https://x.test/a;aspsessionidqsctqtrq=ABCDEFGHIJKLMNOP/c.json",
        "https://x.test/a/c.json;sid=12345",
    ],
)
def test_session_path_parameters_withhold_code(url: str) -> None:
    from scrapescope.find.heuristics import has_random_path_token

    assert has_random_path_token(url), url


@pytest.mark.parametrize(
    "query",
    [
        "__token__=exp=1790000000~acl=/*~hmac=" + "a1b2c3d4" * 8,
        "hdnts=exp=1790000000~acl=/*~hmac=" + "a1b2c3d4" * 8,
        "t=exp=1790000000~hmac=" + "a1b2c3d4" * 8,  # an unlisted name: the embedded hex run decides
        "CFID=1234567&CFTOKEN=87654321",
        "_csrf=abc",
        "xsrf=abc",
        "session_token=abc",
        "phpsessid=abcdefghijklmnopqrstuvwxyz",
        "sessionToken=abc",
        "Policy=eyJTdGF0ZW1lbnQiOlt7IlJlc291cmNlIjoiaHR0cHM6Ly9kLmNsb3VkZnJvbnQubmV0LyoifV19&Key-Pair-Id=K2JCJMDEHXQW5F",
        "api_key=abc",
        "p=v1.eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig12345",
    ],
)
def test_signed_and_session_query_values_withhold_code(query: str) -> None:
    assert has_random_query_token(f"https://x.test/api/stock.json?{query}"), query


@pytest.mark.parametrize(
    "query",
    ["author=tolkien", "design=blue", "sort=price&page=2", "q=summer.sale.2026", "signup=1", "insight=3", "v=1"],
)
def test_ordinary_query_names_stay_eligible(query: str) -> None:
    assert not has_random_query_token(f"https://x.test/api/items.json?{query}"), query


def test_ordinary_path_parameters_stay_eligible() -> None:
    from scrapescope.find.heuristics import has_random_path_token

    assert not has_random_path_token("https://x.test/maps/;lat=52.1;lon=4.3/tiles.json")
    assert not has_random_path_token("https://x.test/api/stock.json;v=2")


# find-r2-8: rows that share host and path show their query; also-eligible lists URLs; text labels.


def test_render_tells_apart_rows_with_the_same_path_and_lists_eligible_urls() -> None:
    result = _found_result()
    m1, m2 = result.matches
    m1.path, m1.flags, m1.code_eligible, m1.code_ineligible_reason = "/lib.js", FindFlags(), True, None
    m2.path = "/lib.js"
    m3 = _match(3, path="/w/load.php", flags=FindFlags(random_query_token=True), code_eligible=False,
                code_ineligible_reason="random-looking query token")
    m4 = _match(4, path="/w/load.php")
    result.matches += [m3, m4]
    result.match_urls = {
        "1": "https://origin-a.test/lib.js",
        "2": "https://origin-a.test/lib.js?v=1",
        "3": "https://origin-a.test/w/load.php?sid=abcdef0123456789abcdef",
        "4": "https://origin-a.test/w/load.php?modules=site.styles&only=styles",
    }
    result.starter_code = [
        StarterCode(rank=r, curl=curl_command(result.match_urls[str(r)]), httpx="import httpx\n") for r in (1, 2, 4)
    ]
    text = render_find_text(result)
    assert "        origin-a.test/lib.js\n" in text and "        origin-a.test/lib.js?v=1\n" in text
    assert "        origin-a.test/w/load.php?modules=site.styles&only=styles\n" in text
    # a row flagged for a random-looking token shows a hash of its query, never the token
    assert "abcdef0123456789abcdef" not in text.split("warnings:")[0].replace(result.match_urls["3"], "")
    assert "        origin-a.test/w/load.php?(query " in text
    # ux-r3-1: separated from the starter code by a blank line, with a heading at the outer indentation
    assert (
        "\n\nalso eligible (other responses that would get starter code):\n  rank 2: origin-a.test/lib.js?v=1\n"
        "  rank 4: origin-a.test/w/load.php?modules"
    ) in text


def test_bodies_without_finer_locations_get_a_text_label() -> None:
    values = prepare_values(["Widget Pro"])
    assert search_body('var n = "Widget Pro";', "js", values).by_value == [["script-text"]]
    assert search_body(".x:after{content:'Widget Pro'}", "css", values).by_value == [["css-text"]]
    assert search_body("<a><b>Widget Pro</b></a>", "xml", values).by_value == [["xml-text"]]
    assert search_body("<svg><text>Widget Pro</text></svg>", "xml", values, text_label="svg-text").by_value == [
        ["svg-text"]
    ]
    assert search_body("Widget Pro", "text", values).by_value == [["plain-text"]]
    assert search_body('{"Widget Pro": 1}', "json", values).by_value == [["json-text"]]
    assert search_body('{"n": "Widget Pro"}', "json", values).by_value == [["json-key:n"]]


# find-r2-9: values that were not found are named under the coverage line, with the initial-load note.


def test_render_names_missing_values_under_the_coverage_line() -> None:
    from scrapescope.find.core import INITIAL_LOAD_NOTE, not_found_note

    result = _found_result()
    result.values_count = 2
    for m in result.matches:
        m.match_kinds, m.values_matched, m.all_values = ["exact", "none"], 1, False
    result.warnings.append(not_found_note([1], 2))
    lines = render_find_text(result).splitlines()
    assert lines[1].startswith("searched 13 inspected responses")
    assert lines[2] == f"not found: value 2; {INITIAL_LOAD_NOTE}"
    assert sum(1 for line in lines if "not found: value 2" in line) == 1  # not repeated under warnings
    assert not_found_note([0], 1) == f"not found: the value; {INITIAL_LOAD_NOTE}"
    assert not_found_note([0, 1], 2) == f"not found: every value; {INITIAL_LOAD_NOTE}"
    assert validate_find_entry(result) == []


def test_render_marks_weak_hits_as_not_counted() -> None:
    result = _found_result()
    result.values_count = 2
    m = result.matches[1]
    m.match_kinds, m.values_matched, m.all_values = ["exact", "variant:substring"], 1, False
    text = render_find_text(result)
    assert "        value 2: variant:substring (only inside a longer number; not counted)" in text


# find-x1: recognising the meter's own replies.


def test_meter_error_code_needs_the_header_and_the_meter_body() -> None:
    from scrapescope.find.browser import is_private_literal, meter_error_code
    from scrapescope.find.core import METER_ERROR_REASONS, meter_error_reason

    headers = [("Content-Type", "text/plain; charset=utf-8"), ("X-Scrapescope-Error", "private-address")]
    assert meter_error_code(headers, "scrapescope: refusing a direct connection ...\n") == "private-address"
    assert meter_error_code(headers) == "private-address"  # sub-responses: header only
    assert meter_error_code(headers, "<html>a site page</html>") is None
    assert meter_error_code([("Content-Type", "text/html")], "scrapescope: x") is None
    assert meter_error_code([("x-scrapescope-error", "\u202eevil code")], "scrapescope: x") == "other"
    assert "--allow-private-targets" in METER_ERROR_REASONS["private-address"]
    assert meter_error_reason("socks-reply-5") == "the SOCKS5 upstream refused the connection (socks-reply-5)"
    assert meter_error_reason("new-code") == "the meter refused the request (new-code)"
    for host, private in [("127.0.0.1", True), ("localhost", True), ("192.168.1.1", True), ("::1", True),
                          ("10.0.0.5", True), ("example.com", False), ("8.8.8.8", False), ("a.localhost", True)]:
        assert is_private_literal(host) is private, host


# --------------------------------------------------------------------------- round 3 review


@pytest.mark.parametrize(
    ("body", "kind", "value", "location"),
    [
        ('{"prices":[19.99,24.99]}', "json", "19.99", "json-key:prices[0]"),
        ('{"prices":[19.99,24.99]}', "json", "24.99", "json-key:prices[1]"),
        ('{"ids":[1299,1499,1599]}', "json", "1499", "json-key:ids[1]"),
        ('{"history":[[1690000000,49.99],[1690086400,51.77]]}', "json", "51.77", "json-key:history[1][1]"),
        ('{"pos":[-73.98,40.75]}', "json", "40.75", "json-key:pos[1]"),
        ('{"sizes":[38,39]}', "json", "39", "json-key:sizes[1]"),  # "38,39" also reads as a decimal comma: the leaf decides
        ('{"sizes":[5,50]}', "json", "5", "json-key:sizes[0]"),
    ],
)
def test_numbers_in_compact_json_arrays_are_found_as_themselves(body: str, kind: str, value: str, location: str) -> None:
    """find3-2: the comma between array elements is not a thousands or decimal separator."""
    hits = search_body(body, kind, prepare_values([value]))
    assert hits.kinds == ["exact"], (body, value, hits.kinds)
    assert location in hits.by_value[0]


def test_numbers_in_script_arrays_and_text_lists_are_found() -> None:
    """find3-2: the same element boundaries in JavaScript data and plain lists."""
    chart = "var d=[[1690000000,49.99],[1690086400,51.77]];"
    assert search_body(chart, "js", prepare_values(["51.77", "49.99"])).kinds == ["exact", "exact"]
    assert kind_of("<script>var ids=[1299,1499,1599]</script>", "html", "1499") == "exact"
    assert search_body("Sizes: 38,39,40", "text", prepare_values(["38", "39", "40"])).kinds == ["exact"] * 3
    # a currency value finds the bare number inside an array too
    assert kind_of('{"p":[19.99,24.99]}', "json", "£24.99") == "variant:number-format"
    # an embedded JSON block's leaf decides like a JSON body's
    hits = search_body('<script type="application/json">{"s":[38,39]}</script>', "html", prepare_values(["39"]))
    assert hits.kinds == ["exact"] and "json-key:s[1]" in hits.by_value[0]


@pytest.mark.parametrize(
    ("body", "value"),
    [
        ("<p>51,77 €</p>", "51"),  # decimal comma: 51 is only the integer part
        ("<p>51,77 €</p>", "77"),
        ("<p>1,500 items</p>", "500"),  # thousands comma
        ("<p>1.299,99 €</p>", "1.299"),  # thousands dot and decimal comma
        ("<p>1,299.00</p>", "299.00"),
        ("<p>5 12,5 kg</p>", "12"),  # a space before a non-group run does not make 12,5 a list
        ("price 51.775", "51.77"),
    ],
)
def test_decimal_commas_and_thousands_groups_still_continue_a_number(body: str, value: str) -> None:
    """find3-2: the element-boundary rule keeps decimal commas and thousands groups as one number."""
    kind = "html" if body.startswith("<") else "text"
    assert kind_of(body, kind, value) == "variant:substring", (body, value)


@pytest.mark.parametrize(
    ("body", "value"),
    [
        ("<p>1 500 €</p>", "500 €"),
        ("<p>1 500 €</p>", "500 €"),
        ("<p>1&nbsp;500&nbsp;€</p>", "500 €"),
        ("<p>1 500 €</p>", "500 €"),
        ("<p>1'299.00 CHF</p>", "299.00"),
        ("<p>12 345 678</p>", "12 345"),
        ("<p>12 345 678</p>", "345 678"),
    ],
)
def test_space_and_apostrophe_grouped_numbers_are_not_exact_for_a_part(body: str, value: str) -> None:
    """find3-4: '500 €' is not the price in '1 500 €' (French, Russian, Swiss, Nordic groupings)."""
    assert kind_of(body, "html", value) == "variant:substring", (body, value)


def test_space_grouped_values_are_still_found_as_a_whole_and_next_to_words() -> None:
    """find3-4: the grouping rule only refuses a continued number."""
    assert kind_of("<p>1 500 €</p>", "html", "1 500 €") == "exact"
    assert kind_of("<p>Stock: 12 items</p>", "html", "12") == "exact"
    assert kind_of("<p>Year 2026 100 units</p>", "html", "2026") == "exact"  # a 4-digit run is no group head
    assert kind_of("<p>12 345 678</p>", "html", "12 345 678") == "exact"
    assert kind_of("<p>1 500 €</p>", "html", "1 500 €") == "variant:space-normalized"


def test_leaf_locations_use_the_match_boundaries() -> None:
    """find3-3: a sibling leaf holding a longer number is not a location of the value."""
    by_value = search_body('{"id":112.99,"price":"12.99","old":"12.990"}', "json", prepare_values(["12.99"])).by_value
    assert by_value == [["json-key:price"]]
    assert search_body('{"sku":"ABC-123","code":"ABC-12"}', "json", prepare_values(["ABC-12"])).by_value == [
        ["json-key:code"]
    ]
    html_hits = search_body(
        '<p>Stock 122 left</p><script>var x={"n":"112"}</script><p>12</p>', "html", prepare_values(["12"])
    )
    assert html_hits.kinds == ["exact"] and html_hits.by_value == [["html-text"]]
    # the real leaf is not pushed out by look-alikes (MAX_JSON_KEY_LOCATIONS is 5)
    crowded = {f"n{i}": f"1{i}12.99" for i in range(6)} | {"price": 12.99}
    assert search_body(json.dumps(crowded), "json", prepare_values(["12.99"])).by_value == [["json-key:price"]]


def test_weak_values_keep_the_leaf_of_the_longer_number() -> None:
    """find3-3: a value seen only inside a longer number still says where that number is."""
    hits = search_body('{"id":112.99}', "json", prepare_values(["12.99"]))
    assert hits.kinds == ["variant:substring"] and hits.by_value == [["json-key:id"]]


@pytest.mark.parametrize(
    ("body", "kind", "value"),
    [
        ('{"price":129.99}', "json", "129,99 zł"),
        ('{"price":499}', "json", "499 kr"),
        ('{"price":499}', "json", "499 Kč"),
        ('{"price":499}', "json", "499 Ft"),
        ('{"price":499}', "json", "руб. 499"),
        ('{"price":499}', "json", "R 499"),
        ("<p>129,99 zł</p>", "html", "129.99 zł"),
    ],
)
def test_letter_currency_affixes_allow_number_matching(body: str, kind: str, value: str) -> None:
    """find3-10: zł, kr, Kč, Ft, руб., R are currency affixes like £ or EUR."""
    assert kind_of(body, kind, value) == "variant:number-format", (body, value)
    assert is_short_value(value)  # numeric-only once the currency is set aside


def test_letter_affixes_are_a_closed_list() -> None:
    """find3-10: units and codes are not currencies."""
    from scrapescope.find.search import strip_currency

    assert strip_currency("12 kg") is None and number_pattern("12 kg") is None
    assert strip_currency("R499") is None  # a one-letter prefix needs a space: R499 may be a product code
    assert strip_currency("Widget Pro") is None
    assert strip_currency("499kr") == "499"
