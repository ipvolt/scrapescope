"""find, round 3 review: starter code, decoding, the page-load share, replay candidates, verify edges.

Most tests here run without a browser: ``run_find`` is driven through a fake
``load_page`` that hands it prepared responses (searched with the real
search code), and ``--verify`` replays go through the fixture HTTP upstream
to a small loopback server started here.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import threading
import time
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

import scrapescope.find.core as core
from scrapescope.config import TLS_HANDSHAKE_ESTIMATE_BYTES
from scrapescope.find import render_find_text, run_find
from scrapescope.find.browser import LoadOutcome, MainDocument, ObservedResponse
from scrapescope.find.core import (
    BILLED_BASIS_NOTE,
    BILLED_BASIS_NOTE_HTTP,
    INITIAL_LOAD_NOTE,
    FindInternalError,
    not_found_note,
    short_value_note,
)
from scrapescope.find.heuristics import (
    NOT_EMITTED_TEXT,
    TOKEN_HEADER_REASON,
    code_eligibility,
    decode_body,
    encoding_tokens,
    has_random_query_token,
    is_token_header,
    replay_candidate,
    select_verify_target,
)
from scrapescope.find.search import prepare_values, search_body
from scrapescope.find.starter import curl_command, starter_code
from scrapescope.find.verify import BoundedDecoder, ReplayDetail, UnsupportedEncoding, verify_replay_detail
from scrapescope.types import ChallengeResult, Coverage, FindFlags, FindMatch, FindResult, VerifyResult
from tests.fixtures import TestWorld
from tests.test_find_support import make_test_catalogs, validate_find_entry

# --------------------------------------------------------------------------- sec3-2: curl globbing


def test_curl_starter_turns_globbing_off_for_brackets_and_braces() -> None:
    """sec3-2: Chromium keeps [ ] { } literal; curl would expand them into many requests."""
    url = "https://origin-a.test/api/[1-3]/items?filter[category]=books&q={a,b}&page=[1-50000]&ids[]=7"
    assert curl_command(url) == f"curl --globoff --compressed '{url}'"
    code = starter_code(1, url, json_body=True)
    assert code.curl.startswith("curl --globoff --compressed '")
    assert f"httpx.get({url!r}" in code.httpx  # the httpx snippet never globs
    # URLs without glob characters keep the plan's plain form
    assert curl_command("https://origin-a.test/api/product.json") == "curl --compressed 'https://origin-a.test/api/product.json'"


class _CountingHandler(BaseHTTPRequestHandler):
    paths: list[str] = []

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - quiet test server
        return

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        type(self).paths.append(self.path)
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.mark.skipif(shutil.which("curl") is None, reason="curl not installed")
def test_curl_starter_command_sends_exactly_one_request() -> None:
    """sec3-2: the printed command, run as printed, sends one request with the literal URL."""
    _CountingHandler.paths = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CountingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        path = "/api/items?filter[category]=books&page=[1-5]&x={a,b}"
        command = curl_command(f"http://127.0.0.1:{server.server_address[1]}{path}")
        proc = subprocess.run(
            ["sh", "-c", command + " --silent --noproxy '*'"], capture_output=True, text=True, timeout=30
        )
    finally:
        server.shutdown()
        server.server_close()
    assert proc.returncode == 0, proc.stderr
    assert _CountingHandler.paths == [path]


# --------------------------------------------------------------------------- sec3-3: site-chosen charsets


@pytest.mark.parametrize("charset", ["undefined", "idna", "punycode", "no-such-codec", "rot13", "base64"])
def test_decode_body_never_raises_for_a_site_chosen_charset(charset: str) -> None:
    """sec3-3: undefined, idna and punycode raise UnicodeError (a ValueError) with errors='replace'."""
    body = "Widget Pro é".encode() + b"\xff"
    text = decode_body(body, f"text/html; charset={charset}", "html")
    assert "Widget Pro" in text  # punycode decodes some inputs (to nonsense) instead of raising
    meta = decode_body(f'<meta charset="{charset}"><p>Widget Pro</p>'.encode(), None, "html")
    assert "Widget Pro" in meta


def test_utf7_is_not_a_web_encoding() -> None:
    """sec3-3 follow-up: browsers have no UTF-7, so find does not decode +ADw-...+AD4- into markup."""
    text = decode_body(b"<p>+ADw-b+AD4-Widget Pro</p>", "text/html; charset=utf-7", "html")
    assert text == "<p>+ADw-b+AD4-Widget Pro</p>"


def test_a_late_value_error_is_never_reported_as_a_usage_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """sec3-3: a ValueError after the arguments were accepted is find's own failure, not exit 2."""

    async def broken_load(*args: Any, **kwargs: Any) -> LoadOutcome:
        raise ValueError("unexpected input from the page")

    monkeypatch.setattr(core, "load_page", broken_load)
    with pytest.raises(FindInternalError) as info:
        asyncio.run(run_find("https://origin-a.test/", ["x"], proxy_url="http://127.0.0.1:9", catalogs=make_test_catalogs()))
    assert not isinstance(info.value, ValueError)
    assert "origin-a" not in str(info.value)
    # bad arguments are still a ValueError (usage)
    with pytest.raises(ValueError):
        asyncio.run(run_find("ftp://origin-a.test/", ["x"], proxy_url="http://127.0.0.1:9", catalogs=make_test_catalogs()))


# --------------------------------------------------------------------------- sec3-6: Content-Encoding text


def test_encoding_tokens_keep_codings_and_drop_text() -> None:
    hostile = "identity, Visit http://evil.example/claim to renew your scrapescope license"
    assert encoding_tokens(hostile) == "identity, other"
    assert encoding_tokens("GZIP, br") == "gzip, br"
    assert encoding_tokens("") == "" and encoding_tokens(None) == ""
    assert encoding_tokens("a,b,c,d,e,f") == "a, b, c, d, ..."
    with pytest.raises(UnsupportedEncoding) as info:
        BoundedDecoder(hostile, 1000)
    assert str(info.value) == "other"
    with pytest.raises(UnsupportedEncoding) as info:
        BoundedDecoder("gzip, " + "x" * 300, 1000)
    assert str(info.value) == "gzip, other"


def test_replay_warning_shows_coding_tokens_only() -> None:
    """sec3-6: the replay warning compares codings, never the site's header text."""
    match = _m(1, billed=1_000, tls=0)
    obs = _obs(1, "http://127.0.0.1:1/a.json")
    obs.content_encoding = "gzip"
    detail = ReplayDetail(
        received_body_bytes=100_000,
        response_header_bytes=200,
        request_header_bytes=100,
        content_encoding="identity, Visit http://evil.example/claim to renew",
        accept_encoding="gzip, deflate",
    )
    warning = core._replay_warning(match, obs, detail)
    assert warning is not None and "evil" not in warning and "identity, other" in warning


# --------------------------------------------------------------------------- helpers: synthetic matches


def _m(rank: int, *, billed: int = 1_000, tls: int = TLS_HANDSHAKE_ESTIMATE_BYTES, **kw: Any) -> FindMatch:
    base: dict[str, Any] = dict(
        rank=rank,
        host="origin-a.test",
        port=443,
        scheme="https" if tls else "http",
        path=f"/r{rank}",
        method="GET",
        resource_type="fetch",
        status=200,
        mime_type="application/json",
        all_values=True,
        values_matched=1,
        match_kinds=["exact"],
        locations=["fetch", "json-key:price"],
        encoded_body_bytes=billed - tls - 300,
        response_header_bytes=200,
        request_header_bytes=100,
        tls_handshake_estimate=tls,
        billed_basis_bytes=billed,
        flags=FindFlags(),
        code_eligible=True,
        code_ineligible_reason=None,
        locations_by_value=[["json-key:price"]],
    )
    base.update(kw)
    return FindMatch(**base)


def _result(matches: list[FindMatch], *, page: int, verify: VerifyResult | None = None) -> FindResult:
    return FindResult(
        status="found",
        target_host="origin-a.test",
        target_path="/",
        values_count=1,
        short_value_warning=False,
        challenge=ChallengeResult(blocked=False, status=200),
        matches=matches,
        coverage=Coverage(inspected=len(matches)),
        verify=verify or VerifyResult(replays="not_tested", reason="not requested"),
        page_reported_bytes=page,
        target_url="https://origin-a.test/",
        match_urls={str(m.rank): f"https://origin-a.test{m.path}" for m in matches},
    )


# --------------------------------------------------------------------------- find3-1, honest-r3-1: the share line


def test_share_compares_body_and_headers_with_devtools_bytes() -> None:
    """find3-1: an https JSON loaded on its own is 100% of its page load, never 810%."""
    only = _m(1, billed=1_014 + TLS_HANDSHAKE_ESTIMATE_BYTES)
    text = render_find_text(_result([only], page=1_014))
    assert "smallest with all values: rank 1, 8,214 B billed-basis\n" in text
    assert "share: 100.0% of this page load (1,014 B body and headers against 1,014 B DevTools-reported" in text
    assert "810" not in text
    # the whole page load saves nothing, even when --verify replayed it
    replayed = render_find_text(_result([only], page=1_014, verify=VerifyResult(replays="yes", status=200)))
    share_line = next(line for line in replayed.splitlines() if line.startswith("share: "))
    assert share_line.endswith("; no saving: this one response is the whole page load"), share_line
    assert "a saving" not in replayed
    # a small JSON on a larger page: 1,014 of 692,000 is 0.1%, not the 1.2% the TLS estimate made it
    small = render_find_text(_result([_m(1, billed=1_014 + TLS_HANDSHAKE_ESTIMATE_BYTES)], page=692_000))
    assert "share: 0.1% of this page load" in small


@pytest.mark.parametrize(
    ("verify", "expected"),
    [
        (VerifyResult(replays="not_tested", reason="not requested"), "not a saving until --verify replays it"),
        (VerifyResult(replays="yes", status=200, received_bytes=700), "a saving: --verify replayed it without a browser"),
        (VerifyResult(replays="no", status=403, reason="status 403"), "not a saving: the --verify replay failed (status 403)"),
        (
            VerifyResult(replays="not_tested", reason="request failed (ConnectError)"),
            "not a saving yet: the --verify replay was not tested (request failed (ConnectError))",
        ),
    ],
)
def test_share_is_called_a_saving_only_when_verify_replayed_it(verify: VerifyResult, expected: str) -> None:
    """honest-r3-1 / plan section 5 step 6: savings appear only for yes."""
    text = render_find_text(_result([_m(1)], page=40_000, verify=verify))
    share_line = next(line for line in text.splitlines() if line.startswith("share: "))
    assert share_line.endswith(expected), share_line
    assert sum("; a saving:" in line for line in text.splitlines()) == (1 if verify.replays == "yes" else 0)


def test_no_share_for_a_top_match_that_needs_the_browser() -> None:
    """honest-r3-1: a cookie-sending top match that was not replayed gets no page-load share."""
    session = _m(1, billed=721, tls=0, flags=FindFlags(sent_cookies=True), code_eligible=False,
                 code_ineligible_reason="sent cookies")
    page_doc = _m(2, billed=37_789, tls=0, resource_type="document")
    for verify in (
        VerifyResult(replays="not_tested", reason="not requested"),
        VerifyResult(replays="no", status=401, reason="status 401"),
    ):
        text = render_find_text(_result([session, page_doc], page=37_789, verify=verify))
        assert "% of this page load" not in text, text
        line = next(line for line in text.splitlines() if line.startswith("share of this page load"))
        assert line.startswith("share of this page load: not shown for rank 1 (")
        if verify.replays == "no":
            assert "did not replay without the browser's cookies: status 401" in line
            assert f"rank 1 (sent cookies): {NOT_EMITTED_TEXT}" in text
        else:
            assert "the browser sent cookies with it; not tested without them" in line
    authorized = _m(1, flags=FindFlags(sent_authorization=True), code_eligible=False,
                    code_ineligible_reason="sent authorization")
    text = render_find_text(_result([authorized], page=40_000))
    assert "share of this page load: not shown for rank 1 (no starter code: sent authorization)" in text


def test_share_line_is_the_same_for_a_result_rebuilt_from_its_report_entry() -> None:
    """find3-1 / honest-r3-1: reports can print the terminal's share line from report.json alone."""
    from scrapescope.find.render import share_line

    session = _m(1, billed=721, tls=0, flags=FindFlags(sent_cookies=True), code_eligible=False,
                 code_ineligible_reason="sent cookies")
    cases = [
        _result([_m(1, billed=1_014 + TLS_HANDSHAKE_ESTIMATE_BYTES)], page=692_000,
                verify=VerifyResult(replays="yes", status=200, received_bytes=700)),
        _result([_m(1)], page=40_000, verify=VerifyResult(replays="no", status=403, reason="status 403")),
        _result([session, _m(2, billed=37_789, tls=0)], page=37_789,
                verify=VerifyResult(replays="no", status=401, reason="status 401")),
        _result([_m(1, billed=1_014)], page=1_014),
    ]
    for result in cases:
        line = share_line(result)
        assert line is not None and line in render_find_text(result)
        assert share_line(FindResult.from_dict(result.to_dict())) == line
    assert share_line(_result([_m(1, billed=50_000)], page=1_000)) is None


def test_share_is_left_out_when_it_cannot_be_like_for_like() -> None:
    """find3-1: never over 100%, and no share for a copy that did not cross the network."""
    too_big = render_find_text(_result([_m(1, billed=50_000)], page=1_000))
    assert "share" not in too_big.split("matches (")[0]
    cached = render_find_text(_result([_m(1, locations=["fetch", "served-from-cache"])], page=40_000))
    assert "share" not in cached.split("matches (")[0]


# --------------------------------------------------------------------------- find3-6: token headers


@pytest.mark.parametrize(
    ("name", "value", "token"),
    [
        ("x-api-key", "k9J2mQ7xL4pZ8vB3nR6tY1wE5", True),
        ("X-CSRF-Token", "abc", True),
        ("x-xsrf-token", "abc", True),
        ("x-auth-token", "a", True),
        ("x-access-token", "a", True),
        ("x-session-id", "1", True),
        ("api-key", "a", True),
        ("ocp-apim-subscription-key", "a", True),
        ("x-request-id", "550e8400-e29b-41d4-a716-446655440000", True),  # a random value in an x- header
        ("x-requested-with", "XMLHttpRequest", False),
        ("x-client-data", "CIa2yQEIo7bJAQipncoBCKijywE=", False),  # Chrome's own header
        ("accept", "*/*", False),
        ("x-author", "bob", False),
        ("cookie", "a=b", False),  # its own flag
        ("authorization", "Bearer x", False),  # its own flag
    ],
)
def test_token_like_request_headers(name: str, value: str, token: bool) -> None:
    assert is_token_header(name, value) is token


def test_token_header_withholds_code_with_its_own_reason() -> None:
    """find3-6: a fetch that sent x-api-key is not 'a GET that sent no ... token'."""
    got = code_eligibility(method="GET", status=200, flags=FindFlags(), sent_token_header=True)
    assert (got.eligible, got.reason) == (False, TOKEN_HEADER_REASON)
    match = _m(1, code_eligible=False, code_ineligible_reason=TOKEN_HEADER_REASON)
    text = render_find_text(_result([match], page=40_000))
    assert "token-header" in text and "starter code" not in text
    assert (
        "rank 1 (sent a token header): not emitted: the browser sent a token header with it and it was not tested "
        "without it (--verify replays it once without it)" in text
    )
    assert "share of this page load: not shown for rank 1 (the browser sent a token header with it; not tested without it)" in text


# --------------------------------------------------------------------------- find3-7: replay candidates


def test_replay_candidates_are_matches_ineligible_only_for_sent_state() -> None:
    cookie = _m(1, flags=FindFlags(sent_cookies=True), code_eligible=False, code_ineligible_reason="sent cookies")
    assert replay_candidate(cookie)
    header = _m(1, code_eligible=False, code_ineligible_reason=TOKEN_HEADER_REASON)
    assert replay_candidate(header)
    for other in (
        _m(1, flags=FindFlags(sent_cookies=True, sent_authorization=True), code_eligible=False,
           code_ineligible_reason="sent cookies"),
        _m(1, flags=FindFlags(sent_cookies=True, random_query_token=True), code_eligible=False,
           code_ineligible_reason="sent cookies"),
        _m(1, flags=FindFlags(sent_cookies=True, non_get=True), method="POST", code_eligible=False,
           code_ineligible_reason="sent cookies"),
        _m(1, flags=FindFlags(sent_cookies=True), status=404, code_eligible=False, code_ineligible_reason="sent cookies"),
        _m(1, flags=FindFlags(sent_cookies=True), locations=["fetch", "served-by-service-worker"], code_eligible=False,
           code_ineligible_reason="sent cookies"),
        _m(1, code_eligible=True),
    ):
        assert not replay_candidate(other)


def test_verify_target_prefers_a_much_smaller_candidate_over_the_page() -> None:
    """find3-7: a 726 B JSON that only sent an analytics cookie is replayed, not the 38 kB HTML."""
    json_xhr = _m(1, billed=726, tls=0, flags=FindFlags(sent_cookies=True), code_eligible=False,
                  code_ineligible_reason="sent cookies")
    html_doc = _m(2, billed=38_000, tls=0, resource_type="document")
    assert select_verify_target([json_xhr, html_doc]) is json_xhr
    # an eligible response of similar size holding the same values is the safer single replay
    similar = _m(2, billed=900, tls=0)
    assert select_verify_target([json_xhr, similar]) is similar
    # ...but not one that holds fewer values
    partial = _m(2, billed=900, tls=0, all_values=False, values_matched=0)
    assert select_verify_target([json_xhr, partial]) is json_xhr
    # the choice is stable once the candidate replayed and became eligible
    json_xhr.code_eligible, json_xhr.code_ineligible_reason = True, None
    assert select_verify_target([json_xhr, html_doc]) is json_xhr
    assert select_verify_target([]) is None


# --------------------------------------------------------------------------- find3-13: content hashes


def test_persisted_query_hashes_and_jsonp_callbacks_are_not_tokens() -> None:
    digest = "a1" * 32
    persisted = (
        "https://origin-a.test/graphql?operationName=ProductQuery&variables=%7B%22id%22%3A42%7D"
        f'&extensions={{"persistedQuery":{{"version":1,"sha256Hash":"{digest}"}}}}'
    )
    assert has_random_query_token(persisted) is False
    jsonp = "https://origin-a.test/p?callback=jQuery112409876543210_1690000000000&_=1690000000000"
    assert has_random_query_token(jsonp) is False
    # the rest of the value is still checked, and other callback names are not exempt
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk"
    mixed = (
        f'https://origin-a.test/graphql?extensions={{"persistedQuery":{{"version":1,"sha256Hash":"{digest}"}},'
        f'"auth":"{jwt}"}}'
    )
    assert has_random_query_token(mixed) is True
    assert has_random_query_token("https://origin-a.test/p?callback=a8Kd93jLmQ2xZ7pR4tV6yB1n") is True
    assert has_random_query_token(f"https://origin-a.test/app.js?v={digest[:16]}") is True  # unchanged


# --------------------------------------------------------------------------- find3-8, find3-14: wording


def test_not_found_on_an_error_document_names_the_status_not_scrolling() -> None:
    """find3-8: a 403 block page is not 'content loaded later by scrolling'."""
    note = not_found_note([0], 1, main_status=403, vendor="Cloudflare")
    assert note.startswith("not found: the value; the main document returned status 403 (Cloudflare signals present)")
    assert "scrolling" not in note
    assert not_found_note([0], 1, main_status=404).startswith("not found: the value; the main document returned status 404,")
    assert not_found_note([0], 1, main_status=200) == f"not found: the value; {INITIAL_LOAD_NOTE}"


def test_readability_nits() -> None:
    """find3-14: plural pronoun, TLS note only for https, merged not-found line."""
    assert "a match for them alone" in short_value_note([0, 1])
    assert "a match for it alone" in short_value_note([1])
    plain = render_find_text(_result([_m(1, tls=0, billed=5_000)], page=40_000))
    assert BILLED_BASIS_NOTE_HTTP in plain and "TLS handshake estimate" not in plain
    tls = render_find_text(_result([_m(1)], page=40_000))
    assert BILLED_BASIS_NOTE in tls
    nothing = FindResult(
        status="not_found", target_host="origin-a.test", target_path="/", values_count=2, short_value_warning=False,
        challenge=ChallengeResult(blocked=False, status=200), coverage=Coverage(inspected=2),
        warnings=[not_found_note([0, 1], 2)],
    )
    lines = render_find_text(nothing).splitlines()
    assert lines[1] == "not found in 2 inspected responses; skipped: none"
    assert lines[2] == INITIAL_LOAD_NOTE
    assert sum("not found" in line for line in lines) == 1


# --------------------------------------------------------------------------- run_find with a fake page load


def _obs(seq: int, url: str, *, body: str = "", kind: str = "json", resource_type: str = "fetch", size: int = 0,
         **kw: Any) -> ObservedResponse:
    import urllib.parse

    parts = urllib.parse.urlsplit(url)
    obs = ObservedResponse(
        seq=seq,
        url=url,
        host=parts.hostname or "",
        port=parts.port or (443 if parts.scheme == "https" else 80),
        scheme=parts.scheme,
        method="GET",
        resource_type=resource_type,
        status=200,
        mime="application/json" if kind == "json" else "text/html",
        body_kind=kind,
        encoded_body_bytes=size or len(body),
        response_header_bytes=200,
        request_header_bytes=300,
    )
    for key, value in kw.items():
        setattr(obs, key, value)
    return obs


def _fake_load(
    monkeypatch: pytest.MonkeyPatch,
    responses: list[tuple[ObservedResponse, str]],
    *,
    main: MainDocument | None = None,
    calls: list[dict[str, Any]] | None = None,
) -> None:
    """Replace load_page: call on_main_document, then search the given bodies with the real search."""

    async def fake(url: str, *, values: Any, raw_values: Any, on_main_document: Callable[[MainDocument], bool],
                   **kwargs: Any) -> LoadOutcome:
        if calls is not None:
            calls.append(kwargs)
        doc = main or MainDocument(200, [("Content-Type", "text/html")], "<p>page</p>", "https", "origin-a.test", 443)
        outcome = LoadOutcome(ok=True, main=doc)
        if not on_main_document(doc):
            return outcome
        outcome.searched = True
        for obs, body in responses:
            if obs.skip is None:
                obs.hits = search_body(body, obs.body_kind or "json", values, base_locations=[obs.resource_type],
                                       raw_values=raw_values)
            outcome.responses.append(obs)
        return outcome

    monkeypatch.setattr(core, "load_page", fake)


def _run(url: str, values: list[str], **kwargs: Any) -> FindResult:
    kwargs.setdefault("catalogs", make_test_catalogs())
    return asyncio.run(run_find(url, values, proxy_url="http://127.0.0.1:9", **kwargs))


def test_page_load_bytes_leave_out_service_worker_and_cache_copies(monkeypatch: pytest.MonkeyPatch) -> None:
    """find3-11: a response a service worker served never crossed the network (its fetch did)."""
    doc = _obs(1, "https://origin-a.test/", body="<p>x</p>", kind="html", resource_type="document", size=5_000)
    backend = _obs(2, "https://origin-a.test/api/sw-backend.json", body='{"m":"SW-1"}', size=400)
    served = _obs(3, "https://origin-a.test/api/sw.json", body='{"m":"SW-1"}', size=400, served_by_service_worker=True)
    cached = _obs(4, "https://origin-a.test/static/app.js", body="var a;", kind="js", resource_type="script",
                  served_from_cache=True)
    cached.encoded_body_bytes = cached.response_header_bytes = cached.request_header_bytes = 0
    _fake_load(monkeypatch, [(doc, "<p>x</p>"), (backend, '{"m":"SW-1"}'), (served, '{"m":"SW-1"}'), (cached, "var a;")])
    result = _run("https://origin-a.test/", ["SW-1"])
    assert result.page_reported_bytes == doc.reported_bytes + backend.reported_bytes
    assert validate_find_entry(result) == []


def test_imitated_meter_reply_on_the_main_document_is_the_sites(monkeypatch: pytest.MonkeyPatch) -> None:
    """sec3-4: a site's forged X-Scrapescope-Error is not reported as the meter's refusal."""
    forged = MainDocument(
        403,
        [("Content-Type", "text/plain"), ("X-Scrapescope-Error", "private-address")],
        "scrapescope: refusing a direct connection to a loopback, private or link-local address\n",
        "http",
        "127.0.0.1",
        18452,
    )
    page = _obs(1, "http://127.0.0.1:18452/", body="scrapescope: refusing", kind="text", resource_type="document")
    asked: list[tuple[str, str, int]] = []

    def no_such_refusal(code: str, host: str, port: int) -> bool:
        asked.append((code, host, port))
        return False

    _fake_load(monkeypatch, [(page, "scrapescope: refusing a direct connection")], main=forged)
    result = _run("http://127.0.0.1:18452/", ["abc"], meter_reply_check=no_such_refusal)
    assert asked == [("private-address", "127.0.0.1", 18452)]
    assert result.status == "not_found"
    text = render_find_text(result)
    assert "--allow-private-targets" not in text
    assert any("the site sent the header itself" in w for w in result.warnings)
    # confirmed by the meter's records: the load error names the meter's reason
    _fake_load(monkeypatch, [], main=forged)
    confirmed = _run("http://127.0.0.1:18452/", ["abc"], meter_reply_check=lambda c, h, p: True)
    assert confirmed.status == "error"
    assert any("is the meter's own reply" in w and "--allow-private-targets" in w for w in confirmed.warnings)
    # no check available: still an error, but the warning says it was not checked
    unchecked = _run("http://127.0.0.1:18452/", ["abc"])
    assert unchecked.status == "error"
    warning = next(w for w in unchecked.warnings if w.startswith("page load failed"))
    assert "not checked against the meter's records" in warning and "X-Scrapescope-Error: private-address" in warning


def test_imitated_meter_reply_of_a_sub_response_is_named(monkeypatch: pytest.MonkeyPatch) -> None:
    """sec3-4: sub-responses the collector found imitated are searched and named, without the hint."""
    doc = _obs(1, "http://127.0.0.1:18452/", body="<p>Widget Pro</p>", kind="html", resource_type="document")
    sub = _obs(2, "http://127.0.0.1:18452/api/x", body='{"n":"Widget Pro"}', imitated_meter_error="private-address")
    _fake_load(monkeypatch, [(doc, "<p>Widget Pro</p>"), (sub, '{"n":"Widget Pro"}')],
               main=MainDocument(200, [], "<p>Widget Pro</p>", "http", "127.0.0.1", 18452))
    result = _run("http://127.0.0.1:18452/", ["Widget Pro"])
    warning = next(w for w in result.warnings if "X-Scrapescope-Error" in w)
    assert "private-address x1" in warning and "searched as the site's responses" in warning
    assert "--allow-private-targets" not in warning
    assert len(result.matches) == 2


def test_error_document_not_found_names_the_vendor(monkeypatch: pytest.MonkeyPatch) -> None:
    """find3-8: a 403 page with vendor signals, value absent: the note names the status, not scrolling."""
    body = "<html><body><h1>Sorry, you have been blocked</h1><p>Error 1020</p></body></html>"
    main = MainDocument(403, [("Content-Type", "text/html"), ("Set-Cookie", "__cf_bm=abc; path=/")], body, "https",
                        "origin-a.test", 443)
    doc = _obs(1, "https://origin-a.test/", body=body, kind="html", resource_type="document")
    doc.status = 403
    _fake_load(monkeypatch, [(doc, body)], main=main)
    result = _run("https://origin-a.test/", ["Widget Pro"])
    assert result.status == "not_found" and result.challenge.vendor_name == "Cloudflare"
    note = next(w for w in result.warnings if w.startswith("not found:"))
    assert "status 403 (Cloudflare signals present)" in note and "scrolling" not in note
    text = render_find_text(result)
    assert "scrolling" not in text


def _verify_stub(monkeypatch: pytest.MonkeyPatch, outcome: VerifyResult, seen: list[str]) -> None:
    async def fake_verify(url: str, *args: Any, **kwargs: Any) -> tuple[VerifyResult, ReplayDetail | None]:
        seen.append(url)
        detail = ReplayDetail(received_body_bytes=outcome.received_bytes or 0, response_header_bytes=150,
                              request_header_bytes=120, content_encoding="", accept_encoding="gzip, deflate")
        return outcome, detail

    monkeypatch.setattr(core, "verify_replay_detail", fake_verify)


def _cookie_page(monkeypatch: pytest.MonkeyPatch) -> None:
    html = "<p>Widget Pro 51.77</p>" + "<p>filler</p>" * 3_000
    doc = _obs(1, "http://127.0.0.1:18460/ck", body=html, kind="html", resource_type="document")
    api = _obs(2, "http://127.0.0.1:18460/api/p2.json", body='{"name":"Widget Pro","price":51.77}', sent_cookies=True)
    _fake_load(monkeypatch, [(doc, html), (api, '{"name":"Widget Pro","price":51.77}')],
               main=MainDocument(200, [], html, "http", "127.0.0.1", 18460))


def test_a_cookie_only_match_is_replayed_and_gets_code_when_it_replays(monkeypatch: pytest.MonkeyPatch) -> None:
    """find3-7: the small JSON that only sent an analytics cookie is what --verify tests."""
    _cookie_page(monkeypatch)
    seen: list[str] = []
    _verify_stub(monkeypatch, VerifyResult(replays="yes", status=200, received_bytes=40), seen)
    result = _run("http://127.0.0.1:18460/ck", ["Widget Pro", "51.77"], verify=True)
    assert seen == ["http://127.0.0.1:18460/api/p2.json"]
    api = result.matches[0]
    assert api.path == "/api/p2.json" and api.flags.sent_cookies is True
    assert api.code_eligible is True and api.code_ineligible_reason is None
    assert [c.rank for c in result.starter_code] == [1, 2]
    text = render_find_text(result)
    assert (
        "starter code (rank 1: one --verify replay without the browser's cookies, headers or tokens returned the "
        "values found in it; check the site's terms):"
    ) in text
    assert "a saving: --verify replayed it without a browser" in text
    assert "replays without a browser: yes (rank 1," in text
    assert validate_find_entry(result) == []


def test_a_cookie_only_match_that_does_not_replay_gets_no_code(monkeypatch: pytest.MonkeyPatch) -> None:
    _cookie_page(monkeypatch)
    seen: list[str] = []
    _verify_stub(monkeypatch, VerifyResult(replays="no", status=401, received_bytes=20, reason="status 401"), seen)
    result = _run("http://127.0.0.1:18460/ck", ["Widget Pro", "51.77"], verify=True)
    api = result.matches[0]
    assert api.code_eligible is False and api.code_ineligible_reason == "sent cookies"
    assert [c.rank for c in result.starter_code] == [2]
    text = render_find_text(result)
    assert f"rank 1 (sent cookies): {NOT_EMITTED_TEXT}" in text
    assert "replays without a browser: no (rank 1, status 401)" in text
    assert "share of this page load: not shown for rank 1 (it did not replay without the browser's cookies: status 401)" in text


def test_without_verify_a_cookie_only_match_says_it_is_untested(monkeypatch: pytest.MonkeyPatch) -> None:
    _cookie_page(monkeypatch)
    result = _run("http://127.0.0.1:18460/ck", ["Widget Pro", "51.77"])
    text = render_find_text(result)
    assert (
        "rank 1 (sent cookies): not emitted: the browser sent cookies with it and it was not tested without them "
        "(--verify replays it once without them)"
    ) in text
    assert NOT_EMITTED_TEXT not in text


def test_no_replay_after_the_budget_tripped(monkeypatch: pytest.MonkeyPatch) -> None:
    """find3-5: the meter refuses new requests once the budget tripped; the replay is not sent."""
    _cookie_page(monkeypatch)
    seen: list[str] = []
    _verify_stub(monkeypatch, VerifyResult(replays="yes", status=200), seen)
    hooked: list[bool] = []
    result = _run("http://127.0.0.1:18460/ck", ["Widget Pro", "51.77"], verify=True,
                  abort_check=lambda: "the byte budget tripped", before_verify=lambda: hooked.append(True))
    assert seen == [] and hooked == []
    assert result.verify.replays == "not_tested" and result.verify.reason == "not sent: the byte budget tripped"
    assert result.verify.replay_billed_basis_bytes is None
    text = render_find_text(result)
    assert "replays without a browser: not tested (not sent: the byte budget tripped)" in text
    # the untested cookie-sending match does not tell the user to run --verify, which they did
    line = next(line for line in text.splitlines() if "not emitted: the browser sent cookies" in line)
    assert line.endswith("(the --verify replay was not sent: the byte budget tripped)"), line
    # an eligible top match whose replay was not sent is "not a saving yet", naming why
    eligible = _result([_m(1)], page=40_000,
                       verify=VerifyResult(replays="not_tested", reason="not sent: the byte budget tripped"))
    share = next(line for line in render_find_text(eligible).splitlines() if line.startswith("share: "))
    assert share.endswith("; not a saving yet: the --verify replay was not sent: the byte budget tripped"), share


def test_meter_reply_check_reaches_the_page_load_and_the_replay(monkeypatch: pytest.MonkeyPatch) -> None:
    _cookie_page(monkeypatch)
    calls: list[dict[str, Any]] = []
    html = "<p>Widget Pro</p>"
    doc = _obs(1, "http://127.0.0.1:18460/", body=html, kind="html", resource_type="document")
    _fake_load(monkeypatch, [(doc, html)], main=MainDocument(200, [], html, "http", "127.0.0.1", 18460), calls=calls)
    received: list[Any] = []

    async def fake_verify(url: str, *args: Any, **kwargs: Any) -> tuple[VerifyResult, None]:
        received.append(kwargs.get("meter_reply_check"))
        return VerifyResult(replays="yes", status=200), None

    monkeypatch.setattr(core, "verify_replay_detail", fake_verify)

    def check(code: str, host: str, port: int) -> bool:
        return True

    _run("http://127.0.0.1:18460/", ["Widget Pro"], verify=True, meter_reply_check=check)
    assert calls[0]["meter_reply_check"] is check and received == [check]


# --------------------------------------------------------------------------- verify against a loopback server


class _ReplayHandler(BaseHTTPRequestHandler):
    """Answers the scrapescope User-Agent according to the path."""

    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - quiet test server
        return

    def _send(self, status: int, headers: list[tuple[str, str]], body: bytes) -> None:
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        path = self.path.split("?", 1)[0]
        if path == "/hostile-encoding":
            body = b"Z9Q-UNIQ-4417 " + b"x" * 100_000
            self._send(200, [("Content-Type", "text/plain"),
                             ("Content-Encoding", "identity, Visit http://evil.example/claim to renew your license")], body)
        elif path == "/meter-like":
            self._send(403, [("Content-Type", "text/plain; charset=utf-8"), ("X-Scrapescope-Error", "budget")],
                       b"scrapescope: byte budget tripped; new requests are refused\n")
        elif path == "/proxy-auth":
            self._send(407, [("Proxy-Authenticate", 'Basic realm="p"')], b"")
        elif path == "/gateway":
            self._send(502, [("Content-Type", "text/html")], b"<h1>502 Bad Gateway</h1>")
        elif path == "/drip":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "1000000")
            self.end_headers()
            try:
                for _ in range(40):
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(0.25)
            except OSError:
                pass
        else:
            self._send(404, [("Content-Type", "text/plain")], b"not found\n")


class _QuietServer(ThreadingHTTPServer):
    def handle_error(self, request: Any, client_address: Any) -> None:
        return  # a client closing a keep-alive or dripping connection is expected here


@pytest.fixture(scope="module")
def replay_site() -> Iterator[str]:
    server = _QuietServer(("127.0.0.1", 0), _ReplayHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def _replay(world: TestWorld, url: str, *, timeout_s: float = 20.0, **kwargs: Any) -> tuple[VerifyResult, Any]:
    values = prepare_values(["Z9Q-UNIQ-4417"])
    return asyncio.run(
        verify_replay_detail(url, values, [0], proxy_url=world.http_upstream_noauth.server, timeout_s=timeout_s,
                             body_cap_bytes=5_000_000, **kwargs)
    )


def test_replay_reason_never_carries_the_sites_content_encoding(world: TestWorld, replay_site: str) -> None:
    """sec3-6: the site's header text does not reach verify.reason or the replay detail."""
    result, detail = _replay(world, f"{replay_site}/hostile-encoding")
    assert result.replays == "not_tested"
    assert result.reason == "unsupported content encoding (other)"  # identity is no coding
    assert detail is not None and detail.content_encoding == "identity, other"
    assert "evil" not in json.dumps(result.to_dict())


@pytest.mark.timeout(60)
def test_replay_has_one_overall_deadline(world: TestWorld, replay_site: str) -> None:
    """sec3-8: a server trickling one byte at a time cannot hold the replay past its deadline."""
    started = time.monotonic()
    result, detail = _replay(world, f"{replay_site}/drip", timeout_s=2.0)
    elapsed = time.monotonic() - started
    assert elapsed < 6.0, elapsed
    assert (result.replays, result.reason) == ("not_tested", "replay exceeded 2 s")
    assert detail is None


def test_replay_answered_by_the_meter_or_a_proxy_is_not_tested(world: TestWorld, replay_site: str) -> None:
    """find3-5: the meter's own 403 (budget, deny) or a proxy 407 never reached the site: not 'no'."""
    meter, detail = _replay(world, f"{replay_site}/meter-like")
    assert (meter.replays, meter.reason) == ("not_tested", "the meter answered itself (budget)")
    assert meter.status is None and detail is None
    # the meter's records say it sent no such reply: the site's own 403 is a real "no"
    site_403, _detail = _replay(world, f"{replay_site}/meter-like", meter_reply_check=lambda c, h, p: False)
    assert (site_403.replays, site_403.reason) == ("no", "status 403")
    proxy, detail = _replay(world, f"{replay_site}/proxy-auth")
    assert (proxy.replays, proxy.reason) == ("not_tested", "the proxy asked for credentials (status 407)")
    assert detail is None
    # a 502 may be a provider's relayed gateway error: it says nothing about replaying
    gateway, detail = _replay(world, f"{replay_site}/gateway")
    assert (gateway.replays, gateway.status, gateway.reason) == ("not_tested", 502, "gateway error (status 502)")
    assert detail is not None


# --------------------------------------------------------------------------- sec3-4: the meter's own records


def _snapshot(
    tunnels: list[tuple[str, int, str]] = (),  # type: ignore[assignment]
    refused: dict[str, int] | None = None,
    budget_tripped: bool = False,
) -> Any:
    from types import SimpleNamespace

    return SimpleNamespace(
        tunnels=[SimpleNamespace(host=h, port=p, status=s) for h, p, s in tunnels],
        refused=refused or {},
        budget_tripped=budget_tripped,
        internal_errors=0,
    )


def test_meter_reply_check_matches_the_code_to_the_meters_records() -> None:
    """sec3-4: only a refusal the meter recorded for that host:port confirms the header."""
    from scrapescope.find import meter_reply_check_from_snapshot

    # the reviewer's repro: the tunnel to the site was fine, so the site forged private-address
    fine = meter_reply_check_from_snapshot(lambda: _snapshot([("127.0.0.1", 18452, "ok")]))
    assert fine("private-address", "127.0.0.1", 18452) is False
    refused = meter_reply_check_from_snapshot(
        lambda: _snapshot([("127.0.0.1", 18452, "failed:private_address"), ("shop.test", 80, "denied")])
    )
    assert refused("private-address", "127.0.0.1", 18452) is True
    assert refused("private-address", "127.0.0.1", 18453) is False  # another port
    assert refused("denied", "127.0.0.1", 18452) is False  # a different refusal
    assert refused("denied", "SHOP.test.", 80) is True  # hosts compared as clean_host
    assert refused("budget", "127.0.0.1", 18452) is False
    budget = meter_reply_check_from_snapshot(lambda: _snapshot(refused={"budget": 2}, budget_tripped=True))
    assert budget("budget", "any.test", 80) is True
    socks = meter_reply_check_from_snapshot(lambda: _snapshot([("a.test", 80, "failed:socks_reply_5")]))
    assert socks("socks-reply-5", "a.test", 80) is True and socks("socks-reply-4", "a.test", 80) is False
    # an IDN host as HTTPX reports it (Unicode) against the record's IDNA form
    idn = meter_reply_check_from_snapshot(lambda: _snapshot([("xn--bcher-kva.test", 80, "failed:dns")]))
    assert idn("dns-failed", "bücher.test", 80) is True
    # a code the meter never sends: confirmed only by some failure for that host:port
    assert idn("other", "bücher.test", 80) is True and fine("other", "127.0.0.1", 18452) is False

    def broken() -> Any:
        raise RuntimeError("meter gone")

    assert meter_reply_check_from_snapshot(broken)("private-address", "127.0.0.1", 1) is None


def test_meter_reply_check_against_a_real_meter(replay_site: str) -> None:
    """sec3-4: the meter's real private-address refusal is confirmed; a site's look-alike reply is not."""
    import httpx

    from scrapescope.config import ForwarderConfig
    from scrapescope.find import meter_reply_check_from_snapshot
    from scrapescope.forwarder import ForwarderThread

    port = int(replay_site.rsplit(":", 1)[1])
    for allow_private, path, expected in (
        (False, "/meter-like", True),  # sizing mode: the meter refuses the loopback target itself
        (True, "/meter-like", False),  # allowed: the 403 with X-Scrapescope-Error is the site's
    ):
        fw = ForwarderThread(ForwarderConfig(allow_private_targets=allow_private))
        fw.start()
        try:
            with httpx.Client(proxy=fw.url, trust_env=False, timeout=10.0) as client:
                reply = client.get(f"{replay_site}{path}")
            code = reply.headers.get("x-scrapescope-error")
            check = meter_reply_check_from_snapshot(fw.snapshot)
            assert code is not None and check(code, "127.0.0.1", port) is expected, (allow_private, code)
        finally:
            fw.stop()


def test_a_saving_that_moved_more_on_replay_says_so_inline() -> None:
    """honest-r3-1: the share is the browser's (br) copy; a replay without br moved more, stated with the claim."""
    verify = VerifyResult(replays="yes", status=200, received_bytes=9_279, replay_billed_basis_bytes=16_953)
    text = render_find_text(_result([_m(1, billed=9_792)], page=184_119, verify=verify))
    share_line = next(line for line in text.splitlines() if line.startswith("share: "))
    # hon4-2: the replay's own figure on the share's basis (TLS left out), and its share of the page load
    assert share_line.endswith(
        "a saving: --verify replayed it without a browser, moving about 9,753 B body and headers "
        "(5.3% of this page load; see warnings)"
    ), share_line
