"""find, round 4 find review (find-r4-1 ... find-r4-8): partial matches, not-emitted reasons, flags, reports.

Most tests drive ``run_find`` through the fake ``load_page`` of
``tests.test_find_round3`` (prepared responses searched with the real search
code) and the ``--verify`` stub there; report tests build report.json with
the real builder.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from scrapescope.catalog import load_catalogs
from scrapescope.find import render_find_text
from scrapescope.find.browser import MainDocument, ObservedResponse
from scrapescope.find.heuristics import NOT_EMITTED_TEXT, TOKEN_HEADER_REASON, code_eligibility, not_emitted_text
from scrapescope.find.search import PreparedValue, SearchText, match_kind, search_body, prepare_values
from scrapescope.report import build_report, render_text
from scrapescope.report._fmt import bucket_label, match_kind_text, verify_hosts
from scrapescope.report.validate import validate
from scrapescope.types import FindFlags, FindResult, ReportOptions, VerifyResult
from tests.test_find_round3 import _fake_load, _obs, _run, _verify_stub
from tests.test_find_support import validate_find_entry

PAGE = "http://127.0.0.1:18460"


def _page_doc(html: str, path: str = "/p3") -> tuple[ObservedResponse, str]:
    return _obs(1, f"{PAGE}{path}", body=html, kind="html", resource_type="document", frame="main"), html


def _main(html: str) -> MainDocument:
    return MainDocument(200, [], html, "http", "127.0.0.1", 18460)


# --------------------------------------------------------------------------- find-r4-1: code for partial matches


def _p3(monkeypatch: pytest.MonkeyPatch) -> None:
    """The reviewer's /p3: the document holds value 1 only; a cookie-sending JSON holds both."""
    html = "<p>Gizmo</p>"
    need = '{"name":"Gizmo","price":9.99}'
    doc = _page_doc(html)
    api = _obs(2, f"{PAGE}/api/need.json", body=need, sent_cookies=True)
    _fake_load(monkeypatch, [doc, (api, need)], main=_main(html))


def test_no_starter_code_for_a_partial_match_while_a_match_with_every_value_exists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _p3(monkeypatch)
    seen: list[str] = []
    _verify_stub(monkeypatch, VerifyResult(replays="no", status=200, received_bytes=20, reason="value missing"), seen)
    result = _run(f"{PAGE}/p3", ["Gizmo", "9.99"], verify=True)
    assert seen == [f"{PAGE}/api/need.json"]
    need, doc = result.matches
    assert need.all_values and not doc.all_values and doc.code_eligible
    # the document lacks value 2: no starter code for it while a response with every value exists
    assert result.starter_code == []
    text = render_find_text(result)
    assert "starter code (" not in text and "curl " not in text
    assert "smallest with all values: rank 1" in text
    assert "replays without a browser: no (rank 1, value missing)" in text
    # the partial eligible document is still listed, with its count
    assert "  rank 2 (holds 1 of 2 values): 127.0.0.1/p3\n" in text
    assert "also eligible" not in text  # nothing above it to be "also" to
    # without --verify the same holds
    plain = _run(f"{PAGE}/p3", ["Gizmo", "9.99"])
    assert plain.starter_code == [] and "starter code (" not in render_find_text(plain)


def test_the_all_values_match_gets_the_code_and_partial_ones_are_listed_with_their_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    html = "<p>Gizmo</p>" + "<p>filler</p>" * 400
    full = '{"name":"Gizmo","price":9.99}'
    part = '{"name":"Gizmo"}'
    doc = _page_doc(html)
    api = _obs(2, f"{PAGE}/api/full.json", body=full)
    small = _obs(3, f"{PAGE}/api/part.json", body=part)
    _fake_load(monkeypatch, [doc, (api, full), (small, part)], main=_main(html))
    result = _run(f"{PAGE}/p3", ["Gizmo", "9.99"])
    assert [m.path for m in result.matches] == ["/api/full.json", "/api/part.json", "/p3"]
    assert [c.rank for c in result.starter_code] == [1]
    text = render_find_text(result)
    assert "starter code (rank 1: a GET that sent no cookies" in text
    assert (
        "also eligible (other responses that would get starter code):\n"
        "  rank 2 (holds 1 of 2 values): 127.0.0.1/api/part.json\n"
        "  rank 3 (holds 1 of 2 values): 127.0.0.1/p3\n"
    ) in text


def test_a_partial_top_match_says_which_value_it_lacks(monkeypatch: pytest.MonkeyPatch) -> None:
    """No response holds every value: the code heading and the verify line name the missing value."""
    part = '{"name":"Quibble-5521"}'
    html = "<p>page</p>"
    doc = _page_doc(html, "/p7")
    api = _obs(2, f"{PAGE}/api/t.json", body=part)
    _fake_load(monkeypatch, [doc, (api, part)], main=_main(html))
    seen: list[str] = []
    _verify_stub(monkeypatch, VerifyResult(replays="yes", status=200, received_bytes=24), seen)
    result = _run(f"{PAGE}/p7", ["Quibble-5521", "Absent-9913"], verify=True)
    assert [c.rank for c in result.starter_code] == [1]
    text = render_find_text(result)
    assert (
        "starter code (rank 1: holds 1 of 2 values (value 2 is not in it); one --verify replay without the "
        "browser's cookies, headers or tokens returned the values found in it; check the site's terms):"
    ) in text
    assert "replays without a browser: yes (rank 1, holds 1 of 2 values (value 2 is not in it), status 200" in text
    # without --verify: the plain heading carries the note too
    plain = render_find_text(_run(f"{PAGE}/p7", ["Quibble-5521", "Absent-9913"]))
    assert "starter code (rank 1: holds 1 of 2 values (value 2 is not in it); a GET that sent no cookies" in plain


def test_a_partial_candidate_that_replays_gets_no_code_while_a_full_match_exists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A POST holds every value; the cookie-sending GET holding one of them replays: listed, no code."""
    both = '{"name":"Gizmo","price":9.99}'
    one = '{"name":"Gizmo"}'
    html = "<p>page</p>" + "<p>filler</p>" * 400
    doc = _page_doc(html)
    post = _obs(2, f"{PAGE}/graphql", body=both, method="POST")
    cookie = _obs(3, f"{PAGE}/api/one.json", body=one, sent_cookies=True)
    _fake_load(monkeypatch, [doc, (post, both), (cookie, one)], main=_main(html))
    seen: list[str] = []
    _verify_stub(monkeypatch, VerifyResult(replays="yes", status=200, received_bytes=16), seen)
    result = _run(f"{PAGE}/p3", ["Gizmo", "9.99"], verify=True)
    assert seen == [f"{PAGE}/api/one.json"]
    replayed = next(m for m in result.matches if m.path == "/api/one.json")
    assert replayed.code_eligible is True
    assert result.starter_code == []
    text = render_find_text(result)
    assert "starter code (" not in text
    assert f"replays without a browser: yes (rank {replayed.rank}, holds 1 of 2 values (value 2 is not in it)" in text


# --------------------------------------------------------------------------- find-r4-2: one text per reason


@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        ("sent cookies", NOT_EMITTED_TEXT),
        ("sent authorization", NOT_EMITTED_TEXT),
        (TOKEN_HEADER_REASON, NOT_EMITTED_TEXT),
        ("random-looking query token", NOT_EMITTED_TEXT),
        ("random-looking token in the path", NOT_EMITTED_TEXT),
        ("not a GET", "not emitted: starter code covers GET only; the request body and headers are not reproduced"),
        ("status 404", "not emitted: the response had status 404"),
        ("status unknown", "not emitted: the response status is unknown"),
        (
            "served by a service worker",
            "not emitted: the page's service worker answered; the network response may differ",
        ),
    ],
)
def test_not_emitted_text_matches_the_reason(reason: str, expected: str) -> None:
    assert not_emitted_text(reason) == expected


def test_a_cookieless_post_and_a_404_are_not_called_session_state(monkeypatch: pytest.MonkeyPatch) -> None:
    """The reviewer's /g1 (GraphQL POST) and /g2 (404 JSON)."""
    html = "<p>page</p>"
    body = '{"data":{"name":"Frobnic-3310"}}'
    post = _obs(2, f"{PAGE}/graphql", body=body, method="POST")
    _fake_load(monkeypatch, [_page_doc(html, "/g1"), (post, body)], main=_main(html))
    text = render_find_text(_run(f"{PAGE}/g1", ["Frobnic-3310"]))
    assert (
        "rank 1 (not a GET): not emitted: starter code covers GET only; the request body and headers are not "
        "reproduced"
    ) in text
    assert "session or anti-bot" not in text
    missing = _obs(2, f"{PAGE}/api/missing.json", body=body, status=404)
    _fake_load(monkeypatch, [_page_doc(html, "/g2"), (missing, body)], main=_main(html))
    text = render_find_text(_run(f"{PAGE}/g2", ["Frobnic-3310"]))
    assert "rank 1 (status 404): not emitted: the response had status 404" in text
    assert "session or anti-bot" not in text
    assert code_eligibility(method="GET", status=None, flags=FindFlags()).reason == "status unknown"


# --------------------------------------------------------------------------- find-r4-3: the token-header flag


def test_the_token_header_flag_survives_a_yes_replay_and_reaches_the_report(monkeypatch: pytest.MonkeyPatch) -> None:
    """The reviewer's /p7: fetch with X-Api-Key, replayed without it: yes."""
    html = "<p>page</p>"
    body = '{"name":"Quibble-5521"}'
    api = _obs(2, f"{PAGE}/api/t.json", body=body, sent_token_header=True)
    _fake_load(monkeypatch, [_page_doc(html, "/p7"), (api, body)], main=_main(html))
    seen: list[str] = []
    _verify_stub(monkeypatch, VerifyResult(replays="yes", status=200, received_bytes=24), seen)
    result = _run(f"{PAGE}/p7", ["Quibble-5521"], verify=True)
    top = result.matches[0]
    assert top.code_eligible is True and top.code_ineligible_reason is None
    assert top.flags.sent_token_header is True
    assert "token-header" in render_find_text(result).split("\n        127.0.0.1/api/t.json")[0]
    assert result.to_dict()["matches"][0]["flags"]["sent_token_header"] is True
    assert validate_find_entry(result) == []
    assert FindResult.from_dict(result.to_dict()).matches[0].flags.sent_token_header is True


def test_the_token_header_flag_shows_next_to_sent_cookies(monkeypatch: pytest.MonkeyPatch) -> None:
    html = "<p>page</p>"
    body = '{"name":"Quibble-5521"}'
    api = _obs(2, f"{PAGE}/api/t.json", body=body, sent_token_header=True, sent_cookies=True)
    _fake_load(monkeypatch, [_page_doc(html, "/p7"), (api, body)], main=_main(html))
    result = _run(f"{PAGE}/p7", ["Quibble-5521"])
    top = result.matches[0]
    assert top.code_ineligible_reason == "sent cookies" and top.flags.sent_token_header is True
    row = next(line for line in render_find_text(result).splitlines() if line.lstrip().startswith("1 "))
    assert "sent-cookies,token-header" in row


def test_report_flags_name_the_token_header() -> None:
    from scrapescope.report._fmt import flags_text

    assert flags_text({"sent_cookies": True, "sent_token_header": True}) == "sent cookies, sent a token header"


# --------------------------------------------------------------------------- find-r4-4, find-r4-7: reports


def _p3_report(monkeypatch: pytest.MonkeyPatch, **verify: Any) -> dict[str, Any]:
    from tests.test_report import _snapshot, _tunnel
    from scrapescope.types import AttributionResult, Buckets

    _p3(monkeypatch)
    seen: list[str] = []
    outcome = VerifyResult(**(verify or dict(replays="no", status=200, received_bytes=20, reason="value missing")))
    _verify_stub(monkeypatch, outcome, seen)
    result = _run(f"{PAGE}/p3", ["Gizmo", "9.99"], verify=True)
    tunnels = [_tunnel(1, "127.0.0.1", 900, 1_700, route="direct", synthetic=(67, 39))]
    attribution = AttributionResult(buckets=Buckets(unattributed=sum(t.bytes_with_connect for t in tunnels)))
    report = build_report(snapshot=_snapshot(tunnels, mode="direct"), attribution=attribution,
                          catalogs=load_catalogs(), options=ReportOptions(command="find"), find_results=[result])
    assert validate(report) == []
    return json.loads(json.dumps(report))


def test_verify_hosts_names_the_host_actually_replayed(monkeypatch: pytest.MonkeyPatch) -> None:
    """The replayed candidate (rank 1, said no) stays ineligible; rank 2 is eligible on another host."""
    report = _p3_report(monkeypatch)
    entry = report["find"][0]
    assert entry["matches"][0]["code_eligible"] is False and entry["matches"][1]["code_eligible"] is True
    entry["matches"][0]["host"] = "api.example"
    assert verify_hosts(report) == {"api.example"}
    assert bucket_label(report, "unattributed", "api.example") == "find page load and --verify replay"
    assert bucket_label(report, "unattributed", "127.0.0.1") == "find page load"


def test_report_find_table_counts_values_and_names_the_replayed_rank(monkeypatch: pytest.MonkeyPatch) -> None:
    report = _p3_report(monkeypatch)
    out = render_text(report)
    rows = [line for line in out.splitlines() if line.startswith("  1  ") or line.startswith("  2  ")]
    assert len(rows) == 2, out
    assert "all 2/2" in rows[0] and "some 1/2" in rows[1]
    assert "replays without a browser: no (rank 1, value missing)" in out
    from scrapescope.report.html import render_html

    page = render_html(report)
    assert "some 1/2" in page and "no (rank 1, value missing)" in page


@pytest.mark.parametrize(
    ("kinds", "expected"),
    [
        (["exact"], "exact"),
        (["exact", "exact"], "exact"),
        (["variant:number-format"], "variant: number-format"),
        (["variant:number-format", "exact"], "mixed: 1 number-format, 2 exact"),
        (["exact", "none"], "mixed: 1 exact, 2 none"),
        (["exact", "variant:substring"], "mixed: 1 exact, 2 substring (not counted)"),
        ([], "-"),
    ],
)
def test_report_match_column_keeps_exact_in_mixed_kinds(kinds: list[str], expected: str) -> None:
    assert match_kind_text(kinds) == expected


# --------------------------------------------------------------------------- find-r4-6: JSON numbers and signs


@pytest.mark.parametrize(
    ("body", "value"),
    [("[1,299]", "1,299"), ('{"a":[1,299]}', "1,299"), ("[12,5]", "12,5"), ('{"a":[1,299.5]}', "1,299.5")],
)
def test_a_json_list_is_not_a_formatted_number(body: str, value: str) -> None:
    kind = match_kind(SearchText(body, "json"), PreparedValue.of(value))
    assert kind == "none", kind
    hits = search_body(body, "json", prepare_values([value]))
    assert hits.values_matched == 0, hits.kinds


def test_json_numbers_and_strings_still_match() -> None:
    assert match_kind(SearchText('{"a":"1,299"}', "json"), PreparedValue.of("1,299")) == "exact"
    assert match_kind(SearchText('{"a":1299}', "json"), PreparedValue.of("1,299")) == "variant:number-format"
    assert match_kind(SearchText('{"p":51.77}', "json"), PreparedValue.of("51.77")) == "exact"
    assert match_kind(SearchText('{"p":51.77}', "json"), PreparedValue.of("£51.77")) == "variant:number-format"
    assert match_kind(SearchText('{"n":-42}', "json"), PreparedValue.of("-42")) == "exact"
    assert match_kind(SearchText("[41,42,43]", "json"), PreparedValue.of("42")) == "exact"
    assert match_kind(SearchText('{"a":122}', "json"), PreparedValue.of("12")) == "variant:substring"
    # the documented limit: JavaScript still reads the list as text
    assert match_kind(SearchText("var a = [1,299];", "js"), PreparedValue.of("1,299")) == "exact"


@pytest.mark.parametrize(
    ("body", "kind"),
    [("<p>ABC-42</p>", "html"), ("ABC-42", "text"), ('{"n":"ABC-42"}', "json"), ("1e-42", "text"), ("v2-42", "text")],
)
def test_a_signed_value_does_not_match_a_hyphen(body: str, kind: str) -> None:
    got = match_kind(SearchText(body, kind), PreparedValue.of("-42"))
    assert got in ("none", "variant:substring"), got


@pytest.mark.parametrize("body", ["-42", "x -42", "(-42)", "price: -42 EUR", "[-42]", "−42", "ABC−42"])
def test_a_signed_value_still_matches_a_sign(body: str) -> None:
    value = "−42" if "−" in body else "-42"
    assert match_kind(SearchText(body, "text"), PreparedValue.of(value)) == "exact"


def test_signed_number_format_does_not_match_a_hyphen_either() -> None:
    assert match_kind(SearchText("ABC-1,299.00", "text"), PreparedValue.of("-1299")) in ("none", "variant:substring")
    assert match_kind(SearchText("total -1,299.00", "text"), PreparedValue.of("-1299")) == "variant:number-format"


def test_a_leading_plus_is_no_sign_to_the_number_formats() -> None:
    """``+42`` as typed is not exact after a letter, but the number formats read it as 42 (method.md section 8)."""
    for body in ("ABC+42", "ABC-42", "42"):
        assert match_kind(SearchText(body, "text"), PreparedValue.of("+42")) == "variant:number-format", body
    assert match_kind(SearchText("x +42", "text"), PreparedValue.of("+42")) == "exact"
    assert match_kind(SearchText("-42", "text"), PreparedValue.of("+42")) == "none"


# --------------------------------------------------------------------------- find-r4-8: verify wording


def test_verify_with_nothing_matched_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    html = "<p>122 items</p>"
    _fake_load(monkeypatch, [_page_doc(html)], main=_main(html))
    result = _run(f"{PAGE}/p3", ["12"], verify=True)
    assert result.status == "not_found"
    assert (result.verify.replays, result.verify.reason) == ("not_tested", "nothing matched")
    assert "replays without a browser: not tested (nothing matched)" in render_find_text(result)


def test_verify_help_names_the_candidate() -> None:
    import argparse

    from scrapescope.cli import build_parser

    subcommands = next(a for a in build_parser()._actions if isinstance(a, argparse._SubParsersAction))
    help_text = " ".join(subcommands.choices["find"].format_help().split())
    assert "the top eligible match, or a higher-ranked one withheld only for the cookies or token header it sent" in (
        help_text
    )


# --------------------------------------------------------------------------- find-r4-5: the meter line


def test_meter_line_does_not_count_tunnels_the_browser_closed_as_failed() -> None:
    from scrapescope.runner import _find_meter_line
    from scrapescope.types import MeterSnapshot, TunnelRecord

    def rec(i: int, status: str) -> TunnelRecord:
        return TunnelRecord(id=i, host="en.wikipedia.test", port=443, kind="connect", route="direct", opened_at=0.0,
                            status=status, upstream_bytes_received=100)

    tunnels = [rec(1, "ok"), rec(2, "failed:client_closed"), rec(3, "failed:client_closed"), rec(4, "failed:connect_refused")]
    snapshot = MeterSnapshot(taken_at=1.0, started_at=0.0, mode="direct", port=1, auth_port=None, tunnels=tunnels,
                             counted_bytes=400, budget_bytes=None, max_tunnel_bytes=None, budget_tripped=False)
    line = _find_meter_line(snapshot, "GB", None)
    assert "in 4 tunnel(s) (1 failed; 2 closed by the browser before the tunnel opened)" in line, line
    clean = MeterSnapshot(taken_at=1.0, started_at=0.0, mode="direct", port=1, auth_port=None, tunnels=[rec(1, "ok")],
                          counted_bytes=100, budget_bytes=None, max_tunnel_bytes=None, budget_tripped=False)
    assert "in 1 tunnel(s) (0 failed);" in _find_meter_line(clean, "GB", None)
