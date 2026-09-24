"""Build the golden example reports in docs/dev/ with scrapescope's own code.

    python scripts/make_example_reports.py            # check: exit 1 when the files differ
    python scripts/make_example_reports.py --write    # rewrite docs/dev/example-report*.json

The inputs are synthetic but go through the real pipeline: a meter snapshot
and helper events -> ``attribution.attribute`` -> ``report.build_report``
(what-if, fixes, costs, warnings), so every generated string (fix titles,
detections, code, caveats, warnings) is exactly what the tool writes. The find
example builds a ``FindResult`` as ``find`` would return it (a real page load
needs a browser) and passes it through the same report builder.

``tests/test_report.py::test_golden_examples_are_generator_output`` rebuilds
both reports and compares them with the files, so a change to any generator
or renderer input shows up as a stale golden file. A future report viewer may
use these files as its sample reports.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from scrapescope.attribution import attribute  # noqa: E402
from scrapescope.catalog import load_catalogs  # noqa: E402
from scrapescope.report import build_report, dumps, validate  # noqa: E402
from scrapescope.types import (  # noqa: E402
    AttachEvent,
    ChallengeResult,
    Coverage,
    FindFlags,
    FindMatch,
    FindResult,
    LaunchEvent,
    MeterSnapshot,
    ReportOptions,
    RequestEvent,
    TimelinePoint,
    TunnelRecord,
    VerifyResult,
)

RUN_PATH = ROOT / "docs" / "dev" / "example-report.json"
FIND_PATH = ROOT / "docs" / "dev" / "example-report-find.json"

#: 2026-09-23T10:00:00Z
T0 = 1_790_157_600.0
#: CONNECT head with a Proxy-Authorization line, and the provider's 200 reply.
CONNECT_SENT, CONNECT_RECEIVED = 146, 39


def _tunnel(i: int, host: str, sent: int, received: int, opened: float, closed: float, *,
            route: str = "http-connect", status: str = "ok", rule: str | None = None,
            upstream_status: int | None = 200) -> TunnelRecord:
    negotiated = route in ("http-connect", "socks5")
    return TunnelRecord(
        id=i, host=host, port=443, kind="connect", route=route, opened_at=T0 + opened,  # type: ignore[arg-type]
        closed_at=T0 + closed, status=status,
        upstream_bytes_sent=sent + (CONNECT_SENT if negotiated else 0),
        upstream_bytes_received=received + (CONNECT_RECEIVED if negotiated else 0),
        negotiation_bytes_sent=CONNECT_SENT if negotiated else 0,
        negotiation_bytes_received=CONNECT_RECEIVED if negotiated else 0,
        connect_request_bytes=CONNECT_SENT if negotiated else 0,
        proxy_authorization_bytes=60 if negotiated else 0,
        upstream_status=upstream_status if negotiated else None,
        auth="injected" if negotiated else "none",  # type: ignore[arg-type]
        rule=rule,
    )


def _request(ts: float, host: str, resource_type: str, body: int, *, status: int = 200, navigation: bool = False,
             path: str | None = None) -> RequestEvent:
    return RequestEvent(
        ts=T0 + ts, source="playwright", host=host, port=443, scheme="https", path=path, method="GET",
        resource_type=resource_type, status=status, frame="main", is_navigation=navigation,
        encoded_body_bytes=body, response_header_bytes=310, request_header_bytes=640, request_body_bytes=0,
        context="4242-1",
    )


def run_inputs() -> tuple[MeterSnapshot, list[Any]]:
    """A 25-page Playwright job through an HTTP CONNECT provider, with background traffic."""
    pages = 25
    events: list[Any] = [
        LaunchEvent(ts=T0 + 0.5, source="playwright", browser="chromium", pid=4242),
        AttachEvent(ts=T0 + 1.0, source="playwright", pid=4242, context="4242-1"),
    ]
    for n in range(pages):
        t = 2.0 + 6.0 * n
        status = 404 if n == 17 else 200
        events.append(_request(t, "origin-a.test", "document", 38_000, status=status, navigation=True))
        events.append(_request(t + 0.3, "origin-a.test", "xhr", 36_000))
        if n == 0:  # the first page fills the cache: scripts, stylesheet, fonts
            events.append(_request(t + 0.2, "origin-a.test", "script", 780_000))
            events.append(_request(t + 0.2, "origin-a.test", "stylesheet", 240_000))
            events.append(_request(t + 0.4, "origin-c.test", "font", 390_000))
            events.append(_request(t + 0.4, "origin-c.test", "font", 400_000))
        for k in range(3):
            events.append(_request(t + 0.5 + 0.1 * k, "origin-c.test", "image", 41_000 + 1_000 * k))
    end = 2.0 + 6.0 * pages
    tunnels = [
        _tunnel(1, "optimizationguide-pa.googleapis.com", 3_000, 1_497_000, 0.7, 40.0),
        _tunnel(2, "origin-a.test", 60_000, 2_300_000, 1.9, end),
        _tunnel(3, "origin-a.test", 30_000, 1_150_000, 2.1, end),
        _tunnel(4, "origin-c.test", 40_000, 3_960_000, 2.3, end),
        _tunnel(5, "origin-b.test", 1_900, 5_500, 2.2, 20.0),
        _tunnel(6, "origin-d.test", 14_000, 52_000, 30.0, 31.0),
        _tunnel(7, "api.openai.com", 900, 4_000, 60.0, 61.0, route="non-target", rule="openai"),
    ]
    target = [t for t in tunnels if t.is_target]
    # Timeline: the background download before the first page, then the pages.
    timeline = [TimelinePoint(t=T0 + 0.75, sent=3_000 + CONNECT_SENT, received=1_497_000 + CONNECT_RECEIVED)]
    remaining = sum(t.upstream_bytes_sent + t.upstream_bytes_received for t in target) - (
        timeline[0].sent + timeline[0].received
    )
    first = 2_300_000
    timeline.append(TimelinePoint(t=T0 + 2.0, sent=40_000, received=first - 40_000))
    rest = remaining - first
    per_page = rest // (pages - 1)
    for n in range(1, pages):
        chunk = per_page if n < pages - 1 else rest - per_page * (pages - 2)
        timeline.append(TimelinePoint(t=T0 + 2.0 + 6.0 * n, sent=chunk // 20, received=chunk - chunk // 20))
    snapshot = MeterSnapshot(
        taken_at=T0 + end + 1.25, started_at=T0, mode="http-connect", port=53211, auth_port=53212,
        tunnels=tunnels, counted_bytes=sum(t.counted_bytes for t in target), budget_bytes=2_000_000_000,
        max_tunnel_bytes=None, budget_tripped=False, refused={"auth_challenge": 2}, timeline=timeline,
    )
    return snapshot, events


def find_result() -> FindResult:
    """A find result as ``run_find`` returns it (sizing mode, two values, --verify)."""
    api = FindMatch(
        rank=1, host="origin-a.test", port=443, scheme="https", path="/api/product.json", method="GET",
        resource_type="fetch", status=200, mime_type="application/json", all_values=True, values_matched=2,
        match_kinds=["exact", "variant:number-format"], locations=["fetch", "json-key:product.name", "json-key:product.price"],
        encoded_body_bytes=1_106, response_header_bytes=0, request_header_bytes=0, tls_handshake_estimate=7_200,
        billed_basis_bytes=8_306, flags=FindFlags(), code_eligible=True, content_encoding="br", multiplexed=True,
        locations_by_value=[["json-key:product.name"], ["json-key:product.price"]],
    )
    document = FindMatch(
        rank=2, host="origin-a.test", port=443, scheme="https", path="/product/1", method="GET",
        resource_type="document", status=200, mime_type="text/html", all_values=True, values_matched=2,
        match_kinds=["exact", "exact"],
        locations=["document", "embedded:ld-json", "json-key:name", "html-text", "json-key:offers.price"],
        encoded_body_bytes=9_402, response_header_bytes=0, request_header_bytes=0, tls_handshake_estimate=7_200,
        billed_basis_bytes=16_602, flags=FindFlags(sent_cookies=True), code_eligible=False,
        code_ineligible_reason="sent cookies", content_encoding="br", multiplexed=True,
        locations_by_value=[["embedded:ld-json", "json-key:name", "html-text"],
                            ["embedded:ld-json", "json-key:offers.price", "html-text"]],
    )
    return FindResult(
        status="found", target_host="origin-a.test", target_path="/product/1", values_count=2,
        short_value_warning=False, challenge=ChallengeResult(blocked=False, status=200),
        matches=[api, document], coverage=Coverage(inspected=9, skipped={"binary": 14, "challenge": 1}),
        verify=VerifyResult(replays="yes", status=200, received_bytes=3_318, replay_billed_basis_bytes=11_106),
        responses_total=24, page_reported_bytes=412_870,
        warnings=[
            "1 response was a challenge page (Cloudflare) although the page itself loaded; not searched (counted "
            "as skipped: challenge page), so a value that request should have carried may be missing",
            "compressed with br or zstd in the browser: rank 1 (br), rank 2 (br); billed-basis uses that size, and "
            "a client that only accepts gzip or deflate (curl without brotli/zstd, httpx without its brotli/zstd "
            "extras) receives a larger body",
            # as run_find writes it when the replay moved more than 1.2x the browser's billed basis
            "the --verify replay of rank 1 moved about 11,106 billed-basis bytes (3,318 body bytes, no compression; "
            "it accepted: gzip, deflate) versus 8,306 for the browser's copy (1,106 body bytes, br)",
        ],
        target_url="https://origin-a.test/product/1",
    )


def find_snapshot() -> MeterSnapshot:
    tunnels = [
        _tunnel(1, "origin-a.test", 9_000, 402_000, 0.4, 6.0, route="direct"),
        _tunnel(2, "origin-c.test", 1_700, 21_000, 0.9, 6.0, route="direct"),
        _tunnel(3, "origin-a.test", 1_300, 11_200, 7.0, 7.5, route="direct"),  # the --verify replay
    ]
    for t in tunnels:
        t.synthetic_negotiation_bytes_sent, t.synthetic_negotiation_bytes_received = 67, 39
    target = [t for t in tunnels if t.is_target]
    return MeterSnapshot(
        taken_at=T0 + 8.0, started_at=T0, mode="direct", port=53301, auth_port=None, tunnels=tunnels,
        counted_bytes=sum(t.counted_bytes for t in target), budget_bytes=None, max_tunnel_bytes=None,
        budget_tripped=False,
        timeline=[TimelinePoint(t=T0 + 0.25, sent=10_700, received=423_000),
                  TimelinePoint(t=T0 + 7.0, sent=1_300, received=11_200)],
    )


def build_examples() -> tuple[dict[str, Any], dict[str, Any]]:
    catalogs = load_catalogs()
    snapshot, events = run_inputs()
    attribution = attribute(snapshot, events, catalogs)
    run_report = build_report(
        snapshot=snapshot, attribution=attribution, catalogs=catalogs,
        options=ReportOptions(command="run", rate=3.0, ended_at=snapshot.taken_at),
        warnings=[
            "--env-all: 1 non-target tunnel(s) to direct.json hosts bypassed the upstream proxy; the meter looked "
            "those names up and connected from this machine's own IP address"
        ],
    )
    fsnap = find_snapshot()
    fattr = attribute(fsnap, [], catalogs)
    fattr.warnings = [w for w in fattr.warnings if not w.startswith("no helper events")]
    find_report = build_report(
        snapshot=fsnap, attribution=fattr, catalogs=catalogs,
        options=ReportOptions(command="find", ended_at=fsnap.taken_at), find_results=[find_result()],
    )
    return run_report, find_report


def main(argv: list[str]) -> int:
    reports = build_examples()
    stale = []
    for path, report in zip((RUN_PATH, FIND_PATH), reports):
        errors = validate(report)
        if errors:
            print(f"{path.name}: invalid: {errors[:3]}")
            return 1
        text = dumps(report)
        if "--write" in argv:
            path.write_text(text, encoding="utf-8")
            print(f"wrote {path.relative_to(ROOT)}")
        elif not path.is_file() or json.loads(path.read_text(encoding="utf-8")) != report:
            stale.append(path.name)
    if stale:
        print("stale golden reports (run with --write): " + ", ".join(stale))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
