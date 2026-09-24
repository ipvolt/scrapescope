"""End-to-end browser tests: the Playwright helper under ``scrapescope run``, and ``scrapescope find``.

Real headless Chromium through the real CLI (subprocess) and the fixture
upstreams. They are marked ``browser`` and skip cleanly when Chromium cannot
launch; on a machine with Playwright's Chromium installed they run.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from scrapescope.catalog import load_catalogs
from scrapescope.find.core import SANDBOX_WARNING
from tests.e2e_support import (
    PYTHON,
    assert_absent,
    bucket_sum,
    cli,
    host_rows,
    load_report,
    read_text,
    secret_forms,
    write_script,
)
from tests.fixtures import UPSTREAM_PASSWORD, UPSTREAM_USERNAME, TestWorld, site
from tests.fixtures.browser import PAGE_DONE_PREDICATE, chromium_sandbox_unavailable_reason, chromium_unavailable_reason

pytestmark = [pytest.mark.browser, pytest.mark.timeout(180)]

HELPER_JOB = """
import sys
from playwright.sync_api import sync_playwright
from scrapescope.helpers.playwright import launch

DONE = {done!r}
chromium_args = sys.argv[1:]
with sync_playwright() as p:
    browser = launch(p.chromium, args=chromium_args)       # browser-wide proxy = the meter
    context = browser.new_context(ignore_https_errors=True)  # instrumented by the helper
    page = context.new_page()
    for path in ("/", "/product/2"):
        page.goto("https://origin-a.test" + path)
        page.wait_for_function(DONE, timeout=30000)
    context.close()
    browser.close()
print("pages done")
"""

PERSISTENT_JOB = """
import sys
from playwright.sync_api import sync_playwright
from scrapescope.helpers.playwright import instrument, proxy_settings

DONE = {done!r}
user_data_dir, chromium_args = sys.argv[1], sys.argv[2:]
with sync_playwright() as p:
    context = p.chromium.launch_persistent_context(
        user_data_dir, channel="chromium", headless=True, proxy=proxy_settings(), args=chromium_args,
        ignore_https_errors=True,
    )
    instrument(context)
    page = context.pages[0] if context.pages else context.new_page()
    page.goto("https://origin-a.test/")
    page.wait_for_function(DONE, timeout=30000)
    page.wait_for_timeout(3000)   # give the preconnect and background fetches time
    context.close()
print("done")
"""


def test_playwright_helper_run_attribution(fresh_world: TestWorld, tmp_path: Path) -> None:
    world = fresh_world
    job = write_script(tmp_path, "job.py", HELPER_JOB.format(done=PAGE_DONE_PREDICATE))
    out = tmp_path / "r.json"
    env = world.subprocess_env({"HTTPS_PROXY": world.http_upstream.url})
    proc = None
    for _attempt in range(2):  # Chromium occasionally fails one whole browser instance at start
        proc = cli(["run", "--out", str(out), "--html", str(tmp_path / "r.html"), "--", PYTHON, job,
                    *world.chromium_args()], env=env, timeout=150)
        if proc.returncode == 0:
            break
    assert proc is not None and proc.returncode == 0, proc.stderr[-3000:]
    world.wait_idle()
    report = load_report(out)
    totals = report["totals"]
    records = world.http_upstream.records()
    assert totals["bytes_sent"] == sum(r.bytes_from_client for r in records)
    assert totals["bytes_received"] == sum(r.bytes_to_client for r in records)
    # Units are the helper-counted main-frame navigations.
    assert report["units"]["count"] == 2 and report["units"]["source"] == "navigations"
    assert report["browser_launches"] == 1 and report["helper_events"]["launch"] == 1
    assert report["success"]["count"] == 2
    assert bucket_sum(report) == totals["with_connect"]
    rows = host_rows(report)
    # The page, its cross-site iframe, worker and service-worker fetches are attributed, never background.
    for host in ("origin-a.test", "origin-b.test"):
        assert set(rows[host]["buckets"]) == {"attributed"}, rows[host]["buckets"]
        assert rows[host]["background_id"] is None
    assert not any(k.startswith("background:") for row in rows.values() for k in row["buckets"]
                   if row["host"].endswith(".test"))
    types = {t["type"] for t in report["types"]}
    assert {"document", "image", "font", "script", "stylesheet"} <= types
    assert sum(t["allocated_bytes"] for t in report["types"]) == report["buckets"]["attributed"]
    assert report["incomplete"] is False
    what_if = {w["id"]: w for w in report["what_if"]}
    assert "block-images-media-fonts" in what_if
    assert "cache loss not modelled" in what_if["block-images-media-fonts"]["caveats"]  # two pages, one context
    assert f"scrapescope report {out}" in proc.stderr  # where the fix code is
    assert {"playwright-cdp-block", "playwright-route-block"} <= {f["id"] for f in report["fixes"]}
    assert_absent(secret_forms(UPSTREAM_USERNAME, UPSTREAM_PASSWORD), stdout=proc.stdout, stderr=proc.stderr,
                  report=read_text(out), html=read_text(tmp_path / "r.html"))


def test_full_chromium_preconnect_and_background_buckets(fresh_world: TestWorld, tmp_path: Path) -> None:
    reason = chromium_unavailable_reason(full_chromium=True)
    if reason is not None:
        pytest.skip(f"full Chromium build unavailable: {reason}")
    world = fresh_world
    job = write_script(tmp_path, "job.py", PERSISTENT_JOB.format(done=PAGE_DONE_PREDICATE))
    out = tmp_path / "r.json"
    env = world.subprocess_env({"HTTPS_PROXY": world.http_upstream.url})
    proc = None
    for _attempt in range(2):
        proc = cli(["run", "--out", str(out), "--", PYTHON, job, str(tmp_path / f"profile{_attempt}"),
                    *world.chromium_args()], env=env, timeout=150)
        if proc.returncode == 0:
            break
    assert proc is not None and proc.returncode == 0, proc.stderr[-3000:]
    report = load_report(out)
    catalogs = load_catalogs()
    assert bucket_sum(report) == report["totals"]["with_connect"]
    for row in report["hosts"]:
        background = [k for k in row["buckets"] if k.startswith("background:")]
        if background:
            # Only catalogued hosts are ever called background.
            assert catalogs.background_id_for(row["host"]) == background[0].split(":", 1)[1]
    rows = host_rows(report)
    # The idle preconnect (when Chromium makes one) is never background.
    if "origin-c.test" in rows:
        assert set(rows["origin-c.test"]["buckets"]) <= {"preconnect_idle", "unattributed"}
    # Uncatalogued Google hosts the full build contacts are never background either.
    for host in ("www.google.com", "accounts.google.com", "android.clients.google.com"):
        if host in rows:
            assert not any(k.startswith("background:") for k in rows[host]["buckets"])


def test_find_through_upstream_finds_verifies_and_keeps_the_value_private(fresh_world: TestWorld, tmp_path: Path) -> None:
    world = fresh_world
    out = tmp_path / "f.json"
    env = world.subprocess_env({"HTTPS_PROXY": world.http_upstream.url})
    proc = None
    for _attempt in range(2):  # one retry for a transient browser start failure under load
        proc = cli(["find", "https://origin-a.test/", "--value", site.PRODUCT_PRICE, "--verify", "--out", str(out)],
                   env=env, timeout=150)
        if proc.returncode == 0:
            break
    assert proc is not None and proc.returncode == 0, proc.stdout + proc.stderr
    assert "origin-a.test/api/product.json" in proc.stdout
    assert "replays without a browser: yes" in proc.stdout
    assert "curl --compressed 'https://origin-a.test/api/product.json'" in proc.stdout
    assert "meter: the page load" in proc.stdout and "tunnel-measured" in proc.stdout
    report = load_report(out)
    assert report["command"] == "find" and report["mode"] == "http-connect"
    assert not any("helper events" in w or "unit" in w for w in report["warnings"])  # no run-only noise
    # The sandbox fallback note appears exactly when Chromium cannot start with its OS sandbox on this
    # machine (probed with the same sandboxed launch find makes first); the output above is complete either
    # way. Where the sandbox works (macOS, most Linux hosts) this is the strict form: no note at all.
    sandbox_blocked = chromium_sandbox_unavailable_reason()
    if sandbox_blocked is None:
        assert "OS sandbox" not in proc.stdout and SANDBOX_WARNING not in report["warnings"]
    else:
        assert f"  - {SANDBOX_WARNING}" in proc.stdout, sandbox_blocked
        assert SANDBOX_WARNING in report["warnings"]
    entry = report["find"][0]
    assert entry["status"] == "found" and entry["verify"]["replays"] == "yes"
    matches = entry["matches"]
    assert all(m["path"] is None for m in matches)  # paths only with --keep-urls
    # Smaller responses that need a signed token or a session cookie rank higher but get no code.
    eligible = [m for m in matches if m["code_eligible"]]
    assert eligible and eligible[0]["resource_type"] == "fetch" and not any(eligible[0]["flags"].values())
    ineligible = {m["code_ineligible_reason"] for m in matches if not m["code_eligible"]}
    assert {"random-looking query token", "sent cookies"} <= ineligible
    assert matches[0]["billed_basis_bytes"] <= eligible[0]["billed_basis_bytes"]
    assert report["totals"]["tunnels"] >= 2 and report["totals"]["with_connect"] > 0
    world.wait_idle()
    # The verify replay went through the meter and the upstream, cookie-less, with the honest User-Agent.
    replays = [r for r in world.origin("origin-a.test").requests()
               if r.path == "/api/product.json" and (r.header("user-agent") or "").startswith("scrapescope/")]
    assert len(replays) == 1 and replays[0].header("cookie") is None
    report_text = read_text(out)
    assert site.PRODUCT_PRICE not in report_text  # the searched value never reaches the report
    assert_absent(secret_forms(UPSTREAM_USERNAME, UPSTREAM_PASSWORD), stdout=proc.stdout, stderr=proc.stderr,
                  report=report_text)


def test_find_reports_a_challenge_page_as_blocked(world: TestWorld, tmp_path: Path) -> None:
    out = tmp_path / "f.json"
    proc = cli(["find", "https://origin-a.test/challenge-cf", "--value", "anything", "--direct", "--keep-urls",
                "--out", str(out)], env=world.subprocess_env(), timeout=150)
    assert proc.returncode == 4, proc.stdout + proc.stderr  # blocked has its own code, never "not found" (1)
    assert "blocked; cannot search (challenge: Cloudflare)" in proc.stdout
    assert "not found" not in proc.stdout
    entry = load_report(out)["find"][0]
    assert entry["status"] == "blocked" and entry["challenge"]["vendor_id"] == "cloudflare"
    assert entry["coverage"]["line"].startswith("blocked; cannot search")
    assert entry["target_path"] == "/challenge-cf"
    assert "sizing mode" in proc.stderr


def test_find_stops_early_when_the_upstream_rejects_credentials(world: TestWorld, tmp_path: Path) -> None:
    user, password = "sentinel-find-user-P4m", "sentinel-find-pass-J8n"
    out = tmp_path / "f.json"
    started = time.monotonic()
    proc = cli(["find", "https://origin-a.test/", "--value", "x", "--timeout", "40", "--out", str(out)],
               env=world.subprocess_env({"HTTPS_PROXY": world.http_upstream.proxy_url(user, password)}), timeout=150)
    assert proc.returncode == 5, proc.stdout + proc.stderr  # the page load failed: its own code
    assert time.monotonic() - started < 30  # the abort check ended the load; Chromium alone waits for the timeout
    assert "407" in proc.stdout
    entry = load_report(out)["find"][0]
    assert entry["status"] == "error"
    assert_absent(secret_forms(user, password), stdout=proc.stdout, stderr=proc.stderr, report=read_text(out))
