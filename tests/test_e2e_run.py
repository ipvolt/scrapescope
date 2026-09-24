"""End-to-end tests of ``scrapescope run`` (the real CLI in a subprocess, no browser).

Covers: totals equal the fixture upstream's own byte counts (HTTP CONNECT and
SOCKS5), direct (sizing) mode through the test connect map, topology-preserving
routing versus ``--env-all`` (LLM hosts carried direct as non-target), the
budget trip stopping the whole process group, exit-code passthrough, the
bypass gate, deny rules, and credential sentinels on success and error paths.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import time
from pathlib import Path

import pytest

from scrapescope.config import synthetic_connect_sizes
from tests.e2e_support import (
    PYTHON,
    assert_absent,
    bucket_sum,
    cli,
    events_path_from,
    host_rows,
    load_report,
    read_text,
    secret_forms,
    wait_dead,
    write_script,
)
from tests.fixtures import UPSTREAM_PASSWORD, UPSTREAM_USERNAME, TestWorld

pytestmark = pytest.mark.timeout(120)

#: Distinctive credentials that must never leave the environment variable they came in.
SENTINEL_USER = "sentinel-user-Zq7Wx3"
SENTINEL_PASS = "sentinel-pass-Kv9Rt2"


HTTP_CLIENTS_JOB = """
import os
import httpx
import requests
from scrapescope.helpers.hooks import instrument_httpx, instrument_requests

ca = os.environ["SCRAPESCOPE_TEST_CA"]
session = instrument_requests(requests.Session())
status = session.get("https://origin-a.test/api/product.json", verify=ca, timeout=20).status_code
print("requests", status)
session.close()
with instrument_httpx(httpx.Client(verify=ca, timeout=20)) as client:
    print("httpx", client.get("https://origin-a.test/static/style.css").status_code)
    print("httpx", client.get("https://origin-b.test/embed").status_code)
"""


def _upstream_totals(records) -> tuple[int, int, int, int]:
    sent = sum(r.bytes_from_client for r in records)
    received = sum(r.bytes_to_client for r in records)
    negotiation = sum(r.negotiation_from_client + r.negotiation_to_client for r in records)
    return sent, received, negotiation, len(records)


def test_run_through_http_upstream_matches_fixture_counts(fresh_world: TestWorld, tmp_path: Path) -> None:
    world = fresh_world
    job = write_script(tmp_path, "job.py", HTTP_CLIENTS_JOB)
    out, html = tmp_path / "r.json", tmp_path / "r.html"
    env = world.subprocess_env({"HTTPS_PROXY": world.http_upstream.url})
    proc = cli(
        ["run", "--upstream-from-env", "HTTPS_PROXY", "--rate", "3", "--keep-events", "--out", str(out),
         "--html", str(html), "--", PYTHON, job],
        env=env,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.count(" 200") == 3  # the job's own stdout stays clean and complete
    world.wait_idle()
    report = load_report(out)
    sent, received, negotiation, n = _upstream_totals(world.http_upstream.records())
    totals = report["totals"]
    assert (totals["bytes_sent"], totals["bytes_received"], totals["tunnels"]) == (sent, received, n)
    assert totals["with_connect"] == sent + received
    assert totals["without_connect"] == sent + received - negotiation
    assert totals["with_connect_estimated"] is False and report["mode"] == "http-connect"
    assert report["units"] == {"count": 3, "source": "requests", "low_sample_warning": True}
    assert report["success"]["count"] == 3
    assert bucket_sum(report) == totals["with_connect"]
    assert set(host_rows(report)) == {"origin-a.test", "origin-b.test"}
    assert report["cost"]["label"] == "estimated billable transfer"
    assert report["incomplete"] is False
    assert "Totals (tunnel-measured)" in proc.stderr and "report written to" in proc.stderr
    # Every upstream connection presented the configured credentials (injected by the meter).
    assert all(r.usernames and set(r.usernames) == {UPSTREAM_USERNAME} for r in world.http_upstream.records())
    # Private events file: 0600 inside a 0700 directory, kept on request, metadata only.
    events = events_path_from(proc.stderr)
    assert events is not None and os.path.exists(events)
    try:
        assert stat.S_IMODE(os.stat(events).st_mode) == 0o600
        assert stat.S_IMODE(os.stat(os.path.dirname(events)).st_mode) == 0o700
        lines = [json.loads(line) for line in read_text(events).splitlines() if line.strip()]
        assert {e["kind"] for e in lines} == {"attach", "request"}
        assert all("path" not in e for e in lines)  # no --keep-urls
        assert_absent(secret_forms(UPSTREAM_USERNAME, UPSTREAM_PASSWORD), events=read_text(events))
    finally:
        shutil.rmtree(os.path.dirname(events), ignore_errors=True)
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o600
    assert_absent(
        [*secret_forms(UPSTREAM_USERNAME, UPSTREAM_PASSWORD), world.http_upstream.url,
         f"127.0.0.1:{world.http_upstream.port}"],
        stdout=proc.stdout, stderr=proc.stderr, report=read_text(out), html=read_text(html),
    )


def test_run_through_socks5_upstream_matches_fixture_counts(fresh_world: TestWorld, tmp_path: Path) -> None:
    world = fresh_world
    job = write_script(tmp_path, "job.py", HTTP_CLIENTS_JOB)
    out = tmp_path / "r.json"
    env = world.subprocess_env({"MY_PROXY": world.socks_upstream.url_h})
    proc = cli(["run", "--upstream-from-env", "MY_PROXY", "--env-all", "--out", str(out), "--quiet", "--", PYTHON, job],
               env=env)
    assert proc.returncode == 0, proc.stderr
    assert proc.stderr == ""  # --quiet
    world.wait_idle()
    records = world.socks_upstream.records()
    assert records and all(r.atyp == "domain" and r.username == UPSTREAM_USERNAME for r in records)  # remote DNS
    report = load_report(out)
    totals = report["totals"]
    assert totals["bytes_sent"] == sum(r.bytes_from_client for r in records)
    assert totals["bytes_received"] == sum(r.bytes_to_client for r in records)
    negotiation = sum(r.negotiation_from_client + r.negotiation_to_client for r in records)
    assert totals["with_connect"] - totals["without_connect"] == negotiation
    assert report["mode"] == "socks5"


def test_run_direct_mode_uses_connect_map_and_estimates_connect(fresh_world: TestWorld, tmp_path: Path) -> None:
    world = fresh_world
    job = write_script(
        tmp_path,
        "job.py",
        """
        import os, httpx
        ca = os.environ["SCRAPESCOPE_TEST_CA"]
        with httpx.Client(verify=ca, timeout=20) as client:   # trust_env: HTTPS_PROXY/HTTP_PROXY = the meter
            print(client.get("https://origin-a.test/api/product.json").status_code)
            print(client.get("http://origin-a.test/plain.html").status_code)
        """,
    )
    out = tmp_path / "r.json"
    proc = cli(["run", "--direct", "--env-all", "--out", str(out), "--", PYTHON, job], env=world.subprocess_env())
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.split() == ["200", "200"]
    world.wait_idle()
    report = load_report(out)
    conns = [c for scheme in ("https", "http") for c in world.origin("origin-a.test", scheme).connections()]
    totals = report["totals"]
    assert totals["bytes_sent"] == sum(c.bytes_in for c in conns)
    assert totals["bytes_received"] == sum(c.bytes_out for c in conns)
    assert totals["without_connect"] == totals["bytes_sent"] + totals["bytes_received"]
    # The with-CONNECT figure adds the estimated CONNECT exchange for the one CONNECT tunnel only: httpx's own
    # CONNECT head (meas2-9; at least the minimal head) and a typical 200 reply.
    minimal = sum(synthetic_connect_sizes("origin-a.test", 443))
    assert minimal <= totals["with_connect"] - totals["without_connect"] < minimal + 200
    assert totals["with_connect_estimated"] is True and report["mode"] == "direct"
    assert any(w.startswith("sizing mode") for w in report["warnings"])
    assert world.http_upstream.records() == [] and world.socks_upstream.records() == []


def test_run_gives_the_job_an_upstream_id_the_helper_can_match(world: TestWorld, tmp_path: Path) -> None:
    """sec2-8: SCRAPESCOPE_UPSTREAM_ID lets the Playwright helper reroute only the run's own upstream."""
    from urllib.parse import urlsplit

    parts = urlsplit(world.http_upstream.url)
    job = write_script(
        tmp_path,
        "job.py",
        f"""
        import os
        from scrapescope.helpers.playwright import _is_run_upstream
        print(os.environ.get("SCRAPESCOPE_UPSTREAM_ID", "")[:3])
        print(_is_run_upstream(({parts.hostname!r}, {parts.port})), _is_run_upstream(("other.example", 8000)))
        """,
    )
    env = world.subprocess_env({"HTTPS_PROXY": world.http_upstream.url, "SCRAPESCOPE_UPSTREAM_ID": "stale"})
    proc = cli(["run", "--quiet", "--out", str(tmp_path / "r.json"), "--", PYTHON, job], env=env)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.split() == ["v1.", "True", "False"]
    assert parts.hostname not in proc.stdout.split()[0]  # a salted fingerprint, not the host
    direct = cli(["run", "--direct", "--quiet", "--out", str(tmp_path / "d.json"), "--", PYTHON, job], env=env)
    assert direct.returncode == 0, direct.stderr
    assert direct.stdout.split() == ["None", "None"]  # no upstream: no id (an inherited one is removed)


def test_run_direct_without_env_all_changes_no_proxy_variables(world: TestWorld, tmp_path: Path) -> None:
    job = write_script(
        tmp_path,
        "job.py",
        """
        import json, os
        keys = ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY", "https_proxy", "NODE_USE_ENV_PROXY")
        print(json.dumps({k: os.environ.get(k) for k in keys}))
        print(json.dumps({k: os.environ.get(k) for k in ("SCRAPESCOPE_PROXY_URL", "SCRAPESCOPE_AUTH_PROXY_URL",
                                                          "SCRAPESCOPE_EVENTS", "SCRAPESCOPE_KEEP_URLS")}))
        """,
    )
    env = world.subprocess_env({"HTTPS_PROXY": "http://proxy.invalid:1"})
    proc = cli(["run", "--direct", "--keep-urls", "--out", str(tmp_path / "r.json"), "--", PYTHON, job], env=env)
    assert proc.returncode == 0, proc.stderr
    proxies, ours = (json.loads(line) for line in proc.stdout.splitlines())
    assert proxies == {"HTTPS_PROXY": "http://proxy.invalid:1", "HTTP_PROXY": None, "ALL_PROXY": None,
                       "NO_PROXY": None, "https_proxy": None, "NODE_USE_ENV_PROXY": None}
    assert ours["SCRAPESCOPE_PROXY_URL"].startswith("http://127.0.0.1:")
    assert ours["SCRAPESCOPE_AUTH_PROXY_URL"].startswith("http://127.0.0.1:")
    assert ours["SCRAPESCOPE_AUTH_PROXY_URL"] != ours["SCRAPESCOPE_PROXY_URL"]
    assert ours["SCRAPESCOPE_KEEP_URLS"] == "1"
    assert ours["SCRAPESCOPE_EVENTS"] and not os.path.exists(ours["SCRAPESCOPE_EVENTS"])  # deleted after the run
    assert "--direct without --env-all changes no proxy variables" in proc.stderr


LLM_AND_SCRAPE_JOB = """
import json, os, sys
import httpx

ca = os.environ["SCRAPESCOPE_TEST_CA"]
llm_port = int(sys.argv[1])
env = {k: os.environ.get(k) for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY",
                                      "no_proxy", "NODE_USE_ENV_PROXY", "SCRAPESCOPE_PROXY_URL")}
print(json.dumps(env))
with httpx.Client(verify=ca, timeout=20) as scraper:      # uses the proxy variables (trust_env)
    print("scrape", scraper.get("https://origin-a.test/api/product.json").status_code)
if sys.argv[2] == "no-proxy":
    # The job's LLM client had no proxy before: it dials the API itself (here the local fake,
    # addressed by IP with the API's hostname for SNI and Host).
    with httpx.Client(verify=ca, timeout=20, trust_env=False) as llm:
        r = llm.get(f"https://127.0.0.1:{llm_port}/v1/models", headers={"Host": "api.openai.com"},
                    extensions={"sni_hostname": "api.openai.com"})
else:
    with httpx.Client(verify=ca, timeout=20) as llm:       # follows the proxy variables
        r = llm.get("https://api.openai.com/v1/models")
print("llm", r.status_code)
"""


def test_default_mode_leaves_an_unproxied_llm_call_alone(fresh_world: TestWorld, tmp_path: Path) -> None:
    world = fresh_world
    job = write_script(tmp_path, "job.py", LLM_AND_SCRAPE_JOB)
    llm_port = world.origin("api.openai.com").address[1]
    out = tmp_path / "r.json"
    upstream = world.http_upstream.url
    env = world.subprocess_env({"HTTPS_PROXY": upstream, "https_proxy": upstream})
    proc = cli(["run", "--out", str(out), "--", PYTHON, job, str(llm_port), "no-proxy"], env=env)
    assert proc.returncode == 0, proc.stderr
    child_env = json.loads(proc.stdout.splitlines()[0])
    meter = child_env["SCRAPESCOPE_PROXY_URL"]
    # Topology preserved: only the variable holding the upstream (and its duplicate) changed.
    assert child_env["HTTPS_PROXY"] == meter and child_env["https_proxy"] == meter
    assert child_env["HTTP_PROXY"] is None and child_env["ALL_PROXY"] is None
    assert child_env["NO_PROXY"] is None and child_env["NODE_USE_ENV_PROXY"] is None
    assert "scrape 200" in proc.stdout and "llm 200" in proc.stdout
    world.wait_idle()
    assert all("api.openai.com" not in t for r in world.http_upstream.records() for t in r.targets)
    assert [r.path for r in world.origin("api.openai.com").requests()] == ["/v1/models"]
    report = load_report(out)
    assert set(host_rows(report)) == {"origin-a.test"} and report["non_target"] == []
    assert_absent(secret_forms(UPSTREAM_USERNAME, UPSTREAM_PASSWORD), stdout=proc.stdout, stderr=proc.stderr)


def test_env_all_carries_llm_hosts_direct_as_non_target(fresh_world: TestWorld, tmp_path: Path) -> None:
    world = fresh_world
    job = write_script(tmp_path, "job.py", LLM_AND_SCRAPE_JOB)
    out = tmp_path / "r.json"
    env = world.subprocess_env({"HTTPS_PROXY": world.http_upstream.url, "NO_PROXY": "internal.example"})
    proc = cli(["run", "--env-all", "--out", str(out), "--", PYTHON, job, "0", "proxy"], env=env)
    assert proc.returncode == 0, proc.stderr
    child_env = json.loads(proc.stdout.splitlines()[0])
    meter = child_env["SCRAPESCOPE_PROXY_URL"]
    assert child_env["HTTP_PROXY"] == child_env["ALL_PROXY"] == child_env["HTTPS_PROXY"] == meter
    assert child_env["NODE_USE_ENV_PROXY"] == "1"
    assert child_env["NO_PROXY"] == child_env["no_proxy"] == "internal.example,127.0.0.1,localhost,::1"
    assert "llm 200" in proc.stdout
    world.wait_idle()
    targets = [t for r in world.http_upstream.records() for t in r.targets]
    assert "origin-a.test:443" in targets
    assert not any("api.openai.com" in t for t in targets)  # never sent to the upstream
    assert [r.path for r in world.origin("api.openai.com").requests()] == ["/v1/models"]
    report = load_report(out)
    assert [(n["host"], n["catalog_id"], n["tunnels"]) for n in report["non_target"]] == [("api.openai.com", "openai", 1)]
    assert set(host_rows(report)) == {"origin-a.test"}  # non-target bytes stay out of hosts and totals
    assert report["totals"]["tunnels"] == 1
    # sec-1: the IP exposure is stated at start and in the report, not only in the docs.
    assert "DIRECT, not through your proxy" in proc.stderr and "own IP address" in proc.stderr
    assert any("bypassed the upstream proxy" in w and "own IP address" in w for w in report["warnings"])


def test_env_all_without_upstream_prints_no_exposure_note(fresh_world: TestWorld, tmp_path: Path) -> None:
    """Sizing mode connects everything from the local IP anyway; the note is only for a configured proxy."""
    job = write_script(tmp_path, "job.py", "print('ok')\n")
    out = tmp_path / "r.json"
    proc = cli(["run", "--direct", "--env-all", "--out", str(out), "--", PYTHON, job], env=fresh_world.subprocess_env())
    assert proc.returncode == 0, proc.stderr
    assert "DIRECT, not through your proxy" not in proc.stderr


def test_budget_trip_stops_the_whole_process_group(fresh_world: TestWorld, tmp_path: Path) -> None:
    world = fresh_world
    pidfile = tmp_path / "grandchild.pid"
    job = write_script(
        tmp_path,
        "job.py",
        """
        import os, subprocess, sys, time
        import httpx
        pidfile = sys.argv[1]
        code = ("import os, signal, time\\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\\n"
                f"open({pidfile!r}, 'w').write(str(os.getpid()))\\n"
                "time.sleep(600)\\n")
        subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
        while not os.path.exists(pidfile) or not open(pidfile).read():
            time.sleep(0.01)
        try:
            with httpx.Client(verify=os.environ["SCRAPESCOPE_TEST_CA"], timeout=30) as client:
                with client.stream("GET", "https://origin-a.test/big.bin?size=40000000&chunk=65536&delay_ms=1") as r:
                    for _ in r.iter_bytes():
                        pass
            print("download finished", flush=True)
        except Exception as exc:
            print("download stopped:", type(exc).__name__, flush=True)
        time.sleep(120)  # scrapescope must stop us
        """,
    )
    out = tmp_path / "r.json"
    started = time.monotonic()
    proc = cli(
        ["run", "--budget", "2MB", "--out", str(out), "--", PYTHON, job, str(pidfile)],
        env=world.subprocess_env({"HTTPS_PROXY": world.http_upstream.url}),
    )
    elapsed = time.monotonic() - started
    assert proc.returncode == 86, proc.stderr
    assert "download stopped" in proc.stdout
    assert elapsed < 60
    grandchild = int(pidfile.read_text())
    assert wait_dead(grandchild), "the grandchild that ignored SIGTERM survived the budget trip"
    assert "byte budget tripped" in proc.stderr and "origin-a.test" in proc.stderr
    assert "80% of the byte budget used" in proc.stderr
    report = load_report(out)
    assert report["budget"]["tripped"] is True and report["budget"]["limit_bytes"] == 2_000_000
    kinds = [e["kind"] for e in report["budget_events"]]
    assert kinds[:2] == ["warn_80", "tripped"]
    tripped = report["budget_events"][1]
    assert tripped["counted_bytes"] >= 2_000_000
    assert tripped["top_hosts"][0]["host"] == "origin-a.test"
    assert any(w.startswith("budget tripped") for w in report["warnings"])
    # The budget is a floor, not a cap: the upstream had already written some bytes into the
    # socket that the meter never read before it aborted the tunnel. What the meter counted is
    # never more than what the upstream handed over, and the gap is bounded by socket buffers.
    world.wait_idle()
    records = world.http_upstream.records()
    handed_over = sum(r.bytes_from_client + r.bytes_to_client for r in records)
    counted = report["budget"]["counted_bytes"]
    assert counted <= handed_over < counted + 4_000_000
    sent_by_meter = sum(r.bytes_from_client for r in records)
    assert report["totals"]["bytes_sent"] == sent_by_meter  # the upload direction is exact


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("import sys; sys.exit(7)", 7),
        ("import sys; sys.exit(0)", 0),
        ("import os, signal; os.kill(os.getpid(), signal.SIGTERM)", 143),
    ],
)
def test_run_passes_the_job_exit_code_through(world: TestWorld, tmp_path: Path, code: str, expected: int) -> None:
    proc = cli(["run", "--direct", "--quiet", "--out", str(tmp_path / "r.json"), "--", PYTHON, "-c", code],
               env=world.subprocess_env())
    assert proc.returncode == expected, proc.stderr
    assert load_report(tmp_path / "r.json")["command"] == "run"


def test_run_missing_or_non_executable_command(world: TestWorld, tmp_path: Path) -> None:
    env = world.subprocess_env()
    missing = cli(["run", "--direct", "--out", str(tmp_path / "a.json"), "--", "scrapescope-no-such-command-x9"], env=env)
    assert missing.returncode == 127 and "command not found" in missing.stderr
    script = tmp_path / "not-executable.sh"
    script.write_text("#!/bin/sh\necho hi\n")
    script.chmod(0o644)
    denied = cli(["run", "--direct", "--out", str(tmp_path / "b.json"), "--", str(script)], env=env)
    assert denied.returncode == 126 and "not executable" in denied.stderr
    # Arguments after "--" belong to the job, including a second "--".
    echo = cli(["run", "--direct", "--quiet", "--out", str(tmp_path / "c.json"), "--", PYTHON, "-c",
                "import sys; print(sys.argv[1:])", "--", "--quiet"], env=env)
    assert echo.returncode == 0 and echo.stdout.strip() == "['--', '--quiet']"


BYPASS_JOB = """
import httpx
from scrapescope.helpers.hooks import instrument_httpx

def handler(request):
    return httpx.Response(200, text="served without the meter")

# A client that never goes through the meter (here: an in-memory transport).
with instrument_httpx(httpx.Client(transport=httpx.MockTransport(handler))) as client:
    print(client.get("https://origin-b.test/api/data").status_code)
"""


def test_bypass_is_detected_and_gated(world: TestWorld, tmp_path: Path) -> None:
    job = write_script(tmp_path, "job.py", BYPASS_JOB)
    env = world.subprocess_env()
    out = tmp_path / "r.json"
    plain = cli(["run", "--direct", "--quiet", "--out", str(out), "--", PYTHON, job], env=env)
    assert plain.returncode == 0, plain.stderr
    report = load_report(out)
    assert report["incomplete"] is True and report["bypass"] == {"hosts": ["origin-b.test"], "requests": 1}
    gated = cli(["run", "--direct", "--fail-on", "bypass", "--out", str(out), "--", PYTHON, job], env=env)
    assert gated.returncode == 87, gated.stderr
    assert "INCOMPLETE" in gated.stderr


def test_deny_catalog_background_refuses_catalogued_hosts(fresh_world: TestWorld, tmp_path: Path) -> None:
    world = fresh_world
    job = write_script(
        tmp_path,
        "job.py",
        """
        import os, httpx
        with httpx.Client(verify=os.environ["SCRAPESCOPE_TEST_CA"], timeout=20) as client:
            try:
                client.get("https://optimizationguide-pa.googleapis.com/")
            except httpx.ProxyError as exc:
                print("refused", "403" in str(exc))
            print(client.get("https://origin-a.test/api/product.json").status_code)
        """,
    )
    out = tmp_path / "r.json"
    proc = cli(["run", "--deny-catalog", "background", "--deny-host", "*.nothing.test", "--out", str(out), "--",
                PYTHON, job], env=world.subprocess_env({"HTTPS_PROXY": world.http_upstream.url}))
    assert proc.returncode == 0, proc.stderr
    assert "refused True" in proc.stdout and "200" in proc.stdout
    world.wait_idle()
    assert not any("optimizationguide" in t for r in world.http_upstream.records() for t in r.targets)
    rows = host_rows(load_report(out))
    assert rows["optimizationguide-pa.googleapis.com"]["denied_tunnels"] == 1
    assert rows["optimizationguide-pa.googleapis.com"]["bytes_with_connect"] == 0


ERROR_JOB = """
import os, sys
import httpx
try:
    with httpx.Client(verify=os.environ["SCRAPESCOPE_TEST_CA"], timeout=15) as client:
        print("status", client.get(sys.argv[1]).status_code)
except Exception as exc:
    print("error", type(exc).__name__, str(exc)[:500])
sys.exit(3)
"""


def _error_case(world: TestWorld, case: str, closed_port: int) -> tuple[str, str, list[str], str]:
    """(upstream URL, target URL, secrets, expected failed-tunnel status prefix)."""
    if case == "unreachable":
        return (f"http://{SENTINEL_USER}:{SENTINEL_PASS}@127.0.0.1:{closed_port}", "https://origin-a.test/",
                secret_forms(SENTINEL_USER, SENTINEL_PASS), "failed:upstream_unreachable")
    if case == "407":
        return (world.http_upstream.proxy_url(SENTINEL_USER, SENTINEL_PASS), "https://origin-a.test/",
                secret_forms(SENTINEL_USER, SENTINEL_PASS), "failed:upstream_status")
    if case == "socks-auth":
        return (world.socks_upstream.proxy_url(SENTINEL_USER, SENTINEL_PASS, scheme="socks5h"), "https://origin-a.test/",
                secret_forms(SENTINEL_USER, SENTINEL_PASS), "failed:socks_auth")
    if case == "upstream-dns":
        return (world.http_upstream.url, "https://no-such-host.test/",
                secret_forms(UPSTREAM_USERNAME, UPSTREAM_PASSWORD), "failed:upstream_status")
    assert case == "tls-error"
    return (world.http_upstream.url, "https://badcert.test/", secret_forms(UPSTREAM_USERNAME, UPSTREAM_PASSWORD), "ok")


@pytest.mark.parametrize("case", ["unreachable", "407", "socks-auth", "upstream-dns", "tls-error"])
def test_credentials_never_leak_on_error_paths(world: TestWorld, tmp_path: Path, closed_port: int, case: str) -> None:
    upstream, target, secrets, status = _error_case(world, case, closed_port)
    job = write_script(tmp_path, "job.py", ERROR_JOB)
    out, html = tmp_path / "r.json", tmp_path / "r.html"
    proc = cli(["run", "--keep-events", "--out", str(out), "--html", str(html), "--", PYTHON, job, target],
               env=world.subprocess_env({"HTTPS_PROXY": upstream}))
    assert proc.returncode == 3, proc.stderr  # the job's own code
    assert ("error" in proc.stdout) if case != "upstream-dns" else ("error" in proc.stdout or "status" in proc.stdout)
    events = events_path_from(proc.stderr)
    try:
        report_text = read_text(out)
        assert_absent(
            [*secrets, upstream, upstream.split("@")[-1]],
            stdout=proc.stdout, stderr=proc.stderr, report=report_text, html=read_text(html),
            events=read_text(events) if events else "",
        )
    finally:
        if events:
            shutil.rmtree(os.path.dirname(events), ignore_errors=True)
    report = load_report(out)
    host = target.split("/")[2]
    row = host_rows(report)[host]
    assert row["tunnels"] >= 1
    if status != "ok":
        assert row["failed_tunnels"] >= 1 and report["totals"]["failed_tunnels"] >= 1
    # docs-2: the likely cause is named (the variable, never its value).
    expected = {
        "unreachable": ("every tunnel failed (upstream_unreachable x", "$HTTPS_PROXY did not accept connections"),
        "407": ("every tunnel failed (upstream_status 407 x", "check the credentials in $HTTPS_PROXY"),
        "socks-auth": ("every tunnel failed (socks_auth x", "rejected the credentials in $HTTPS_PROXY"),
    }.get(case)
    failure_warnings = [w for w in report["warnings"] if "tunnel failed" in w or "tunnels failed" in w]
    if expected is None:
        assert failure_warnings == [] or case == "upstream-dns"
    else:
        assert any(all(part in w for part in expected) for w in failure_warnings), report["warnings"]
        assert expected[1] in proc.stderr  # the terminal summary shows it too


def test_upstream_configuration_errors_exit_89_without_echoing_the_url(world: TestWorld, tmp_path: Path) -> None:
    env = world.subprocess_env()
    missing = cli(["run", "--out", str(tmp_path / "r.json"), "--", PYTHON, "-c", "pass"], env=env)
    assert missing.returncode == 89 and "--direct" in missing.stderr
    bad = f"https://{SENTINEL_USER}:{SENTINEL_PASS}@proxy.invalid:8443"
    https = cli(["run", "--upstream-from-env", "UP", "--out", str(tmp_path / "r.json"), "--", PYTHON, "-c", "pass"],
                env={**env, "UP": bad})
    assert https.returncode == 89 and "UP" in https.stderr
    socks4 = cli(["find", "https://origin-a.test/", "--value", "x", "--out", str(tmp_path / "f.json")],
                 env={**env, "HTTPS_PROXY": f"socks4://{SENTINEL_USER}@proxy.invalid:1080"})
    assert socks4.returncode == 89
    for proc in (https, socks4):
        assert_absent([*secret_forms(SENTINEL_USER, SENTINEL_PASS), "proxy.invalid"], stdout=proc.stdout,
                      stderr=proc.stderr)
    assert not (tmp_path / "r.json").exists()


# ---------------------------------------------------------------------------- open-file limit (meas2-4, sec2-6)
HOLD_TUNNELS_JOB = """
import os, resource, socket, sys, time
proxy = os.environ["SCRAPESCOPE_PROXY_URL"].rsplit("/", 1)[-1]
host, port = proxy.rsplit(":", 1)
socks, ok = [], 0
for _ in range(int(sys.argv[1])):
    s = socket.create_connection((host, int(port)), timeout=10)
    s.sendall(b"CONNECT hold.test:443 HTTP/1.1\\r\\nHost: hold.test:443\\r\\n\\r\\n")
    head = b""
    while b"\\r\\n\\r\\n" not in head:
        chunk = s.recv(4096)
        if not chunk:
            break
        head += chunk
    ok += head.startswith(b"HTTP/1.1 200")
    socks.append(s)
    time.sleep(0.005)
print("ok", ok, "limit", resource.getrlimit(resource.RLIMIT_NOFILE)[0], flush=True)
for s in socks:
    s.close()
"""

LOW_LIMIT_WRAPPER = """
import resource, sys
resource.setrlimit(resource.RLIMIT_NOFILE, (int(sys.argv[1]), resource.getrlimit(resource.RLIMIT_NOFILE)[1]))
from scrapescope.cli import main
sys.exit(main(sys.argv[2:]))
"""


def test_run_raises_the_meters_file_limit_and_the_job_keeps_its_own(world: TestWorld, tmp_path: Path) -> None:
    """64 held tunnels need 128+ descriptors in the meter: fine under a 128 soft limit once raised.

    The job itself still runs with the 128 it was started with (its own limit is
    part of what it does without the meter).
    """
    import socket

    from tests.test_forwarder_helpers import LocalServer

    def hold(sock: socket.socket) -> None:
        sock.settimeout(60)
        try:
            while sock.recv(65536):
                pass
        except OSError:
            pass

    job = write_script(tmp_path, "job.py", HOLD_TUNNELS_JOB)
    wrapper = write_script(tmp_path, "wrapper.py", LOW_LIMIT_WRAPPER)
    out = tmp_path / "r.json"
    with LocalServer(hold) as server:
        env = world.subprocess_env({"SCRAPESCOPE_TEST_CONNECT_MAP": json.dumps({"hold.test:443": f"127.0.0.1:{server.port}"})})
        import subprocess

        proc = subprocess.run(
            [PYTHON, wrapper, "128", "run", "--direct", "--out", str(out), "--", PYTHON, job, "64"],
            env=env, capture_output=True, text=True, timeout=90, stdin=subprocess.DEVNULL,
        )
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert "ok 64 limit 128" in proc.stdout, proc.stdout
    report = load_report(out)
    assert report["totals"]["tunnels"] == 64 and report["totals"]["failed_tunnels"] == 0
    assert not any("file descriptors" in w for w in report["warnings"])
