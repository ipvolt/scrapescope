"""In-process tests of ``scrapescope.cli.main``: parsing, usage errors, config errors and ``report``.

Everything here runs ``main(argv)`` in the test process (no job, no browser);
the subprocess end-to-end tests live in tests/test_e2e_*.py.
"""

from __future__ import annotations

import copy
import json
import os
import re
import stat
import subprocess
import sys
from html import escape as html_escape
from pathlib import Path
from typing import Any

import pytest

from scrapescope import __version__
from scrapescope.cli import _split_run_command, build_parser, main
from scrapescope.report import content_security_policy

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "docs" / "dev" / "example-report.json"
EXAMPLE_FIND = ROOT / "docs" / "dev" / "example-report-find.json"
SENTINEL = "sentinel-cli-pass-W2e"


def _example(**changes: Any) -> dict[str, Any]:
    report = json.loads(EXAMPLE.read_text())
    for dotted, value in changes.items():
        target = report
        *parents, leaf = dotted.split(".")
        for key in parents:
            target = target[key]
        target[leaf] = value
    return report


def _write(tmp_path: Path, name: str, report: dict[str, Any]) -> str:
    path = tmp_path / name
    path.write_text(json.dumps(report))
    return str(path)


# ---------------------------------------------------------------------------- parsing


def test_version_and_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--version"]) == 0
    assert capsys.readouterr().out.strip() == f"scrapescope {__version__}"
    for sub in ([], ["run"], ["serve"], ["find"], ["report"]):
        assert main([*sub, "--help"]) == 0
        assert "usage: scrapescope" in capsys.readouterr().out


def test_python_dash_m_entry_point() -> None:
    proc = subprocess.run([sys.executable, "-m", "scrapescope", "--version"], capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0 and proc.stdout.strip() == f"scrapescope {__version__}"


def test_no_subcommand_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 2
    assert "usage: scrapescope" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv",
    [
        ["run", "--direct", "--upstream-from-env", "HTTPS_PROXY", "--", "true"],  # mutually exclusive
        ["run", "--budget", "lots", "--direct", "--", "true"],
        ["run", "--budget", "0", "--direct", "--", "true"],
        ["run", "--rate", "-1", "--direct", "--", "true"],
        ["run", "--rate", "nan", "--direct", "--", "true"],
        ["run", "--max-tunnel-mb", "0", "--direct", "--", "true"],
        ["run", "--port", "70000", "--direct", "--", "true"],
        ["run", "--units", "0", "--direct", "--", "true"],
        ["run", "--deny-host", "evil[.]test", "--direct", "--", "true"],
        ["run", "--deny-catalog", "ads", "--direct", "--", "true"],
        ["run", "--fail-on", "budget", "--direct", "--", "true"],  # run gates only on bypass
        ["run", "--direct"],  # no command
        ["run", "--direct", "--"],
        ["serve", "--env-all"],  # run-only option
        ["find", "https://origin-a.test/"],  # --value is required
        ["find", "--value", "x"],  # URL is required
        ["report"],
        ["report", "r.json", "--format", "pdf"],
        ["report", "r.json", "--fail-on", "everything"],
        ["frobnicate"],
    ],
)
def test_usage_errors_exit_2(argv: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    assert main(argv) == 2
    assert capsys.readouterr().err


def test_split_run_command_keeps_the_jobs_own_double_dash() -> None:
    assert _split_run_command(["run", "--direct", "--", "python", "--", "-x"]) == (["run", "--direct"], ["python", "--", "-x"])
    assert _split_run_command(["find", "u", "--value", "--"]) == (["find", "u", "--value", "--"], None)
    parser = build_parser()
    ns = parser.parse_args(["run", "--direct", "python", "job.py"])
    assert ns.command == ["python", "job.py"]  # a command without "--" also works


def test_find_value_and_url_checks_happen_before_anything_starts(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    out = str(tmp_path / "f.json")
    assert main(["find", "ftp://origin-a.test/", "--value", SENTINEL, "--direct", "--out", out]) == 2
    assert main(["find", "https://origin-a.test/", "--value", "  ", "--direct", "--out", out]) == 2
    too_many = [arg for i in range(51) for arg in ("--value", f"v{i}")]
    assert main(["find", "https://origin-a.test/", *too_many, "--direct", "--out", out]) == 2
    err = capsys.readouterr().err
    assert SENTINEL not in err and "at most 50" in err
    assert not os.path.exists(out)


def test_report_paths_are_checked_before_the_job_runs(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    marker = tmp_path / "ran"
    job = [sys.executable, "-c", f"open({str(marker)!r}, 'w').write('x')"]
    assert main(["run", "--direct", "--out", str(tmp_path / "missing" / "r.json"), "--", *job]) == 2
    assert main(["run", "--direct", "--out", str(tmp_path), "--", *job]) == 2
    assert main(["run", "--direct", "--html", str(tmp_path / "nope" / "r.html"), "--", *job]) == 2
    assert not marker.exists()
    assert "does not exist" in capsys.readouterr().err


def test_upstream_config_errors_exit_89_and_never_echo_the_value(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = str(tmp_path / "r.json")
    monkeypatch.delenv("HTTPS_PROXY", raising=False)
    assert main(["run", "--out", out, "--", "true"]) == 89
    assert "--direct" in capsys.readouterr().err
    for value in (f"https://u:{SENTINEL}@proxy.invalid:1", f"socks4://u:{SENTINEL}@proxy.invalid:1",
                  f"http://u:{SENTINEL}@proxy.invalid:1/path", f"ftp://u:{SENTINEL}@proxy.invalid"):
        monkeypatch.setenv("SS_TEST_UP", value)
        assert main(["serve", "--upstream-from-env", "SS_TEST_UP", "--out", out]) == 89
        err = capsys.readouterr().err
        assert "SS_TEST_UP" in err and SENTINEL not in err and "proxy.invalid" not in err
    assert main(["serve", "--upstream-from-env", "NOT-A-VAR", "--out", out]) == 89
    assert main(["serve", "--upstream-from-env", "SS_TEST_UNSET_VAR", "--out", out]) == 89
    assert not os.path.exists(out)


def test_port_in_use_exits_88(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    import socket

    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        port = busy.getsockname()[1]
        assert main(["run", "--direct", "--port", str(port), "--out", str(tmp_path / "r.json"), "--", "true"]) == 88
    assert "could not" in capsys.readouterr().err


# ---------------------------------------------------------------------------- report


def test_report_text_json_and_html(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    path = str(EXAMPLE)
    assert main(["report", path]) == 0
    text = capsys.readouterr().out
    assert "Totals (tunnel-measured)" in text and "not a bill" in text
    assert main(["report", path, "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out) == json.loads(EXAMPLE.read_text())
    assert main(["report", path, "--format", "html"]) == 0
    html = capsys.readouterr().out
    assert html.startswith("<!DOCTYPE html>") and "<script" not in html
    assert html_escape(content_security_policy(), quote=True) in html
    out = tmp_path / "out.html"
    assert main(["report", path, "--format", "html", "--html", str(out)]) == 0
    assert capsys.readouterr().out == ""
    assert out.read_text() == html
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o600
    assert main(["report", str(EXAMPLE_FIND)]) == 0
    assert "find" in capsys.readouterr().out.lower()


def test_report_fail_on_gates(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    ok = str(EXAMPLE)
    tripped = _write(tmp_path, "tripped.json", _example(**{"budget.tripped": True}))
    incomplete = _write(tmp_path, "incomplete.json", _example(incomplete=True))
    both = _write(tmp_path, "both.json", _example(**{"budget.tripped": True, "incomplete": True}))
    assert main(["report", ok, "--fail-on", "budget", "--fail-on", "bypass"]) == 0
    assert main(["report", tripped, "--fail-on", "budget"]) == 86
    assert main(["report", tripped, "--fail-on", "bypass"]) == 0
    assert main(["report", incomplete, "--fail-on", "bypass"]) == 87
    assert main(["report", incomplete]) == 0  # no gate, no failure
    assert main(["report", both, "--fail-on", "bypass", "--fail-on", "budget"]) == 86  # 86 wins
    assert main(["report", both, "--format", "json", "--fail-on", "bypass"]) == 87
    capsys.readouterr()


def test_report_rejects_unreadable_or_invalid_files(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["report", str(tmp_path / "missing.json")]) == 2
    (tmp_path / "junk.json").write_text("{not json")
    assert main(["report", str(tmp_path / "junk.json")]) == 2
    bad = _example()
    bad["extra_field"] = SENTINEL
    assert main(["report", _write(tmp_path, "bad.json", bad)]) == 2
    wrong = copy.deepcopy(_example())
    wrong["totals"]["with_connect"] = f"{SENTINEL}"
    assert main(["report", _write(tmp_path, "wrong.json", wrong)]) == 2
    captured = capsys.readouterr()
    assert SENTINEL not in captured.err and SENTINEL not in captured.out
    assert captured.err.count("scrapescope: error:") == 4


# ---------------------------------------------------------------------------- wiring


def test_upstream_url_is_never_accepted_on_argv(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    url = f"http://user:{SENTINEL}@proxy.invalid:8000"
    assert main(["run", "--upstream-from-env", url, "--out", str(tmp_path / "r.json"), "--", "true"]) == 89
    err = capsys.readouterr().err
    assert "environment variable name" in err and SENTINEL not in err
    run_parser = build_parser()._subparsers._group_actions[0].choices["run"]  # type: ignore[union-attr]
    value_options = {opt for action in run_parser._actions if action.option_strings and action.nargs != 0
                     for opt in action.option_strings}
    # Every option that takes a value, and none of them is a proxy URL.
    assert value_options == {"--upstream-from-env", "--rate", "--budget", "--max-tunnel-mb", "--deny-host",
                             "--deny-catalog", "--units", "--out", "--html", "--port", "--fail-on"}


def test_max_tunnel_mb_is_decimal_megabytes_regardless_of_gib() -> None:
    from scrapescope.cli import _common_kwargs

    for argv in (["run", "--max-tunnel-mb", "1.5", "--direct", "true"],
                 ["run", "--max-tunnel-mb", "1.5", "--gib", "--direct", "true"]):
        assert _common_kwargs(build_parser().parse_args(argv))["max_tunnel_bytes"] == 1_500_000


def _fake_find(monkeypatch: pytest.MonkeyPatch, *, raises: Exception | None = None,
               status: str = "not_found", missing: list[int] | None = None) -> dict[str, Any]:
    import scrapescope.find as find_pkg
    from scrapescope import runner
    from scrapescope.types import ChallengeResult, FindResult

    seen: dict[str, Any] = {}
    # pkg-r3-1: find is faked, so the Playwright package (an optional extra) is not needed here; without this
    # the runner's availability check exits 3 before the fake runs where Playwright is not installed.
    monkeypatch.setattr(runner, "_playwright_installed", lambda: True)

    async def fake_run_find(url: str, values: list[str], **kwargs: Any) -> FindResult:
        seen.update(kwargs, url=url, values=values)
        if raises is not None:
            raise raises
        return FindResult(status=status, target_host="origin-a.test", target_path="/", values_count=len(values),  # type: ignore[arg-type]
                          short_value_warning=False, challenge=ChallengeResult(blocked=status == "blocked"),
                          target_url=url, missing_values=list(missing or []))

    monkeypatch.setattr(find_pkg, "run_find", fake_run_find)
    return seen


def test_find_passes_options_and_maps_outcomes(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
                                               tmp_path: Path) -> None:
    seen = _fake_find(monkeypatch)
    out = tmp_path / "f.json"
    assert main(["find", "https://origin-a.test/", "--value", SENTINEL, "--direct", "--out", str(out)]) == 1
    assert seen["body_cap_bytes"] == 5_000_000 and seen["timeout_s"] == 45.0 and seen["verify"] is False
    assert seen["proxy_url"].startswith("http://127.0.0.1:") and seen["values"] == [SENTINEL]
    assert main(["find", "https://origin-a.test/", "--value", "v", "--direct", "--body-cap-mb", "2.5",
                 "--timeout", "12", "--verify", "--out", str(out)]) == 1
    assert seen["body_cap_bytes"] == 2_500_000 and seen["timeout_s"] == 12.0 and seen["verify"] is True
    report = json.loads(out.read_text())
    assert report["command"] == "find" and report["find"][0]["status"] == "not_found"
    captured = capsys.readouterr()
    assert "not found in 0 inspected responses" in captured.out
    assert SENTINEL not in out.read_text()


@pytest.mark.parametrize("status,code", [("not_found", 1), ("blocked", 4), ("error", 5)])
def test_find_outcomes_have_distinct_exit_codes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
                                               status: str, code: int) -> None:
    """find-13: a script can tell "blocked" and "load failed" from "not found" without parsing the report."""
    _fake_find(monkeypatch, status=status)
    out = tmp_path / "f.json"
    assert main(["find", "https://origin-a.test/", "--value", "v", "--direct", "--out", str(out)]) == code
    assert json.loads(out.read_text())["find"][0]["status"] == status


def test_find_partial_result_exits_6(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """find-r2-9: some values found, one missing everywhere: exit 6, so `find ... && next` stops."""
    out = tmp_path / "f.json"
    _fake_find(monkeypatch, status="found", missing=[1])
    assert main(["find", "https://origin-a.test/", "--value", "a", "--value", "b", "--direct", "--out", str(out)]) == 6
    assert json.loads(out.read_text())["find"][0]["status"] == "found"
    _fake_find(monkeypatch, status="found")
    assert main(["find", "https://origin-a.test/", "--value", "a", "--value", "b", "--direct", "--out", str(out)]) == 0


def test_find_abort_check_names_meter_refusals_of_the_https_target() -> None:
    """honest-2: a refused CONNECT to the target ends the load with the reason (no retry, no bare net error)."""
    from scrapescope.runner import _find_abort_check
    from scrapescope.types import MeterSnapshot, TunnelRecord

    def snap(*tunnels: TunnelRecord) -> MeterSnapshot:
        return MeterSnapshot(taken_at=1.0, started_at=0.0, mode="direct", port=1, auth_port=None, tunnels=list(tunnels),
                             counted_bytes=0, budget_bytes=None, max_tunnel_bytes=None, budget_tripped=False)

    class FakeMeter:
        def __init__(self, snapshot: MeterSnapshot) -> None:
            self.value = snapshot

        def snapshot(self) -> MeterSnapshot:
            return self.value

    def record(host: str, port: int, status: str, kind: str = "connect", route: str = "direct") -> TunnelRecord:
        return TunnelRecord(id=1, host=host, port=port, kind=kind, route=route, opened_at=0.0, status=status)  # type: ignore[arg-type]

    url = "https://192.168.1.1/"
    cases = [
        (record("192.168.1.1", 443, "failed:private_address"), "--allow-private-targets"),
        (record("192.168.1.1", 443, "denied", route="refused"), "--deny-host"),
        (record("192.168.1.1", 443, "failed:self_loop"), "the meter itself"),
    ]
    for tunnel, needle in cases:
        reason = _find_abort_check(FakeMeter(snap(tunnel)), None, url)()
        assert reason is not None and needle in reason, reason
    # another host (a subresource) or a plain-http target is not the https target's refusal
    assert _find_abort_check(FakeMeter(snap(record("10.0.0.2", 443, "failed:private_address"))), None, url)() is None
    assert _find_abort_check(
        FakeMeter(snap(record("192.168.1.1", 80, "failed:private_address", kind="http"))), None, "http://192.168.1.1/"
    )() is None


def test_find_abort_check_compares_canonical_hosts_and_advises_the_flag_only_for_the_first_connection() -> None:
    """sec4-3 / sec4-2 (runner side): the target is matched in the meter's canonical spelling, and
    --allow-private-targets is advised only when the first connection to the target was refused.

    A refusal after an earlier connection to the target succeeded means its name moved to a private
    address (rebinding or split DNS): the page did that, so the flag is not advised; a target given
    as a name gets the rebinding caution.
    """
    from scrapescope.runner import _find_abort_check
    from scrapescope.types import MeterSnapshot, TunnelRecord

    class FakeMeter:
        def __init__(self, *tunnels: TunnelRecord) -> None:
            self.value = MeterSnapshot(taken_at=1.0, started_at=0.0, mode="direct", port=1, auth_port=None,
                                       tunnels=list(tunnels), counted_bytes=0, budget_bytes=None,
                                       max_tunnel_bytes=None, budget_tripped=False)

        def snapshot(self) -> MeterSnapshot:
            return self.value

    def record(i: int, host: str, status: str, port: int = 443) -> TunnelRecord:
        return TunnelRecord(id=i, host=host, port=port, kind="connect", route="direct", opened_at=float(i),
                            status=status)

    refused = "failed:private_address"
    # the meter records 127.0.0.1 for an IPv4-mapped literal; Chromium keeps the URL's spelling
    for url in ("https://[::ffff:127.0.0.1]:8443/", "https://[::ffff:7f00:1]:8443/", "https://127.1:8443/"):
        reason = _find_abort_check(FakeMeter(record(1, "127.0.0.1", refused, 8443)), None, url)()
        assert reason is not None and "pass --allow-private-targets to load it" in reason, (url, reason)
        assert "rebinding" not in reason
    # a name that resolved privately: the flag, with the rebinding caution
    reason = _find_abort_check(FakeMeter(record(1, "intranet.example", refused)), None, "https://intranet.example/")()
    assert reason is not None and "only if you expect this name on your own network" in reason
    assert "DNS-rebinding attack" in reason
    # the page loaded from the target, then its name answered privately: never "pass the flag"
    for first in ("ok", "open"):
        meter = FakeMeter(record(1, "rebind.example", first), record(2, "rebind.example", refused))
        reason = _find_abort_check(meter, None, "https://rebind.example/")()
        assert reason is not None and "DNS rebinding or split DNS" in reason, reason
        assert "pass --allow-private-targets" not in reason and "only for a site you trust" in reason
    # an earlier refusal of the same target is still the first connection
    meter = FakeMeter(record(1, "10.0.0.5", refused), record(2, "10.0.0.5", refused))
    reason = _find_abort_check(meter, None, "https://10.0.0.5/")()
    assert reason is not None and "pass --allow-private-targets to load it" in reason


def test_find_reports_the_whole_abort_reason() -> None:
    """The flag advice sits at the end of the runner's reason; find must not cut it off (it once kept 80 characters)."""
    from scrapescope.find.browser import _abort_reason
    from scrapescope.runner import _TARGET_NAME_PRIVATE, _TARGET_REBOUND, _TARGET_REFUSALS

    for text in (*_TARGET_REFUSALS.values(), _TARGET_NAME_PRIVATE, _TARGET_REBOUND):
        assert _abort_reason(lambda text=text: text) == text


def test_find_meter_line_splits_the_page_load_from_the_verify_replay() -> None:
    """find-r2-2: the meter: line reports the page load and the --verify replay separately."""
    from scrapescope.runner import _find_meter_line
    from scrapescope.types import MeterSnapshot, TunnelRecord

    def rec(i: int, received: int) -> TunnelRecord:
        return TunnelRecord(id=i, host="origin-a.test", port=443, kind="connect", route="http-connect", opened_at=0.0,
                            status="ok", upstream_bytes_received=received)

    snapshot = MeterSnapshot(taken_at=1.0, started_at=0.0, mode="http-connect", port=1, auth_port=None,
                             tunnels=[rec(1, 100_000), rec(2, 50_000), rec(3, 7_000)], counted_bytes=157_000,
                             budget_bytes=None, max_tunnel_bytes=None, budget_tripped=False)
    line = _find_meter_line(snapshot, "GB", {1, 2})
    assert "page load moved 150.00 kB" in line and "in 2 tunnel(s)" in line
    assert "the --verify replay moved 7.00 kB with CONNECT in 1 tunnel(s)" in line and line.endswith("tunnel-measured\n")
    assert "--verify" not in _find_meter_line(snapshot, "GB", None)


def test_find_internal_error_still_writes_the_meter_report(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """sec-8: an unexpected exception inside find exits 88 but keeps the report and the terminal result."""
    _fake_find(monkeypatch, raises=RuntimeError(SENTINEL))
    out = tmp_path / "f.json"
    assert main(["find", "https://origin-a.test/p?q=1", "--value", SENTINEL, "--direct", "--out", str(out)]) == 88
    report = json.loads(out.read_text())
    entry = report["find"][0]
    assert entry["status"] == "error" and entry["target_host"] == "origin-a.test"
    assert any("internal error (RuntimeError)" in w for w in entry["warnings"])
    captured = capsys.readouterr()
    assert "internal error (RuntimeError)" in captured.err and "cannot search" in captured.out
    assert SENTINEL not in out.read_text() and SENTINEL not in captured.err


def test_find_without_a_browser_exits_3(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
                                        tmp_path: Path) -> None:
    from scrapescope.find import BrowserUnavailableError

    _fake_find(monkeypatch, raises=BrowserUnavailableError("Playwright is not installed; install the browser extra"))
    assert main(["find", "https://origin-a.test/", "--value", "v", "--direct", "--out", str(tmp_path / "f.json")]) == 3
    assert "Playwright, which is not installed" in capsys.readouterr().err


def test_find_checks_for_playwright_before_starting_the_meter(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """core-1: no meter banner before a missing package; uv, pipx and pip advice."""
    from scrapescope import runner

    seen = _fake_find(monkeypatch)
    monkeypatch.setattr(runner, "_playwright_installed", lambda: False)
    out = tmp_path / "f.json"
    assert main(["find", "https://origin-a.test/", "--value", "v", "--direct", "--out", str(out)]) == 3
    err = capsys.readouterr().err
    assert "through the meter" not in err and seen == {} and not out.exists()
    # The package is installed from GitHub, not PyPI: every recipe names the repository.
    repo = "git+https://github.com/ipvolt/scrapescope"
    assert f"uv tool install 'scrapescope[browser] @ {repo}' --with-executables-from playwright" in err
    assert "pipx inject --include-apps scrapescope playwright" in err
    assert f"pip install 'scrapescope[browser] @ {repo}'" in err
    assert "uvx scrapescope" not in err and "pipx install scrapescope" not in err


def test_find_with_chromium_missing_gets_browser_advice_not_pip(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    from scrapescope.find import BrowserUnavailableError

    _fake_find(monkeypatch, raises=BrowserUnavailableError("Chromium could not be started; install the browser extra"))
    assert main(["find", "https://origin-a.test/", "--value", "v", "--direct", "--out", str(tmp_path / "f.json")]) == 3
    err = capsys.readouterr().err
    assert "Playwright is installed but its Chromium could not be started" in err
    assert "playwright install chromium" in err and "pip install" not in err


@pytest.mark.parametrize("value,expected", [("2B", 2), ("2kB", 2000), ("1.5GiB", 3 * 2**29), ("500 MB", 500_000_000)])
def test_budget_accepts_sizes_with_units(value: str, expected: int) -> None:
    from scrapescope.cli import _common_kwargs

    ns = build_parser().parse_args(["run", "--budget", value, "--direct", "true"])
    assert _common_kwargs(ns)["budget_bytes"] == expected


@pytest.mark.parametrize("value", ["2", "2.5", " 100 "])
def test_budget_without_a_unit_is_a_usage_error(value: str, capsys: pytest.CaptureFixture[str]) -> None:
    """core-1: --budget 2 used to mean two bytes and trip at once."""
    assert main(["run", "--budget", value, "--direct", "--", "true"]) == 2
    assert "a unit is required" in capsys.readouterr().err


def test_help_lists_every_exit_code_without_uninstalled_docs(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--help"]) == 0
    text = " ".join(capsys.readouterr().out.split())
    assert "docs/exit-codes.md" not in text
    for fragment in ("0 found (every value)", "6 found but at least one value", "1 not found", "4 blocked",
                     "5 page load failed", "3 Playwright", "130 interrupted", "86 budget", "87 bypass", "88 meter",
                     "89 upstream", "2 usage"):
        assert fragment in text, fragment
    assert main(["run", "--help"]) == 0
    run_help = " ".join(capsys.readouterr().out.split())
    assert "a floor, not a cap" not in run_help and "a few MB more per open tunnel" in run_help
    assert "own IP address" in run_help  # --env-all states the exposure


def test_lowercase_proxy_variable_is_named_in_the_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    monkeypatch.delenv("HTTPS_PROXY", raising=False)
    monkeypatch.setenv("https_proxy", f"http://u:{SENTINEL}@127.0.0.1:9")
    assert main(["run", "--out", str(tmp_path / "r.json"), "--", "true"]) == 89
    err = capsys.readouterr().err
    assert "https_proxy is" in err and "--upstream-from-env https_proxy" in err and SENTINEL not in err


def test_serve_banner_example_uses_compressed() -> None:
    from types import SimpleNamespace

    from scrapescope.runner import ServeOptions, _serve_banner, _Setup

    fw = SimpleNamespace(url="http://127.0.0.1:1234", port=1234)
    setup = _Setup(upstream=None, upstream_var=None, catalogs=None, deny_rules=(), connect_map=None)  # type: ignore[arg-type]
    lines = _serve_banner(fw, setup, "tok", ServeOptions(direct=True))
    example = [line for line in lines if "example:" in line]
    assert len(example) == 1
    assert "curl --compressed" in example[0]
    # sec2-5: the token goes in the environment, never in curl's argv (ps shows argv to other users).
    assert "HTTPS_PROXY=http://ss-tok:x@127.0.0.1:1234 curl --compressed https://" in example[0]
    assert "-x " not in example[0] and "--proxy " not in example[0]
    assert not any("docs/" in line for line in lines)
    # sec4-7: with a token file the token appears in no line; the example reads the file instead.
    filed = _serve_banner(fw, setup, "tok", ServeOptions(direct=True), Path("/tmp/a dir/proxy-url"))
    assert not any("ss-tok" in line for line in filed)
    assert any("HTTPS_PROXY=\"$(cat '/tmp/a dir/proxy-url')\" curl --compressed" in line for line in filed)
    assert any("stderr is not a terminal" in line for line in filed)


def test_serve_rewrites_its_report_while_running(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    import threading
    import time

    from scrapescope.runner import ServeOptions, serve_command

    out = tmp_path / "serve.json"
    stop = threading.Event()
    result: list[int] = []
    opts = ServeOptions(direct=True, out=str(out), quiet=True, rewrite_interval_s=0.2)
    thread = threading.Thread(target=lambda: result.append(serve_command(opts, environ={}, stop_event=stop)))
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not out.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert out.exists(), "serve did not write its report while running"
        assert json.loads(out.read_text())["command"] == "serve"
    finally:
        stop.set()
        thread.join(timeout=15)
    assert result == [0]
    err = capsys.readouterr().err
    # sec4-7: stderr is not a terminal here, so the token went to a private file, removed on exit.
    assert "proxy username: ss-" not in err
    match = re.search(r"proxy URL with username ss-<token>: in (\S+) \(mode 0600", err)
    assert match is not None and not Path(match.group(1)).exists()


def test_allow_private_targets_flag_reaches_every_command() -> None:
    from scrapescope.cli import _common_kwargs

    parser = build_parser()
    for argv in (["run", "--direct", "--allow-private-targets", "true"], ["serve", "--direct", "--allow-private-targets"],
                 ["find", "https://origin-a.test/", "--value", "v", "--direct", "--allow-private-targets"]):
        assert _common_kwargs(parser.parse_args(argv))["allow_private_targets"] is True
    assert _common_kwargs(parser.parse_args(["run", "--direct", "true"]))["allow_private_targets"] is False


# ---------------------------------------------------------------------------- round-2 core fixes
def _snap_with(statuses: list[tuple[str, int | None]], accept: int = 0, route: str = "http-connect") -> Any:
    from scrapescope.types import MeterSnapshot, TunnelRecord

    tunnels = [
        TunnelRecord(id=i + 1, host="origin-a.test", port=443, kind="connect", route=route,  # type: ignore[arg-type]
                     opened_at=1.0, status=status, upstream_status=code)
        for i, (status, code) in enumerate(statuses)
    ]
    return MeterSnapshot(taken_at=2.0, started_at=1.0, mode=route, port=1, auth_port=None, tunnels=tunnels,  # type: ignore[arg-type]
                         counted_bytes=0, budget_bytes=None, max_tunnel_bytes=None, budget_tripped=False,
                         accept_limit_errors=accept)


def test_failure_warning_names_the_reason_and_the_variable_only() -> None:
    """docs-2: when every (or most) tunnel failed, say why; never the upstream URL."""
    from scrapescope.runner import _tunnel_failure_warnings as warn

    assert warn(_snap_with([("ok", None), ("failed:upstream_unreachable", None)]), "HTTPS_PROXY", None) == []
    (w,) = warn(_snap_with([("failed:upstream_unreachable", None)]), "HTTPS_PROXY", None)
    assert w.startswith("every tunnel failed (upstream_unreachable x1): ") and "$HTTPS_PROXY" in w
    (w,) = warn(_snap_with([("failed:upstream_status", 407)] * 3), "PROVIDER", None)
    assert "upstream_status 407 x3" in w and "check the credentials in $PROVIDER" in w
    mostly = [("failed:socks_auth", None)] * 3 + [("ok", None)] * 2
    (w,) = warn(_snap_with(mostly), "HTTPS_PROXY", None)
    assert w.startswith("3 of 5 tunnels failed (socks_auth x3)") and "rejected the credentials" in w
    # A client going away is not a provider problem.
    assert warn(_snap_with([("failed:client_closed", None)]), "HTTPS_PROXY", None) == []
    (w,) = warn(_snap_with([("failed:connect_refused", None)], route="direct"), None, None)
    assert "the targets refused the connections" in w


def test_descriptor_limit_warning_blames_this_machine() -> None:
    """meas2-4/sec2-6: local_limit failures and accept pauses get their own warning, not the target's."""
    from scrapescope.runner import _tunnel_failure_warnings as warn

    snap = _snap_with([("ok", None)] * 3 + [("failed:local_limit", None)] * 2, accept=4)
    (w,) = warn(snap, "HTTPS_PROXY", 256)
    assert "ran out of file descriptors (open-files limit 256)" in w
    assert "2 tunnel(s) failed with local_limit" in w and "paused 4 time(s)" in w
    assert "not the target or the provider" in w
    only_limit = _snap_with([("failed:local_limit", None)] * 2)
    assert len(warn(only_limit, "HTTPS_PROXY", None)) == 1  # no "every tunnel failed" on top


def test_serve_keeps_no_timeline_and_run_find_do(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """sec2-7: a standing serve does not grow a timeline its report never uses."""
    import threading

    import scrapescope.runner as runner

    configs: list[Any] = []
    real = runner._start_forwarder

    def capture(fw_config: Any, connect_map: Any) -> Any:
        configs.append(fw_config)
        return real(fw_config, connect_map)

    monkeypatch.setattr(runner, "_start_forwarder", capture)
    stop = threading.Event()
    stop.set()
    opts = runner.ServeOptions(direct=True, out=str(tmp_path / "s.json"), quiet=True)
    assert runner.serve_command(opts, environ={}, stop_event=stop) == 0
    assert main(["run", "--direct", "--quiet", "--out", str(tmp_path / "r.json"), "--", sys.executable, "-c", "pass"]) == 0
    assert [c.record_timeline for c in configs] == [False, True]


def test_find_help_and_exit_130(capsys: pytest.CaptureFixture[str]) -> None:
    """ux-1: find ranks partial matches too, and its Ctrl-C exit code is documented."""
    assert main(["find", "--help"]) == 0
    text = " ".join(capsys.readouterr().out.split())
    assert "contain any --value" in text and "every value first" in text
    assert "130 interrupted" in text
    assert main(["--help"]) == 0
    assert "130 interrupted" in " ".join(capsys.readouterr().out.split())


def test_quiet_help_says_what_each_command_keeps(capsys: pytest.CaptureFixture[str]) -> None:
    """ux-r3-1: find --quiet still prints its result to stdout; its help says so."""
    assert main(["find", "--help"]) == 0
    find_help = " ".join(capsys.readouterr().out.split())
    assert "--quiet no progress notes on stderr; the result and the meter line still go to stdout" in find_help
    assert "no terminal summary" not in find_help
    for sub in ("run", "serve"):
        assert main([sub, "--help"]) == 0
        assert "--quiet no terminal summary" in " ".join(capsys.readouterr().out.split())


def test_low_open_file_limit_is_mentioned_at_start(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    import scrapescope.forwarder.limits as limits
    from scrapescope.runner import _raise_fd_limit

    monkeypatch.setattr(limits, "raise_open_file_limit", lambda: (256, 256))
    assert _raise_fd_limit(quiet=False) == 256
    err = capsys.readouterr().err
    assert "at most 256 files" in err and "two per tunnel" in err
    assert _raise_fd_limit(quiet=True) == 256 and capsys.readouterr().err == ""
    monkeypatch.setattr(limits, "raise_open_file_limit", lambda: (256, 65536))
    assert _raise_fd_limit(quiet=False) == 65536 and capsys.readouterr().err == ""


def test_run_names_proxy_variables_that_still_reach_the_provider(
    monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str], tmp_path: Path, closed_port: int
) -> None:
    """sec2-10: a *_proxy variable with other credentials for the same provider is named (never its value)."""
    monkeypatch.setenv("HTTPS_PROXY", f"http://custA:{SENTINEL}@127.0.0.1:{closed_port}")
    monkeypatch.setenv("https_proxy", f"http://custA:{SENTINEL}@127.0.0.1:{closed_port}/")  # duplicate: replaced
    monkeypatch.setenv("http_proxy", f"http://custB:{SENTINEL}x@127.0.0.1:{closed_port}")  # other account: named
    out = tmp_path / "r.json"
    job = "import os; print(os.environ['https_proxy'].startswith('http://127.0.0.1:'), 'custB' in os.environ['http_proxy'])"
    assert main(["run", "--out", str(out), "--", sys.executable, "-c", job]) == 0
    captured = capfd.readouterr()  # the job writes to the real stdout
    assert "True True" in captured.out
    assert "note: $http_proxy still names your upstream proxy" in captured.err
    report = json.loads(out.read_text())
    assert any(w.startswith("$http_proxy still named the upstream proxy") for w in report["warnings"])
    assert SENTINEL not in captured.err and SENTINEL not in out.read_text()


def test_run_names_a_case_twin_that_shadows_the_metered_variable(
    monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str], tmp_path: Path, closed_port: int
) -> None:
    """sec4-4 (b): https_proxy set to another proxy is read before HTTPS_PROXY by urllib/requests/curl/Node."""
    for name in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HTTPS_PROXY", f"http://custA:{SENTINEL}@127.0.0.1:{closed_port}")
    monkeypatch.setenv("https_proxy", f"http://other:{SENTINEL}y@gw.provider-b.example:9000")
    out = tmp_path / "r.json"
    job = "import urllib.request as u; print(u.getproxies()['https'].startswith('http://127.0.0.1:'))"
    assert main(["run", "--out", str(out), "--", sys.executable, "-c", job]) == 0
    captured = capfd.readouterr()
    assert "False" in captured.out  # the job's urllib really picks the other proxy
    assert "note: $https_proxy names another proxy and was left unchanged" in captured.err
    assert "read $https_proxy before $HTTPS_PROXY" in captured.err
    report = json.loads(out.read_text())
    assert any(w.startswith("$https_proxy named another proxy") for w in report["warnings"])
    assert SENTINEL not in captured.err and SENTINEL not in out.read_text()
    assert "provider-b" not in captured.err and "provider-b" not in out.read_text()


def test_budget_announcer_skips_the_80_percent_line_when_the_same_read_tripped(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """ux4-2: '80% of the byte budget used (624 B of 300 B)' contradicted itself."""
    from scrapescope.runner import _budget_announcer
    from scrapescope.types import BudgetEvent

    announce = _budget_announcer("GB", "stopping")
    announce(BudgetEvent(ts=1.0, kind="warn_80", counted_bytes=624, limit_bytes=300))
    announce(BudgetEvent(ts=1.0, kind="tripped", counted_bytes=624, limit_bytes=300, closed_tunnels=1))
    err = capsys.readouterr().err
    assert "80%" not in err and "byte budget tripped: 624 B counted against 300 B" in err
    announce(BudgetEvent(ts=1.0, kind="warn_80", counted_bytes=250, limit_bytes=300))
    assert "80% of the byte budget used (250 B of 300 B)" in capsys.readouterr().err


def test_accept_failures_for_lack_of_descriptors_are_recognised() -> None:
    import errno

    from scrapescope.forwarder.server import _is_accept_limit

    msg = "socket.accept() out of system resource"
    assert _is_accept_limit({"message": msg, "exception": OSError(errno.EMFILE, "Too many open files")})
    assert _is_accept_limit({"message": msg, "exception": OSError(errno.ENFILE, "Too many open files in system")})
    assert not _is_accept_limit({"message": msg, "exception": OSError(errno.ENOBUFS, "No buffer space")})
    assert not _is_accept_limit({"message": "other", "exception": OSError(errno.EMFILE, "x")})


def test_run_passes_the_events_cap_count_to_attribution(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """sec4-5: run hands EventsLog.capped to attribute(), so the report says lines were skipped at the cap
    ("not read"), not "not read or were invalid", which attribution says when it must infer the cap."""
    import functools
    import sys

    import scrapescope.attribution as attribution

    monkeypatch.setattr(attribution, "read_events", functools.partial(attribution.read_events, max_events=3))
    job = tmp_path / "job.py"
    job.write_text(
        "import json, os, time\n"
        "with open(os.environ['SCRAPESCOPE_EVENTS'], 'a') as fh:\n"
        "    for _ in range(8):\n"
        "        fh.write(json.dumps({'v': 1, 'kind': 'attach', 'ts': time.time(), 'source': 'httpx'}) + '\\n')\n"
    )
    out = tmp_path / "r.json"
    assert main(["run", "--direct", "--quiet", "--out", str(out), "--", sys.executable, str(job)]) == 0
    warnings = json.loads(out.read_text())["warnings"]
    (line,) = [w for w in warnings if "helper event lines were not read" in w]
    assert line.startswith("5 helper event lines were not read: the reader keeps at most 3 events"), line
