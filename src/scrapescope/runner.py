"""Runner: forwarder lifecycle, the child's process group, reports and exit codes.

One function per subcommand (contract: docs/dev/contracts.md sections 12 and
13); ``scrapescope.cli`` parses arguments into the option dataclasses below and
calls them.

- :func:`run_command` meters a child command. The child runs in its own
  session (``start_new_session=True``), so it leads its own process group and
  a budget trip can stop it together with every grandchild: SIGTERM to the
  group, then SIGKILL after ``config.STOP_GRACE_S`` seconds. SIGINT, SIGTERM
  and SIGHUP received by scrapescope are forwarded to that group; a second
  SIGINT sends SIGKILL.
- :func:`serve_command` runs the forwarder alone until SIGINT/SIGTERM and
  rewrites the report every 60 seconds.
- :func:`find_command` runs ``find`` through a tokenless forwarder, so the
  page load and the single ``--verify`` request are tunnel-measured too.
- :func:`report_command` re-renders or gates a saved report.

Secrets: the upstream URL is read only from the environment (never argv) and
lives only inside :class:`~scrapescope.config.UpstreamConfig`, which redacts
itself. Nothing here prints or stores it; error messages name the variable,
never its value. Only ``serve`` shows its token: once, on stderr when that is a
terminal, and otherwise in a private 0600 file (``--token-file``) whose path is
printed instead (round 4, sec4-7). ``serve`` always requires its token (the
plan's rule; round 4, hon4-3).

Accuracy: the meter stops at its own count. Bytes already in flight at the
provider when the budget trips can add roughly (open tunnels x a few MB).

Descriptors: each tunnel costs the meter two file descriptors, so every
command raises this process's soft open-file limit toward the hard limit
(``forwarder.raise_open_file_limit``); ``run`` does it after starting the job,
which keeps the limit it would have had without the meter.
"""

from __future__ import annotations

import asyncio
import os
import shlex
import signal
import subprocess
import sys
import threading
import time
import urllib.parse
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import config
from .config import (
    DEFAULT_REPORT_PATH,
    EXIT_BLOCKED,
    EXIT_BROWSER_UNAVAILABLE,
    EXIT_BUDGET,
    EXIT_BYPASS,
    EXIT_INTERNAL,
    EXIT_LOAD_ERROR,
    EXIT_NOT_FOUND,
    EXIT_OK,
    EXIT_PARTIAL,
    EXIT_USAGE,
    FIND_BODY_CAP_BYTES,
    STOP_GRACE_S,
    ConfigError,
    ForwarderConfig,
    HostRule,
    PrivateEventsFile,
    UpstreamConfig,
    format_size,
)
from .types import (
    TUNNEL_DENIED,
    TUNNEL_OPEN,
    AttributionResult,
    BudgetEvent,
    Catalogs,
    GbUnit,
    MeterSnapshot,
    ReportOptions,
    canonical_host,
    clean_host,
    ip_literal,
    safe_text,
    validate_host_glob,
)

#: Exit status of a job whose command was found but could not be executed.
EXIT_NOT_EXECUTABLE = 126
#: Exit status of a job whose command was not found.
EXIT_COMMAND_NOT_FOUND = 127
#: Exit status when scrapescope itself is interrupted before a job exists.
EXIT_INTERRUPTED = 130
#: Seconds allowed for tunnels to drain after the job exits.
DRAIN_S = 1.0
#: ``serve`` rewrites its report this often.
SERVE_REWRITE_S = 60.0
#: Largest number of --value options ``find`` accepts.
MAX_FIND_VALUES = 50
#: At most this many per-tunnel-cap closures are announced on stderr.
MAX_CAP_MESSAGES = 3

_FORWARDED_SIGNALS = tuple(
    s for s in (getattr(signal, "SIGINT", None), getattr(signal, "SIGTERM", None), getattr(signal, "SIGHUP", None)) if s
)


# ---------------------------------------------------------------------------
# Options (filled by scrapescope.cli)
# ---------------------------------------------------------------------------


@dataclass
class CommonOptions:
    """Options shared by run, serve and find. Never holds the upstream URL."""

    upstream_var: str | None = None
    direct: bool = False
    rate: float | None = None
    gib: bool = False
    budget_bytes: int | None = None
    #: --max-tunnel-mb N, already converted to bytes (N x 10^6).
    max_tunnel_bytes: int | None = None
    deny_hosts: tuple[str, ...] = ()
    deny_catalogs: tuple[str, ...] = ()
    out: str = DEFAULT_REPORT_PATH
    html: str | None = None
    keep_urls: bool = False
    redact_hosts: bool = False
    quiet: bool = False
    port: int = 0
    #: --allow-private-targets: direct/non-target connections may reach loopback and private addresses.
    allow_private_targets: bool = False

    @property
    def gb_unit(self) -> GbUnit:
        return "GiB" if self.gib else "GB"


@dataclass
class RunOptions(CommonOptions):
    command: tuple[str, ...] = ()
    env_all: bool = False
    units: int | None = None
    keep_events: bool = False
    fail_on: tuple[str, ...] = ()


@dataclass
class ServeOptions(CommonOptions):
    units: int | None = None
    rewrite_interval_s: float = SERVE_REWRITE_S
    #: --token-file PATH: write the proxy URL with the token there (0600, new file) instead of printing it.
    token_file: str | None = None


@dataclass
class FindOptions(CommonOptions):
    url: str = ""
    values: tuple[str, ...] = ()
    verify: bool = False
    timeout_s: float = 45.0
    body_cap_bytes: int = FIND_BODY_CAP_BYTES


@dataclass
class ReportCommandOptions:
    path: str
    format: str = "text"
    html: str | None = None
    fail_on: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


class _Abort(Exception):
    """Stop a command with an exit code and a one-line message for stderr."""

    def __init__(self, code: int, message: str | None = None) -> None:
        super().__init__(message or "")
        self.code = code
        self.message = message


def _err(message: str) -> None:
    """One sanitised line on stderr (never raises)."""
    try:
        sys.stderr.write("scrapescope: " + safe_text(message, 2000) + "\n")
        sys.stderr.flush()
    except (OSError, ValueError):
        pass


def _out(text: str, stream: Any = None) -> None:
    target = stream if stream is not None else sys.stdout
    try:
        target.write(text)
        target.flush()
    except (OSError, ValueError):
        pass


def _check_output_path(path: str | None, option: str) -> None:
    """Refuse report paths that cannot be written, before any job runs (exit 2)."""
    if path is None:
        return
    target = Path(path)
    if target.is_dir():
        raise _Abort(EXIT_USAGE, f"{option} {path} is a directory; give a file path")
    parent = target.parent if str(target.parent) else Path(".")
    if not parent.is_dir():
        raise _Abort(EXIT_USAGE, f"{option}: the directory {parent} does not exist")
    if not os.access(parent, os.W_OK | os.X_OK):
        raise _Abort(EXIT_USAGE, f"{option}: the directory {parent} is not writable")


@dataclass
class _Setup:
    upstream: UpstreamConfig | None
    upstream_var: str | None
    catalogs: Catalogs
    deny_rules: tuple[HostRule, ...]
    connect_map: config.ConnectMap | None


def _prepare(opts: CommonOptions, environ: Mapping[str, str]) -> _Setup:
    """Resolve the upstream, catalogs, deny rules and the test connect map."""
    _check_output_path(opts.out, "--out")
    _check_output_path(opts.html, "--html")
    try:
        upstream, var = config.resolve_upstream(direct=opts.direct, upstream_var=opts.upstream_var, environ=environ)
    except ConfigError as exc:
        raise _Abort(exc.exit_code, str(exc)) from None
    from .catalog import CatalogError, background_deny_rules, load_catalogs

    try:
        catalogs = load_catalogs()
    except CatalogError as exc:
        raise _Abort(EXIT_INTERNAL, f"the packaged catalogs are invalid ({safe_text(exc, 200)})") from None
    rules: list[HostRule] = []
    for glob in opts.deny_hosts:
        try:
            pattern = validate_host_glob(glob)
        except ValueError as exc:
            raise _Abort(EXIT_USAGE, f"--deny-host: {exc}") from None
        rules.append(HostRule(pattern=pattern, label=f"deny-host:{pattern}"))
    for name in dict.fromkeys(opts.deny_catalogs):
        if name != "background":
            raise _Abort(EXIT_USAGE, "--deny-catalog accepts only 'background' in v1")
        rules.extend(background_deny_rules(catalogs))
    try:
        connect_map = config.connect_map_from_env(environ)
    except ValueError:
        raise _Abort(EXIT_USAGE, f"{config.ENV_TEST_CONNECT_MAP} is malformed") from None
    return _Setup(upstream, var, catalogs, tuple(rules), connect_map)


def _raise_fd_limit(quiet: bool) -> int | None:
    """Raise the open-file limit for the meter (two descriptors per tunnel); returns the soft limit in force."""
    from .forwarder.limits import LOW_OPEN_FILES, raise_open_file_limit

    _before, after = raise_open_file_limit()
    if after is not None and after < LOW_OPEN_FILES and not quiet:
        _err(
            f"note: this process may open at most {after} files and the meter uses two per tunnel, so about "
            f"{max(1, after // 2 - 16)} tunnels can be open at once; raise the hard limit (ulimit -Hn) for more"
        )
    return after


#: Short cause hints for the tunnel failure warning, by failure reason; {var} names the upstream variable.
_FAILURE_HINTS = {
    "upstream_unreachable": "the upstream proxy in {var} did not accept connections; check its host and port",
    "upstream_timeout": "the upstream proxy in {var} did not answer in time; check its host and port",
    "upstream_closed": "the upstream proxy in {var} closed connections without replying; check the scheme "
    "(http:// or socks5://) and port",
    "upstream_protocol": "the upstream in {var} did not speak HTTP CONNECT or SOCKS5 as configured; check the scheme",
    "socks_auth": "the SOCKS5 upstream rejected the credentials in {var}",
    "socks_method": "the SOCKS5 upstream accepted none of the offered authentication methods; check {var}",
    "socks_auth_unsupported": "these credentials cannot be sent over SOCKS5; check {var}",
    "dns": "target names did not resolve",
    "connect_refused": "the targets refused the connections",
    "connect_timeout": "the targets did not answer in time",
    "private_address": "the targets resolve to loopback or private addresses, or to this machine or its own "
    "network link (--allow-private-targets permits them)",
    "self_loop": "a name resolved to the meter itself",
    "upstream_reset": "the upstream reset connections",
}


def _failure_reason(tunnel: Any) -> str:
    return str(tunnel.status).split(":", 1)[1] if ":" in str(tunnel.status) else str(tunnel.status)


def _tunnel_failure_warnings(snapshot: MeterSnapshot, upstream_var: str | None, fd_limit: int | None) -> list[str]:
    """Report warnings that name why tunnels failed (never the upstream URL, only its variable).

    One warning when every target tunnel, or at least half of four or more,
    failed for reasons other than the client going away or the meter's own
    descriptor limit; and one for descriptor-limit failures, which come from
    this machine rather than the target or the provider.
    """
    out: list[str] = []
    target = snapshot.target_tunnels()
    failed = [t for t in target if t.failed and t.status not in ("failed:client_closed", "failed:local_limit")]
    if failed and (len(failed) == len(target) or (len(target) >= 4 and 2 * len(failed) >= len(target))):
        reasons: Counter[str] = Counter()
        for tunnel in failed:
            reason = _failure_reason(tunnel)
            if reason == "upstream_status" and tunnel.upstream_status is not None:
                reason = f"upstream_status {tunnel.upstream_status}"
            reasons[reason] += 1
        breakdown = ", ".join(f"{safe_text(reason, 40)} x{n}" for reason, n in reasons.most_common(4))
        lead = "every tunnel failed" if len(failed) == len(target) else f"{len(failed)} of {len(target)} tunnels failed"
        top = reasons.most_common(1)[0][0]
        var = f"${upstream_var}" if upstream_var else "the upstream URL"
        if top == "upstream_status 407":
            hint = f"the upstream proxy answered 407: check the credentials in {var}"
        elif top.startswith("upstream_status"):
            hint = (
                f"the upstream proxy in {var} answered {top.split(' ', 1)[-1]} instead of opening the tunnels "
                "(the job received that reply)"
            )
        elif top.startswith("socks_reply_"):
            hint = f"the SOCKS5 upstream refused the connections (reply {top.rsplit('_', 1)[-1]})"
        else:
            hint = _FAILURE_HINTS.get(top, "see the tunnel statuses in report.json").format(var=var)
        out.append(f"{lead} ({breakdown}): {hint}")
    limit_failures = sum(1 for t in snapshot.tunnels if t.status == "failed:local_limit")
    pauses = snapshot.accept_limit_errors
    if limit_failures or pauses:
        parts = []
        if limit_failures:
            parts.append(f"{limit_failures} tunnel(s) failed with local_limit")
        if pauses:
            parts.append(f"accepting new connections paused {pauses} time(s)")
        limit = f" (open-files limit {fd_limit})" if fd_limit else ""
        out.append(
            f"the meter ran out of file descriptors{limit}: {'; '.join(parts)}. It uses two per tunnel; raise the "
            "limit (ulimit -n) and run again. These failures came from this machine, not the target or the provider"
        )
    return out


def _start_forwarder(fw_config: ForwarderConfig, connect_map: config.ConnectMap | None) -> Any:
    from .forwarder import ForwarderError, ForwarderThread

    fw = ForwarderThread(fw_config, connect_map=connect_map)
    try:
        fw.start()
    except ForwarderError as exc:
        # ForwarderError messages never contain the upstream URL (forwarder contract).
        raise _Abort(EXIT_INTERNAL, f"the meter could not start: {exc}") from None
    return fw


def _env_all_exposure_note(rules: Sequence[HostRule]) -> str:
    """The start-time warning for --env-all with an upstream: these hosts leave from the user's own IP."""
    examples = ", ".join(dict.fromkeys(r.pattern for r in rules[:3]))
    return (
        f"note: --env-all carries the {len(rules)} host patterns of direct.json (LLM APIs, "
        f"such as {examples}) DIRECT, not through your proxy: the meter looks them up and connects from this "
        "machine's own IP address, for every client of the meter, a browser included"
    )


def _other_proxy_reason(name: str, upstream_var: str | None) -> str:
    """Why a proxy variable left pointing at another proxy matters (sec4-4); names only, never values."""
    if upstream_var and config.case_twin(upstream_var) == name:
        if name.islower():
            return f"curl, Python (urllib, Requests, HTTPX) and Node read ${name} before ${upstream_var}"
        return f"Go reads ${name} before ${upstream_var}"
    kind = name.upper()
    if kind == "HTTP_PROXY":
        return "clients use it for http:// URLs"
    if kind == "HTTPS_PROXY":
        return "clients use it for https:// URLs"
    return "clients without a scheme-specific proxy variable use it"


def _mode_text(setup: _Setup) -> str:
    if setup.upstream is None:
        return "direct sizing mode, no upstream"
    return f"{setup.upstream.kind} upstream from ${setup.upstream_var}"


def _hosts_text(event: BudgetEvent, gb_unit: GbUnit, limit: int = 5) -> str:
    return ", ".join(f"{safe_text(h.host, 253)} ({format_size(h.bytes, gb_unit)})" for h in event.top_hosts[:limit])


def _budget_announcer(gb_unit: GbUnit, action: str) -> Callable[[BudgetEvent], None]:
    """A budget callback that prints one stderr line per event (runs on the forwarder thread)."""
    caps = [0]
    lock = threading.Lock()

    def announce(event: BudgetEvent) -> None:
        limit = format_size(event.limit_bytes or 0, gb_unit)
        counted = format_size(event.counted_bytes, gb_unit)
        if event.kind == "warn_80":
            if event.limit_bytes is not None and event.counted_bytes >= event.limit_bytes:
                return  # ux4-2: the same count tripped the budget; the trip line follows at once
            _err(f"80% of the byte budget used ({counted} of {limit})")
        elif event.kind == "tripped":
            heaviest = _hosts_text(event, gb_unit)
            _err(
                f"byte budget tripped: {counted} counted against {limit}; closed {event.closed_tunnels} tunnel(s), "
                f"refusing new ones and {action}"
                + (f". Heaviest hosts in the final minute: {heaviest}" if heaviest else "")
            )
        elif event.kind == "tunnel_cap":
            with lock:
                caps[0] += 1
                n = caps[0]
            if n <= MAX_CAP_MESSAGES:
                host = safe_text(event.host or "?", 253)
                _err(f"closed a tunnel to {host} at the per-tunnel cap ({limit})")
            elif n == MAX_CAP_MESSAGES + 1:
                _err("more tunnels reached the per-tunnel cap; the report lists them")

    return announce


def _drain(fw: Any, timeout: float = DRAIN_S) -> None:
    """Give open tunnels up to ``timeout`` seconds to finish after the job exits.

    Polls the open-tunnel count, not full snapshots: a snapshot copies every
    record, which is wasteful every 50 ms after a job that opened many tunnels.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            count = getattr(fw, "open_tunnel_count", None)
            if count is not None:
                still_open = count() > 0
            else:
                still_open = any(t.status == TUNNEL_OPEN for t in fw.snapshot().tunnels)
        except Exception:  # noqa: BLE001 - draining is best effort
            return
        if not still_open:
            return
        time.sleep(0.05)


def _write_outputs(report: dict[str, Any], opts: CommonOptions) -> None:
    from .report import ReportError, write_report

    try:
        write_report(report, opts.out, opts.html)
    except ReportError as exc:
        raise _Abort(EXIT_INTERNAL, f"internal error: {exc}") from None
    except OSError as exc:
        raise _Abort(EXIT_INTERNAL, f"could not write the report: {exc.strerror or type(exc).__name__}") from None


def _written_line(opts: CommonOptions) -> str:
    extra = f" and {opts.html}" if opts.html else ""
    return f"report written to {opts.out}{extra}"


def _build(
    *,
    command: str,
    snapshot: MeterSnapshot,
    attribution: AttributionResult,
    catalogs: Catalogs,
    opts: CommonOptions,
    find_results: Sequence[Any] = (),
    warnings: Sequence[str] = (),
) -> dict[str, Any]:
    from .report import build_report

    options = ReportOptions(
        command=command,  # type: ignore[arg-type]
        gb_unit=opts.gb_unit,
        rate=opts.rate,
        keep_urls=opts.keep_urls,
        redact_hosts=opts.redact_hosts,
        ended_at=time.time(),
    )
    return build_report(
        snapshot=snapshot,
        attribution=attribution,
        catalogs=catalogs,
        options=options,
        find_results=find_results,
        warnings=warnings,
    )


def _summary(report: dict[str, Any], out_path: str) -> str:
    """The terminal summary (fix code omitted; the report and ``scrapescope report`` have it)."""
    from .report import render_text

    text = render_text(report, show_code=False)
    if report.get("fixes"):
        text += f"The fix code is in the report: scrapescope report {safe_text(out_path, 500)}\n"
    return text


class _SignalGuard:
    """Install handlers for SIGINT/SIGTERM/SIGHUP (main thread only) and restore them."""

    def __init__(self, handler: Callable[[int], None]) -> None:
        self._handler = handler
        self._saved: dict[int, Any] = {}

    def __enter__(self) -> _SignalGuard:
        if threading.current_thread() is not threading.main_thread():
            return self
        for sig in _FORWARDED_SIGNALS:
            try:
                if signal.getsignal(sig) == signal.SIG_IGN:
                    continue  # ignored when we started (nohup, background jobs): keep it that way
                self._saved[sig] = signal.signal(sig, lambda signum, _frame: self._handler(signum))
            except (ValueError, OSError):
                pass
        return self

    def __exit__(self, *exc: object) -> None:
        for sig, previous in self._saved.items():
            try:
                signal.signal(sig, previous)
            except (ValueError, OSError, TypeError):
                pass
        self._saved.clear()


# ---------------------------------------------------------------------------
# Process groups
# ---------------------------------------------------------------------------


def _signal_group(pgid: int, sig: int, proc: subprocess.Popen[bytes] | None = None) -> None:
    """Send ``sig`` to the child's process group; ignore a group that is already gone."""
    killpg = getattr(os, "killpg", None)
    try:
        if killpg is not None:
            killpg(pgid, sig)
        elif proc is not None and proc.poll() is None:  # pragma: no cover - non-POSIX fallback
            proc.send_signal(sig)
    except (ProcessLookupError, PermissionError, OSError):
        pass


def _group_alive(pgid: int) -> bool:
    killpg = getattr(os, "killpg", None)
    if killpg is None:  # pragma: no cover - non-POSIX
        return False
    try:
        killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def _exit_status(returncode: int) -> int:
    """Shell-style status: a job killed by signal N gives 128 + N."""
    return 128 - returncode if returncode < 0 else returncode


class _ChildWaiter:
    """Waits for the child while enforcing budget trips and forwarding signals."""

    def __init__(self, proc: subprocess.Popen[bytes], fw: Any) -> None:
        self.proc = proc
        self.pgid = proc.pid
        self.fw = fw
        self._sigint_count = 0
        self._kill_deadline: float | None = None
        self._trip_handled = False

    def on_signal(self, signum: int) -> None:
        """Forward a signal scrapescope received to the child's group (second SIGINT: SIGKILL)."""
        if signum == getattr(signal, "SIGINT", -1):
            self._sigint_count += 1
            if self._sigint_count >= 2:
                _signal_group(self.pgid, signal.SIGKILL, self.proc)
                return
        _signal_group(self.pgid, signum, self.proc)

    def _stop_group(self) -> None:
        _signal_group(self.pgid, signal.SIGTERM, self.proc)
        self._kill_deadline = time.monotonic() + STOP_GRACE_S

    def wait(self) -> int:
        while True:
            if not self._trip_handled and self.fw.budget_tripped.is_set():
                self._trip_handled = True
                self._stop_group()
            returncode = self.proc.poll()
            if self._kill_deadline is not None:
                if time.monotonic() >= self._kill_deadline:
                    _signal_group(self.pgid, getattr(signal, "SIGKILL", signal.SIGTERM), self.proc)
                    self._kill_deadline = None
                elif returncode is not None and not _group_alive(self.pgid):
                    self._kill_deadline = None
            if returncode is not None and self._kill_deadline is None:
                return returncode
            try:
                self.proc.wait(timeout=0.05)
            except subprocess.TimeoutExpired:
                pass


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


def run_command(opts: RunOptions, *, environ: Mapping[str, str] | None = None) -> int:
    """``scrapescope run [options] -- CMD ...``; returns the exit code (contracts section 13)."""
    env = dict(os.environ if environ is None else environ)
    if not opts.command:
        _err("run needs a command after --, for example: scrapescope run --direct -- python job.py")
        return EXIT_USAGE
    try:
        setup = _prepare(opts, env)
    except _Abort as abort:
        if abort.message:
            _err(abort.message)
        return abort.code
    from .catalog import direct_rules

    carried_direct = direct_rules(setup.catalogs) if opts.env_all else ()
    fw_config = ForwarderConfig(
        upstream=setup.upstream,
        token=None,  # run is tokenless on loopback; a token would only make "ss-" usernames collide
        require_token=False,
        auth_listener=True,
        port=opts.port,
        budget_bytes=opts.budget_bytes,
        max_tunnel_bytes=opts.max_tunnel_bytes,
        deny_rules=setup.deny_rules,
        direct_rules=carried_direct,
        allow_private_targets=opts.allow_private_targets,
    )
    events = PrivateEventsFile.create()
    keep_events = False
    try:
        try:
            fw = _start_forwarder(fw_config, setup.connect_map)
        except _Abort as abort:
            _err(abort.message or "the meter could not start")
            return abort.code
        try:
            fw.on_budget(
                _budget_announcer(opts.gb_unit, "stopping the job (SIGTERM, then SIGKILL after 5 s if still running)")
            )
            child_env = config.build_child_env(
                env,
                meter_url=fw.url,
                events_path=str(events.path),
                upstream_var=setup.upstream_var,
                env_all=opts.env_all,
                keep_urls=opts.keep_urls,
                auth_meter_url=fw.auth_url,
                upstream_id=(
                    config.upstream_id(setup.upstream.host, setup.upstream.port) if setup.upstream is not None else None
                ),
            )
            unmetered = config.unmetered_proxy_variables(child_env, setup.upstream)
            # sec4-4: other proxies in the standard variables, the metered variable's case twin first.
            others = (
                [n for n in config.other_proxy_variables(child_env, setup.upstream_var) if n not in unmetered]
                if setup.upstream is not None
                else []
            )
            if not opts.quiet:
                _err(f"metering on {fw.url} ({_mode_text(setup)})")
                for name in unmetered:
                    _err(
                        f"note: ${name} still names your upstream proxy (its host on another port or scheme, or "
                        "with other credentials, or its credentials on another host) and was left unchanged; "
                        "traffic that uses it goes to the provider without the meter"
                    )
                for name in others:
                    _err(
                        f"note: ${name} names another proxy and was left unchanged; "
                        f"{_other_proxy_reason(name, setup.upstream_var)}, and that traffic goes around the meter"
                    )
                if carried_direct and setup.upstream is not None:
                    # Says which requests leave from the user's own IP; the report repeats it.
                    _err(_env_all_exposure_note(carried_direct))
                if setup.upstream is None and not opts.env_all:
                    _err(
                        "note: --direct without --env-all changes no proxy variables; only clients that use the "
                        "helpers or $SCRAPESCOPE_PROXY_URL are metered"
                    )
            try:
                proc = subprocess.Popen(list(opts.command), env=child_env, start_new_session=True)
            except FileNotFoundError:
                _err(f"command not found: {opts.command[0]}")
                return EXIT_COMMAND_NOT_FOUND
            except (PermissionError, IsADirectoryError, NotADirectoryError):
                _err(f"command is not executable: {opts.command[0]}")
                return EXIT_NOT_EXECUTABLE
            except OSError as exc:
                _err(f"could not start the command ({exc.strerror or type(exc).__name__})")
                return EXIT_NOT_EXECUTABLE
            # After the job started: it keeps its own open-file limit; the meter needs two per tunnel.
            fd_limit = _raise_fd_limit(opts.quiet)
            waiter = _ChildWaiter(proc, fw)
            with _SignalGuard(waiter.on_signal):
                returncode = waiter.wait()
            keep_events = opts.keep_events  # the job ran: keep its events even if the report fails
            _drain(fw)
        finally:
            snapshot = fw.stop()
        meter_crashed = fw.error is not None
        from .attribution import attribute, read_events

        log = read_events(events.path)
        extra: list[str] = []
        if log.error:
            extra.append(f"helper events could not be read ({log.error}); per-type figures are unavailable")
        if meter_crashed:
            extra.append("the meter stopped unexpectedly; traffic after that point is missing")
        if setup.upstream is not None:
            carried = snapshot.non_target_tunnels()
            if carried:
                extra.append(
                    f"--env-all: {len(carried)} non-target tunnel(s) to direct.json hosts bypassed the upstream proxy; "
                    "the meter looked those names up and connected from this machine's own IP address"
                )
        for name in unmetered:
            extra.append(
                f"${name} still named the upstream proxy (its host on another port or scheme, or with other "
                "credentials, or its credentials on another host); any traffic that used it reached the provider "
                "without the meter (and is missing from these totals)"
            )
        for name in others:
            extra.append(
                f"${name} named another proxy ({_other_proxy_reason(name, setup.upstream_var)}); any traffic "
                "that used it went around the meter (and is missing from these totals)"
            )
        extra.extend(_tunnel_failure_warnings(snapshot, setup.upstream_var, fd_limit))
        attribution = attribute(
            snapshot, log.events, setup.catalogs, units_override=opts.units, events_dropped=log.dropped,
            events_capped=log.capped,
        )
        try:
            report = _build(
                command="run", snapshot=snapshot, attribution=attribution, catalogs=setup.catalogs, opts=opts,
                warnings=extra,
            )
            _write_outputs(report, opts)
        except _Abort as abort:
            _err(abort.message or "could not write the report")
            return abort.code
        if not opts.quiet:
            _out(_summary(report, opts.out), sys.stderr)
            _err(_written_line(opts))
        if meter_crashed:
            return EXIT_INTERNAL
        if snapshot.budget_tripped:
            return EXIT_BUDGET
        if "bypass" in opts.fail_on and report.get("incomplete") is True:
            return EXIT_BYPASS
        return _exit_status(returncode)
    finally:
        if keep_events:
            _err(f"helper events kept at {events.path} (private; delete it when done)")
        else:
            events.cleanup()


# ---------------------------------------------------------------------------
# serve
# ---------------------------------------------------------------------------


def _stderr_is_terminal() -> bool:
    try:
        return bool(sys.stderr.isatty())
    except (AttributeError, ValueError, OSError):
        return False


class _TokenFile:
    """The private file that holds serve's proxy URL with its token (sec4-7).

    Created with ``O_EXCL`` and mode 0600 before the meter starts, filled once
    the port is known, and removed when serve stops (the token is dead then).
    ``--token-file PATH`` names it; otherwise, when stderr is not a terminal
    (a log file, journald, ``docker logs``, a CI log that other users can
    read), it goes into a fresh 0700 temporary directory.
    """

    def __init__(self, path: Path, fd: int, directory: Path | None) -> None:
        self.path = path
        self._fd: int | None = fd
        self._directory = directory

    @classmethod
    def create(cls, requested: str | None) -> _TokenFile:
        directory: Path | None = None
        if requested is None:
            import tempfile

            directory = Path(tempfile.mkdtemp(prefix="scrapescope-serve-"))
            os.chmod(directory, 0o700)
            path = directory / "proxy-url"
        else:
            path = Path(os.path.abspath(requested))
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError:
            raise _Abort(EXIT_USAGE, f"--token-file {path} already exists; give a path that does not exist yet") from None
        except OSError as exc:
            if directory is not None:
                import shutil

                shutil.rmtree(directory, ignore_errors=True)
            raise _Abort(
                EXIT_USAGE, f"could not create the token file {path}: {exc.strerror or type(exc).__name__}"
            ) from None
        return cls(path, fd, directory)

    def write(self, text: str) -> None:
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, text.encode("ascii"))
        finally:
            os.close(fd)

    def remove(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
        try:
            self.path.unlink()
        except OSError:
            pass
        if self._directory is not None:
            import shutil

            shutil.rmtree(self._directory, ignore_errors=True)


def _serve_banner(fw: Any, setup: _Setup, token: str, opts: ServeOptions, token_path: Path | None = None) -> list[str]:
    """serve's start lines; the token appears in them only when ``token_path`` is None (sec4-7)."""
    lines = [f"serve: listening on {fw.url} ({_mode_text(setup)})"]
    user = config.token_username(token)
    creds = "your upstream credentials are added" if setup.upstream is not None and setup.upstream.has_credentials else "no upstream credentials are added"
    if token_path is None:
        lines.append(f"  proxy username: {user}  (any password; {creds})")
        lines.append(f"  or {user}~<your-proxy-username> with your proxy password, passed through unchanged")
        # The example keeps the token out of argv: other local users can read command lines (ps).
        lines.append(
            f"  example: HTTPS_PROXY=http://{user}:x@127.0.0.1:{fw.port} curl --compressed https://example.com/"
        )
        lines.append(
            "  keep the token in the environment or a client config file, never in command-line arguments "
            "(other local users can list those)"
        )
    else:
        lines.append(
            f"  proxy URL with username ss-<token>: in {token_path} (mode 0600, removed when serve stops; {creds})"
        )
        lines.append("  or username ss-<token>~<your-proxy-username> with your proxy password, passed through unchanged")
        lines.append(f'  example: HTTPS_PROXY="$(cat {shlex.quote(str(token_path))})" curl --compressed https://example.com/')
        lines.append(
            "  the token is not printed because stderr is not a terminal (logs are often readable by other "
            "users); --token-file PATH picks the file"
            if opts.token_file is None
            else "  the token is not printed (--token-file)"
        )
    lines.append(
        f"  report: {opts.out} (rewritten every {int(opts.rewrite_interval_s)} s and on exit); stop with Ctrl-C or SIGTERM"
    )
    return lines


def serve_command(
    opts: ServeOptions,
    *,
    environ: Mapping[str, str] | None = None,
    stop_event: threading.Event | None = None,
) -> int:
    """``scrapescope serve``: the forwarder alone until SIGINT/SIGTERM (or ``stop_event``, for embedding)."""
    env = dict(os.environ if environ is None else environ)
    try:
        setup = _prepare(opts, env)
    except _Abort as abort:
        if abort.message:
            _err(abort.message)
        return abort.code
    token = config.new_token()
    # sec4-7: the token is the only access control; print it only to a terminal.
    token_file: _TokenFile | None = None
    if opts.token_file is not None or not _stderr_is_terminal():
        try:
            token_file = _TokenFile.create(opts.token_file)
        except _Abort as abort:
            _err(abort.message or "could not create the token file")
            return abort.code
    try:
        return _serve(opts, setup, token, token_file, stop_event)
    finally:
        if token_file is not None:
            token_file.remove()


def _serve(
    opts: ServeOptions,
    setup: _Setup,
    token: str,
    token_file: _TokenFile | None,
    stop_event: threading.Event | None,
) -> int:
    # The plan: "serve always requires the per-run token" (hon4-3: no tokenless serve).
    fw_config = ForwarderConfig(
        upstream=setup.upstream,
        token=token,
        require_token=True,
        auth_listener=False,
        port=opts.port,
        budget_bytes=opts.budget_bytes,
        max_tunnel_bytes=opts.max_tunnel_bytes,
        deny_rules=setup.deny_rules,
        allow_private_targets=opts.allow_private_targets,
        # No helper events in serve, so no timeline figures; a standing meter would only grow it.
        record_timeline=False,
    )
    fd_limit = _raise_fd_limit(opts.quiet)
    try:
        fw = _start_forwarder(fw_config, setup.connect_map)
    except _Abort as abort:
        _err(abort.message or "the meter could not start")
        return abort.code
    stop = stop_event if stop_event is not None else threading.Event()
    from .attribution import attribute

    def current_report(snapshot: MeterSnapshot) -> dict[str, Any]:
        attribution = attribute(snapshot, [], setup.catalogs, units_override=opts.units)
        extra = ["the meter stopped unexpectedly; traffic after that point is missing"] if fw.error else []
        extra.extend(_tunnel_failure_warnings(snapshot, setup.upstream_var, fd_limit))
        return _build(
            command="serve", snapshot=snapshot, attribution=attribution, catalogs=setup.catalogs, opts=opts,
            warnings=extra,
        )

    try:
        fw.on_budget(_budget_announcer(opts.gb_unit, "refusing every request until serve restarts"))
        if token_file is not None:
            token_file.write(f"http://{config.token_username(token)}:x@127.0.0.1:{fw.port}\n")
        # The token is printed here, once, to a terminal only (never to reports or logs), or it
        # goes to the private token file.
        for line in _serve_banner(fw, setup, token, opts, token_file.path if token_file is not None else None):
            _err(line)
        write_failed = False
        next_write = time.monotonic() + opts.rewrite_interval_s
        with _SignalGuard(lambda _signum: stop.set()):
            while not stop.is_set():
                stop.wait(min(1.0, max(0.05, next_write - time.monotonic())))
                if fw.error is not None:
                    _err("the meter stopped unexpectedly")
                    break
                if time.monotonic() >= next_write and not stop.is_set():
                    next_write = time.monotonic() + opts.rewrite_interval_s
                    try:
                        _write_outputs(current_report(fw.snapshot()), opts)
                        write_failed = False
                    except _Abort as abort:
                        if not write_failed:
                            _err(abort.message or "could not write the report")
                        write_failed = True
    finally:
        snapshot = fw.stop()
    try:
        report = current_report(snapshot)
        _write_outputs(report, opts)
    except _Abort as abort:
        _err(abort.message or "could not write the report")
        return abort.code
    if not opts.quiet:
        _out(_summary(report, opts.out), sys.stderr)
        _err(_written_line(opts))
    if fw.error is not None:
        return EXIT_INTERNAL
    if snapshot.budget_tripped:
        return EXIT_BUDGET
    return EXIT_OK


# ---------------------------------------------------------------------------
# find
# ---------------------------------------------------------------------------


#: find without the Playwright package (exit 3). The same commands as the README's install section
#: (the package is installed from GitHub; it is not on PyPI yet).
_INSTALL_PLAYWRIGHT = (
    "find needs Playwright, which is not installed where scrapescope runs. Install the browser extra and "
    "Playwright's Chromium, matching how you installed scrapescope:",
    "  uv tool:  uv tool install 'scrapescope[browser] @ git+https://github.com/ipvolt/scrapescope'"
    " --with-executables-from playwright && playwright install chromium",
    "  pipx:     pipx inject --include-apps scrapescope playwright && playwright install chromium",
    "  pip:      pip install 'scrapescope[browser] @ git+https://github.com/ipvolt/scrapescope'"
    " && python -m playwright install chromium",
)
#: find with Playwright present but Chromium failing to start (exit 3).
_INSTALL_CHROMIUM = (
    "Playwright is installed but its Chromium could not be started; usually Chromium is not installed yet. "
    "Install it with the Playwright of the environment scrapescope runs in:",
    "  uv tool or pipx:  playwright install chromium",
    "  pip (virtual environment):  python -m playwright install chromium",
    "  on Linux, missing system libraries also stop Chromium:  playwright install-deps chromium",
)


def _playwright_installed() -> bool:
    """True when the Playwright package can be imported here (no import, no browser start)."""
    import importlib.util

    try:
        return importlib.util.find_spec("playwright") is not None
    except (ImportError, ValueError):
        return False


def _check_find_arguments(opts: FindOptions) -> None:
    """Usage checks that must fail before anything starts; never echo the URL or values."""
    try:
        parts = urllib.parse.urlsplit(opts.url.strip())
        _ = parts.port
    except ValueError:
        raise _Abort(EXIT_USAGE, "find needs a valid http:// or https:// URL (bad host or port)") from None
    if parts.scheme.lower() not in ("http", "https") or clean_host(parts.hostname or "") is None:
        raise _Abort(EXIT_USAGE, "find needs an http:// or https:// URL with a valid host")
    if not opts.values:
        raise _Abort(EXIT_USAGE, "find needs at least one --value")
    if len(opts.values) > MAX_FIND_VALUES:
        raise _Abort(EXIT_USAGE, f"find accepts at most {MAX_FIND_VALUES} --value options")
    if any(not v.strip() for v in opts.values):
        raise _Abort(EXIT_USAGE, "--value must not be empty")


#: find: why the meter refused a CONNECT to the target itself (honest-2), by tunnel status.
_TARGET_REFUSALS = {
    "failed:private_address": "the meter refused the target's private or local address (loopback, private, "
    "link-local, this machine's own or a host on its IPv6 link); pass --allow-private-targets to load it",
    TUNNEL_DENIED: "the host matches --deny-host or --deny-catalog",
    "failed:self_loop": "the target resolves to the meter itself",
}
#: sec4-2: the target is a name, not an address, and it resolved to a private address: the flag is
#: advised with a caution, since a public name that resolves privately can be a rebinding attack.
_TARGET_NAME_PRIVATE = (
    "the target's name resolved to a private or local address, which the meter refuses; pass "
    "--allow-private-targets only if you expect this name on your own network: a public name that resolves "
    "to a private address can be a DNS-rebinding attack"
)
#: sec4-2: a later connection to the target was refused after an earlier one to it succeeded (the page
#: loaded): its name moved to a private address. The page caused this, so the flag is not advised.
_TARGET_REBOUND = (
    "a later connection to the target's own name was refused as a private or local address although the "
    "page loaded from it (DNS rebinding or split DNS); use --allow-private-targets only for a site you trust"
)


def _target_endpoint(url: str) -> tuple[str, int] | None:
    """(host as the meter records it, port) of an https:// find target, whose refusals only show as tunnel records.

    None for any other URL. IP literals are canonical (``types.canonical_host``), as in the
    meter's records: ``[::ffff:127.0.0.1]`` is ``127.0.0.1`` (sec4-3).
    """
    try:
        parts = urllib.parse.urlsplit(url.strip())
        host = clean_host(parts.hostname or "")
        port = parts.port or 443
    except ValueError:
        return None
    if parts.scheme.lower() != "https" or host is None:
        return None
    return canonical_host(host), port


def _is_dns_name(host: str) -> bool:
    """True for a DNS name, False for an IP literal or a ``localhost`` name."""
    return ip_literal(host) is None and host != "localhost" and not host.endswith(".localhost")


def _find_abort_check(fw: Any, upstream_var: str | None, url: str = "") -> Callable[[], str | None]:
    """Stop the page load early when it cannot work (Chromium would wait for the timeout, or retry).

    Reasons: the budget tripped; the upstream answered 407, rejected SOCKS5
    credentials or is unreachable; or (https targets) the meter refused the
    CONNECT to the target itself: a private address in sizing mode, a deny
    rule, or a name resolving to the meter. Only tunnels to the target's own
    host and port count for the last group (hosts compared canonically), since
    the check is also polled while subresources load and before the
    ``--verify`` replay. For http:// targets the meter's refusal is the main
    document, which find reports itself.

    sec4-2: ``--allow-private-targets`` is advised only for the first
    connection to the target. A private-address refusal after an earlier
    connection to the target succeeded means that its name moved (the page
    loaded, then a rebinding or split-DNS name answered privately), and a
    target given as a name gets the rebinding caution.
    """
    where = f"${upstream_var}" if upstream_var else "the upstream URL"
    target = _target_endpoint(url)
    target_is_name = target is not None and _is_dns_name(target[0])

    def check() -> str | None:
        try:
            snapshot = fw.snapshot()
        except Exception:  # noqa: BLE001 - the check is advisory
            return None
        if snapshot.budget_tripped:
            return "the byte budget tripped"
        reached_target = False
        for tunnel in sorted(snapshot.tunnels, key=lambda t: t.id):
            own = (
                target is not None
                and tunnel.kind == "connect"
                and (canonical_host(tunnel.host), tunnel.port) == target
            )
            if own and tunnel.status in _TARGET_REFUSALS:
                if tunnel.status == "failed:private_address":
                    if reached_target:
                        return _TARGET_REBOUND
                    if target_is_name:
                        return _TARGET_NAME_PRIVATE
                return _TARGET_REFUSALS[tunnel.status]
            if own and not tunnel.failed and not tunnel.denied:
                reached_target = True
            if not tunnel.is_target:
                continue
            if tunnel.status == "failed:upstream_status" and tunnel.upstream_status == 407:
                return f"the upstream proxy answered 407 (check the credentials in {where})"
            if tunnel.status == "failed:socks_auth":
                return f"the SOCKS5 upstream rejected the credentials in {where}"
            if tunnel.status in ("failed:upstream_unreachable", "failed:upstream_timeout"):
                return f"the upstream proxy in {where} is unreachable"
        return None

    return check


def _find_meter_line(snapshot: MeterSnapshot, gb_unit: GbUnit, page_tunnels: set[int] | None = None) -> str:
    """The tunnel-measured ``meter:`` line: the page load, and the --verify replay separately when it ran.

    ``page_tunnels`` holds the ids of the tunnels that existed when the replay
    started (find closes its browser first, so every later tunnel is the
    replay's); None when no replay was sent.

    Tunnels the browser closed before they opened (``failed:client_closed``:
    Chromium drops speculative connections) are not failures; they are named
    separately, as ``_tunnel_failure_warnings`` leaves them out.
    """
    target = snapshot.target_tunnels()
    page = [t for t in target if page_tunnels is None or t.id in page_tunnels]
    replay = [t for t in target if page_tunnels is not None and t.id not in page_tunnels]
    estimated = " (estimated: sizing mode)" if snapshot.mode == "direct" and any(t.negotiation_estimated for t in page) else ""
    closed = sum(1 for t in page if t.status == "failed:client_closed")
    failed = sum(1 for t in page if t.failed and t.status != "failed:client_closed")
    closed_note = f"; {closed} closed by the browser before the tunnel opened" if closed else ""
    line = (
        f"meter: the page load moved {format_size(sum(t.bytes_with_connect for t in page), gb_unit)} with CONNECT"
        f"{estimated}, {format_size(sum(t.bytes_without_connect for t in page), gb_unit)} without, in {len(page)} "
        f"tunnel(s) ({failed} failed{closed_note})"
    )
    if page_tunnels is not None:
        line += (
            f"; the --verify replay moved {format_size(sum(t.bytes_with_connect for t in replay), gb_unit)} with "
            f"CONNECT in {len(replay)} tunnel(s)"
        )
    return line + "; tunnel-measured\n"


def _find_exit_code(result: Any) -> int:
    """find's own outcome codes: 0 found, 6 found but some value missing, 1 not found, 4 blocked, 5 load failed."""
    status = result.status
    if status == "found":
        return EXIT_PARTIAL if getattr(result, "missing_values", None) else EXIT_OK
    return {"not_found": EXIT_NOT_FOUND, "blocked": EXIT_BLOCKED}.get(status, EXIT_LOAD_ERROR)


def _internal_error_result(opts: FindOptions, exc: BaseException) -> Any:
    """A find result for an unexpected failure inside find, so the meter report is still written."""
    from .types import ChallengeResult, FindResult, VerifyResult

    try:
        host = clean_host(urllib.parse.urlsplit(opts.url.strip()).hostname or "") or "unknown"
    except ValueError:
        host = "unknown"
    return FindResult(
        status="error",
        target_host=host,
        target_path=None,
        values_count=max(1, len(opts.values)),
        short_value_warning=False,
        challenge=ChallengeResult(blocked=False),
        verify=VerifyResult(replays="not_tested", reason="page load failed"),
        warnings=[f"find stopped with an internal error ({safe_text(type(exc).__name__, 40)}); nothing was searched"],
        target_url=opts.url,
    )


def find_command(opts: FindOptions, *, environ: Mapping[str, str] | None = None) -> int:
    """``scrapescope find URL --value V ...``: exit 0 found, 6 partly found, 1 not found, 4 blocked, 5 load error,
    3 no browser."""
    env = dict(os.environ if environ is None else environ)
    try:
        _check_find_arguments(opts)
        setup = _prepare(opts, env)
    except _Abort as abort:
        if abort.message:
            _err(abort.message)
        return abort.code
    if not _playwright_installed():
        # Checked before the meter starts: nothing is loaded and nothing is metered.
        for line in _INSTALL_PLAYWRIGHT:
            _err(line)
        return EXIT_BROWSER_UNAVAILABLE
    fw_config = ForwarderConfig(
        upstream=setup.upstream,
        token=None,
        require_token=False,
        auth_listener=False,
        port=opts.port,
        budget_bytes=opts.budget_bytes,
        max_tunnel_bytes=opts.max_tunnel_bytes,
        deny_rules=setup.deny_rules,
        allow_private_targets=opts.allow_private_targets,
    )
    fd_limit = _raise_fd_limit(opts.quiet)
    try:
        fw = _start_forwarder(fw_config, setup.connect_map)
    except _Abort as abort:
        _err(abort.message or "the meter could not start")
        return abort.code
    from .find import BrowserUnavailableError, meter_reply_check_from_snapshot, render_find_text, run_find

    find_crashed = False
    page_tunnels: list[set[int]] = []

    def before_verify() -> None:
        # find-r2-2: the tunnels so far are the page load's; later ones carry the --verify replay.
        try:
            page_tunnels.append({t.id for t in fw.snapshot().tunnels})
        except Exception:  # noqa: BLE001 - the split is informational
            pass

    try:
        fw.on_budget(_budget_announcer(opts.gb_unit, "stopping the page load"))
        if not opts.quiet:
            _err(f"loading the page through the meter on {fw.url} ({_mode_text(setup)})")
        try:
            result = asyncio.run(
                run_find(
                    opts.url,
                    list(opts.values),
                    proxy_url=fw.url,
                    catalogs=setup.catalogs,
                    verify=opts.verify,
                    body_cap_bytes=opts.body_cap_bytes,
                    timeout_s=opts.timeout_s,
                    ca_file=config.test_ca_from_env(env),
                    abort_check=_find_abort_check(fw, setup.upstream_var, opts.url),
                    before_verify=before_verify,
                    # sec3-4: an X-Scrapescope-Error reply counts as the meter's own only when its records hold it
                    meter_reply_check=meter_reply_check_from_snapshot(fw.snapshot),
                )
            )
        except BrowserUnavailableError as exc:
            detail = str(exc)
            lines = _INSTALL_PLAYWRIGHT if detail.startswith("Playwright is not installed") else _INSTALL_CHROMIUM
            for line in lines:
                _err(line)
            return EXIT_BROWSER_UNAVAILABLE
        except ValueError as exc:
            _err(str(exc))
            return EXIT_USAGE
        except KeyboardInterrupt:
            _err("interrupted")
            return EXIT_INTERRUPTED
        except Exception as exc:  # noqa: BLE001 - keep the meter report when find itself fails (sec-8)
            _err(f"find stopped with an internal error ({type(exc).__name__}); writing the meter report anyway")
            result = _internal_error_result(opts, exc)
            find_crashed = True
        _drain(fw, 0.5)
    finally:
        snapshot = fw.stop()
    from .attribution import attribute
    from .attribution.core import NO_EVENTS_WARNING

    attribution = attribute(snapshot, [], setup.catalogs)
    # find never has helper events; its per-response figures are in the find section.
    attribution.warnings = [w for w in attribution.warnings if w != NO_EVENTS_WARNING]
    extra = ["the meter stopped unexpectedly; traffic after that point is missing"] if fw.error else []
    extra.extend(_tunnel_failure_warnings(snapshot, setup.upstream_var, fd_limit))
    try:
        report = _build(
            command="find", snapshot=snapshot, attribution=attribution, catalogs=setup.catalogs, opts=opts,
            find_results=[result], warnings=extra,
        )
        _write_outputs(report, opts)
    except _Abort as abort:
        _out(render_find_text(result))
        _err(abort.message or "could not write the report")
        return abort.code
    _out(render_find_text(result))
    _out(_find_meter_line(snapshot, opts.gb_unit, page_tunnels[0] if page_tunnels else None))
    if not opts.quiet:
        for warning in report.get("warnings", []):
            if warning.startswith(("sizing mode", "budget tripped")):
                _err("note: " + warning)
        _err(_written_line(opts))
    if fw.error is not None or find_crashed:
        return EXIT_INTERNAL
    if snapshot.budget_tripped:
        return EXIT_BUDGET
    return _find_exit_code(result)


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


def report_command(opts: ReportCommandOptions) -> int:
    """``scrapescope report REPORT.json``: re-render (text, json, html) and apply ``--fail-on`` gates."""
    from .report import ReportError, dumps, gate, load_report, render_html, render_text, write_html

    try:
        report = load_report(opts.path)
    except ReportError as exc:
        _err(f"error: {exc}")
        return EXIT_USAGE
    if opts.html is not None:
        try:
            _check_output_path(opts.html, "--html")
            write_html(report, opts.html)
        except _Abort as abort:
            _err(abort.message or "cannot write the HTML file")
            return abort.code
        except OSError as exc:
            _err(f"could not write the HTML file: {exc.strerror or type(exc).__name__}")
            return EXIT_INTERNAL
    if opts.format == "json":
        _out(dumps(report))
    elif opts.format == "html":
        if opts.html is None:
            _out(render_html(report))
    else:
        _out(render_text(report))
    try:
        return gate(report, opts.fail_on)
    except ValueError as exc:
        _err(str(exc))
        return EXIT_USAGE


__all__ = [
    "CommonOptions",
    "FindOptions",
    "ReportCommandOptions",
    "RunOptions",
    "ServeOptions",
    "find_command",
    "report_command",
    "run_command",
    "serve_command",
]
