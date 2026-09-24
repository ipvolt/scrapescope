"""Command-line interface: ``scrapescope run | serve | find | report``.

Parses arguments with argparse (usage errors exit 2) and dispatches to
:mod:`scrapescope.runner`. Contract: docs/dev/contracts.md sections 12 and 13;
exit codes are listed in :data:`_EPILOG` (and docs/exit-codes.md in the source tree).

The upstream proxy URL is never accepted on the command line: it is read from
an environment variable (``--upstream-from-env VAR``, or HTTPS_PROXY by
default), because argv is visible to every local user and ends up in shell
history and CI logs.
"""

from __future__ import annotations

import argparse
import math
import sys
from collections.abc import Sequence

from ._version import __version__
from .config import DEFAULT_REPORT_PATH, EXIT_INTERNAL, EXIT_USAGE, FIND_BODY_CAP_BYTES, MB, budget_arg

_DESCRIPTION = (
    "A local metering proxy for scrapers and browser agents: counts the bytes of every tunnel to your "
    "proxy provider (or direct, in sizing mode), attributes them, enforces a byte budget and finds the "
    "smallest response that already contains your data. No telemetry; never terminates TLS."
)

#: The complete exit-code list (the docs directory is not installed with the wheel).
_EPILOG = (
    "Exit codes: run passes the job's own code through; find: 0 found (every value), 6 found but at least "
    "one value in no inspected response, 1 not found, 4 blocked by a challenge page, 5 page load failed, "
    "3 Playwright or its Chromium missing, 130 interrupted (Ctrl-C; no report is written); report: 0, or 86/87 with "
    "--fail-on; 2 usage error; "
    "86 budget tripped; 87 bypass detected with --fail-on bypass; 88 meter internal error; "
    "89 upstream configuration error."
)


# ---------------------------------------------------------------------------
# Argument types
# ---------------------------------------------------------------------------


def _positive_float(name: str, *, allow_zero: bool = False):  # noqa: ANN202 - argparse type factory
    def parse(text: str) -> float:
        try:
            value = float(text)
        except ValueError:
            raise argparse.ArgumentTypeError(f"{name} must be a number") from None
        if not math.isfinite(value) or value < 0 or (value == 0 and not allow_zero):
            raise argparse.ArgumentTypeError(f"{name} must be {'zero or ' if allow_zero else ''}a positive number")
        return value

    return parse


def _int_range(name: str, low: int, high: int):  # noqa: ANN202 - argparse type factory
    def parse(text: str) -> int:
        try:
            value = int(text, 10)
        except ValueError:
            raise argparse.ArgumentTypeError(f"{name} must be a whole number") from None
        if not low <= value <= high:
            raise argparse.ArgumentTypeError(f"{name} must be between {low} and {high}")
        return value

    return parse


def _host_glob(text: str) -> str:
    from .types import validate_host_glob

    try:
        return validate_host_glob(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def _add_upstream(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("upstream (the proxy URL is read from the environment, never from argv)")
    exclusive = group.add_mutually_exclusive_group()
    exclusive.add_argument(
        "--upstream-from-env",
        metavar="VAR",
        dest="upstream_var",
        help="read the upstream proxy URL (http://, socks5:// or socks5h://, credentials included) from "
        "environment variable VAR; default: HTTPS_PROXY when it is set",
    )
    exclusive.add_argument(
        "--direct",
        action="store_true",
        help="sizing mode: no upstream, connect directly (the with-CONNECT figure is then estimated)",
    )


#: --quiet for run and serve: their summary goes to stderr.
_QUIET_HELP = "no terminal summary (errors and budget messages still go to stderr)"
#: --quiet for find: its result is the command's output (ux-r3-1).
_FIND_QUIET_HELP = (
    "no progress notes on stderr; the result and the meter line still go to stdout "
    "(errors and budget messages still go to stderr)"
)


def _add_common(parser: argparse.ArgumentParser, *, units: bool, quiet_help: str = _QUIET_HELP) -> None:
    group = parser.add_argument_group("metering and reports")
    group.add_argument(
        "--rate", type=_positive_float("--rate", allow_zero=True), metavar="USD",
        help="your price in USD per GB (per GiB with --gib); no default: costs appear only when given",
    )
    group.add_argument("--gib", action="store_true", help="report in GiB (2^30 bytes) instead of GB (10^9 bytes)")
    group.add_argument(
        "--budget", type=budget_arg, metavar="SIZE", dest="budget_bytes",
        help="stop at this many bytes to and from the upstream; a unit is required, e.g. 2GB, 500MB, 1.5GiB. "
        "The meter stops at its own count; the provider may count up to a few MB more per open tunnel",
    )
    group.add_argument(
        "--max-tunnel-mb", type=_positive_float("--max-tunnel-mb"), metavar="N",
        help="close any single tunnel (one upstream connection, however many hosts it served) after "
        "N x 10^6 bytes",
    )
    group.add_argument(
        "--deny-host", action="append", default=[], type=_host_glob, metavar="GLOB", dest="deny_hosts",
        help="refuse matching hosts with 403 (repeatable; '*' matches any characters, dots included)",
    )
    group.add_argument(
        "--deny-catalog", action="append", default=[], choices=["background"], dest="deny_catalogs",
        help="refuse every host in the background catalog (costs security updates; see the catalog entries)",
    )
    if units:
        group.add_argument(
            "--units", type=_int_range("--units", 1, 10**12), metavar="N",
            help="number of units (pages, items) the run produced, for per-1,000 figures",
        )
    group.add_argument(
        "--out", default=DEFAULT_REPORT_PATH, metavar="PATH",
        help=f"report.json path (default ./{DEFAULT_REPORT_PATH}); written with mode 0600",
    )
    group.add_argument("--html", metavar="PATH", help="also write a self-contained report.html")
    group.add_argument("--keep-urls", action="store_true", help="keep URL paths (never query strings) in reports")
    group.add_argument(
        "--redact-hosts", action="store_true",
        help="replace hosts in reports with catalog ids or per-report keyed hashes",
    )
    group.add_argument("--quiet", action="store_true", help=quiet_help)
    group.add_argument(
        "--port", type=_int_range("--port", 0, 65535), default=0, metavar="N",
        help="listening port on 127.0.0.1 (default: random)",
    )
    group.add_argument(
        "--allow-private-targets", action="store_true",
        help="sizing mode (--direct): let the meter connect to loopback, private and link-local addresses, "
        "this machine's own addresses and hosts on its own IPv6 link; "
        "off by default because a page loaded through the meter could otherwise reach services on this "
        "machine or its network",
    )


def build_parser() -> argparse.ArgumentParser:
    """The ``scrapescope`` argument parser."""
    parser = argparse.ArgumentParser(
        prog="scrapescope", description=_DESCRIPTION, epilog=_EPILOG,
    )
    parser.add_argument("--version", action="version", version=f"scrapescope {__version__}")
    sub = parser.add_subparsers(dest="subcommand", metavar="{run,serve,find,report}")

    run = sub.add_parser(
        "run",
        help="meter a job: scrapescope run [options] -- CMD [ARG ...]",
        description="Run CMD with its proxy pointed at the meter, then write a report. The job's own exit code "
        "is passed through unless a scrapescope condition applies (86 budget, 87 bypass, 88 internal).",
        usage="scrapescope run [options] -- CMD [ARG ...]",
        epilog=_EPILOG,
    )
    _add_upstream(run)
    run.add_argument(
        "--env-all", action="store_true",
        help="also point HTTP(S)_PROXY, ALL_PROXY (and lowercase), NODE_USE_ENV_PROXY=1 at the meter; "
        "LLM API hosts (direct.json) then bypass your proxy: the meter looks them up and "
        "connects from this machine's own IP address, for every client (a browser too), and reports them "
        "as non-target",
    )
    _add_common(run, units=True)
    run.add_argument(
        "--keep-events", action="store_true",
        help="keep the private helper events file after the run and print its path",
    )
    run.add_argument(
        "--fail-on", action="append", default=[], choices=["bypass"],
        help="exit 87 when the helpers or hooks saw traffic that did not pass through the meter",
    )
    run.add_argument("command", nargs=argparse.REMAINDER, help=argparse.SUPPRESS)

    serve = sub.add_parser(
        "serve",
        help="a standing meter for hand-configured clients and CI",
        description="Run the meter until SIGINT or SIGTERM. Clients must use the username ss-<token> (or "
        "ss-<token>~<your-proxy-username>); serve always requires it. The token is printed once at start when "
        "stderr is a terminal; otherwise it is written to a private file whose path is printed.",
        epilog=_EPILOG,
    )
    _add_upstream(serve)
    serve.add_argument(
        "--token-file", metavar="PATH",
        help="write the proxy URL with the token (http://ss-<token>:x@127.0.0.1:PORT) to PATH instead of "
        "printing the token; PATH must not exist yet, is created with mode 0600 and is removed when serve stops. "
        "Without it, the token is printed only when stderr is a terminal, and otherwise goes to such a file in "
        "a private temporary directory",
    )
    _add_common(serve, units=True)

    find = sub.add_parser(
        "find",
        help="find the smallest response that already contains your value",
        description="Load URL once in headless Chromium through the meter and rank the responses that contain "
        "any --value: those holding every value first, then by how many values they hold, smaller responses "
        "before larger ones. Needs the [browser] extra. Exit 0 found, 6 some value not found, 1 not found, "
        "4 blocked (challenge page), 5 page load failed, 3 browser missing, 130 interrupted (no report). "
        "The values never appear in reports.",
        epilog=_EPILOG,
    )
    find.add_argument("url", metavar="URL", help="http:// or https:// page to load")
    find.add_argument(
        "--value", action="append", required=True, dest="values", metavar="V",
        help="value to search for (repeatable, up to 50); responses containing all values rank first",
    )
    find.add_argument(
        "--verify", action="store_true",
        help=(
            "replay one match once, cookie-less, with an honest User-Agent: the top eligible match, or a "
            "higher-ranked one withheld only for the cookies or token header it sent"
        ),
    )
    find.add_argument(
        "--timeout", type=_positive_float("--timeout"), default=45.0, dest="timeout_s", metavar="SECONDS",
        help="time budget for the page load (default 45)",
    )
    find.add_argument(
        "--body-cap-mb", type=_positive_float("--body-cap-mb"), default=FIND_BODY_CAP_BYTES / MB, metavar="N",
        help=f"largest response body searched, in 10^6 bytes (default {FIND_BODY_CAP_BYTES // MB})",
    )
    _add_upstream(find)
    _add_common(find, units=False, quiet_help=_FIND_QUIET_HELP)

    report = sub.add_parser(
        "report",
        help="re-render or gate a saved report",
        description="Validate a saved report.json and print it as text (default), JSON or HTML. "
        "--fail-on budget exits 86 when its budget tripped; --fail-on bypass exits 87 when it is "
        "incomplete (86 wins). An unreadable or invalid file exits 2.",
        epilog=_EPILOG,
    )
    report.add_argument("path", metavar="REPORT.json")
    report.add_argument("--format", choices=["text", "html", "json"], default="text", help="output format (default text)")
    report.add_argument("--html", metavar="OUT", help="write the HTML rendering to OUT")
    report.add_argument(
        "--fail-on", action="append", default=[], choices=["budget", "bypass"],
        help="gate on a condition (repeatable): budget -> 86, bypass -> 87",
    )
    return parser


def _split_run_command(argv: list[str]) -> tuple[list[str], list[str] | None]:
    """Split ``run [options] -- CMD ...`` at the first ``--`` (argparse's handling varies by version)."""
    if not argv or argv[0] != "run" or "--" not in argv:
        return argv, None
    index = argv.index("--")
    return argv[:index], argv[index + 1 :]


def _max_tunnel_bytes(value: float | None) -> int | None:
    return None if value is None else max(1, round(value * MB))


def _common_kwargs(ns: argparse.Namespace) -> dict:
    return {
        "upstream_var": ns.upstream_var,
        "direct": ns.direct,
        "rate": ns.rate,
        "gib": ns.gib,
        "budget_bytes": ns.budget_bytes,
        "max_tunnel_bytes": _max_tunnel_bytes(ns.max_tunnel_mb),
        "deny_hosts": tuple(ns.deny_hosts),
        "deny_catalogs": tuple(ns.deny_catalogs),
        "out": ns.out,
        "html": ns.html,
        "keep_urls": ns.keep_urls,
        "redact_hosts": ns.redact_hosts,
        "quiet": ns.quiet,
        "port": ns.port,
        "allow_private_targets": ns.allow_private_targets,
    }


def _dispatch(parser: argparse.ArgumentParser, argv: list[str]) -> int:
    from . import runner

    head, tail = _split_run_command(argv)
    ns = parser.parse_args(head)
    if ns.subcommand is None:
        parser.print_help(sys.stderr)
        return EXIT_USAGE
    if ns.subcommand == "run":
        command = list(ns.command)
        if tail is not None:
            # Tokens before "--" that argparse left over belong to the command itself.
            command = [*command, "--", *tail] if command else tail
        if not command:
            sys.stderr.write(
                "usage: scrapescope run [options] -- CMD [ARG ...]\n"
                "scrapescope run: error: missing the command to run after --\n"
            )
            return EXIT_USAGE
        return runner.run_command(
            runner.RunOptions(
                **_common_kwargs(ns),
                command=tuple(command),
                env_all=ns.env_all,
                units=ns.units,
                keep_events=ns.keep_events,
                fail_on=tuple(ns.fail_on),
            )
        )
    if ns.subcommand == "serve":
        return runner.serve_command(
            runner.ServeOptions(**_common_kwargs(ns), units=ns.units, token_file=ns.token_file)
        )
    if ns.subcommand == "find":
        return runner.find_command(
            runner.FindOptions(
                **_common_kwargs(ns),
                url=ns.url,
                values=tuple(ns.values),
                verify=ns.verify,
                timeout_s=ns.timeout_s,
                body_cap_bytes=max(1, round(ns.body_cap_mb * MB)),
            )
        )
    return runner.report_command(
        runner.ReportCommandOptions(path=ns.path, format=ns.format, html=ns.html, fail_on=tuple(ns.fail_on))
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments and dispatch to scrapescope.runner; returns the exit code."""
    args = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    try:
        return _dispatch(parser, args)
    except SystemExit as exc:  # argparse: --help/--version (0) and usage errors (2)
        code = exc.code
        if code is None:
            return 0
        return code if isinstance(code, int) else EXIT_USAGE
    except KeyboardInterrupt:
        sys.stderr.write("scrapescope: interrupted\n")
        return 130
    except Exception as exc:  # noqa: BLE001 - last resort; never print values that may hold secrets
        sys.stderr.write(f"scrapescope: internal error ({type(exc).__name__})\n")
        return EXIT_INTERNAL


__all__ = ["build_parser", "main"]
