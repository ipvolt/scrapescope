"""Writing, loading and gating saved reports.

- ``write_report`` validates first (an invalid report is a scrapescope bug and
  raises :class:`ReportError` rather than writing something ``report`` cannot
  read back), then writes report.json and optionally report.html atomically:
  a temporary file in the same directory, flushed and fsynced, then
  ``os.replace``. Files are created with mode 0600 (reports name the hosts a
  job contacted); ``chmod`` them to share.
- ``load_report`` reads, parses (rejecting NaN/Infinity) and validates a report;
  every failure is a :class:`ReportError` whose message never echoes content.
- ``gate`` maps ``--fail-on`` conditions to exit codes.
- ``dumps`` never re-emits the stored fix code of a report it did not build:
  for a report read from a file (``report FILE --format json``) the fixes are
  rebuilt from their ids, as the text and HTML renderers show them, so a
  foreign report cannot present its own code or title as scrapescope's.
"""

from __future__ import annotations

import json
import os
import secrets
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from ..config import EXIT_BUDGET, EXIT_BYPASS, EXIT_OK
from ..types import REPORT_SCHEMA_VERSION
from ._fmt import fix_views, is_generated
from .errors import ReportError
from .html import render_html
from .validate import validate

#: Largest report file ``load_report`` accepts.
MAX_REPORT_BYTES = 64 * 1024 * 1024
GATE_CONDITIONS = ("budget", "bypass")


def _atomic_write(path: str | os.PathLike[str], data: str) -> None:
    target = Path(path)
    directory = target.parent if str(target.parent) else Path(".")
    tmp = directory / f".{target.name}.{secrets.token_hex(6)}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


#: Keys of a stored fix (report.json ``fixes[]``).
_FIX_KEYS = ("id", "title", "detection", "language", "code", "caveats")


def _with_rebuilt_fixes(report: dict[str, Any]) -> dict[str, Any]:
    """A shallow copy whose fixes are rebuilt from their ids (reports this process did not build)."""
    if is_generated(report) or not isinstance(report, dict) or not isinstance(report.get("fixes"), list):
        return report
    views, _generated = fix_views(report)
    out = dict(report)
    out["fixes"] = [{key: view.get(key) for key in _FIX_KEYS} for view in views if not view.get("unknown")]
    return out


def dumps(report: dict[str, Any]) -> str:
    """report.json text: indented, ASCII-only, no NaN, trailing newline.

    A report ``build_report`` assembled in this process is written as it is.
    Any other dict (a report read from a file) is untrusted: its fixes are
    written as this scrapescope rebuilds them from their ids (title, detection,
    code and caveats regenerated from the report's own figures; ids this version
    does not generate are left out), never as stored.
    """
    return json.dumps(_with_rebuilt_fixes(report), indent=2, ensure_ascii=True, allow_nan=False) + "\n"


def write_report(
    report: dict[str, Any],
    json_path: str | os.PathLike[str],
    html_path: str | os.PathLike[str] | None = None,
) -> None:
    """Validate, then atomically write report.json (and report.html when asked)."""
    problems = validate(report)
    if problems:
        raise ReportError(
            f"refusing to write an invalid report ({len(problems)} problem(s)); first: " + "; ".join(problems[:3])
        )
    _atomic_write(json_path, dumps(report))
    if html_path is not None:
        _atomic_write(html_path, render_html(report))


def write_html(report: dict[str, Any], html_path: str | os.PathLike[str]) -> None:
    """Atomically write report.html (mode 0600) for an already validated report."""
    _atomic_write(html_path, render_html(report))


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-standard JSON constant {name}")


def load_report(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Read and validate a saved report. Raises :class:`ReportError`."""
    try:
        size = os.stat(path).st_size
        if size > MAX_REPORT_BYTES:
            raise ReportError(f"report file is larger than {MAX_REPORT_BYTES // (1024 * 1024)} MiB")
        with open(path, "rb") as fh:
            raw = fh.read(MAX_REPORT_BYTES + 1)
    except ReportError:
        raise
    except OSError as exc:
        raise ReportError(f"cannot read the report file: {exc.strerror or 'I/O error'}") from None
    try:
        data = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
    except UnicodeDecodeError:
        raise ReportError("the report file is not UTF-8 text") from None
    except json.JSONDecodeError as exc:
        raise ReportError(f"the report file is not valid JSON (line {exc.lineno}, column {exc.colno})") from None
    except (ValueError, RecursionError):
        raise ReportError("the report file is not valid report JSON") from None
    if not isinstance(data, dict):
        raise ReportError("the report file does not contain a JSON object")
    version = data.get("schema_version")
    if isinstance(version, int) and not isinstance(version, bool) and version > REPORT_SCHEMA_VERSION:
        # ux4-4: a newer scrapescope wrote it; say so instead of listing schema problems
        raise ReportError(
            f"this report uses schema version {min(version, 10**6)}; this scrapescope reads version "
            f"{REPORT_SCHEMA_VERSION}, so upgrade scrapescope to read it"
        )
    problems = validate(data)
    if problems:
        raise ReportError(
            f"not a valid scrapescope report v1 ({len(problems)} problem(s)); first: " + "; ".join(problems[:5])
        )
    return data


def gate(report: dict[str, Any], fail_on: Iterable[str]) -> int:
    """Exit code for ``report --fail-on``: 86 budget tripped, 87 bypass (86 wins), else 0.

    Raises ``ValueError`` for an unknown condition.
    """
    conditions = set(fail_on)
    unknown = conditions - set(GATE_CONDITIONS)
    if unknown:
        raise ValueError(f"unknown --fail-on condition(s): {', '.join(sorted(unknown))}")
    budget = report.get("budget") if isinstance(report, dict) else None
    if "budget" in conditions and isinstance(budget, dict) and budget.get("tripped") is True:
        return EXIT_BUDGET
    if "bypass" in conditions and isinstance(report, dict) and report.get("incomplete") is True:
        return EXIT_BYPASS
    return EXIT_OK


__all__ = ["GATE_CONDITIONS", "MAX_REPORT_BYTES", "dumps", "gate", "load_report", "write_html", "write_report"]
