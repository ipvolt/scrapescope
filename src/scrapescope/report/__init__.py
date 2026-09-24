"""report.json v1: build, validate, render (text and HTML), write, load, gate.

- ``build_report`` assembles the report dict from a meter snapshot, the
  attribution result, find results and options (``report.build``).
- ``validate`` checks a dict against ``report/schema.json`` with a small
  built-in validator for the JSON Schema subset the schema uses
  (``report.validate``).
- ``render_text`` is the terminal summary; ``render_html`` is a self-contained,
  script-free page with a strict CSP (``report.text``, ``report.html``).
- ``write_report``, ``load_report`` and ``gate`` handle files and ``--fail-on``
  (``report.io``).

Accuracy labels are part of the format: totals "tunnel-measured", per-type
bytes "allocated", hook sizes "hook-reported", costs "estimated billable
transfer". Reports never contain bodies, query strings, cookies, header values,
credentials, the upstream host, the command line or find values.
Contract: docs/dev/contracts.md section 11.
"""

from __future__ import annotations

from .build import LABELS, SIZING_WARNING, build_report, coverage_line, rfc3339
from .errors import ReportError
from .html import content_security_policy, render_html, style_hash
from .io import GATE_CONDITIONS, dumps, gate, load_report, write_html, write_report
from .text import render_text
from .validate import SchemaError, Validator, load_schema, validate

__all__ = [
    "GATE_CONDITIONS",
    "LABELS",
    "SIZING_WARNING",
    "ReportError",
    "SchemaError",
    "Validator",
    "build_report",
    "content_security_policy",
    "coverage_line",
    "dumps",
    "gate",
    "load_report",
    "load_schema",
    "render_html",
    "render_text",
    "rfc3339",
    "style_hash",
    "validate",
    "write_html",
    "write_report",
]
