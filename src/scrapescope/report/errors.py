"""Report errors (kept separate so every report module can import them)."""

from __future__ import annotations


class ReportError(Exception):
    """Unreadable, non-JSON or invalid report (CLI exit 2). Messages never echo report values."""


__all__ = ["ReportError"]
