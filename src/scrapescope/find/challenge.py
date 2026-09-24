"""Challenge-page classifier for ``find`` (classification only).

Runs the ``challenges.json`` signals against the main document so ``find``
can say "blocked; cannot search" instead of a misleading "not found".
scrapescope never tries to get past a challenge: this module only reads the
status, response headers, ``Set-Cookie`` names and the first 64 KiB of the
decoded body that the browser already received.

Signal semantics (docs/dev/contracts.md section 8):

========  =====================================================================
type      fires when
========  =====================================================================
header    header ``name`` (case-insensitive) is present and, when ``pattern`` is
          set, one of its values matches ``re.search(pattern, value, re.I)``
cookie    a ``Set-Cookie`` cookie name matches the glob ``name``
          (``fnmatch.fnmatchcase``) and, when ``pattern`` is set, its value
          matches
status    the status is in ``statuses``
body      ``pattern`` matches (``re.search``, ``re.I``) the first 64 KiB of the body
========  =====================================================================

For every type a non-empty ``statuses`` list additionally requires the status
to be in it. ``strength: "challenge"`` signals make the response blocked;
``strength: "vendor"`` signals only name the vendor.

Accuracy limits: a vendor can change its markers at any time, and a site can
serve a challenge that no catalogued signal describes; the result is then
"not blocked" and the value search runs on whatever the page contained.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterable, Sequence
from functools import lru_cache

from ..types import Catalogs, ChallengeResult, ChallengeSignal, ChallengeVendor

#: Bytes of decoded body text the body signals look at.
BODY_WINDOW_CHARS = 64 * 1024
_SIGNAL_NAME_RE = re.compile(r"[\x21-\x7e]{1,128}")
_VENDOR_NAME_RE = re.compile(r"[\x20-\x7e]{1,64}")
_MAX_SIGNALS = 50


@lru_cache(maxsize=512)
def _compiled(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.I)


def parse_set_cookie_names(values: Iterable[str]) -> list[tuple[str, str]]:
    """``(name, value)`` of every cookie in ``Set-Cookie`` header values.

    Values joined with newlines (as some clients report repeated headers) are
    split first. Attributes after the first ``;`` are ignored.
    """
    out: list[tuple[str, str]] = []
    for value in values:
        for line in str(value).split("\n"):
            first = line.split(";", 1)[0].strip()
            if not first:
                continue
            name, sep, cookie_value = first.partition("=")
            if sep and name.strip():
                out.append((name.strip(), cookie_value.strip()))
    return out


def _signal_label(vendor: ChallengeVendor, sig: ChallengeSignal, index: int) -> str:
    name = sig.name if sig.name and _SIGNAL_NAME_RE.fullmatch(sig.name) else str(index)
    return f"{vendor.id}:{sig.type}:{name}"


def _fires(
    sig: ChallengeSignal,
    status: int | None,
    headers: Sequence[tuple[str, str]],
    cookies: Sequence[tuple[str, str]],
    body: str,
) -> bool:
    if sig.statuses and status not in sig.statuses:
        return False
    if sig.type == "status":
        return bool(sig.statuses)
    if sig.type == "header":
        if not sig.name:
            return False
        wanted = sig.name.lower()
        values = [v for n, v in headers if n == wanted]
        if not values:
            return False
        if sig.pattern is None:
            return True
        rx = _compiled(sig.pattern)
        return any(rx.search(v) for v in values)
    if sig.type == "cookie":
        if not sig.name:
            return False
        for name, value in cookies:
            if fnmatch.fnmatchcase(name, sig.name):
                if sig.pattern is None or _compiled(sig.pattern).search(value):
                    return True
        return False
    if sig.type == "body":
        if sig.pattern is None or not body:
            return False
        return _compiled(sig.pattern).search(body) is not None
    return False


def _vendor_name(vendor: ChallengeVendor) -> str:
    name = vendor.name.strip()
    if _VENDOR_NAME_RE.fullmatch(name):
        return name
    cleaned = "".join(c for c in name if 0x20 <= ord(c) <= 0x7E)[:64].strip()
    return cleaned or vendor.id


def classify_challenge(
    status: int | None,
    headers: Sequence[tuple[str, str]],
    body_text: str | None,
    catalogs: Catalogs,
) -> ChallengeResult:
    """Classify a main-document response against ``catalogs.challenges``.

    ``headers`` is every response header as ``(name, value)`` pairs, repeated
    headers (such as ``Set-Cookie``) listed once per value. ``body_text`` is
    the decoded body (only its first 64 KiB is examined) or None when it could
    not be read. Returns ``blocked=True`` when any challenge-strength signal
    fires; ``vendor_id`` is the vendor of the first firing challenge signal,
    else of the first firing vendor signal. ``signals`` lists catalog
    references (``"<vendor_id>:<type>:<name or index>"``), never page content.
    """
    lowered = [(str(n).strip().lower(), str(v)) for n, v in headers]
    cookies = parse_set_cookie_names(v for n, v in lowered if n == "set-cookie")
    body = (body_text or "")[:BODY_WINDOW_CHARS]
    first_challenge: ChallengeVendor | None = None
    first_vendor: ChallengeVendor | None = None
    signals: list[str] = []
    for vendor in catalogs.challenges:
        for index, sig in enumerate(vendor.signals):
            try:
                fired = _fires(sig, status, lowered, cookies, body)
            except re.error:
                fired = False
            if not fired:
                continue
            label = _signal_label(vendor, sig, index)
            if label not in signals and len(signals) < _MAX_SIGNALS:
                signals.append(label)
            if sig.strength == "challenge":
                first_challenge = first_challenge or vendor
            else:
                first_vendor = first_vendor or vendor
    chosen = first_challenge or first_vendor
    return ChallengeResult(
        blocked=first_challenge is not None,
        vendor_id=chosen.id if chosen else None,
        vendor_name=_vendor_name(chosen) if chosen else None,
        signals=signals,
        status=status if isinstance(status, int) and 0 <= status <= 999 else None,
    )


__all__ = ["BODY_WINDOW_CHARS", "classify_challenge", "parse_set_cookie_names"]
