"""Host labelling for ``--redact-hosts`` and scrubbing of free text.

``--redact-hosts`` replaces every host in a report by ``catalog:<id>`` when it
matches a background.json or direct.json entry (public data), otherwise by
``redacted:<first 12 hex of HMAC-SHA256(key, host)>``. The 32-byte key is random
per report and never stored, so labels are stable within one report and cannot
be linked across reports or reversed with a dictionary of hostnames (a plain
hash could). Hosts that also appear inside free text (warnings, caveats) are
replaced there too.

``scrub_text`` is a defensive pass applied to every free-text string before it
enters a report: it removes URL credentials, query strings and fragments, and
the values of ``Authorization``/``Cookie`` style headers and Basic/Bearer
tokens, in case a caller ever passes such text. It is a safety net, not a
licence to pass secrets in: callers must still keep them out.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets

from ..types import Catalogs, clean_host, safe_text

INVALID_HOST = "invalid-host"

_URL_USERINFO_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.-]{0,15})://[^\s/?#@]*@[^\s/?#]*")
_URL_QUERY_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.-]{0,15}://[^\s?#]*)[?#]\S*")
_AUTH_TOKEN_RE = re.compile(r"(?i)\b(basic|bearer|digest|negotiate)\s+[A-Za-z0-9+/=._~-]{6,}")
_SECRET_HEADER_RE = re.compile(r"(?i)\b(proxy-authorization|authorization|set-cookie|cookie)\s*[:=]\s*\S.*$")


def scrub_text(text: str) -> str:
    """Remove URL credentials, query strings and auth/cookie values from ``text``."""
    text = _URL_USERINFO_RE.sub(lambda m: f"{m.group(1)}://<redacted>", text)
    text = _URL_QUERY_RE.sub(lambda m: m.group(1), text)
    text = _AUTH_TOKEN_RE.sub(lambda m: f"{m.group(1)} <redacted>", text)
    text = _SECRET_HEADER_RE.sub(lambda m: f"{m.group(1)}: <redacted>", text)
    return text


class HostLabeler:
    """Maps hosts to report labels (identity unless ``redact``)."""

    def __init__(self, catalogs: Catalogs, *, redact: bool) -> None:
        self.catalogs = catalogs
        self.redact = redact
        self._key = secrets.token_bytes(32) if redact else b""
        self._labels: dict[str, str] = {}
        self._text_re: re.Pattern[str] | None = None

    def label(self, host: object) -> str:
        """The report form of ``host``: cleaned, or a catalog/redacted label."""
        h = clean_host(host)
        if h is None:
            return INVALID_HOST
        cached = self._labels.get(h)
        if cached is not None:
            return cached
        if not self.redact:
            result = h
        else:
            cid = self.catalogs.background_id_for(h) or self.catalogs.direct_id_for(h)
            if cid:
                result = f"catalog:{cid}"
            else:
                digest = hmac.new(self._key, h.encode("ascii"), hashlib.sha256).hexdigest()
                result = f"redacted:{digest[:12]}"
        self._labels[h] = result
        self._text_re = None
        return result

    def register(self, hosts: object) -> None:
        """Label every host in an iterable (so text scrubbing knows them)."""
        for host in hosts:  # type: ignore[attr-defined]
            self.label(host)

    def replace_in_text(self, text: str) -> str:
        """Replace known hosts inside free text by their labels (redact mode only)."""
        if not self.redact or not self._labels:
            return text
        if self._text_re is None:
            names = sorted((h for h, lab in self._labels.items() if h != lab), key=len, reverse=True)
            if not names:
                return text
            alternation = "|".join(re.escape(n) for n in names)
            self._text_re = re.compile(
                rf"(?i)(?<![A-Za-z0-9_.-])(?:{alternation})(?![A-Za-z0-9_-]|\.[A-Za-z0-9])"
            )
        return self._text_re.sub(lambda m: self._labels.get(m.group(0).lower(), INVALID_HOST), text)

    def text(self, value: object, max_len: int = 500) -> str:
        """Free text for a report: scrubbed, hosts replaced when redacting, then ``safe_text``."""
        raw = value if isinstance(value, str) else str(value)
        return safe_text(self.replace_in_text(scrub_text(raw)), max_len)


__all__ = ["INVALID_HOST", "HostLabeler", "scrub_text"]
