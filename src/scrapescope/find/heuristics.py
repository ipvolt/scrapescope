"""Heuristics for ``find``: body kinds, random-looking tokens, third parties, code eligibility.

Every rule here is a heuristic and errs on the side of *not* emitting code:
a false "random-looking token" only withholds starter code, while a missed
token could hand the user code that replays session or anti-bot state.

Accuracy limits:
- ``looks_random`` judges the shape of a query value, not its meaning. Long
  mixed identifiers (``SKU2026WIDGETPRO01``) and UUID product ids can be
  flagged; short signed tokens can be missed. Query parameters with
  signature- or session-like names are flagged whatever their value looks
  like: the names in :data:`SIGNATURE_PARAM_NAMES`, and names with a word
  such as ``token``, ``session``, ``sig``, ``auth``, ``csrf``, ``xsrf`` or
  ``hmac`` (``sessionToken``, ``x_csrf``; not ``author`` or ``design``).
  Compound values (Akamai ``exp=...~acl=...~hmac=...``) are also split on
  ``~ = : , . ; | !`` and each part checked, and a JWT anywhere in a value
  counts. Path segments are checked more narrowly (JWTs, UUIDs, 24+ hex), so
  a build id made of a git hash in a path such as ``/_next/data/<id>/`` also
  withholds code; ``;name=value`` path parameters (Java's
  ``;jsessionid=...``) are flagged by name or by a random-looking value.
- ``is_token_header`` flags request headers by credential- or session-like
  names (``x-api-key``, ``x-csrf-token``...) and ``x-`` headers with a
  random-looking value, so tracing ids (``x-request-id``) count too; such a
  match is still replayed by ``--verify`` without the header, which then
  decides. A token under a neutral non-``x-`` name is missed.
- GraphQL persisted-query hashes and jQuery JSONP callback names are
  content-addressed and do not count as tokens; other build or content
  hashes in the query still do.
- ``is_third_party`` compares the last two host labels, without a public
  suffix list, so ``a.example.co.uk`` and ``b.other.co.uk`` look like the
  same site. It is a label, not a security boundary.
"""

from __future__ import annotations

import codecs
import ipaddress
import json
import re
import urllib.parse
from collections.abc import Sequence
from dataclasses import dataclass

from ..types import FindFlags, FindMatch, is_path_token_segment

_MIME_RE = re.compile(r"[a-z0-9!#$&^_.+-]{1,64}/[a-z0-9!#$&^_.+-]{1,64}")
_CHARSET_RE = re.compile(r"charset\s*=\s*[\"']?([A-Za-z0-9._:-]{1,40})", re.I)
_META_CHARSET_RE = re.compile(rb"<meta[^>]{0,200}?charset\s*=\s*[\"']?([A-Za-z0-9._:-]{1,40})", re.I)

_JS_MIMES = frozenset(
    {
        "application/javascript",
        "application/x-javascript",
        "application/ecmascript",
        "text/javascript",
        "text/ecmascript",
        "text/jscript",
        "application/x-ecmascript",
    }
)
_JSON_MIMES = frozenset({"application/json", "text/json", "application/x-ndjson", "application/jsonl"})
_XML_MIMES = frozenset({"application/xml", "text/xml", "application/xhtml+xml", "application/rss+xml", "application/atom+xml"})
_TEXT_APP_MIMES = frozenset({"application/x-www-form-urlencoded", "application/graphql", "application/csv"})

#: Query parameter names that carry signatures or session state whatever their value looks like.
SIGNATURE_PARAM_NAMES = frozenset(
    {
        "sig",
        "signature",
        "token",
        "access_token",
        "auth",
        "auth_token",
        "authtoken",
        "hmac",
        "jwt",
        "nonce",
        "csrf",
        "csrf_token",
        "_token",
        "session",
        "sessionid",
        "session_id",
        "sid",
        "x-amz-signature",
        "x-amz-security-token",
        "x-goog-signature",
        # round 2: CDN signed URLs (Akamai EdgeAuth, CloudFront), ColdFusion and other session ids
        "__token__",
        "hdnts",
        "policy",
        "key-pair-id",
        "cfid",
        "cftoken",
        "jsessionid",
        "phpsessid",
        "aspsessionid",
        "apikey",
        "api_key",
        "access_key",
        "secret",
    }
)
#: Words that make a parameter name session- or signature-like (matched per word of the name).
SESSION_NAME_WORDS = frozenset(
    {
        "token",
        "tokens",
        "sess",
        "session",
        "sessid",
        "sessionid",
        "sid",
        "sig",
        "sign",
        "signed",
        "signature",
        "auth",
        "authtoken",
        "csrf",
        "xsrf",
        "hmac",
        "jwt",
        "nonce",
        "apikey",
        "secret",
    }
)


def mime_of(content_type: str | None) -> str | None:
    """Lowercase ``type/subtype`` without parameters, or None when absent or malformed."""
    if not content_type:
        return None
    mime = content_type.split(";", 1)[0].strip().lower()
    return mime if _MIME_RE.fullmatch(mime) else None


def body_kind(mime: str | None, resource_type: str) -> str | None:
    """The search kind for a response, or None when the body is not text we read.

    Text kinds: ``html``, ``json``, ``js``, ``xml``, ``css``, ``text``. Without a
    Content-Type the resource type decides (documents are read as HTML,
    scripts as JavaScript, fetch/XHR as text after a binary sniff).
    """
    if mime is None:
        return {
            "document": "html",
            "script": "js",
            "stylesheet": "css",
            "xhr": "text",
            "fetch": "text",
            "eventsource": "text",
        }.get(resource_type)
    if mime in ("text/html",):
        return "html"
    if mime in _JSON_MIMES or mime.endswith("+json"):
        return "json"
    if mime in _JS_MIMES:
        return "js"
    if mime in _XML_MIMES or mime.endswith("+xml"):
        return "html" if mime == "application/xhtml+xml" else "xml"
    if mime == "text/css":
        return "css"
    if mime.startswith("text/") or mime in _TEXT_APP_MIMES:
        return "text"
    return None


_ENCODING_TOKEN_RE = re.compile(r"[a-z0-9._+-]{1,20}")
#: Most content codings kept from one Content-Encoding header.
_MAX_ENCODING_TOKENS = 4


def encoding_tokens(value: str | None) -> str:
    """A Content-Encoding header value as short coding tokens (``"gzip"``, ``"gzip, br"``), never raw text.

    Each comma-separated coding is lowercased and kept only when it looks like
    a coding token; anything else becomes ``other``, so a site cannot place
    its own text in find's output or report through this header. At most four
    codings are kept (``...`` marks more). ``""`` when the header is empty.
    """
    codings = [c.strip().lower() for c in str(value or "").split(",") if c.strip()]
    tokens = [c if _ENCODING_TOKEN_RE.fullmatch(c) else "other" for c in codings]
    if len(tokens) > _MAX_ENCODING_TOKENS:
        tokens = tokens[:_MAX_ENCODING_TOKENS] + ["..."]
    return ", ".join(tokens)


def looks_binary(data: bytes) -> bool:
    """A NUL byte in the first 1 KiB means binary (used when no Content-Type was sent)."""
    return b"\x00" in data[:1024]


#: Python codecs that are no web encoding: a browser ignores such a label, so find reads UTF-8.
#: UTF-7 is among them (the WHATWG Encoding Standard has no UTF-7): Python would decode
#: ``+ADw-script+AD4-`` into markup the browser never saw.
_NOT_WEB_CODECS = frozenset(
    {"punycode", "idna", "undefined", "unicode-escape", "raw-unicode-escape", "mbcs", "oem", "utf-7"}
)


def decode_body(data: bytes, content_type: str | None, kind: str | None) -> str:
    """Decode a body with the Content-Type charset, a BOM, an HTML meta charset, or UTF-8.

    The charset comes from the site, so it can name anything: a codec Python
    does not know, or one that cannot decode with ``errors="replace"``
    (``undefined``, ``idna``, ``punycode``). Those bodies, and bodies labelled
    with a Python codec that is no web encoding (``punycode`` would "decode"
    an ASCII page into nonsense), are read as UTF-8; this function never
    raises for a site-chosen charset.
    """
    charset = None
    if content_type:
        m = _CHARSET_RE.search(content_type)
        if m:
            charset = m.group(1)
    if charset is None and data.startswith(b"\xef\xbb\xbf"):
        charset = "utf-8-sig"
    if charset is None and kind == "html":
        m = _META_CHARSET_RE.search(data[:4096])
        if m:
            charset = m.group(1).decode("ascii", "replace")
    try:
        if charset is not None and codecs.lookup(charset).name in _NOT_WEB_CODECS:
            charset = None
        return data.decode(charset or "utf-8", errors="replace")
    except (LookupError, ValueError):
        # an unknown name, or a codec that refuses errors="replace" or the bytes themselves
        # (undefined, idna, punycode raise UnicodeError): read the body as UTF-8
        return data.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Tokens and sites
# ---------------------------------------------------------------------------

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
_UUID_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}(?![0-9A-Fa-f])")
_HEX_RE = re.compile(r"[0-9a-fA-F]{16,}")
_B64_RE = re.compile(r"[A-Za-z0-9_\-+/]{20,}={0,2}")
_ID_CHARS_RE = re.compile(r"[A-Za-z0-9_-]{20,}")
_ALNUM_RE = re.compile(r"[A-Za-z0-9]{16,}")


def _class_transitions(value: str) -> int:
    kinds = ["d" if c.isdigit() else "a" for c in value if c.isalnum()]
    return sum(1 for a, b in zip(kinds, kinds[1:]) if a != b)


def looks_random(value: str) -> bool:
    """True for values shaped like tokens.

    JWTs and UUIDs (any case, also inside a longer value), 16+ hex, 20+
    base64url with both cases, 20+ ``[A-Za-z0-9_-]`` in either case with at
    least two digits, two letters and five letter/digit alternations (so
    slugs such as ``summer-sale-2026-v2`` stay allowed), and 16+ mixed
    alphanumerics.
    """
    v = urllib.parse.unquote(value).strip()
    if not v:
        return False
    if _JWT_RE.fullmatch(v) or _UUID_RE.search(v):
        return True
    has_digit = any(c.isdigit() for c in v)
    has_alpha = any(c.isalpha() for c in v)
    has_upper = any(c.isupper() for c in v)
    has_lower = any(c.islower() for c in v)
    digits = sum(c.isdigit() for c in v)
    letters = sum(c.isalpha() for c in v)
    if _HEX_RE.fullmatch(v) and has_digit and has_alpha:
        return True
    if _B64_RE.fullmatch(v) and has_digit and has_upper and has_lower:
        return True
    if _ID_CHARS_RE.fullmatch(v) and digits >= 2 and letters >= 2 and _class_transitions(v) >= 5:
        return True
    if _ALNUM_RE.fullmatch(v) and has_digit and has_alpha:
        if digits >= 2 and letters >= 2 and (_class_transitions(v) >= 3 or (has_upper and has_lower)):
            return True
    return False


_NAME_WORD_RE = re.compile(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])")
_VALUE_PART_SPLIT_RE = re.compile(r"[~=:,.;|!]")
_EMBEDDED_HEX_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{16,}(?![0-9A-Fa-f])")


def is_session_like_name(name: str) -> bool:
    """True for a parameter name that suggests a session, signature or credential.

    Exact names from :data:`SIGNATURE_PARAM_NAMES`, names starting with a
    known session-cookie name (``aspsessionidqsctqtrq``), and names that
    contain a word from :data:`SESSION_NAME_WORDS` (``session_token``,
    ``sessionToken``, ``x-csrf``, ``__token__``), split at non-alphanumerics
    and camelCase boundaries so ``author`` or ``design`` are not flagged.
    """
    raw = urllib.parse.unquote(name).strip()
    low = raw.lower()
    if not low:
        return False
    if low in SIGNATURE_PARAM_NAMES or low.startswith(("aspsessionid", "jsessionid", "phpsessid")):
        return True
    words = {w.lower() for w in _NAME_WORD_RE.findall(raw)}
    return bool(words & SESSION_NAME_WORDS) or low.endswith(("token", "sessid", "sessionid"))


def value_has_embedded_token(value: str) -> bool:
    """True when a value looks random, holds a JWT, or has a random-looking part.

    Compound signed values such as Akamai's ``exp=...~acl=/*~hmac=<hex>`` are
    split on ``~ = : , . ; | !``; a 16+ hex run with letters and digits
    anywhere in the value also counts.
    """
    v = urllib.parse.unquote(value).strip()
    if not v:
        return False
    if looks_random(v) or _JWT_RE.search(v):
        return True
    for run in _EMBEDDED_HEX_RE.findall(v):
        if any(c.isdigit() for c in run) and any(c.isalpha() for c in run):
            return True
    return any(looks_random(part) for part in _VALUE_PART_SPLIT_RE.split(v) if part)


#: Query names that carry a JSONP callback name.
_JSONP_NAMES = frozenset({"callback", "jsonp", "jsoncallback", "jsonp_callback", "cb"})
#: jQuery's generated JSONP callback: "jQuery" + version and random digits + "_" + a timestamp.
_JQUERY_CALLBACK_RE = re.compile(r"jQuery[0-9]{6,32}_[0-9]{10,16}")
_SHA256_HEX_RE = re.compile(r"[0-9a-fA-F]{64}")


def _checked_query_value(name: str, value: str) -> str | None:
    """The part of a query value to check for tokens; None for a known content-addressed parameter.

    Two deterministic shapes are not session state: jQuery's JSONP callback
    name (``callback=jQuery1124098765_1690000000000``) and a GraphQL persisted
    query's ``extensions={"persistedQuery":{"version":1,"sha256Hash":"<64 hex>"}}``
    (the hash of the query text; the rest of the value is still checked).
    """
    low = name.strip().lower()
    if low in _JSONP_NAMES and _JQUERY_CALLBACK_RE.fullmatch(value.strip()):
        return None
    if low == "extensions" and "persistedQuery" in value:
        try:
            obj = json.loads(value)
        except ValueError:
            return value
        pq = obj.get("persistedQuery") if isinstance(obj, dict) else None
        digest = pq.get("sha256Hash") if isinstance(pq, dict) else None
        if isinstance(digest, str) and _SHA256_HEX_RE.fullmatch(digest):
            rest = dict(obj)
            rest["persistedQuery"] = {k: v for k, v in pq.items() if k != "sha256Hash"}
            return json.dumps(rest, separators=(",", ":"))
    return value


def has_random_query_token(url: str) -> bool:
    """True when any query value looks random (also inside a compound value) or sits under a session-like name.

    A GraphQL persisted-query hash and a jQuery JSONP callback name are
    content-addressed, not tokens (:func:`_checked_query_value`).
    """
    try:
        query = urllib.parse.urlsplit(url).query
    except ValueError:
        return False
    if not query:
        return False
    for name, value in urllib.parse.parse_qsl(query, keep_blank_values=True):
        if value and is_session_like_name(name):
            return True
        checked = _checked_query_value(name, value)
        if checked is not None and value_has_embedded_token(checked):
            return True
    return False


#: Request headers that browsers add themselves (never site session state).
_BROWSER_HEADER_NAMES = frozenset({"x-client-data"})
_BROWSER_HEADER_PREFIXES = ("x-browser-",)
_HEADER_WORD_SPLIT_RE = re.compile(r"[-_.]")


def is_token_header(name: str, value: str) -> bool:
    """True for a sent request header that looks like a credential or session token.

    Cookie and Authorization have their own flags. Other headers count when
    their name is session- or credential-like (``x-api-key``,
    ``x-csrf-token``, ``x-xsrf-token``, ``x-auth-token``, ``x-access-token``,
    ``x-session-id``, any name with the word ``key``, ``token``, ``session``...)
    or, for ``x-`` headers, when the value holds a random-looking token
    (:func:`value_has_embedded_token`). Headers browsers add themselves
    (``x-client-data``, ``x-browser-*``) are ignored. Only presence is
    recorded, never a name or value.
    """
    low = str(name).strip().lower()
    if not low or low in ("cookie", "authorization", "proxy-authorization") or low in _BROWSER_HEADER_NAMES:
        return False
    if low.startswith(_BROWSER_HEADER_PREFIXES):
        return False
    stem = low[2:] if low.startswith("x-") else low
    words = {w for w in _HEADER_WORD_SPLIT_RE.split(stem) if w}
    if "key" in words or is_session_like_name(stem) or is_session_like_name(stem.replace("-", "_")):
        return True
    return low.startswith("x-") and value_has_embedded_token(str(value))


def looks_random_path_segment(segment: str) -> bool:
    """True for a path segment that reports would show as ``{token}`` (``types.is_path_token_segment``).

    A JWT, a segment containing a UUID, or a stem (extension ignored) of 24+
    hex characters, or of 32+ base64url characters with both cases, digits
    and at least four letter/digit alternations that do not read as
    separated words. One heuristic for find's flags and the reports' path
    cleaning (sec2-12). Narrower than :func:`looks_random`: slugs, SKUs and
    short content hashes in file names stay allowed.
    """
    return is_path_token_segment(segment.strip())


def has_session_path_parameter(segment: str) -> bool:
    """True for a ``;name=value`` path parameter with a session-like name or a random-looking value.

    Java's URL rewriting puts the session id there (``stock.json;jsessionid=...``).
    """
    for param in segment.split(";")[1:]:
        name, sep, value = param.partition("=")
        if not sep or not value.strip():
            continue
        if is_session_like_name(name) or value_has_embedded_token(value):
            return True
    return False


def has_random_path_token(url: str) -> bool:
    """True when a URL path segment looks like a session or request token.

    JWTs, UUIDs and 24+ hex segments (:func:`looks_random_path_segment`), and
    ``;name=value`` path parameters with a session-like name or random value.
    """
    try:
        path = urllib.parse.urlsplit(url).path
    except ValueError:
        return False
    for seg in path.split("/"):
        if not seg:
            continue
        stem = seg.split(";", 1)[0]
        if has_session_path_parameter(seg) or looks_random_path_segment(stem) or looks_random_path_segment(seg):
            return True
    return False


def has_random_token(url: str) -> bool:
    """:func:`has_random_query_token` or :func:`has_random_path_token`."""
    return has_random_query_token(url) or has_random_path_token(url)


def site_key(host: str) -> str:
    """The last two labels of a hostname (the whole host for IP literals)."""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    labels = [label for label in host.split(".") if label]
    return ".".join(labels[-2:])


def is_third_party(host: str, target_host: str) -> bool:
    """Heuristic: the last two host labels differ from the target's."""
    return site_key(host) != site_key(target_host)


# ---------------------------------------------------------------------------
# Code eligibility
# ---------------------------------------------------------------------------

#: Why a match that carried session state (cookies, Authorization, a token header, a random-looking
#: token) gets no starter code.
NOT_EMITTED_TEXT = (
    "not emitted: this response depends on session or anti-bot state; use the page or the "
    "site's official API, and check its terms"
)
#: Reason for a match whose request carried a credential- or token-like header (:func:`is_token_header`).
TOKEN_HEADER_REASON = "sent a token header"
#: Ineligibility reasons a cookie-less --verify replay can test: the state was sent in headers the
#: replay leaves out, not in the URL it repeats.
REPLAY_CANDIDATE_REASONS = frozenset({"sent cookies", TOKEN_HEADER_REASON})
#: Ineligibility reasons that are session state the request carried (:data:`NOT_EMITTED_TEXT`).
SESSION_STATE_REASONS = frozenset(
    {
        "sent cookies",
        "sent authorization",
        TOKEN_HEADER_REASON,
        "random-looking query token",
        "random-looking token in the path",
    }
)
_STATUS_REASON_RE = re.compile(r"status ([0-9]{1,3})")


def not_emitted_text(reason: str | None) -> str:
    """Why a match with this ineligibility reason (:func:`code_eligibility`) gets no starter code.

    Only session state (cookies, Authorization, a token header, a
    random-looking token) is called "session or anti-bot state"
    (:data:`NOT_EMITTED_TEXT`). A request that is not a GET, a non-2xx or
    unknown status and a service worker's answer each say what they are: a
    cookie-less, token-free POST is often the site's own API. An unknown
    reason (from a report) reads ``not emitted``.
    """
    if reason in SESSION_STATE_REASONS:
        return NOT_EMITTED_TEXT
    if reason == "not a GET":
        return "not emitted: starter code covers GET only; the request body and headers are not reproduced"
    if reason == "status unknown":
        return "not emitted: the response status is unknown"
    m = _STATUS_REASON_RE.fullmatch(reason or "")
    if m is not None:
        return f"not emitted: the response had status {m.group(1)}"
    if reason == "served by a service worker":
        return "not emitted: the page's service worker answered; the network response may differ"
    return "not emitted"


@dataclass(frozen=True)
class Eligibility:
    eligible: bool
    reason: str | None


def code_eligibility(
    *,
    method: str,
    status: int | None,
    flags: FindFlags,
    served_by_service_worker: bool = False,
    token_in_path: bool = False,
    sent_token_header: bool = False,
) -> Eligibility:
    """Starter code only for a GET with 2xx that sent no cookies, no Authorization and no token.

    Reasons, first failing rule wins: ``sent cookies``, ``sent authorization``,
    ``sent a token header`` (a credential- or token-like request header,
    :func:`is_token_header`), ``random-looking query token``
    (``random-looking token in the path`` when ``token_in_path`` says the
    token sits in a path segment), ``not a GET``, ``status <n>`` (or ``status
    unknown``), ``served by a service worker`` (the page's request never
    reached the network, so a replay would fetch something else).
    ``flags.sent_token_header`` counts as ``sent_token_header``.
    :func:`not_emitted_text` gives each reason's explanation.
    """
    if flags.sent_cookies:
        return Eligibility(False, "sent cookies")
    if flags.sent_authorization:
        return Eligibility(False, "sent authorization")
    if sent_token_header or flags.sent_token_header:
        return Eligibility(False, TOKEN_HEADER_REASON)
    if flags.random_query_token:
        return Eligibility(False, "random-looking token in the path" if token_in_path else "random-looking query token")
    if method != "GET":
        return Eligibility(False, "not a GET")
    if status is None:
        return Eligibility(False, "status unknown")
    if not 200 <= status <= 299:
        return Eligibility(False, f"status {status}")
    if served_by_service_worker:
        return Eligibility(False, "served by a service worker")
    return Eligibility(True, None)


def replay_candidate(match: FindMatch) -> bool:
    """True for a match that is ineligible only because of cookies or a token header it sent.

    Its URL holds no token and it is a 2xx network GET, so ``--verify`` can
    test it with one cookie-less request that replays nothing captured: the
    cookies and headers are simply not sent. Starter code follows only when
    that replay returns every value.
    """
    if match.code_eligible or match.code_ineligible_reason not in REPLAY_CANDIDATE_REASONS:
        return False
    f = match.flags
    if f.sent_authorization or f.random_query_token or f.non_get or match.method != "GET":
        return False
    if match.status is None or not 200 <= match.status <= 299:
        return False
    return "served-by-service-worker" not in match.locations


#: A replay candidate is replayed instead of an eligible match holding the same values only when
#: that eligible match is more than this many times its size (body and headers, TLS left out).
CANDIDATE_SIZE_ADVANTAGE = 2


def _body_and_headers(match: FindMatch) -> int:
    return max(0, match.billed_basis_bytes - match.tls_handshake_estimate)


def select_verify_target(matches: Sequence[FindMatch]) -> FindMatch | None:
    """The match ``--verify`` replays (its one request), or None.

    The top match (rank order) that is code-eligible or a
    :func:`replay_candidate`. A candidate gives way to the top eligible match
    holding the same values when that one is at most
    :data:`CANDIDATE_SIZE_ADVANTAGE` times its size: the eligible response
    then answers the question with little to gain from testing the smaller
    one without the browser's state. A much larger eligible response (often
    the page's own HTML) leaves the replay to the candidate. The choice is the
    same before and after the replay (a candidate that replayed becomes
    eligible and stays first), so renderers can recompute it.
    """
    ordered = sorted(matches, key=lambda m: m.rank)
    first = next((m for m in ordered if m.code_eligible or replay_candidate(m)), None)
    if first is None or first.code_eligible:
        return first
    alternative = next(
        (
            m
            for m in ordered
            if m.code_eligible and m.all_values == first.all_values and m.values_matched == first.values_matched
        ),
        None,
    )
    if alternative is not None and _body_and_headers(alternative) <= CANDIDATE_SIZE_ADVANTAGE * _body_and_headers(first):
        return alternative
    return first


__all__ = [
    "CANDIDATE_SIZE_ADVANTAGE",
    "Eligibility",
    "NOT_EMITTED_TEXT",
    "REPLAY_CANDIDATE_REASONS",
    "SESSION_STATE_REASONS",
    "TOKEN_HEADER_REASON",
    "SESSION_NAME_WORDS",
    "SIGNATURE_PARAM_NAMES",
    "body_kind",
    "code_eligibility",
    "decode_body",
    "encoding_tokens",
    "has_random_path_token",
    "has_random_query_token",
    "has_random_token",
    "has_session_path_parameter",
    "is_session_like_name",
    "is_third_party",
    "is_token_header",
    "looks_binary",
    "looks_random",
    "looks_random_path_segment",
    "mime_of",
    "not_emitted_text",
    "replay_candidate",
    "select_verify_target",
    "site_key",
    "value_has_embedded_token",
]
