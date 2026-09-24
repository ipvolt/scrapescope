"""Shared data model for scrapescope (the only types modules exchange).

Every structure that crosses a module boundary lives here, so the forwarder,
attribution, find, model/report and helpers can be written in parallel against
one definition. docs/dev/contracts.md is the prose contract; this file is the
executable one.

Conventions
-----------
- Timestamps are wall-clock ``time.time()`` floats (seconds since the epoch),
  because helper events are written by another process and must be comparable
  with forwarder timestamps. Reports render them as RFC 3339 UTC strings.
- Byte counts are ``int``. Nothing here is billing-grade: forwarder totals are
  *tunnel-measured* (bytes on the upstream socket, which is as close as a local
  meter can get, but a provider may count differently); per-request and
  per-type figures are *allocated*; costs are *estimated billable transfer*.
- ``to_dict()`` returns JSON-compatible data (tuples become lists; fields marked
  ``terminal_only`` are omitted). ``from_dict()`` rebuilds the dataclass,
  ignoring unknown keys and raising ``ValueError`` on wrong types or missing
  required fields. Neither performs report redaction: that is the report
  builder's job (scrapescope.report).
- Helper events (the JSONL events file) are untrusted input: parse them only
  with :func:`parse_event`, which validates types, charsets and lengths.

Nothing in this module performs I/O or imports optional dependencies.
"""

from __future__ import annotations

import dataclasses
import fnmatch
import ipaddress
import math
import re
import socket as _socket
import types as _pytypes
import typing
import unicodedata
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Literal, Union

# ---------------------------------------------------------------------------
# Versions and small shared constants
# ---------------------------------------------------------------------------

#: Version of the helper -> meter events file protocol (field ``v``).
EVENTS_VERSION = 1
#: ``schema_version`` of report.json.
REPORT_SCHEMA_VERSION = 1

GbUnit = Literal["GB", "GiB"]
Mode = Literal["direct", "http-connect", "socks5"]
TunnelKind = Literal["connect", "http"]
Route = Literal["http-connect", "socks5", "direct", "non-target", "refused"]
AuthUse = Literal["none", "injected", "passthrough", "token-mapped"]
Listener = Literal["main", "auth"]
EventSource = Literal["playwright", "requests", "httpx"]
FrameKind = Literal["main", "sub", "worker", "service_worker", "other"]
BrowserName = Literal["chromium", "firefox", "webkit", "other"]
BudgetEventKind = Literal["warn_80", "tripped", "tunnel_cap"]
UnitsSource = Literal["navigations", "requests", "override", "none"]
SuccessBasis = Literal["navigations", "requests"]
Replays = Literal["yes", "no", "not_tested"]
FindStatus = Literal["found", "not_found", "blocked", "error"]
SignalType = Literal["header", "cookie", "status", "body"]
SignalStrength = Literal["challenge", "vendor"]
FixLanguage = Literal["python", "shell", "json", "text"]
ReportCommand = Literal["run", "serve", "find"]

#: Bucket names for tunnel bytes (background buckets are "background:<catalog id>").
BUCKET_ATTRIBUTED = "attributed"
BUCKET_PRECONNECT_IDLE = "preconnect_idle"
BUCKET_BEFORE_ATTACH = "before_attach"
BUCKET_UNATTRIBUTED = "unattributed"
BUCKET_BACKGROUND_PREFIX = "background:"

#: Tunnel status values (failed ones are "failed:<reason>", see contracts.md).
TUNNEL_OPEN = "open"
TUNNEL_OK = "ok"
TUNNEL_DENIED = "denied"
TUNNEL_BUDGET = "budget"
TUNNEL_CAP = "tunnel_cap"
TUNNEL_FAILED_PREFIX = "failed:"

#: Routes that reach a billed target through the upstream (or direct in sizing mode).
TARGET_ROUTES: frozenset[str] = frozenset({"http-connect", "socks5", "direct"})

#: Coverage skip reasons understood by :meth:`Coverage.summary`.
COVERAGE_SKIP_LABELS: dict[str, str] = {
    "over_cap": "over the size cap",
    "evicted": "evicted before it could be read",
    "no_session": "in a frame or worker without a session",
    "websocket": "WebSocket",
    "binary": "binary",
    "failed": "failed",
    "no_body": "no body (redirect, 204 or 304)",
    "challenge": "challenge page (not searched; see warnings)",
    "other": "other",
}

# ---------------------------------------------------------------------------
# Sanitisers for untrusted strings (hosts, paths, free text) and host globs
# ---------------------------------------------------------------------------

_HOST_RE = re.compile(r"[a-z0-9_.:-]{1,253}")
_HOST_GLOB_RE = re.compile(r"[a-z0-9_.:*-]{1,253}")
_CATALOG_ID_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
_METHOD_RE = re.compile(r"[A-Z]{1,16}")
_RESOURCE_TYPE_RE = re.compile(r"[a-z_]{1,32}")
_SCHEME_RE = re.compile(r"[a-z][a-z0-9+.-]{0,31}")
_CONTEXT_RE = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
#: Characters that must never reach a terminal or HTML page raw. For ASCII text
#: these patterns are the whole check; non-ASCII text is checked by Unicode
#: category as well (see :data:`UNSAFE_CATEGORIES`).
_UNSAFE_TEXT_RE = re.compile("[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069\ufeff]")
_UNSAFE_CODE_RE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069\ufeff]")
#: Unicode categories escaped by :func:`safe_text` and :func:`safe_code`: controls
#: (Cc), format characters (Cf: bidi marks, overrides and isolates, zero-width
#: characters, the BOM, U+061C), line and paragraph separators (Zl, Zp) and
#: lone surrogates (Cs, which cannot even be encoded for a terminal).
UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp", "Cs"})


def _escape_char(cp: int) -> str:
    if cp <= 0xFF:
        return f"\\x{cp:02x}"
    if cp <= 0xFFFF:
        return f"\\u{cp:04x}"
    return f"\\U{cp:08x}"


def _escape_unsafe(text: str, ascii_re: re.Pattern[str], keep: str) -> str:
    if text.isascii():
        return ascii_re.sub(lambda m: _escape_char(ord(m.group(0))), text)
    out: list[str] = []
    for ch in text:
        if ch not in keep and unicodedata.category(ch) in UNSAFE_CATEGORIES:
            out.append(_escape_char(ord(ch)))
        else:
            out.append(ch)
    return "".join(out)


MAX_HOST_LEN = 253
MAX_PATH_LEN = 512
MAX_TEXT_LEN = 500
MAX_JS_SAFE_INT = 2**53 - 1


def clean_host(value: object) -> str | None:
    """Return a normalised hostname or IP literal, or ``None`` if unusable.

    Lowercases, strips one pair of IPv6 brackets and a trailing dot, converts
    non-ASCII names with IDNA, and enforces ``[a-z0-9_.:-]{1,253}``. The result
    is safe to print and to put in reports. IPv6 literals are returned without
    brackets (``::1``); zone ids (``%eth0``) are rejected.
    """
    if not isinstance(value, str):
        return None
    host = value.strip().lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    host = host.rstrip(".")
    if not host:
        return None
    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii").lower()
        except UnicodeError:
            return None
    if len(host) > MAX_HOST_LEN or not _HOST_RE.fullmatch(host):
        return None
    return host


#: Replaces path segments (or the part of one) that look like session or request tokens.
PATH_TOKEN_PLACEHOLDER = "{token}"

_PATH_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
_PATH_UUID_RE = re.compile(
    r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}(?![0-9A-Fa-f])"
)
_PATH_HEX_RE = re.compile(r"[0-9A-Fa-f]{24,}")
_PATH_B64_RE = re.compile(r"[A-Za-z0-9+_-]{32,}={0,2}")
_PATH_EXT_RE = re.compile(r"\.[A-Za-z0-9]{1,8}$")


def _digit_letter_transitions(value: str) -> int:
    kinds = ["d" if c.isdigit() else "a" for c in value if c.isascii() and c.isalnum()]
    return sum(1 for a, b in zip(kinds, kinds[1:]) if a != b)


def _word_like(stem: str) -> bool:
    """Three or more ``_``/``-``-separated words (titles such as ``Galaxy_S24_Ultra_512GB``), not a token."""
    parts = [p for p in re.split(r"[_-]+", stem) if p]
    return len(parts) >= 3 and all(p.isalpha() or p.isdigit() or len(p) <= 5 for p in parts)


def _clean_segment(segment: str) -> str:
    """One path segment without ``;`` parameters and with token-like parts replaced.

    Tokens: a JWT, any UUID inside the segment, a stem (file extension kept)
    of 24+ hex characters with digits and letters, or of 32+ base64url
    characters with upper case, lower case, digits and at least four
    letter/digit alternations that do not read as separated words. The same
    shapes ``find`` treats as path tokens, plus long base64; shorter or
    word-like tokens are not recognised.
    """
    segment = segment.split(";", 1)[0]
    if not segment:
        return segment
    decoded = urllib.parse.unquote(segment)
    if _PATH_JWT_RE.fullmatch(decoded):
        return PATH_TOKEN_PLACEHOLDER
    if _PATH_UUID_RE.search(segment):
        return _PATH_UUID_RE.sub(PATH_TOKEN_PLACEHOLDER, segment)
    ext = _PATH_EXT_RE.search(decoded)
    stem = decoded[: ext.start()] if ext else decoded
    suffix = ext.group(0) if ext else ""
    has_digit = any(c.isdigit() for c in stem)
    if _PATH_HEX_RE.fullmatch(stem) and has_digit and any(c.isalpha() for c in stem):
        return PATH_TOKEN_PLACEHOLDER + suffix
    if (
        _PATH_B64_RE.fullmatch(stem)
        and has_digit
        and any(c.isupper() for c in stem)
        and any(c.islower() for c in stem)
        and _digit_letter_transitions(stem) >= 4
        and not _word_like(stem)
    ):
        return PATH_TOKEN_PLACEHOLDER + suffix
    return segment


def is_path_token_segment(segment: str) -> bool:
    """True when :func:`clean_path` would replace this path segment, or part of it, with ``{token}``.

    The one path-token heuristic: ``find`` uses it to flag token-bearing URLs
    (``find.heuristics.looks_random_path_segment``), and reports use it to hide
    them. ``;`` path parameters are ignored here (``clean_path`` drops them).
    """
    base = segment.split(";", 1)[0] if isinstance(segment, str) else ""
    return bool(base) and _clean_segment(base) != base


def clean_path(value: object) -> str | None:
    """Return a URL path without query or fragment, safe for reports, or ``None``.

    Drops everything from the first ``?`` or ``#`` and every ``;`` path
    parameter (``;jsessionid=...``); replaces segments that look like session
    or request tokens (JWTs, UUIDs, long hex or base64; see
    :func:`_clean_segment`) with ``{token}``; percent-encodes any character
    outside printable ASCII (UTF-8); caps the length at ``MAX_PATH_LEN``
    (truncated paths end in ``...``). The result always starts with ``/``.
    Query strings never survive this function; token detection is a
    heuristic, so a kept path can still carry an identifier it does not
    recognise.
    """
    if not isinstance(value, str) or not value:
        return None
    path = value.split("#", 1)[0].split("?", 1)[0]
    if not path.startswith("/"):
        return None
    path = "/".join(_clean_segment(segment) for segment in path.split("/"))
    out: list[str] = []
    for ch in path:
        if 0x21 <= ord(ch) <= 0x7E:
            out.append(ch)
        else:
            out.append(urllib.parse.quote(ch, safe=""))
    cleaned = "".join(out)
    if len(cleaned) > MAX_PATH_LEN:
        cleaned = cleaned[: MAX_PATH_LEN - 3] + "..."
    return cleaned


def safe_text(value: object, max_len: int = MAX_TEXT_LEN) -> str:
    """Render any value as one line of text safe for terminals, HTML and JSON.

    Every character in the Unicode categories Cc, Cf, Zl, Zp and Cs (controls,
    C1 controls, bidi marks, overrides and isolates, zero-width characters,
    BOMs, line/paragraph separators, lone surrogates) is replaced with a
    visible ``\\xNN``/``\\uNNNN``/``\\UNNNNNNNN`` escape, so ANSI escape
    sequences, right-to-left tricks and invisible characters cannot act; the
    result is capped at ``max_len`` characters (ending in ``...`` when cut).
    HTML escaping is still the HTML renderer's job; this only removes
    characters that are unsafe everywhere.
    """
    text = value if isinstance(value, str) else str(value)
    text = _escape_unsafe(text, _UNSAFE_TEXT_RE, "")
    if len(text) > max_len:
        text = text[: max(0, max_len - 3)] + "..."
    return text


def safe_code(value: str, max_len: int = 8000) -> str:
    """Like :func:`safe_text` but keeps newlines and tabs (for generated fix snippets)."""
    text = _escape_unsafe(value, _UNSAFE_CODE_RE, "\t\n")
    if len(text) > max_len:
        text = text[: max(0, max_len - 3)] + "..."
    return text


def validate_host_glob(pattern: str) -> str:
    """Normalise and validate a host glob such as ``*.example.com``.

    Allowed characters: ``[a-z0-9_.:*-]`` (lowercased). ``*`` is the only
    wildcard and matches zero or more characters, dots included. Raises
    ``ValueError`` for anything else (``?`` and ``[...]`` classes are not
    supported, so user globs cannot smuggle regex-like syntax).
    """
    if not isinstance(pattern, str):
        raise ValueError("host glob must be a string")
    glob = pattern.strip().lower().rstrip(".")
    if not glob or not _HOST_GLOB_RE.fullmatch(glob):
        raise ValueError("host glob may contain only letters, digits, '.', '-', '_', ':' and '*'")
    if "*" not in glob and (glob[0].isdigit() or ":" in glob):
        # An IP literal glob matches the address in any spelling (sec3-5): the
        # forwarder compares canonical hosts (see canonical_host).
        glob = canonical_host(glob)
    return glob


_LEGACY_IPV4_CHARS = frozenset("0123456789abcdefx.")


def ip_literal(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """The address an IP literal names, or None for a hostname.

    Besides the canonical forms this accepts the legacy IPv4 spellings that
    ``getaddrinfo`` (``inet_aton``) also accepts, such as ``127.1``,
    ``0x7f.0.0.1``, ``2130706433`` and ``127.000.000.001``, so a check on the
    literal sees the address the operating system would really connect to.
    IPv4-mapped IPv6 addresses (``::ffff:127.0.0.1``) are returned as IPv4.
    One pair of IPv6 brackets is accepted.
    """
    text = host.strip().lower()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(text)
    except ValueError:
        if not text or not set(text) <= _LEGACY_IPV4_CHARS or not text[0].isdigit():
            return None
        try:
            packed = _socket.inet_aton(text)
        except (OSError, ValueError):
            return None
        return ipaddress.IPv4Address(packed)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def canonical_host(host: str) -> str:
    """``host`` with an IP literal in its one canonical spelling; hostnames are returned unchanged.

    ``1.2.3.04``, ``0x01020304``, ``16909060``, ``1.2.772`` and
    ``::ffff:1.2.3.4`` all become ``1.2.3.4``; ``2001:DB8:0::1`` becomes
    ``2001:db8::1``. Deny rules, routing rules and records use this form, so a
    rule on an address cannot be bypassed by spelling it differently.
    """
    ip = ip_literal(host)
    return host if ip is None else str(ip)


#: IPv6 forms that carry an IPv4 address in their low 32 bits (round 4, sec4-1): the NAT64
#: well-known prefix (RFC 6052), IPv4-compatible (``::a.b.c.d``, deprecated) and IPv4-translated
#: (``::ffff:0:a.b.c.d``, RFC 2765) addresses. IPv4-mapped ``::ffff:a.b.c.d`` is unwrapped by
#: ``ipaddress`` itself (``ipv4_mapped``).
_IPV4_EMBEDDING_NETS = (
    ipaddress.IPv6Network("64:ff9b::/96"),
    ipaddress.IPv6Network("::ffff:0:0:0/96"),
    ipaddress.IPv6Network("::/96"),
)


def embedded_ipv4(ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None) -> ipaddress.IPv4Address | None:
    """The IPv4 address an IPv6 address stands for, or None.

    IPv4-mapped (``::ffff:a.b.c.d``), NAT64 well-known prefix
    (``64:ff9b::a.b.c.d``), IPv4-translated (``::ffff:0:a.b.c.d``) and
    IPv4-compatible (``::a.b.c.d``; ``::`` and ``::1`` excluded, they are the
    IPv6 unspecified and loopback addresses) forms. On a NAT64 network a
    connection to ``64:ff9b::a00:5`` reaches ``10.0.0.5`` through the
    gateway, so address checks must look at the IPv4 address too.
    Network-specific NAT64 prefixes (RFC 6052 section 2.2) cannot be
    recognised from the address alone.
    """
    if not isinstance(ip, ipaddress.IPv6Address):
        return None
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    value = int(ip)
    for net in _IPV4_EMBEDDING_NETS:
        if ip in net:
            if net.network_address == ipaddress.IPv6Address("::") and value <= 1:
                return None
            return ipaddress.IPv4Address(value & 0xFFFFFFFF)
    return None


def host_glob_match(pattern: str, host: str) -> bool:
    """True when ``host`` matches the host glob ``pattern`` (case-insensitive).

    ``*`` matches zero or more characters including dots, so ``*.example.com``
    matches ``a.b.example.com`` but not ``example.com`` itself (list both when
    both are wanted). A pattern without ``*`` matches only that exact host.
    Invalid patterns never match.
    """
    try:
        glob = validate_host_glob(pattern)
    except ValueError:
        return False
    h = clean_host(host)
    if h is None:
        return False
    return fnmatch.fnmatchcase(h, glob)


def is_catalog_id(value: object) -> bool:
    """True for catalog ids: ``[a-z0-9][a-z0-9_-]{0,63}``."""
    return isinstance(value, str) and bool(_CATALOG_ID_RE.fullmatch(value))


# ---------------------------------------------------------------------------
# Generic (de)serialisation
# ---------------------------------------------------------------------------

_HINTS: dict[type, dict[str, Any]] = {}


def _hints(cls: type) -> dict[str, Any]:
    hints = _HINTS.get(cls)
    if hints is None:
        hints = typing.get_type_hints(cls)
        _HINTS[cls] = hints
    return hints


def _jsonable(value: Any) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            f.name: _jsonable(getattr(value, f.name))
            for f in dataclasses.fields(value)
            if not f.metadata.get("terminal_only")
        }
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non-finite float cannot be serialised")
    return value


def _convert(tp: Any, value: Any, where: str) -> Any:
    if tp is Any:
        return value
    origin = typing.get_origin(tp)
    args = typing.get_args(tp)
    if origin is Union or origin is _pytypes.UnionType:
        if value is None:
            if type(None) in args:
                return None
            raise ValueError(f"{where}: null is not allowed")
        last: ValueError | None = None
        for arg in args:
            if arg is type(None):
                continue
            try:
                return _convert(arg, value, where)
            except ValueError as exc:  # try the next member
                last = exc
        raise last or ValueError(f"{where}: no type matched")
    if origin is Literal:
        for allowed in args:
            if type(value) is type(allowed) and value == allowed:
                return value
        raise ValueError(f"{where}: {value!r} is not one of {list(args)!r}")
    if origin in (list, tuple):
        if not isinstance(value, (list, tuple)):
            raise ValueError(f"{where}: expected a list")
        if origin is tuple:
            item_tp = args[0] if args else Any
            return tuple(_convert(item_tp, v, f"{where}[{i}]") for i, v in enumerate(value))
        item_tp = args[0] if args else Any
        return [_convert(item_tp, v, f"{where}[{i}]") for i, v in enumerate(value)]
    if origin is dict:
        if not isinstance(value, dict):
            raise ValueError(f"{where}: expected an object")
        key_tp, val_tp = args if args else (str, Any)
        out = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise ValueError(f"{where}: object keys must be strings")
            out[_convert(key_tp, k, where)] = _convert(val_tp, v, f"{where}.{k}")
        return out
    if isinstance(tp, type) and dataclasses.is_dataclass(tp):
        if isinstance(value, tp):
            return value
        if not isinstance(value, dict):
            raise ValueError(f"{where}: expected an object")
        return tp.from_dict(value)  # type: ignore[attr-defined]
    if tp is bool:
        if isinstance(value, bool):
            return value
        raise ValueError(f"{where}: expected a boolean")
    if tp is int:
        if isinstance(value, int) and not isinstance(value, bool):
            return value
        raise ValueError(f"{where}: expected an integer")
    if tp is float:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            f = float(value)
            if not math.isfinite(f):
                raise ValueError(f"{where}: expected a finite number")
            return f
        raise ValueError(f"{where}: expected a number")
    if tp is str:
        if isinstance(value, str):
            return value
        raise ValueError(f"{where}: expected a string")
    raise ValueError(f"{where}: unsupported type {tp!r}")


class Serializable:
    """Mixin giving dataclasses ``to_dict()`` and ``from_dict()``."""

    def to_dict(self) -> dict[str, Any]:
        """JSON-compatible dict; omits fields marked ``terminal_only``."""
        return _jsonable(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]):  # noqa: ANN206 - returns cls
        """Rebuild from :meth:`to_dict` output. Unknown keys are ignored."""
        if not isinstance(data, dict):
            raise ValueError(f"{cls.__name__}: expected an object")
        hints = _hints(cls)
        kwargs: dict[str, Any] = {}
        for f in dataclasses.fields(cls):  # type: ignore[arg-type]
            if not f.init:
                continue
            if f.name in data:
                kwargs[f.name] = _convert(hints[f.name], data[f.name], f"{cls.__name__}.{f.name}")
            elif f.default is dataclasses.MISSING and f.default_factory is dataclasses.MISSING:
                raise ValueError(f"{cls.__name__}: missing required field {f.name!r}")
        return cls(**kwargs)


def terminal_only(default: Any = dataclasses.MISSING, *, default_factory: Any = dataclasses.MISSING) -> Any:
    """Field that ``to_dict()`` never serialises (never reaches report.json)."""
    if default_factory is not dataclasses.MISSING:
        return field(default_factory=default_factory, repr=False, metadata={"terminal_only": True})
    return field(default=default, repr=False, metadata={"terminal_only": True})


# ---------------------------------------------------------------------------
# Forwarder: tunnels, budget events, snapshots
# ---------------------------------------------------------------------------


@dataclass
class TunnelRecord(Serializable):
    """One client connection's upstream connection (one tunnel).

    A tunnel is one (client connection, upstream connection) pair with a single
    target authority. A keep-alive plain-HTTP client connection that switches
    authority starts a new TunnelRecord. On the SOCKS5, direct and non-target
    routes the upstream connection belongs to the old authority, so the meter
    closes it and opens a new one. On the HTTP CONNECT route the upstream
    connection goes to the provider, which serves every authority, so the meter
    keeps it, as the client did (round 3, meas3-3): the new record continues
    the same upstream connection, counts from the request boundary on, and
    names the previous record in ``continued_from``. Count upstream
    connections with :attr:`opened_connection`, not with the number of records.

    Accuracy: ``upstream_bytes_*`` are counted on the meter's side of the
    upstream socket (every byte written to / read from it, including the
    CONNECT or SOCKS negotiation). That is "tunnel-measured": complete for
    this hop, but a provider may meter at a different point.
    """

    id: int
    host: str
    port: int
    kind: TunnelKind
    route: Route
    opened_at: float
    closed_at: float | None = None
    #: "open" | "ok" | "failed:<reason>" | "denied" | "budget" | "tunnel_cap"
    status: str = TUNNEL_OPEN
    #: Every byte written to the upstream socket (negotiation included).
    upstream_bytes_sent: int = 0
    #: Every byte read from the upstream socket (negotiation included).
    upstream_bytes_received: int = 0
    #: CONNECT request / SOCKS greeting+auth+connect bytes written (part of upstream_bytes_sent).
    negotiation_bytes_sent: int = 0
    #: CONNECT response head / SOCKS replies read (part of upstream_bytes_received).
    negotiation_bytes_received: int = 0
    #: Direct mode only: CONNECT the meter would have sent (NOT in upstream_bytes_sent).
    synthetic_negotiation_bytes_sent: int = 0
    #: Direct mode only: typical 200 line the meter would have read (NOT in upstream_bytes_received).
    synthetic_negotiation_bytes_received: int = 0
    #: Size of the CONNECT request head sent upstream, Proxy-Authorization included.
    connect_request_bytes: int = 0
    #: Size of the ``Proxy-Authorization: ...\r\n`` line sent upstream (0 if none).
    proxy_authorization_bytes: int = 0
    #: HTTP upstream: CONNECT reply status (kind=connect) or last relayed response status (kind=http).
    upstream_status: int | None = None
    #: SOCKS5 upstream: REP field of the CONNECT reply (0 = succeeded), or None.
    socks_reply: int | None = None
    #: Bytes read from / written to the client socket (diagnostics only; not billed).
    client_bytes_received: int = 0
    client_bytes_sent: int = 0
    #: Plain-HTTP requests forwarded on this tunnel (kind=http); 0 for CONNECT tunnels.
    requests: int = 0
    #: How upstream credentials were chosen for this tunnel.
    auth: AuthUse = "none"
    #: Label of the deny rule (status "denied") or direct.json entry (route "non-target").
    rule: str | None = None
    #: Which loopback listener accepted the client connection.
    listener: Listener = "main"
    #: Plain HTTP over an HTTP CONNECT upstream: id of the previous record on the
    #: same upstream connection when a keep-alive client switched authority
    #: (no new connection was opened); None when this record opened its own.
    continued_from: int | None = None

    @property
    def opened_connection(self) -> bool:
        """True when this record opened an upstream connection of its own.

        False for deny-rule records (no connection) and for records that
        continue an earlier record's connection (``continued_from``).
        """
        return self.continued_from is None and self.route != "refused"

    @property
    def is_target(self) -> bool:
        """True when this tunnel went (or tried to go) to a billed target."""
        return self.route in TARGET_ROUTES

    @property
    def failed(self) -> bool:
        return self.status.startswith(TUNNEL_FAILED_PREFIX)

    @property
    def denied(self) -> bool:
        return self.status == TUNNEL_DENIED

    @property
    def negotiation_estimated(self) -> bool:
        """True when the "with CONNECT" figure uses synthesised negotiation bytes."""
        return (self.synthetic_negotiation_bytes_sent + self.synthetic_negotiation_bytes_received) > 0

    @property
    def counted_bytes(self) -> int:
        """Bytes this tunnel contributes to the budget: all upstream socket bytes."""
        return self.upstream_bytes_sent + self.upstream_bytes_received

    @property
    def bytes_with_connect(self) -> int:
        """Upstream socket bytes, plus synthesised CONNECT bytes in direct mode."""
        return (
            self.upstream_bytes_sent
            + self.upstream_bytes_received
            + self.synthetic_negotiation_bytes_sent
            + self.synthetic_negotiation_bytes_received
        )

    @property
    def bytes_without_connect(self) -> int:
        """Upstream socket bytes minus the CONNECT/SOCKS negotiation."""
        return max(
            0,
            self.upstream_bytes_sent
            + self.upstream_bytes_received
            - self.negotiation_bytes_sent
            - self.negotiation_bytes_received,
        )

    @property
    def payload_bytes_sent(self) -> int:
        """Bytes sent upstream after negotiation (used for the preconnect/idle test)."""
        return max(0, self.upstream_bytes_sent - self.negotiation_bytes_sent)

    @property
    def payload_bytes_received(self) -> int:
        """Bytes received from upstream after negotiation."""
        return max(0, self.upstream_bytes_received - self.negotiation_bytes_received)


@dataclass
class HostBytes(Serializable):
    """A host and a byte count (e.g. heaviest hosts in the final minute)."""

    host: str
    bytes: int


@dataclass
class BudgetEvent(Serializable):
    """A budget warning, trip or per-tunnel cap closure recorded by the meter."""

    ts: float
    kind: BudgetEventKind
    #: The meter's budget counter when the event fired (for tunnel_cap: that tunnel's bytes).
    counted_bytes: int
    #: The budget (warn_80/tripped) or the per-tunnel cap (tunnel_cap), in bytes.
    limit_bytes: int | None
    tunnel_id: int | None = None
    host: str | None = None
    #: Heaviest target hosts by upstream bytes in the 60 s before the event (max 10).
    top_hosts: list[HostBytes] = field(default_factory=list)
    #: Tunnels the meter closed because of this event.
    closed_tunnels: int = 0


@dataclass
class TimelinePoint(Serializable):
    """Target upstream bytes in one timeline bucket starting at ``t``."""

    t: float
    sent: int
    received: int


@dataclass
class Totals(Serializable):
    """Run totals over target tunnels (routes http-connect, socks5, direct).

    ``with_connect`` is all upstream socket bytes (plus synthesised CONNECT bytes
    in direct mode, flagged by ``with_connect_estimated``); ``without_connect``
    subtracts the negotiation. Denied and non-target tunnels are excluded;
    failed tunnels are included (their negotiation bytes did cross the socket).

    ``tunnels`` counts TunnelRecords; ``connections`` counts the upstream
    connections the meter opened (or tried to open) for them: records with
    :attr:`TunnelRecord.opened_connection`. They differ when a keep-alive
    plain-HTTP client switched authority on the HTTP CONNECT route: one
    provider connection then carries several records (round 4, meas4-6).
    """

    with_connect: int
    without_connect: int
    bytes_sent: int
    bytes_received: int
    tunnels: int
    failed_tunnels: int
    denied_tunnels: int
    with_connect_estimated: bool
    #: Upstream connections opened (or attempted) for target records (<= ``tunnels``).
    connections: int = 0


@dataclass
class MeterSnapshot(Serializable):
    """A point-in-time copy of everything the forwarder measured.

    Produced by ``Forwarder.snapshot()`` / ``ForwarderThread.snapshot()`` /
    ``ForwarderThread.stop()``. Contains no credentials, no upstream host, no
    paths or query strings: only target authorities and counters.
    """

    taken_at: float
    started_at: float
    mode: Mode
    port: int
    #: Port of the credential-challenging listener (run/find), else None.
    auth_port: int | None
    tunnels: list[TunnelRecord]
    #: Budget counter: upstream socket bytes (both directions, negotiation included) of target tunnels.
    counted_bytes: int
    budget_bytes: int | None
    max_tunnel_bytes: int | None
    budget_tripped: bool
    budget_events: list[BudgetEvent] = field(default_factory=list)
    #: Client requests refused before any tunnel existed, by reason (see contracts.md).
    refused: dict[str, int] = field(default_factory=dict)
    #: Non-empty buckets of target upstream bytes over time, oldest first.
    timeline: list[TimelinePoint] = field(default_factory=list)
    timeline_resolution_s: float = 0.25
    #: Exceptions caught in connection handlers (the tunnel was closed; > 0 adds a warning).
    internal_errors: int = 0
    #: Times a listener could not accept a connection because the meter process ran out of
    #: file descriptors (EMFILE/ENFILE); asyncio then pauses accepting for about 1 s.
    accept_limit_errors: int = 0

    def target_tunnels(self) -> list[TunnelRecord]:
        """Tunnels whose route is http-connect, socks5 or direct."""
        return [t for t in self.tunnels if t.is_target]

    def non_target_tunnels(self) -> list[TunnelRecord]:
        """Tunnels carried direct because they matched direct.json (--env-all)."""
        return [t for t in self.tunnels if t.route == "non-target"]

    def denied_tunnels(self) -> list[TunnelRecord]:
        return [t for t in self.tunnels if t.status == TUNNEL_DENIED]

    def totals(self) -> Totals:
        """Authoritative run totals; every consumer must use this, not re-derive."""
        target = self.target_tunnels()
        return Totals(
            with_connect=sum(t.bytes_with_connect for t in target),
            without_connect=sum(t.bytes_without_connect for t in target),
            bytes_sent=sum(t.upstream_bytes_sent for t in target),
            bytes_received=sum(t.upstream_bytes_received for t in target),
            tunnels=len(target),
            failed_tunnels=sum(1 for t in target if t.failed),
            denied_tunnels=len(self.denied_tunnels()),
            with_connect_estimated=self.mode == "direct" and any(t.negotiation_estimated for t in target),
            connections=sum(1 for t in target if t.opened_connection),
        )


# ---------------------------------------------------------------------------
# Helper events (events file, JSONL, v=1)
# ---------------------------------------------------------------------------


@dataclass
class AttachEvent(Serializable):
    """A helper started observing (Playwright context instrumented, or a hook installed)."""

    ts: float
    source: EventSource
    pid: int | None = None
    #: Opaque per-process context id (e.g. "4242-1"), or None for hooks.
    context: str | None = None
    v: int = EVENTS_VERSION
    kind: Literal["attach"] = "attach"


@dataclass
class LaunchEvent(Serializable):
    """A browser launch seen by the Playwright helper."""

    ts: float
    source: EventSource
    browser: BrowserName = "chromium"
    pid: int | None = None
    v: int = EVENTS_VERSION
    kind: Literal["launch"] = "launch"


@dataclass
class RequestEvent(Serializable):
    """Metadata for one network request seen by a helper or hook.

    Never carries bodies, cookies, header values, credentials or query strings.
    ``path`` is present only when the helper ran with SCRAPESCOPE_KEEP_URLS=1.
    Sizes are as reported by the client (DevTools ``sizes()`` for Playwright;
    hook-reported for Requests/HTTPX) and may be None when unknown.
    """

    ts: float
    source: EventSource
    host: str
    port: int | None = None
    scheme: str = "https"
    path: str | None = None
    method: str = "GET"
    resource_type: str = "other"
    status: int | None = None
    failed: bool = False
    from_cache: bool = False
    from_service_worker: bool = False
    frame: FrameKind = "other"
    is_navigation: bool = False
    encoded_body_bytes: int | None = None
    response_header_bytes: int | None = None
    request_header_bytes: int | None = None
    request_body_bytes: int | None = None
    sent_cookies: bool = False
    sent_authorization: bool = False
    #: Opaque context id matching the context's AttachEvent (optional extension).
    context: str | None = None
    v: int = EVENTS_VERSION
    kind: Literal["request"] = "request"

    @property
    def reported_bytes(self) -> int:
        """Client-reported wire bytes: encoded body + both header blocks + request body."""
        return (
            (self.encoded_body_bytes or 0)
            + (self.response_header_bytes or 0)
            + (self.request_header_bytes or 0)
            + (self.request_body_bytes or 0)
        )

    @property
    def hit_network(self) -> bool:
        """False for cache hits and responses served by a service worker."""
        return not self.from_cache and not self.from_service_worker


HelperEvent = Union[AttachEvent, LaunchEvent, RequestEvent]

#: Maximum accepted length of one events-file line (bytes, newline excluded).
MAX_EVENT_LINE_BYTES = 4096
_NETWORK_SCHEMES = frozenset({"http", "https", "ws", "wss"})


def _opt_count(obj: dict[str, Any], key: str) -> int | None:
    value = obj.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_JS_SAFE_INT:
        raise ValueError(f"{key}: expected a non-negative integer or null")
    return value


def _bool(obj: dict[str, Any], key: str) -> bool:
    value = obj.get(key, False)
    if not isinstance(value, bool):
        raise ValueError(f"{key}: expected a boolean")
    return value


def _ts(obj: dict[str, Any]) -> float:
    value = obj.get("ts")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("ts: expected a number")
    f = float(value)
    if not math.isfinite(f) or f < 0:
        raise ValueError("ts: expected a finite non-negative number")
    return f


def _context(obj: dict[str, Any]) -> str | None:
    value = obj.get("context")
    if value is None:
        return None
    if not isinstance(value, str) or not _CONTEXT_RE.fullmatch(value):
        raise ValueError("context: invalid")
    return value


def parse_event(obj: Any) -> HelperEvent:
    """Validate one decoded events-file object and return the typed event.

    Raises ``ValueError`` when ``v`` is not :data:`EVENTS_VERSION`, the kind is
    unknown, a field has the wrong type, or a string fails its charset/length
    check. Unknown keys are ignored. Hosts are normalised with
    :func:`clean_host`; paths with :func:`clean_path` (query strings removed).
    Only network schemes (http, https, ws, wss) are accepted for requests.
    """
    if not isinstance(obj, dict):
        raise ValueError("event must be a JSON object")
    if obj.get("v") != EVENTS_VERSION or isinstance(obj.get("v"), bool):
        raise ValueError("unsupported events version")
    kind = obj.get("kind")
    source = obj.get("source")
    if source not in ("playwright", "requests", "httpx"):
        raise ValueError("source: invalid")
    ts = _ts(obj)
    pid = obj.get("pid")
    if pid is not None and (isinstance(pid, bool) or not isinstance(pid, int) or not 0 <= pid < 2**31):
        raise ValueError("pid: invalid")
    if kind == "attach":
        return AttachEvent(ts=ts, source=source, pid=pid, context=_context(obj))
    if kind == "launch":
        browser = obj.get("browser", "chromium")
        if browser not in ("chromium", "firefox", "webkit", "other"):
            browser = "other"
        return LaunchEvent(ts=ts, source=source, browser=browser, pid=pid)
    if kind != "request":
        raise ValueError("kind: invalid")
    host = clean_host(obj.get("host"))
    if host is None:
        raise ValueError("host: invalid")
    port = obj.get("port")
    if port is not None and (isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536):
        raise ValueError("port: invalid")
    scheme = obj.get("scheme", "https")
    if not isinstance(scheme, str) or not _SCHEME_RE.fullmatch(scheme) or scheme not in _NETWORK_SCHEMES:
        raise ValueError("scheme: invalid")
    path_raw = obj.get("path")
    path = clean_path(path_raw) if path_raw is not None else None
    method = obj.get("method", "GET")
    if not isinstance(method, str) or not _METHOD_RE.fullmatch(method):
        raise ValueError("method: invalid")
    resource_type = obj.get("resource_type", "other")
    if not isinstance(resource_type, str) or not _RESOURCE_TYPE_RE.fullmatch(resource_type):
        raise ValueError("resource_type: invalid")
    status = obj.get("status")
    if status is not None and (isinstance(status, bool) or not isinstance(status, int) or not 0 <= status <= 999):
        raise ValueError("status: invalid")
    frame = obj.get("frame", "other")
    if frame not in ("main", "sub", "worker", "service_worker", "other"):
        raise ValueError("frame: invalid")
    return RequestEvent(
        ts=ts,
        source=source,
        host=host,
        port=port,
        scheme=scheme,
        path=path,
        method=method,
        resource_type=resource_type,
        status=status,
        failed=_bool(obj, "failed"),
        from_cache=_bool(obj, "from_cache"),
        from_service_worker=_bool(obj, "from_service_worker"),
        frame=frame,
        is_navigation=_bool(obj, "is_navigation"),
        encoded_body_bytes=_opt_count(obj, "encoded_body_bytes"),
        response_header_bytes=_opt_count(obj, "response_header_bytes"),
        request_header_bytes=_opt_count(obj, "request_header_bytes"),
        request_body_bytes=_opt_count(obj, "request_body_bytes"),
        sent_cookies=_bool(obj, "sent_cookies"),
        sent_authorization=_bool(obj, "sent_authorization"),
        context=_context(obj),
    )


def event_to_json_line(event: HelperEvent) -> str:
    """Serialise an event as one compact JSON line (newline included).

    Writers (helpers) must use this so field names and ``v`` stay in sync.
    """
    import json

    data = event.to_dict()
    if isinstance(event, RequestEvent) and data.get("path") is None:
        data.pop("path", None)
    return json.dumps(data, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n"


# ---------------------------------------------------------------------------
# find
# ---------------------------------------------------------------------------


@dataclass
class ChallengeResult(Serializable):
    """Outcome of the challenge classifier on the main document.

    Classification only: scrapescope never tries to get past a challenge.
    ``signals`` are catalog references ("<vendor_id>:<type>:<name-or-index>"),
    never page content.
    """

    blocked: bool
    vendor_id: str | None = None
    vendor_name: str | None = None
    signals: list[str] = field(default_factory=list)
    status: int | None = None


@dataclass
class FindFlags(Serializable):
    """Request properties that make a response unsafe to fetch without the page.

    "sent" means the browser sent it, not that the server needed it.
    """

    sent_cookies: bool = False
    sent_authorization: bool = False
    random_query_token: bool = False
    third_party: bool = False
    non_get: bool = False
    #: A credential- or token-like request header was sent (``find.heuristics.is_token_header``;
    #: presence only). Kept when a --verify replay without it said yes.
    sent_token_header: bool = False


@dataclass
class FindMatch(Serializable):
    """One response that contains at least one searched value.

    ``billed_basis_bytes`` = encoded body + response headers + request headers
    + one new TLS handshake estimate (https only): an estimate of what fetching
    this response alone on a fresh connection would transfer. For HTTP/2 and
    HTTP/3 responses (``multiplexed``) DevTools has no separate header sizes:
    both header fields are 0, the encoded body includes the response header
    frames, and request headers are left out of the billed basis.
    """

    rank: int
    host: str
    port: int
    scheme: str
    #: URL path without query; None when unknown or when it contains a searched value.
    path: str | None
    method: str
    resource_type: str
    status: int | None
    mime_type: str | None
    all_values: bool
    values_matched: int
    #: One entry per --value in order: "exact" | "variant:<id>" | "none". Never the value itself.
    match_kinds: list[str]
    #: Where the match sits, e.g. "document", "xhr", "embedded:next-data", "json-key:offers.price".
    locations: list[str]
    encoded_body_bytes: int
    response_header_bytes: int
    request_header_bytes: int
    tls_handshake_estimate: int
    billed_basis_bytes: int
    flags: FindFlags = field(default_factory=FindFlags)
    code_eligible: bool = False
    code_ineligible_reason: str | None = None
    #: The response's Content-Encoding token as the browser received it ("br", "gzip"...), or None.
    #: A client that cannot accept the same encoding receives a larger body.
    content_encoding: str | None = None
    #: HTTP/2 or HTTP/3: header sizes are not reported separately (see the class docstring).
    multiplexed: bool = False
    #: One list per --value, in order: where that value matched (never the value itself).
    locations_by_value: list[list[str]] = field(default_factory=list)


@dataclass
class Coverage(Serializable):
    """What the value search looked at, so "not found" is never overstated."""

    inspected: int = 0
    #: Reason -> count; reasons are the keys of COVERAGE_SKIP_LABELS.
    skipped: dict[str, int] = field(default_factory=dict)

    def summary(self, found: bool) -> str:
        """The coverage line, e.g. "not found in 41 inspected responses; skipped: 2 binary"."""
        skipped = ", ".join(
            f"{n} {COVERAGE_SKIP_LABELS.get(reason, reason)}"
            for reason, n in sorted(self.skipped.items())
            if n > 0
        )
        noun = "response" if self.inspected == 1 else "responses"
        head = (
            f"searched {self.inspected} inspected {noun}"
            if found
            else f"not found in {self.inspected} inspected {noun}"
        )
        return f"{head}; skipped: {skipped or 'none'}"


@dataclass
class VerifyResult(Serializable):
    """Result of the single cookie-less --verify replay."""

    replays: Replays = "not_tested"
    status: int | None = None
    #: Body bytes received by the replay (as sent on the wire, before decompression).
    received_bytes: int | None = None
    #: Short fixed-vocabulary reason, e.g. "not requested", "nothing matched", "no eligible match",
    #: "status 403", "value missing".
    reason: str | None = None
    #: The replay's billed basis: body bytes received + its response and request header
    #: bytes + the same TLS estimate as the match; None when no response arrived.
    replay_billed_basis_bytes: int | None = None


@dataclass
class StarterCode(Serializable):
    """Generated starter code for one eligible match (terminal only, never in reports)."""

    rank: int
    curl: str
    httpx: str


@dataclass
class FindResult(Serializable):
    """Everything ``find`` learned. Never contains the searched values.

    ``to_dict()`` omits the terminal-only fields (full URLs, starter code).
    """

    status: FindStatus
    target_host: str
    target_path: str | None
    values_count: int
    short_value_warning: bool
    challenge: ChallengeResult
    matches: list[FindMatch] = field(default_factory=list)
    coverage: Coverage = field(default_factory=Coverage)
    verify: VerifyResult = field(default_factory=VerifyResult)
    responses_total: int = 0
    #: Sum of DevTools-reported wire bytes of every response in the load.
    page_reported_bytes: int = 0
    warnings: list[str] = field(default_factory=list)
    #: The URL exactly as given (terminal only).
    target_url: str = terminal_only("")
    #: Starter code for eligible matches (terminal only; contains full URLs).
    starter_code: list[StarterCode] = terminal_only(default_factory=list)
    #: rank -> full URL of each match, query included (terminal only).
    match_urls: dict[str, str] = terminal_only(default_factory=dict)
    #: 0-based indices of values no inspected response contained as themselves (terminal only;
    #: the report carries the "not found: value N" warning). find exits 6 when a "found" result has any.
    missing_values: list[int] = terminal_only(default_factory=list)


# ---------------------------------------------------------------------------
# Attribution results (report pieces)
# ---------------------------------------------------------------------------


@dataclass
class BucketTally(Serializable):
    tunnels: int = 0
    bytes: int = 0


@dataclass
class HostAttribution(Serializable):
    """Per-target-host figures. Bytes are tunnel-measured; allocated_by_type is allocated."""

    host: str
    ports: list[int]
    tunnels: int
    failed_tunnels: int
    denied_tunnels: int
    bytes_sent: int
    bytes_received: int
    bytes_with_connect: int
    bytes_without_connect: int
    #: Helper/hook request events for this host that hit the network.
    requests: int
    #: Bucket name -> tally; names are the BUCKET_* constants or "background:<id>".
    buckets: dict[str, BucketTally] = field(default_factory=dict)
    #: resource type -> allocated bytes (sums to bytes_with_connect when requests > 0).
    allocated_by_type: dict[str, int] = field(default_factory=dict)
    background_id: str | None = None
    #: Only filled when paths were kept (--keep-urls): top paths by reported bytes.
    paths: list[PathBytes] = field(default_factory=list)


@dataclass
class PathBytes(Serializable):
    path: str
    requests: int
    reported_bytes: int


@dataclass
class TypeAllocation(Serializable):
    """Per resource type over the whole run: reported and allocated bytes."""

    type: str
    requests: int
    reported_bytes: int
    allocated_bytes: int


@dataclass
class Buckets(Serializable):
    """Run-level bytes per bucket (with-CONNECT basis; sums to totals.with_connect)."""

    attributed: int = 0
    preconnect_idle: int = 0
    before_attach: int = 0
    unattributed: int = 0
    #: catalog id -> bytes
    background: dict[str, int] = field(default_factory=dict)


@dataclass
class NonTargetHost(Serializable):
    """A direct.json host carried direct under --env-all (never sent to the upstream)."""

    host: str
    catalog_id: str
    tunnels: int
    bytes_sent: int
    bytes_received: int


@dataclass
class UnitsInfo(Serializable):
    count: int = 0
    source: UnitsSource = "none"
    low_sample_warning: bool = True


@dataclass
class PerUnitBytes(Serializable):
    """First unit versus the rest, from the meter timeline (approximate to its resolution)."""

    first_unit_bytes: int
    rest_units: int
    rest_bytes: int
    rest_mean_bytes: int | None
    resolution_s: float


@dataclass
class SuccessInfo(Serializable):
    count: int
    basis: SuccessBasis
    rate: float | None


@dataclass
class BypassInfo(Serializable):
    """Requests helpers saw whose host no tunnel carried (run marked incomplete)."""

    incomplete: bool = False
    hosts: list[str] = field(default_factory=list)
    requests: int = 0


@dataclass
class EventCounts(Serializable):
    attach: int = 0
    launch: int = 0
    request: int = 0
    dropped: int = 0


@dataclass
class AttributionResult(Serializable):
    """Output of ``scrapescope.attribution.attribute``; input to the report builder."""

    hosts: list[HostAttribution] = field(default_factory=list)
    types: list[TypeAllocation] = field(default_factory=list)
    buckets: Buckets = field(default_factory=Buckets)
    non_target: list[NonTargetHost] = field(default_factory=list)
    units: UnitsInfo = field(default_factory=UnitsInfo)
    browser_launches: int = 0
    bytes_before_first_navigation: int | None = None
    per_unit: PerUnitBytes | None = None
    #: HTTP status (as a string) or "failed" -> count, from helper/hook events that hit the network.
    status_histogram: dict[str, int] = field(default_factory=dict)
    success: SuccessInfo | None = None
    bypass: BypassInfo = field(default_factory=BypassInfo)
    #: True when any context loaded more than one page (what-if "cache loss not modelled").
    multi_page_context: bool = False
    #: Event sources seen, e.g. ["playwright"]; drives which fixes apply.
    sources: list[str] = field(default_factory=list)
    events: EventCounts = field(default_factory=EventCounts)
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Model and snippets (report pieces)
# ---------------------------------------------------------------------------


@dataclass
class CostInfo(Serializable):
    """Transfer x the user's own rate. Label: "estimated billable transfer"."""

    rate: float
    rate_unit: Literal["USD per GB", "USD per GiB"]
    with_connect: float
    without_connect: float
    per_1000_units: float | None = None
    per_1000_successes: float | None = None
    label: Literal["estimated billable transfer"] = "estimated billable transfer"
    currency: Literal["USD"] = "USD"


@dataclass
class WhatIf(Serializable):
    """A modelled saving (allocated basis), always with caveats."""

    id: str
    title: str
    bytes_saved: int
    share: float
    caveats: list[str]
    basis: Literal["allocated"] = "allocated"


@dataclass
class Fix(Serializable):
    """A generated fix snippet, emitted only when its detection fired."""

    id: str
    title: str
    detection: str
    language: FixLanguage
    code: str
    caveats: list[str]


# ---------------------------------------------------------------------------
# Catalogs
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BackgroundEntry(Serializable):
    id: str
    hosts: tuple[str, ...]
    component: str
    evidence: tuple[str, ...]
    security_tradeoff: str
    last_verified: str


@dataclass(frozen=True)
class ChallengeSignal(Serializable):
    """One challenge/vendor signal. Semantics per type: docs/dev/contracts.md section 8."""

    type: SignalType
    name: str | None = None
    pattern: str | None = None
    statuses: tuple[int, ...] = ()
    strength: SignalStrength = "challenge"


@dataclass(frozen=True)
class ChallengeVendor(Serializable):
    id: str
    name: str
    signals: tuple[ChallengeSignal, ...]
    docs: tuple[str, ...] = ()
    #: Attribution when patterns come from another project (e.g. is-antibot, MIT).
    source: str | None = None


@dataclass(frozen=True)
class DirectEntry(Serializable):
    id: str
    hosts: tuple[str, ...]
    reason: str


def _check_catalog_version(doc: Any, name: str) -> str:
    if not isinstance(doc, dict):
        raise ValueError(f"{name}: expected an object")
    version = doc.get("version")
    if not isinstance(version, str) or not re.fullmatch(r"[0-9A-Za-z.+-]{1,32}", version):
        raise ValueError(f"{name}: version must be a short string")
    return version


def _check_entry_ids_and_hosts(entries: tuple[Any, ...], name: str) -> None:
    seen: set[str] = set()
    for entry in entries:
        if not is_catalog_id(entry.id):
            raise ValueError(f"{name}: invalid id {entry.id!r}")
        if entry.id in seen:
            raise ValueError(f"{name}: duplicate id {entry.id!r}")
        seen.add(entry.id)
        for glob in getattr(entry, "hosts", ()):
            validate_host_glob(glob)


@dataclass(frozen=True)
class Catalogs(Serializable):
    """The three versioned catalogs, loaded by ``scrapescope.catalog.load_catalogs()``."""

    background_version: str
    background: tuple[BackgroundEntry, ...]
    challenges_version: str
    challenges: tuple[ChallengeVendor, ...]
    direct_version: str
    direct: tuple[DirectEntry, ...]

    @classmethod
    def from_documents(cls, background: Any, challenges: Any, direct: Any) -> Catalogs:
        """Validate and build from the three parsed JSON documents.

        background: {"version", "entries": [BackgroundEntry]}
        challenges: {"version", "vendors": [ChallengeVendor]}
        direct:     {"version", "entries": [DirectEntry]}
        Extra top-level keys (e.g. "attribution", "notes") are ignored.
        """
        bv = _check_catalog_version(background, "background.json")
        cv = _check_catalog_version(challenges, "challenges.json")
        dv = _check_catalog_version(direct, "direct.json")
        bg = tuple(
            _convert(BackgroundEntry, e, "background.json.entries") for e in background.get("entries", [])
        )
        ch = tuple(_convert(ChallengeVendor, e, "challenges.json.vendors") for e in challenges.get("vendors", []))
        di = tuple(_convert(DirectEntry, e, "direct.json.entries") for e in direct.get("entries", []))
        _check_entry_ids_and_hosts(bg, "background.json")
        _check_entry_ids_and_hosts(ch, "challenges.json")
        _check_entry_ids_and_hosts(di, "direct.json")
        for vendor in ch:
            for sig in vendor.signals:
                if sig.pattern is not None:
                    re.compile(sig.pattern)
        return cls(bv, bg, cv, ch, dv, di)

    def versions(self) -> dict[str, str]:
        """For report.json ``catalog_versions``."""
        return {
            "background": self.background_version,
            "challenges": self.challenges_version,
            "direct": self.direct_version,
        }

    def background_entry_for(self, host: str) -> BackgroundEntry | None:
        """First background.json entry whose host globs match ``host``."""
        for entry in self.background:
            if any(host_glob_match(g, host) for g in entry.hosts):
                return entry
        return None

    def background_id_for(self, host: str) -> str | None:
        entry = self.background_entry_for(host)
        return entry.id if entry else None

    def direct_entry_for(self, host: str) -> DirectEntry | None:
        """First direct.json entry whose host globs match ``host``."""
        for entry in self.direct:
            if any(host_glob_match(g, host) for g in entry.hosts):
                return entry
        return None

    def direct_id_for(self, host: str) -> str | None:
        entry = self.direct_entry_for(host)
        return entry.id if entry else None

    def vendor(self, vendor_id: str) -> ChallengeVendor | None:
        for vendor in self.challenges:
            if vendor.id == vendor_id:
                return vendor
        return None


# ---------------------------------------------------------------------------
# Report options
# ---------------------------------------------------------------------------


@dataclass
class ReportOptions(Serializable):
    """Options the report builder needs (never the command line or env)."""

    command: ReportCommand
    gb_unit: GbUnit = "GB"
    #: USD per gb_unit (per GB, or per GiB with --gib); None = no costs.
    rate: float | None = None
    keep_urls: bool = False
    redact_hosts: bool = False
    #: Defaults to snapshot.taken_at when None.
    ended_at: float | None = None


__all__ = [
    "AttachEvent",
    "AttributionResult",
    "BackgroundEntry",
    "BucketTally",
    "Buckets",
    "BudgetEvent",
    "BypassInfo",
    "Catalogs",
    "ChallengeResult",
    "ChallengeSignal",
    "ChallengeVendor",
    "CostInfo",
    "Coverage",
    "DirectEntry",
    "EventCounts",
    "FindFlags",
    "FindMatch",
    "FindResult",
    "Fix",
    "HelperEvent",
    "HostAttribution",
    "HostBytes",
    "LaunchEvent",
    "MeterSnapshot",
    "NonTargetHost",
    "PathBytes",
    "PerUnitBytes",
    "ReportOptions",
    "RequestEvent",
    "Serializable",
    "StarterCode",
    "SuccessInfo",
    "TimelinePoint",
    "Totals",
    "TunnelRecord",
    "TypeAllocation",
    "UnitsInfo",
    "VerifyResult",
    "WhatIf",
    "canonical_host",
    "clean_host",
    "clean_path",
    "embedded_ipv4",
    "is_path_token_segment",
    "event_to_json_line",
    "host_glob_match",
    "ip_literal",
    "is_catalog_id",
    "parse_event",
    "safe_code",
    "safe_text",
    "validate_host_glob",
]

