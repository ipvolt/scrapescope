"""Configuration: upstream URL parsing, sizes, child environment, shared constants.

Secrets rule: the upstream URL (which usually embeds provider credentials) is
read only from an environment variable, never from argv. Nothing in this module
logs, prints or includes it in an exception message; :class:`UpstreamConfig`
redacts itself in ``repr``/``str``. Callers must keep it that way: never
``dataclasses.asdict`` an UpstreamConfig or a ForwarderConfig, never log them
with ``%r`` of their fields, and never put ``ConfigError`` context that holds the
raw value into output.

Accuracy notes: :data:`TLS_HANDSHAKE_ESTIMATE_BYTES` and the preconnect/idle
limits are typical figures from the plan's local measurements, not constants of
nature; reports label anything derived from them as an estimate.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import tempfile
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from ._version import __version__
from .types import GbUnit, Mode, canonical_host, clean_host, ip_literal, validate_host_glob

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

KB = 10**3
MB = 10**6
GB = 10**9
TB = 10**12
KIB = 2**10
MIB = 2**20
GIB = 2**30
TIB = 2**40

#: The only address the meter ever binds.
METER_HOST = "127.0.0.1"

#: Username prefix carrying the per-run token: "ss-<token>" or "ss-<token>~<upstream-user>".
TOKEN_PREFIX = "ss-"
TOKEN_SEPARATOR = "~"
#: Realm of the meter's own 407 challenges.
PROXY_REALM = "scrapescope"

#: Honest User-Agent for scrapescope's own requests (find --verify): the tool, its
#: version and the project's contact URL (the public repository), so that a site
#: operator can reach whoever runs it, as Wikimedia's User-Agent policy asks.
#: Nothing else: no browser impersonation, no operating-system details.
USER_AGENT = f"scrapescope/{__version__} (+https://github.com/ipvolt/scrapescope)"

#: One new TLS handshake, both directions, as used for find's billed basis [Est].
TLS_HANDSHAKE_ESTIMATE_BYTES = 7200
#: A tunnel with no request and at most this many payload bytes up/down is "preconnect_idle".
#: 3 KB up because Chromium's post-quantum TLS ClientHello (X25519MLKEM768) alone is
#: about 2 KB: a measured idle preconnect sent 2.0-2.3 KB of payload (Chromium 153).
PRECONNECT_IDLE_MAX_SENT = 3072
PRECONNECT_IDLE_MAX_RECEIVED = 6144
#: Per-1,000 figures from fewer units than this carry a warning.
LOW_UNITS_THRESHOLD = 20
#: The budget warns once at this fraction.
BUDGET_WARN_FRACTION = 0.8
#: SIGTERM -> SIGKILL grace period when stopping the child's process group.
STOP_GRACE_S = 5.0
#: The forwarder never closes an idle tunnel sooner than this.
MIN_IDLE_TIMEOUT_S = 600.0
#: Resolution of the meter timeline (MeterSnapshot.timeline).
TIMELINE_RESOLUTION_S = 0.25
#: Window for "heaviest hosts of the final minute".
TOP_HOSTS_WINDOW_S = 60.0
#: The 200 line a typical provider returns to CONNECT (used for direct-mode estimates).
SYNTHETIC_CONNECT_RESPONSE = b"HTTP/1.1 200 Connection established\r\n\r\n"
#: Default report path (relative to the current directory).
DEFAULT_REPORT_PATH = "scrapescope-report.json"
#: Default size cap for bodies read by find.
FIND_BODY_CAP_BYTES = 5 * MB

# Environment variables -----------------------------------------------------

#: Meter URL for the child (no credentials), e.g. http://127.0.0.1:53211
ENV_PROXY_URL = "SCRAPESCOPE_PROXY_URL"
#: Meter URL of the credential-challenging listener, for clients that bring their own proxy credentials.
ENV_AUTH_PROXY_URL = "SCRAPESCOPE_AUTH_PROXY_URL"
#: Path of the private JSONL events file helpers append to.
ENV_EVENTS = "SCRAPESCOPE_EVENTS"
#: "1" when --keep-urls was given; helpers then include paths (never queries).
ENV_KEEP_URLS = "SCRAPESCOPE_KEEP_URLS"
#: "1" enables the test-only variables below. Never set it outside tests.
ENV_TESTING = "SCRAPESCOPE_TESTING"
#: Test only: JSON {"host:port": "ip:port"} used for the meter's own direct connections.
ENV_TEST_CONNECT_MAP = "SCRAPESCOPE_TEST_CONNECT_MAP"
#: Test only: CA bundle for find's browser (ignore_https_errors) and --verify (httpx verify=).
ENV_TEST_CA = "SCRAPESCOPE_TEST_CA"
#: ``run`` with an upstream: a salted fingerprint of the upstream's host:port (:func:`upstream_id`), so the
#: Playwright helper reroutes only ``proxy=`` servers that are that upstream (sec2-8).
ENV_UPSTREAM_ID = "SCRAPESCOPE_UPSTREAM_ID"

#: Variables --env-all sets to the meter URL.
PROXY_ENV_VARS: tuple[str, ...] = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
)
#: Entries --env-all guarantees in NO_PROXY/no_proxy (merged with existing ones).
NO_PROXY_DEFAULTS: tuple[str, ...] = ("127.0.0.1", "localhost", "::1")

# Exit codes (docs/exit-codes.md) ------------------------------------------

EXIT_OK = 0
#: find: no inspected response contained the values.
EXIT_NOT_FOUND = 1
#: Usage error (argparse), including an unreadable or invalid report file.
EXIT_USAGE = 2
#: find: Playwright or its Chromium is not installed.
EXIT_BROWSER_UNAVAILABLE = 3
#: find: the page was a challenge page ("blocked; cannot search"), never "not found".
EXIT_BLOCKED = 4
#: find: the page did not load (navigation error, timeout, upstream failure); nothing was searched.
EXIT_LOAD_ERROR = 5
#: find: some responses matched, but at least one value was not found (as itself) in any inspected
#: response; the report's status is still "found" (round 2, find-r2-9).
EXIT_PARTIAL = 6
EXIT_BUDGET = 86
EXIT_BYPASS = 87
EXIT_INTERNAL = 88
EXIT_UPSTREAM_CONFIG = 89


class ConfigError(Exception):
    """Invalid configuration detected before start (exit code 89).

    Messages name the environment variable, never its value.
    """

    exit_code = EXIT_UPSTREAM_CONFIG


# ---------------------------------------------------------------------------
# Upstream URL
# ---------------------------------------------------------------------------

_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
_DEFAULT_PORTS = {"http-connect": 80, "socks5": 1080}


@dataclass(frozen=True, repr=False)
class UpstreamConfig:
    """The user's real upstream proxy. Redacted in repr/str; never serialise it.

    ``kind`` is "http-connect" (HTTP proxy, CONNECT for tunnels, absolute-form
    for plain HTTP, Basic auth) or "socks5" (RFC 1928 with remote DNS, RFC 1929
    username/password). ``username``/``password`` are percent-decoded; they are
    None when the URL carried no userinfo.
    """

    kind: Mode
    host: str
    port: int
    username: str | None = field(default=None, compare=True)
    password: str | None = field(default=None, compare=True)

    @property
    def mode(self) -> Mode:
        return self.kind

    @property
    def has_credentials(self) -> bool:
        return self.username is not None

    def proxy_authorization(self) -> str | None:
        """``Basic ...`` value for the configured credentials, or None."""
        if self.username is None:
            return None
        return basic_auth_value(self.username, self.password or "")

    def __repr__(self) -> str:
        creds = "yes" if self.has_credentials else "no"
        return f"UpstreamConfig(kind={self.kind!r}, host=<hidden>, port=<hidden>, credentials={creds})"

    __str__ = __repr__


def parse_upstream_url(value: str, *, source: str = "the upstream proxy URL") -> UpstreamConfig:
    """Parse a proxy URL into an :class:`UpstreamConfig`.

    Accepted: ``http://[user:pass@]host[:port]`` (default port 80),
    ``socks5://`` and ``socks5h://`` (both use remote DNS; default port 1080),
    and a bare ``[user:pass@]host:port`` (treated as http). Rejected with
    :class:`ConfigError`: ``https://`` proxies (TLS to the proxy is not
    supported in v1), socks4, other schemes, paths, queries, fragments, bad
    ports and bad hosts. ``source`` names the variable in error messages; the
    value itself is never echoed.
    """
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{source} is empty")
    raw = value.strip()
    if "://" not in raw:
        raw = "http://" + raw
    try:
        parts = urllib.parse.urlsplit(raw)
        port = parts.port
    except ValueError:
        raise ConfigError(f"{source} is not a valid proxy URL (bad port or host)") from None
    scheme = parts.scheme.lower()
    if scheme == "http":
        kind: Mode = "http-connect"
    elif scheme in ("socks5", "socks5h"):
        kind = "socks5"
    elif scheme == "https":
        raise ConfigError(
            f"{source} uses https:// (TLS to the proxy), which scrapescope v1 does not support; "
            "use your provider's http:// or socks5:// endpoint"
        )
    else:
        raise ConfigError(
            f"{source} uses an unsupported scheme; use http://, socks5:// or socks5h://"
        )
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ConfigError(f"{source} must not contain a path, query or fragment")
    host = clean_host(parts.hostname or "")
    if host is None:
        raise ConfigError(f"{source} has no valid host")
    if port is None:
        port = _DEFAULT_PORTS[kind]
    if not 0 < port < 65536:
        raise ConfigError(f"{source} has an invalid port")
    username = urllib.parse.unquote(parts.username) if parts.username is not None else None
    password = urllib.parse.unquote(parts.password) if parts.password is not None else None
    if username is None and password is not None:
        username = ""
    if kind == "socks5" and username is not None:
        if len(username.encode("utf-8")) > 255 or len((password or "").encode("utf-8")) > 255:
            raise ConfigError(f"{source}: SOCKS5 usernames and passwords are limited to 255 bytes")
    return UpstreamConfig(kind=kind, host=host, port=port, username=username, password=password)


def upstream_from_env(var: str, environ: Mapping[str, str] | None = None) -> UpstreamConfig:
    """Read and parse the upstream URL from environment variable ``var``."""
    env = os.environ if environ is None else environ
    if not isinstance(var, str) or not _ENV_NAME_RE.fullmatch(var):
        raise ConfigError("--upstream-from-env needs an environment variable name such as HTTPS_PROXY")
    value = env.get(var)
    if not value:
        raise ConfigError(
            f"{var} is not set. Set it to your proxy URL, name another variable with "
            "--upstream-from-env, or use --direct to measure without a proxy (sizing mode)"
        )
    return parse_upstream_url(value, source=var)


def resolve_upstream(
    *,
    direct: bool,
    upstream_var: str | None,
    environ: Mapping[str, str] | None = None,
) -> tuple[UpstreamConfig | None, str | None]:
    """Pick the upstream for run/serve/find.

    Returns ``(upstream, var)``: ``(None, None)`` for ``--direct``; otherwise the
    parsed upstream and the variable it came from. Without either flag,
    HTTPS_PROXY is used when set; otherwise :class:`ConfigError` suggests
    ``--direct``.
    """
    env = os.environ if environ is None else environ
    if direct and upstream_var:
        raise ConfigError("--direct and --upstream-from-env cannot be used together")
    if direct:
        return None, None
    if upstream_var:
        return upstream_from_env(upstream_var, env), upstream_var
    if env.get("HTTPS_PROXY"):
        return upstream_from_env("HTTPS_PROXY", env), "HTTPS_PROXY"
    # Round 4 (ux4-4): HTTP_PROXY/http_proxy too, which http:// scrapers often set alone.
    others = [name for name in ("https_proxy", "all_proxy", "ALL_PROXY", "HTTP_PROXY", "http_proxy") if env.get(name)]
    if others:
        # Never guess: name the variable that is set, never its value.
        raise ConfigError(
            f"no upstream proxy: HTTPS_PROXY is not set, but {others[0]} is. scrapescope reads only "
            f"HTTPS_PROXY by default; use --upstream-from-env {others[0]} to use it, or --direct to "
            "measure without a proxy (sizing mode)"
        )
    raise ConfigError(
        "no upstream proxy: HTTPS_PROXY is not set. Use --upstream-from-env VAR to name the "
        "variable that holds your proxy URL, or --direct to measure without a proxy (sizing mode)"
    )


# ---------------------------------------------------------------------------
# Authorities and Basic auth
# ---------------------------------------------------------------------------


def split_authority(authority: str, default_port: int | None = None) -> tuple[str, int]:
    """Split ``host:port`` (IPv6 in brackets) into ``(clean host, port)``.

    Raises ``ValueError`` on anything malformed. Hosts are normalised with
    :func:`scrapescope.types.clean_host` and are never resolved.
    """
    text = authority.strip()
    if text.startswith("["):
        end = text.find("]")
        if end < 0:
            raise ValueError("unterminated IPv6 literal")
        host_part, rest = text[1:end], text[end + 1 :]
        if rest.startswith(":"):
            port_part = rest[1:]
        elif rest == "" and default_port is not None:
            port_part = str(default_port)
        else:
            raise ValueError("bad authority")
    else:
        host_part, sep, port_part = text.rpartition(":")
        if not sep:
            if default_port is None:
                raise ValueError("port required")
            host_part, port_part = text, str(default_port)
        elif ":" in host_part:
            raise ValueError("IPv6 literals need brackets")
    if not port_part.isdigit() or len(port_part) > 5:
        raise ValueError("bad port")
    port = int(port_part)
    if not 0 < port < 65536:
        raise ValueError("port out of range")
    host = clean_host(host_part)
    if host is None:
        raise ValueError("bad host")
    return host, port


def format_authority(host: str, port: int) -> str:
    """``host:port`` with IPv6 literals bracketed."""
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def basic_auth_value(username: str, password: str) -> str:
    """``Basic base64(username:password)`` (UTF-8)."""
    raw = f"{username}:{password}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def parse_basic_auth(value: str | None) -> tuple[str, str] | None:
    """Decode a ``Basic`` credentials value; None when absent, non-Basic or malformed.

    A value without ``:`` yields ``(username, "")``.
    """
    if not value:
        return None
    scheme, _, token = value.strip().partition(" ")
    if scheme.lower() != "basic" or not token.strip():
        return None
    try:
        decoded = base64.b64decode(token.strip(), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    username, _, password = decoded.partition(":")
    return username, password


#: Version prefix of :func:`upstream_id` values.
UPSTREAM_ID_PREFIX = "v1"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def upstream_fingerprint(key: bytes, host: str, port: int) -> bytes:
    """HMAC-SHA256(key, "host:port"): the digest inside an :func:`upstream_id` value."""
    return hmac.new(key, f"{host}:{port}".encode("ascii"), hashlib.sha256).digest()


def upstream_id(host: str, port: int, key: bytes | None = None) -> str:
    """The ``SCRAPESCOPE_UPSTREAM_ID`` value for an upstream proxy at ``host:port``.

    ``v1.<key>.<HMAC-SHA256(key, "host:port")>`` (URL-safe base64), with a fresh
    random key unless one is given and the host normalised like
    :func:`scrapescope.types.clean_host`. It lets the helpers test whether a
    ``proxy=`` server is the run's upstream without the upstream's name being
    written into the job's environment (a guessed name can still be checked
    against it: it is a salted fingerprint, not a secret). Raises ValueError for
    an invalid host or port.
    """
    clean = clean_host(host)
    if clean is None or not isinstance(port, int) or not 0 < port < 65536:
        raise ValueError("invalid upstream host or port")
    key = secrets.token_bytes(16) if key is None else key
    return ".".join((UPSTREAM_ID_PREFIX, _b64(key), _b64(upstream_fingerprint(key, clean, port))))


def synthetic_connect_sizes(host: str, port: int) -> tuple[int, int]:
    """(request, response) sizes of a minimal CONNECT exchange: the direct-mode starting estimate.

    ``CONNECT a:p HTTP/1.1\\r\\nHost: a:p\\r\\n\\r\\n`` without Proxy-Authorization,
    and :data:`SYNTHETIC_CONNECT_RESPONSE`. In direct (sizing) mode the meter
    opens each CONNECT tunnel with these sizes and then replaces the request
    size with the client's own CONNECT head (without Proxy-Authorization),
    which is usually larger: Chromium sends Host, Proxy-Connection and its
    User-Agent (about 236 bytes). It can also be smaller: Python 3.11's
    ``http.client`` sends ``CONNECT host:port HTTP/1.0`` and a blank line
    without ``Host`` (38 bytes for ``origin-a.test:443``), forwarded as is.
    Provider credentials would add their ``Proxy-Authorization`` line on top
    (often 50-150 bytes).
    """
    authority = format_authority(host, port)
    request = f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode("ascii")
    return len(request), len(SYNTHETIC_CONNECT_RESPONSE)


# ---------------------------------------------------------------------------
# Sizes
# ---------------------------------------------------------------------------

_SIZE_RE = re.compile(r"\s*([0-9]+(?:\.[0-9]+)?)\s*([A-Za-z]*)\s*")
_SIZE_UNITS = {
    "": 1,
    "b": 1,
    "k": KB,
    "kb": KB,
    "ki": KIB,
    "kib": KIB,
    "m": MB,
    "mb": MB,
    "mi": MIB,
    "mib": MIB,
    "g": GB,
    "gb": GB,
    "gi": GIB,
    "gib": GIB,
    "t": TB,
    "tb": TB,
    "ti": TIB,
    "tib": TIB,
}


def parse_size(text: str) -> int:
    """Parse ``2GB``, ``500MB``, ``1.5GiB``, ``750kB`` or a plain byte count.

    Decimal units (kB, MB, GB, TB = powers of 1000) and binary units (KiB, MiB,
    GiB, TiB = powers of 1024) always mean what they say, independent of
    ``--gib`` (which only changes how results are displayed and priced).
    Case-insensitive; a space is allowed. Raises ``ValueError`` for zero,
    negative or malformed sizes.
    """
    if not isinstance(text, str):
        raise ValueError("size must be a string such as 2GB")
    m = _SIZE_RE.fullmatch(text)
    if not m:
        raise ValueError(f"not a size: {text!r} (examples: 2GB, 500MB, 1.5GiB)")
    number, unit = m.group(1), m.group(2).lower()
    if unit not in _SIZE_UNITS:
        raise ValueError(f"unknown size unit {m.group(2)!r} (use B, kB, MB, GB, TB or KiB, MiB, GiB, TiB)")
    value = round(float(number) * _SIZE_UNITS[unit])
    if value < 1:
        raise ValueError("size must be at least 1 byte")
    return int(value)


def size_arg(text: str) -> int:
    """argparse ``type=`` wrapper around :func:`parse_size`."""
    import argparse

    try:
        return parse_size(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


_BARE_NUMBER_RE = re.compile(r"\s*[0-9]+(?:\.[0-9]+)?\s*")


def budget_arg(text: str) -> int:
    """argparse ``type=`` for ``--budget``: like :func:`size_arg`, but a unit is required.

    ``--budget 2`` would otherwise mean two bytes and trip at once; ``2B`` still
    means bytes when that is really wanted.
    """
    import argparse

    if isinstance(text, str) and _BARE_NUMBER_RE.fullmatch(text):
        number = text.strip()
        raise argparse.ArgumentTypeError(
            f"a unit is required, for example {number}GB or {number}MB ({number}B for bytes)"
        )
    return size_arg(text)


def unit_bytes(gb_unit: GbUnit) -> int:
    """Bytes in one reporting unit: 10**9 for "GB", 2**30 for "GiB"."""
    return GIB if gb_unit == "GiB" else GB


def to_unit(n: int | float, gb_unit: GbUnit = "GB") -> float:
    """Convert bytes to GB (10**9) or GiB (2**30)."""
    return n / unit_bytes(gb_unit)


def format_size(n: int | float, gb_unit: GbUnit = "GB", digits: int = 2) -> str:
    """Human-readable size: SI steps (kB, MB, GB, TB) or binary (KiB, MiB, GiB, TiB)."""
    n = float(n)
    if gb_unit == "GiB":
        base, names = 1024.0, ("B", "KiB", "MiB", "GiB", "TiB")
    else:
        base, names = 1000.0, ("B", "kB", "MB", "GB", "TB")
    sign = "-" if n < 0 else ""
    n = abs(n)
    if n < base:
        return f"{sign}{int(n)} B"
    idx = 0
    while n >= base and idx < len(names) - 1:
        n /= base
        idx += 1
    return f"{sign}{n:.{digits}f} {names[idx]}"


# ---------------------------------------------------------------------------
# Token
# ---------------------------------------------------------------------------


def new_token() -> str:
    """A fresh per-run token: 24 URL-safe characters (never contains '~' or ':')."""
    return secrets.token_urlsafe(18)


def token_username(token: str, upstream_user: str | None = None) -> str:
    """The proxy username a client uses: ``ss-<token>`` or ``ss-<token>~<upstream-user>``."""
    base = TOKEN_PREFIX + token
    return base if upstream_user is None else base + TOKEN_SEPARATOR + upstream_user


# ---------------------------------------------------------------------------
# Forwarder configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HostRule:
    """A host glob plus the label recorded when it matches.

    Labels: ``deny-host:<glob>`` for --deny-host, ``catalog:background:<id>``
    for --deny-catalog background, and the direct.json entry id for non-target
    carriage under --env-all.
    """

    pattern: str
    label: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "pattern", validate_host_glob(self.pattern))


@dataclass(frozen=True)
class ForwarderConfig:
    """Everything the forwarder needs. ``token`` and ``upstream`` stay out of repr."""

    upstream: UpstreamConfig | None = None
    token: str | None = field(default=None, repr=False)
    #: serve: always True (round 4, hon4-3). run/find: False (tokenless loopback accepted).
    require_token: bool = False
    #: run/find: also listen on a second port that answers 407 when no credentials are sent.
    auth_listener: bool = False
    #: 0 = pick a random free port.
    port: int = 0
    budget_bytes: int | None = None
    max_tunnel_bytes: int | None = None
    deny_rules: tuple[HostRule, ...] = ()
    #: --env-all only: direct.json hosts, carried direct and reported as non-target.
    #: The meter connects to them itself (local DNS, this machine's own IP), even
    #: when an upstream is configured.
    direct_rules: tuple[HostRule, ...] = ()
    #: --allow-private-targets: let direct-route (sizing mode) connections reach
    #: loopback, private, link-local, CGNAT and other non-global addresses. Off
    #: by default; see forwarder.upstream. (Non-target routes are never checked
    #: for private addresses; the self-loop check applies everywhere.)
    allow_private_targets: bool = False
    connect_timeout_s: float = 30.0
    idle_timeout_s: float = MIN_IDLE_TIMEOUT_S
    budget_warn_fraction: float = BUDGET_WARN_FRACTION
    timeline_resolution_s: float = TIMELINE_RESOLUTION_S
    #: Keep the byte timeline (run/find). serve turns it off: its report has no helper
    #: events to align it with, and a standing meter would otherwise keep adding slots.
    record_timeline: bool = True

    def __post_init__(self) -> None:
        if self.idle_timeout_s < MIN_IDLE_TIMEOUT_S:
            raise ValueError("idle_timeout_s must be at least 600 seconds")
        if self.require_token and not self.token:
            raise ValueError("require_token needs a token")
        if not 0 <= self.port < 65536:
            raise ValueError("port out of range")

    @property
    def mode(self) -> Mode:
        return self.upstream.kind if self.upstream is not None else "direct"


# ---------------------------------------------------------------------------
# Child environment
# ---------------------------------------------------------------------------


def _same_proxy_url(a: str, b: str) -> bool:
    return a.strip().rstrip("/") == b.strip().rstrip("/")


def is_proxy_variable_name(name: str) -> bool:
    """True for proxy-setting variable names (``*_proxy`` in any case), never NO_PROXY."""
    lower = name.lower()
    return lower.endswith("proxy") and lower not in ("no_proxy", "noproxy")


def _proxy_identity(value: str) -> tuple[str, str, int, str | None, str | None] | None:
    """(kind, host, port, username, password) of a proxy URL, or None when it does not parse."""
    try:
        up = parse_upstream_url(value)
    except (ConfigError, ValueError, TypeError):
        return None
    return (up.kind, up.host, up.port, up.username, up.password)


def _same_upstream(value: str, upstream_value: str, upstream_identity: tuple | None) -> bool:
    """Same proxy URL as text, or (for proxy-variable values) the same parsed endpoint and credentials."""
    if _same_proxy_url(value, upstream_value):
        return True
    return upstream_identity is not None and _proxy_identity(value) == upstream_identity


#: Default ports by proxy URL scheme, for :func:`_lenient_proxy_endpoint` (detection only).
_LENIENT_DEFAULT_PORTS = {"http": 80, "https": 443, "socks": 1080, "socks4": 1080, "socks4a": 1080, "socks5": 1080, "socks5h": 1080}


def _lenient_proxy_endpoint(value: str) -> tuple[str, int | None, str | None, str | None] | None:
    """(host, port, username, password) of a proxy URL in any scheme, or None when it names no host.

    For detection only (sec4-4): unlike :func:`parse_upstream_url` it accepts
    ``https://``, ``socks4://`` and other schemes, and ignores paths, queries
    and fragments, because a variable the meter cannot use can still lead a
    client to the provider. Hosts are compared canonically (IP literals in one
    spelling). ``port`` is None when it is missing or invalid and the scheme
    has no known default.
    """
    raw = value.strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = "http://" + raw
    try:
        parts = urllib.parse.urlsplit(raw)
    except ValueError:
        return None
    host = clean_host(parts.hostname or "")
    if host is None:
        return None
    try:
        port = parts.port
    except ValueError:
        port = None
    if port is None:
        port = _LENIENT_DEFAULT_PORTS.get(parts.scheme.lower())
    username = urllib.parse.unquote(parts.username) if parts.username is not None else None
    password = urllib.parse.unquote(parts.password) if parts.password is not None else None
    return canonical_host(host), port, username, password


def unmetered_proxy_variables(env: Mapping[str, str], upstream: UpstreamConfig | None) -> list[str]:
    """Names of proxy variables in ``env`` that still lead to the provider around the meter.

    For a start-time note and a report warning after :func:`build_child_env`,
    which replaces only exact duplicates of the metered URL. A variable is
    named when it points at the upstream proxy's host on any port or scheme
    (providers serve HTTP CONNECT and SOCKS5 on several ports of one gateway,
    and ports often select sessions or countries, so it is left alone rather
    than rerouted), or when it carries the upstream's username and password on
    another host (sec3-7). Round 4 (sec4-4): values are parsed leniently, so
    ``https://`` (a provider's TLS proxy port), ``socks4://`` and URLs with a
    path count too. For a loopback upstream (a local relay) only the same port
    counts, since other local ports are other programs. Values equal to the
    meter's own URLs are never named. Returns names only, never values.
    """
    if upstream is None:
        return []
    meter_urls = [v for v in (env.get(ENV_PROXY_URL), env.get(ENV_AUTH_PROXY_URL)) if v]
    local_upstream = upstream.host == "localhost" or _is_loopback_host(upstream.host)
    upstream_host = canonical_host(upstream.host)
    out: list[str] = []
    for key, value in env.items():
        if not isinstance(value, str) or not is_proxy_variable_name(key) or key.startswith("SCRAPESCOPE_"):
            continue
        if any(_same_proxy_url(value, url) for url in meter_urls):
            continue
        parsed = _lenient_proxy_endpoint(value)
        if parsed is None:
            continue
        host, port, username, password = parsed
        same_host = host == upstream_host and (port == upstream.port or not local_upstream)
        same_credentials = bool(upstream.username) and (username, password) == (upstream.username, upstream.password)
        if same_host or same_credentials:
            out.append(key)
    return sorted(out)


def case_twin(name: str) -> str | None:
    """The other-case spelling of a standard proxy variable (``HTTPS_PROXY`` <-> ``https_proxy``), else None."""
    if name.upper() in _TWIN_NAMES and name in (name.upper(), name.lower()):
        return name.lower() if name.isupper() else name.upper()
    return None


_TWIN_NAMES = frozenset(n.upper() for n in PROXY_ENV_VARS)


def other_proxy_variables(env: Mapping[str, str], upstream_var: str | None) -> list[str]:
    """Standard proxy variables in ``env`` set to a proxy other than the meter (round 4, sec4-4).

    For ``run`` with an upstream, after :func:`build_child_env`: any of
    HTTP_PROXY, HTTPS_PROXY and ALL_PROXY, in either case, whose non-empty
    value is not one of the meter's URLs. Clients that read such a variable
    send that traffic around the meter: most importantly the case twin of the
    metered variable, because curl, Python (urllib, Requests, HTTPX) and Node
    read lowercase ``https_proxy`` before ``HTTPS_PROXY`` and Go reads the
    uppercase name first; ``HTTP_PROXY`` serves ``http://`` URLs and
    ``ALL_PROXY`` clients without a scheme-specific variable. Returns names
    only (the case twin of ``upstream_var`` first), never values.
    """
    meter_urls = [v for v in (env.get(ENV_PROXY_URL), env.get(ENV_AUTH_PROXY_URL)) if v]
    names = [n for n in PROXY_ENV_VARS if n != upstream_var]
    twin = case_twin(upstream_var) if upstream_var else None
    if twin in names:
        names.remove(twin)
        names.insert(0, twin)
    out: list[str] = []
    for name in names:
        value = env.get(name)
        if not isinstance(value, str) or not value.strip():
            continue
        if any(_same_proxy_url(value, url) for url in meter_urls):
            continue
        out.append(name)
    return out


def _is_loopback_host(host: str) -> bool:
    ip = ip_literal(host)
    return ip is not None and ip.is_loopback


def merge_no_proxy(*existing: str | None) -> str:
    """Union of existing NO_PROXY lists with 127.0.0.1, localhost and ::1 (order kept)."""
    seen: list[str] = []
    for value in existing:
        for item in (value or "").split(","):
            item = item.strip()
            if item and item not in seen:
                seen.append(item)
    for item in NO_PROXY_DEFAULTS:
        if item not in seen:
            seen.append(item)
    return ",".join(seen)


def build_child_env(
    base: Mapping[str, str],
    *,
    meter_url: str,
    events_path: str | None,
    upstream_var: str | None,
    env_all: bool = False,
    keep_urls: bool = False,
    auth_meter_url: str | None = None,
    upstream_id: str | None = None,
) -> dict[str, str]:
    """Environment for the child of ``scrapescope run``.

    Topology-preserving default: ``upstream_var`` (e.g. HTTPS_PROXY) gets the
    meter URL instead of the upstream URL. Any other variable whose value is the
    same upstream URL (e.g. a lowercase ``https_proxy`` duplicate) is replaced
    too, because leaving it would both bypass the meter and keep the credentials
    in the child. For proxy variables (``*_proxy`` names in any case, NO_PROXY
    excepted) "the same" means the same parsed endpoint and credentials: host
    case, the scheme-less ``user:pass@host:port`` form, an explicit default
    port and socks5 versus socks5h do not matter. Other variables are replaced
    only on an exact (trailing-slash-insensitive) match; everything else is
    untouched. :func:`unmetered_proxy_variables` finds proxy variables that
    still name the provider's host.

    ``env_all``: additionally sets HTTP_PROXY/HTTPS_PROXY/ALL_PROXY and their
    lowercase forms, NODE_USE_ENV_PROXY=1, and NO_PROXY/no_proxy to the union of
    their existing entries with 127.0.0.1,localhost,::1.

    Always sets SCRAPESCOPE_PROXY_URL (and SCRAPESCOPE_AUTH_PROXY_URL when
    given), SCRAPESCOPE_EVENTS when ``events_path`` is given, and
    SCRAPESCOPE_KEEP_URLS=1 only with ``keep_urls`` (removed otherwise), and
    SCRAPESCOPE_UPSTREAM_ID when ``upstream_id`` is given (the runner passes
    :func:`upstream_id` of its upstream; removed otherwise).
    """
    env = dict(base)
    if upstream_var is not None:
        upstream_value = base.get(upstream_var)
        env[upstream_var] = meter_url
        if upstream_value:
            identity = _proxy_identity(upstream_value)
            for key, value in base.items():
                if key == upstream_var or not isinstance(value, str):
                    continue
                if _same_upstream(value, upstream_value, identity if is_proxy_variable_name(key) else None):
                    env[key] = meter_url
    if env_all:
        for key in PROXY_ENV_VARS:
            env[key] = meter_url
        env["NODE_USE_ENV_PROXY"] = "1"
        merged = merge_no_proxy(base.get("NO_PROXY"), base.get("no_proxy"))
        env["NO_PROXY"] = merged
        env["no_proxy"] = merged
    env[ENV_PROXY_URL] = meter_url
    if auth_meter_url:
        env[ENV_AUTH_PROXY_URL] = auth_meter_url
    else:
        env.pop(ENV_AUTH_PROXY_URL, None)
    if events_path:
        env[ENV_EVENTS] = events_path
    else:
        env.pop(ENV_EVENTS, None)
    if keep_urls:
        env[ENV_KEEP_URLS] = "1"
    else:
        env.pop(ENV_KEEP_URLS, None)
    if upstream_id:
        env[ENV_UPSTREAM_ID] = upstream_id
    else:
        env.pop(ENV_UPSTREAM_ID, None)
    return env


# ---------------------------------------------------------------------------
# Test-only hooks (honoured only with SCRAPESCOPE_TESTING=1)
# ---------------------------------------------------------------------------

ConnectMap = dict[tuple[str, int], tuple[str, int]]


def testing_enabled(environ: Mapping[str, str] | None = None) -> bool:
    env = os.environ if environ is None else environ
    return env.get(ENV_TESTING) == "1"


def parse_connect_map(text: str) -> ConnectMap:
    """Parse ``{"host:port": "ip:port", ...}`` into ``{(host, port): (ip, port)}``.

    Keys are normalised with :func:`split_authority` (lowercase hosts, IPv6 in
    brackets). Raises ``ValueError`` on malformed input.
    """
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("connect map must be a JSON object")
    out: ConnectMap = {}
    for key, value in data.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError("connect map keys and values must be strings")
        out[split_authority(key)] = split_authority(value)
    return out


def connect_map_from_env(environ: Mapping[str, str] | None = None) -> ConnectMap | None:
    """The test connect map, or None unless SCRAPESCOPE_TESTING=1 and the map is set."""
    env = os.environ if environ is None else environ
    if not testing_enabled(env):
        return None
    text = env.get(ENV_TEST_CONNECT_MAP)
    if not text:
        return None
    return parse_connect_map(text)


def test_ca_from_env(environ: Mapping[str, str] | None = None) -> str | None:
    """Path of the test CA bundle, or None unless SCRAPESCOPE_TESTING=1."""
    env = os.environ if environ is None else environ
    if not testing_enabled(env):
        return None
    return env.get(ENV_TEST_CA) or None


test_ca_from_env.__test__ = False  # type: ignore[attr-defined]  # not a pytest test


# ---------------------------------------------------------------------------
# Private events file
# ---------------------------------------------------------------------------


@dataclass
class PrivateEventsFile:
    """A 0600 events file inside a fresh 0700 temporary directory."""

    directory: Path
    path: Path

    @classmethod
    def create(cls) -> PrivateEventsFile:
        directory = Path(tempfile.mkdtemp(prefix="scrapescope-"))
        os.chmod(directory, 0o700)
        path = directory / "events.jsonl"
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        os.chmod(path, 0o600)
        return cls(directory=directory, path=path)

    def cleanup(self) -> None:
        """Delete the file and its directory (ignores errors)."""
        shutil.rmtree(self.directory, ignore_errors=True)


__all__ = [
    "ConfigError",
    "ConnectMap",
    "ForwarderConfig",
    "HostRule",
    "PrivateEventsFile",
    "UpstreamConfig",
    "basic_auth_value",
    "budget_arg",
    "build_child_env",
    "case_twin",
    "connect_map_from_env",
    "format_authority",
    "format_size",
    "is_proxy_variable_name",
    "merge_no_proxy",
    "new_token",
    "other_proxy_variables",
    "parse_basic_auth",
    "parse_connect_map",
    "parse_size",
    "parse_upstream_url",
    "resolve_upstream",
    "size_arg",
    "split_authority",
    "synthetic_connect_sizes",
    "upstream_fingerprint",
    "upstream_id",
    "test_ca_from_env",
    "testing_enabled",
    "to_unit",
    "token_username",
    "unit_bytes",
    "unmetered_proxy_variables",
    "upstream_from_env",
]
