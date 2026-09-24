"""Events-file writer shared by the Playwright helper and the HTTP-client hooks.

The runner (``scrapescope run``) creates a private events file (0600 inside a
0700 temporary directory) and passes its path to the job as
``SCRAPESCOPE_EVENTS``. Helpers append one JSON line per event; the runner reads
the file after the job exits. Contract: docs/dev/contracts.md sections 4 and 5.1.

What this writer guarantees:

- It opens the EXISTING file with ``O_WRONLY | O_APPEND`` (plus ``O_NOFOLLOW``
  and ``O_CLOEXEC`` where available). It never creates the file, never follows a
  symlink in the last path component and refuses anything that is not a
  regular file.
- Each line is built with :func:`scrapescope.types.event_to_json_line`,
  validated with :func:`scrapescope.types.parse_event` (so the reader will not
  drop it), capped at :data:`scrapescope.types.MAX_EVENT_LINE_BYTES` and written
  with ONE ``os.write`` call. With ``O_APPEND`` concurrent writers (threads,
  forked workers) do not overwrite each other's lines.
- Only network schemes (http, https, ws, wss) are written; ``data:``, ``blob:``,
  ``about:``, ``chrome:`` and extension URLs never are. Paths are written only
  when ``SCRAPESCOPE_KEEP_URLS=1`` and never contain a query string or fragment.
  Bodies, cookies, header values and credentials are never part of an event.
- It never raises into the caller: failures are swallowed with one
  ``RuntimeWarning`` per process.

When ``SCRAPESCOPE_EVENTS`` is unset every helper is a no-op and one
``RuntimeWarning`` is issued per process (see :func:`warn_inactive`).
"""

from __future__ import annotations

import dataclasses
import itertools
import json
import os
import stat
import threading
import time
import urllib.parse
import warnings
from dataclasses import dataclass

from ..config import ENV_EVENTS, ENV_KEEP_URLS
from ..types import (
    MAX_EVENT_LINE_BYTES,
    HelperEvent,
    RequestEvent,
    canonical_host,
    clean_host,
    clean_path,
    event_to_json_line,
    parse_event,
)

#: Schemes helpers ever write (everything else, e.g. data: or blob:, is skipped).
NETWORK_SCHEMES: frozenset[str] = frozenset({"http", "https", "ws", "wss"})
#: Optional key of a request line for a request that never reached the network. Its value is one of
#: :data:`NO_NETWORK_KINDS`. ``types.parse_event`` ignores unknown keys, so the line stays valid for
#: any reader; ``scrapescope.attribution.read_events`` reads the marker.
NO_NETWORK_KEY = "no_network"
#: ``fulfilled``: answered by request interception (Playwright ``route.fulfill``, ``route_from_har``);
#: ``aborted``: failed by ``route.abort``; ``blocked``: stopped by the browser before any request was sent
#: (mixed content, CSP, a DevTools/CDP block list such as ``Network.setBlockedURLs``, an extension).
NO_NETWORK_KINDS: frozenset[str] = frozenset({"fulfilled", "aborted", "blocked"})
_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}
#: Largest integer JSON consumers (the viewer) represent exactly.
_MAX_SAFE_INT = 2**53 - 1

INACTIVE_MESSAGE = (
    "scrapescope helpers inactive: {var} is not set; run the job under `scrapescope run`"
)
WRITE_FAILED_MESSAGE = (
    "scrapescope helpers: could not append to the events file; some request metadata "
    "will be missing from the report"
)

_lock = threading.Lock()
_counter = itertools.count(1)
_warned_inactive = False
_warned_write = False
#: (pid, path, fd) of the cached descriptor; re-opened after fork or a path change.
_fd_cache: tuple[int, str, int] | None = None


def _after_fork_in_child() -> None:
    """A forked child gets a fresh lock (the parent's may have been held by another thread)."""
    global _lock
    _lock = threading.Lock()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------


def events_path() -> str | None:
    """The events file path from ``SCRAPESCOPE_EVENTS``, or None when unset or empty."""
    value = os.environ.get(ENV_EVENTS)
    return value or None


def enabled() -> bool:
    """True when ``SCRAPESCOPE_EVENTS`` is set and names an existing regular file."""
    path = events_path()
    if path is None:
        return False
    try:
        return stat.S_ISREG(os.stat(path).st_mode)
    except OSError:
        return False


def keep_urls() -> bool:
    """True when ``SCRAPESCOPE_KEEP_URLS == "1"`` (then paths, never queries, are written)."""
    return os.environ.get(ENV_KEEP_URLS) == "1"


def new_context_id() -> str:
    """Opaque per-process context id, ``f"{os.getpid()}-{n}"`` (n counts from 1)."""
    return f"{os.getpid()}-{next(_counter)}"


def warn_inactive(variable: str = ENV_EVENTS) -> None:
    """Issue the single per-process "helpers inactive" ``RuntimeWarning``.

    Never raises, even when warnings are configured as errors.
    """
    global _warned_inactive
    with _lock:
        if _warned_inactive:
            return
        _warned_inactive = True
    try:
        warnings.warn(INACTIVE_MESSAGE.format(var=variable), RuntimeWarning, stacklevel=3)
    except Exception:
        pass


def _warn_write_failure() -> None:
    global _warned_write
    with _lock:
        if _warned_write:
            return
        _warned_write = True
    try:
        warnings.warn(WRITE_FAILED_MESSAGE, RuntimeWarning, stacklevel=3)
    except Exception:  # warnings configured as errors must not reach the user's code
        pass


def _reset_for_tests() -> None:
    """Forget warnings and the cached descriptor (tests only)."""
    global _warned_inactive, _warned_write, _fd_cache
    with _lock:
        _warned_inactive = False
        _warned_write = False
        if _fd_cache is not None:
            try:
                os.close(_fd_cache[2])
            except OSError:
                pass
        _fd_cache = None


# ---------------------------------------------------------------------------
# URL handling shared by the helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class UrlParts:
    """The parts of a request URL helpers may record (never the query or fragment)."""

    scheme: str
    #: Cleaned (:func:`scrapescope.types.clean_host`); an IP literal in the meter's canonical spelling.
    host: str
    port: int | None
    #: Only when SCRAPESCOPE_KEEP_URLS=1; cleaned with :func:`scrapescope.types.clean_path`.
    path: str | None


def url_parts(url: object) -> UrlParts | None:
    """Split a URL into what an event may carry, or None for non-network URLs.

    Returns None for ``data:``, ``blob:``, ``about:``, ``chrome:``, extension and
    any other non-network scheme, and for URLs whose host fails
    :func:`scrapescope.types.clean_host`. An IP-literal host is written in its
    canonical spelling (:func:`scrapescope.types.canonical_host`: ``1.2.3.04``,
    ``[2001:db8:0:0::1]`` and Chromium's ``[::ffff:102:304]`` become ``1.2.3.4``
    and ``2001:db8::1``), the spelling the meter records tunnels under, so
    attribution matches the request to the tunnel that carried it. The port is
    the explicit port or the scheme default. The path is included only with
    ``SCRAPESCOPE_KEEP_URLS=1`` and never includes the query string or fragment.
    """
    if not isinstance(url, str) or not url:
        return None
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in NETWORK_SCHEMES:
        return None
    host = clean_host(parts.hostname or "")
    if host is None:
        return None
    host = canonical_host(host)
    try:
        port = parts.port
    except ValueError:
        port = None
    if port is None or not 0 < port < 65536:
        port = _DEFAULT_PORTS[scheme]
    path = clean_path(parts.path or "/") if keep_urls() else None
    return UrlParts(scheme=scheme, host=host, port=port, path=path)


def count(value: object) -> int | None:
    """A non-negative JSON-safe byte count, or None for unknown or negative values."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if value != value or value < 0:  # NaN or negative (DevTools reports -1 / negatives)
        return None
    return min(int(value), _MAX_SAFE_INT)


def now() -> float:
    """Wall-clock timestamp used for events (``time.time()``)."""
    return time.time()


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------


def _open_flags() -> int:
    flags = os.O_WRONLY | os.O_APPEND
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    return flags


def _descriptor(path: str) -> int:
    """The cached append-only descriptor for ``path`` (opened without O_CREAT)."""
    global _fd_cache
    pid = os.getpid()
    with _lock:
        cached = _fd_cache
        if cached is not None and cached[0] == pid and cached[1] == path:
            return cached[2]
        if cached is not None:
            # Another path, or we are a forked child holding the parent's copy.
            try:
                os.close(cached[2])
            except OSError:
                pass
            _fd_cache = None
        fd = os.open(path, _open_flags())
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError("events path is not a regular file")
        except BaseException:
            os.close(fd)
            raise
        _fd_cache = (pid, path, fd)
        return fd


def _drop_descriptor(fd: int) -> None:
    global _fd_cache
    with _lock:
        if _fd_cache is not None and _fd_cache[2] == fd:
            _fd_cache = None
            try:
                os.close(fd)
            except OSError:
                pass


def encode_event(event: HelperEvent, *, no_network: str | None = None) -> bytes | None:
    """The validated line for ``event`` (newline included), or None if it must not be written.

    Enforces the writer rules: network schemes only, no path unless
    ``SCRAPESCOPE_KEEP_URLS=1`` (and then query-free), a line the reader's
    :func:`scrapescope.types.parse_event` accepts, and at most
    ``MAX_EVENT_LINE_BYTES`` bytes. An over-long request line is retried
    without its path before being dropped. ``no_network`` (one of
    :data:`NO_NETWORK_KINDS`, request events only) adds the
    :data:`NO_NETWORK_KEY` marker.
    """
    marker = no_network if isinstance(event, RequestEvent) and no_network in NO_NETWORK_KINDS else None
    if isinstance(event, RequestEvent):
        if event.scheme not in NETWORK_SCHEMES:
            return None
        if event.path is not None:
            path = clean_path(event.path) if keep_urls() else None
            event = dataclasses.replace(event, path=path)
    candidates = [event]
    if isinstance(event, RequestEvent) and event.path is not None:
        candidates.append(dataclasses.replace(event, path=None))
    for candidate in candidates:
        try:
            line = event_to_json_line(candidate)
            if marker is not None:
                data = json.loads(line)
                data[NO_NETWORK_KEY] = marker
                line = json.dumps(data, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n"
            parse_event(json.loads(line))
        except (ValueError, TypeError):
            return None
        data = line.encode("ascii")
        if len(data) - 1 <= MAX_EVENT_LINE_BYTES:
            return data
    return None


def emit(event: HelperEvent, *, no_network: str | None = None) -> None:
    """Append one event line to the events file; never raises.

    No-op (with the single per-process warning) when ``SCRAPESCOPE_EVENTS`` is
    unset. Events that fail validation are dropped silently; I/O failures are
    swallowed with one ``RuntimeWarning`` per process. ``no_network`` marks a
    request that never reached the network (see :data:`NO_NETWORK_KINDS`).
    """
    path = events_path()
    if path is None:
        warn_inactive()
        return
    try:
        data = encode_event(event, no_network=no_network)
        if data is None:
            return
        fd = _descriptor(path)
        try:
            os.write(fd, data)
        except OSError:
            _drop_descriptor(fd)
            raise
    except Exception:
        _warn_write_failure()


__all__ = [
    "INACTIVE_MESSAGE",
    "NETWORK_SCHEMES",
    "NO_NETWORK_KEY",
    "NO_NETWORK_KINDS",
    "UrlParts",
    "count",
    "emit",
    "enabled",
    "encode_event",
    "events_path",
    "keep_urls",
    "new_context_id",
    "now",
    "url_parts",
    "warn_inactive",
]
