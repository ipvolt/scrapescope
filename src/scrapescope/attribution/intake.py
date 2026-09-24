"""Reading the helper events file (JSONL, v=1) written by scrapescope.helpers.

The file is untrusted input (any process that knows the path can append to
it), so every line goes through :func:`scrapescope.types.parse_event`, which
validates types, charsets and lengths. Invalid lines, lines longer than
:data:`scrapescope.types.MAX_EVENT_LINE_BYTES` and lines whose ``v`` is not 1
are dropped and counted.

Memory: every accepted event is kept as an object until attribution has run.
Repeated strings (host, source, scheme, method, type, frame, context and, up
to a bound, paths) are shared between events, which keeps an ordinary request
event at about 0.5 KB (measured with CPython 3.12: about 470 bytes each). At
:data:`MAX_EVENTS` that is about 0.5 GB, more with ``--keep-urls`` paths that
differ per request, plus the attribution's own working lists. Reading stops
after :data:`MAX_EVENTS` accepted events, so a runaway writer cannot grow
memory without bound; the lines past the cap are not read and are counted in
``dropped`` and in ``capped``, and attribution then says in a warning that its
figures cover only the events read.

A request line may carry the helpers' ``no_network`` marker (``fulfilled``,
``aborted`` or ``blocked``: a request answered or stopped by request
interception, or blocked by the browser before anything was sent). Such a line
becomes a :class:`NoNetworkRequestEvent`, whose ``hit_network`` is False, so
attribution leaves it out of the status histogram, the allocation and the
bypass checks. Any other marker value is ignored (the event stays an ordinary
network request).
"""

from __future__ import annotations

import errno
import json
import os
import stat
from dataclasses import dataclass, field, fields
from typing import Any

from ..helpers.events import NO_NETWORK_KEY, NO_NETWORK_KINDS
from ..types import MAX_EVENT_LINE_BYTES, HelperEvent, RequestEvent, parse_event

#: Upper bound on accepted events per file; further lines are counted as dropped (and as capped).
MAX_EVENTS = 1_000_000
#: String fields whose values are shared between events (see the module docstring).
_SHARED_FIELDS = ("kind", "source", "host", "scheme", "path", "method", "resource_type", "frame", "context",
                  "browser")
#: Distinct strings shared per file; past it, new values are kept per event (unique paths gain nothing).
_SHARED_MAX = 65_536


@dataclass
class NoNetworkRequestEvent(RequestEvent):
    """A request event whose request never reached the network (see the module docstring)."""

    #: ``fulfilled`` | ``aborted`` | ``blocked``
    no_network: str = "blocked"

    @property
    def hit_network(self) -> bool:
        return False


def _with_marker(event: HelperEvent, obj: Any) -> HelperEvent:
    """Turn a request event whose line carries a valid ``no_network`` marker into a NoNetworkRequestEvent."""
    if type(event) is not RequestEvent or not isinstance(obj, dict):
        return event
    kind = obj.get(NO_NETWORK_KEY)
    if not isinstance(kind, str) or kind not in NO_NETWORK_KINDS:
        return event
    values = {f.name: getattr(event, f.name) for f in fields(RequestEvent) if f.init}
    return NoNetworkRequestEvent(**values, no_network=kind)


def _share_strings(event: HelperEvent, pool: dict[str, str]) -> HelperEvent:
    """Replace the event's repeated string values with one shared object each (saves memory, same values)."""
    values = getattr(event, "__dict__", None)
    if values is None:
        return event
    for name in _SHARED_FIELDS:
        value = values.get(name)
        if type(value) is not str:
            continue
        shared = pool.get(value)
        if shared is not None:
            values[name] = shared
        elif len(pool) < _SHARED_MAX:
            pool[value] = value
    return event


@dataclass
class EventsLog:
    """Parsed events file."""

    events: list[HelperEvent] = field(default_factory=list)
    #: Invalid, oversized or wrong-version lines that were dropped, plus the lines past the cap.
    dropped: int = 0
    #: Non-blank lines after the cap (``max_events``) was reached; not read, counted in ``dropped`` too.
    capped: int = 0
    #: Why the file could not be read at all (e.g. permission denied), else None.
    #: A missing file is not an error: it simply yields an empty log.
    error: str | None = None


#: Open flags: never block on a FIFO or device, never follow a symlink the job put in place.
_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOCTTY", 0)
)
NOT_REGULAR_ERROR = "events path is not a regular file"


def _open_regular(path: str | os.PathLike[str]) -> int:
    """Open ``path`` read-only without blocking or following a symlink; raise unless it is a regular file.

    The events file is untrusted: the job could replace it with a FIFO (a plain
    ``open`` would block forever), a device or a symlink. The check is made on
    the opened descriptor (``fstat``), so a swap after the check cannot matter.
    """
    fd = os.open(path, _OPEN_FLAGS)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise IsADirectoryError(NOT_REGULAR_ERROR)
        if hasattr(os, "set_blocking"):
            os.set_blocking(fd, True)
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_events(path: str | os.PathLike[str], *, max_events: int = MAX_EVENTS) -> EventsLog:
    """Read the JSONL events file; a missing file gives an empty log.

    Blank lines are ignored. A final line without a newline (a writer killed
    mid-write) is parsed like any other and dropped if invalid. Never raises for
    file content and never blocks: an unreadable path (a FIFO, device, directory
    or symlink, permission denied) gives an empty log with ``error`` set to a
    short reason (never the path).
    """
    log = EventsLog()
    pool: dict[str, str] = {}
    try:
        fd = _open_regular(path)
    except FileNotFoundError:
        return log
    except IsADirectoryError:
        log.error = NOT_REGULAR_ERROR
        return log
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK, errno.ENXIO):  # symlink (O_NOFOLLOW) or socket
            log.error = NOT_REGULAR_ERROR
        else:
            log.error = f"events file unreadable ({type(exc).__name__})"
        return log
    with os.fdopen(fd, "rb") as handle:
        try:
            while True:
                line = handle.readline(MAX_EVENT_LINE_BYTES + 2)
                if not line:
                    break
                if not line.endswith(b"\n") and len(line) > MAX_EVENT_LINE_BYTES:
                    # Oversized line: count it once and skip to its end.
                    log.dropped += 1
                    if len(log.events) >= max_events:
                        log.capped += 1
                    while line and not line.endswith(b"\n"):
                        line = handle.readline(1 << 16)
                    continue
                body = line.rstrip(b"\r\n")
                if not body.strip():
                    continue
                if len(log.events) >= max_events:
                    log.dropped += 1
                    log.capped += 1
                    continue
                if len(body) > MAX_EVENT_LINE_BYTES:
                    log.dropped += 1
                    continue
                try:
                    obj = json.loads(body.decode("utf-8"))
                    log.events.append(_share_strings(_with_marker(parse_event(obj), obj), pool))
                except (ValueError, TypeError, UnicodeDecodeError, RecursionError):
                    log.dropped += 1
        except OSError as exc:
            log.error = f"events file unreadable ({type(exc).__name__})"
    return log


__all__ = ["MAX_EVENTS", "NOT_REGULAR_ERROR", "EventsLog", "NoNetworkRequestEvent", "read_events"]
