"""Requests and HTTPX hooks that append request metadata events ("hook-reported").

Contract: docs/dev/contracts.md section 5.3. Usage::

    session = scrapescope.helpers.hooks.instrument_requests(requests.Session())
    client = scrapescope.helpers.hooks.instrument_httpx(httpx.Client())
    # or: httpx.Client(event_hooks=scrapescope.helpers.hooks.httpx_event_hooks())

Every event has ``source`` ``requests``/``httpx``, ``resource_type
"http_client"``, ``frame "other"`` and ``is_navigation false``. Each response
(redirect hops included) gives one event; the hook-reported requests are the
``units`` of an HTTP-client job when no browser navigations exist.

Accuracy limits (these figures are *hook-reported*; the meter's tunnel totals
stay authoritative):

- HTTPX: ``encoded_body_bytes`` is the raw body bytes read from the transport
  (``response.num_bytes_downloaded``: after transfer decoding, before content
  decoding), taken when the response is closed, i.e. after the body is read.
  A streamed response that is never closed is recorded when it is garbage
  collected (or at interpreter exit).
- Requests: the response hook runs before Requests reads the body, so the
  event is written when the body is released (read to the end, or the
  response closed) or, for a response never closed, when it is garbage
  collected (or at interpreter exit). ``encoded_body_bytes`` is then the raw
  body bytes urllib3 read (``raw.tell()``: before content decoding), which for
  a ``stream=True`` response read only in part is what was read, not the
  declared ``Content-Length``. It is null when unknown: chunked responses
  (urllib3 does not count their bytes) and responses without a urllib3 body.
  Bytes a client or the kernel buffered beyond what was read are only in the
  tunnel totals.
- Header sizes are reconstructed as HTTP/1.1 header blocks from the header
  lists the client exposes; headers added below the client (for example by the
  proxy layer) and exact whitespace are not seen. On HTTP/2 and HTTP/3
  (``httpx.Client(http2=True)``, or an HTTP/2-capable urllib3) the header
  blocks are compressed on the wire (HPACK/QPACK), so both header sizes are
  written as unknown (null), as the Playwright helper does; attribution then
  applies its allowance for unknown headers.
- ``failed``: :func:`instrument_requests` and :func:`instrument_httpx` also wrap
  ``send`` to record requests that raised before any response. The plain
  ``httpx_event_hooks()`` dictionaries cannot see such failures. A body read
  that fails after the headers arrived is marked failed for HTTPX and not seen
  by the Requests hook.
- Hooks never read or store bodies, cookies or header values; only the
  presence of ``Cookie`` and ``Authorization`` request headers is recorded.

All functions are no-ops, with one ``RuntimeWarning`` per process, when
``SCRAPESCOPE_EVENTS`` is unset, and never raise into the user's code because
of scrapescope problems. Requests is imported lazily (it is not a core
dependency); HTTPX classes are resolved on first use.
"""

from __future__ import annotations

import contextvars
import functools
import os
import threading
import urllib.parse
import weakref
from collections.abc import Iterable
from typing import Any

from ..types import AttachEvent, EventSource, RequestEvent, clean_host
from . import events as _events

_INSTRUMENTED_ATTR = "_scrapescope_instrumented"
#: HTTP versions whose header blocks are compressed on the wire (HPACK/QPACK): header sizes unknown.
_MULTIPLEXED_VERSIONS = frozenset({"HTTP/2", "HTTP/2.0", "HTTP/3", "HTTP/3.0"})
_RESPONDED_ATTR = "_scrapescope_responded"
_START_ATTR = "_scrapescope_start"
_NO_BODY_STATUSES = frozenset({204, 304})

#: Inside an instrumented ``send``: the request of the current HTTPX redirect hop (set by the
#: request hook), for failure events. ``None`` outside an instrumented ``send``, so the plain
#: ``httpx_event_hooks()`` never keep a request referenced here.
_current_httpx_request: contextvars.ContextVar[Any] = contextvars.ContextVar(
    "scrapescope_httpx_request", default=None
)
_IN_SEND = object()


# ---------------------------------------------------------------------------
# Shared pieces
# ---------------------------------------------------------------------------


def _text_len(value: Any) -> int:
    if isinstance(value, (bytes, bytearray)):
        return len(value)
    return len(str(value).encode("utf-8", "replace"))


def _header_block_size(first_line_len: int, items: Iterable[tuple[Any, Any]]) -> int:
    """Bytes of an HTTP/1.1 header block: first line, ``name: value`` lines, blank line."""
    total = first_line_len + 2
    for name, value in items:
        total += _text_len(name) + 2 + _text_len(value) + 2
    return total + 2


def _names(headers: Any) -> set[str]:
    try:
        return {(k.decode("latin-1") if isinstance(k, bytes) else str(k)).lower() for k in headers.keys()}
    except Exception:
        return set()


def _int_header(headers: Any, name: str) -> int | None:
    try:
        value = headers.get(name)
    except Exception:
        return None
    if isinstance(value, bytes):
        value = value.decode("latin-1", "replace")
    if isinstance(value, str) and value.strip().isdigit():
        return _events.count(int(value.strip()))
    return None


def _emit_attach(source: EventSource) -> None:
    _events.emit(AttachEvent(ts=_events.now(), source=source, pid=os.getpid()))


def _request_event(
    *,
    source: EventSource,
    parts: _events.UrlParts,
    ts: float,
    method: str,
    status: int | None,
    failed: bool,
    encoded_body: int | None,
    response_headers: int | None,
    request_headers: int | None,
    request_body: int | None,
    header_names: set[str],
) -> RequestEvent:
    method = method.upper() if isinstance(method, str) else "GET"
    if not method.isascii() or not method.isalpha() or not 1 <= len(method) <= 16:
        method = "OTHER"
    return RequestEvent(
        ts=ts,
        source=source,
        host=parts.host,
        port=parts.port,
        scheme=parts.scheme,
        path=parts.path,
        method=method,
        resource_type="http_client",
        status=status if isinstance(status, int) and 0 <= status <= 999 else None,
        failed=failed,
        frame="other",
        is_navigation=False,
        encoded_body_bytes=encoded_body,
        response_header_bytes=response_headers,
        request_header_bytes=request_headers,
        request_body_bytes=request_body,
        sent_cookies="cookie" in header_names,
        sent_authorization="authorization" in header_names,
    )


def _mark(obj: Any, attr: str, value: Any = True) -> None:
    try:
        setattr(obj, attr, value)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------


def _written_host(request: Any, parts: _events.UrlParts) -> str:
    """The host as the URL spells it (the client's Host header), not the canonical form events carry."""
    try:
        return clean_host(urllib.parse.urlsplit(str(request.url)).hostname or "") or parts.host
    except Exception:
        return parts.host


def _requests_request_sizes(request: Any, parts: _events.UrlParts) -> tuple[int | None, int | None, set[str]]:
    headers = getattr(request, "headers", None) or {}
    names = _names(headers)
    method = str(getattr(request, "method", "GET") or "GET")
    try:
        target = request.path_url
    except Exception:
        target = "/"
    items = list(headers.items())
    if "host" not in names:
        items.append(("Host", _written_host(request, parts)))
    request_headers = _header_block_size(len(f"{method} {target} HTTP/1.1"), items)
    body = getattr(request, "body", None)
    if body is None:
        request_body: int | None = 0
    elif isinstance(body, (bytes, bytearray, str)):
        request_body = _text_len(body)
    else:
        request_body = _int_header(headers, "content-length")
    return _events.count(request_headers), request_body, names


class _RequestsRecord:
    """One Requests response whose event waits until its body is released or closed."""

    def __init__(self, fields: dict[str, Any]) -> None:
        self.fields = fields
        self._done = False
        self._lock = threading.Lock()

    def finish(self, raw: Any) -> None:
        """Write the event once, with the raw body bytes read so far; never raises."""
        with self._lock:
            if self._done:
                return
            self._done = True
        try:
            _events.emit(_request_event(encoded_body=_raw_bytes_read(raw), **self.fields))
        except Exception:
            pass


def _raw_bytes_read(raw: Any) -> int | None:
    """Body bytes urllib3 read from the connection (before content decoding), or None when unknown.

    urllib3 counts them in ``tell()`` except for chunked responses, whose chunks
    it reads without counting.
    """
    try:
        if raw is None or getattr(raw, "chunked", False):
            return None
        tell = getattr(raw, "tell", None)
        return _events.count(tell()) if callable(tell) else None
    except Exception:
        return None


def _raw_exhausted(raw: Any) -> bool:
    try:
        return bool(raw.isclosed())
    except Exception:
        return False


def _defer_until_released(response: Any, raw: Any, record: _RequestsRecord) -> bool:
    """Write ``record`` once the body has been read to the end or closed (or the response is collected).

    Wraps this response's ``raw.read`` (the event is written after the read
    that exhausts the body, once urllib3 has counted its bytes) and
    ``raw.close`` (Requests' ``Response.close()`` calls it for a body not read
    to the end). ``release_conn`` is not used: urllib3 calls it before it counts
    the last read. Returns False (nothing deferred) when ``raw`` has neither.
    """
    read = getattr(raw, "read", None)
    close = getattr(raw, "close", None)
    if not callable(read) or not callable(close):
        return False

    def read_wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return read(*args, **kwargs)
        finally:
            if _raw_exhausted(raw):
                record.finish(raw)

    def close_wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return close(*args, **kwargs)
        finally:
            record.finish(raw)

    try:
        raw.read = read_wrapper
        raw.close = close_wrapper
    except Exception:
        return False
    # A stream=True response that is never closed: record it when it is collected (or at exit).
    weakref.finalize(response, record.finish, raw)
    return True


def _requests_response_hook(response: Any, *args: Any, **kwargs: Any) -> None:
    """Requests ``response`` hook: one event per response. Returns None (response unchanged).

    The event is written when the body is released or closed (see the module
    docstring), so ``encoded_body_bytes`` is what was read, never the declared
    ``Content-Length``.
    """
    try:
        request = response.request
        parts = _events.url_parts(getattr(request, "url", None))
        if parts is None:
            return None
        method = str(getattr(request, "method", "GET") or "GET").upper()
        status = response.status_code
        raw = getattr(response, "raw", None)
        version = {10: "HTTP/1.0", 11: "HTTP/1.1", 20: "HTTP/2", 30: "HTTP/3"}.get(getattr(raw, "version", 11), "HTTP/1.1")
        request_headers, request_body, names = _requests_request_sizes(request, parts)
        response_headers: int | None = None
        if version in _MULTIPLEXED_VERSIONS:
            request_headers = None  # compressed on the wire; the rebuilt HTTP/1.1 text is not what was sent
        else:
            raw_headers = getattr(raw, "headers", None)
            items = list(raw_headers.items()) if raw_headers is not None else list(response.headers.items())
            response_headers = _events.count(
                _header_block_size(len(f"{version} {status} {response.reason or ''}"), items)
            )
        ts = _events.now()
        elapsed = getattr(response, "elapsed", None)
        if elapsed is not None:
            ts -= max(0.0, elapsed.total_seconds())
        _mark(request, _RESPONDED_ATTR)
        fields = {
            "source": "requests",
            "parts": parts,
            "ts": ts,
            "method": method,
            "status": status,
            "failed": False,
            "response_headers": response_headers,
            "request_headers": request_headers,
            "request_body": request_body,
            "header_names": names,
        }
        record = _RequestsRecord(fields)
        if method == "HEAD" or status in _NO_BODY_STATUSES or 100 <= status < 200:
            _events.emit(_request_event(encoded_body=0, **fields))
        elif getattr(response, "_content_consumed", False) or not _defer_until_released(response, raw, record):
            record.finish(raw)
    except Exception:
        pass
    return None


def _requests_failure(request: Any, ts: float) -> None:
    try:
        if getattr(request, _RESPONDED_ATTR, False):
            return
        parts = _events.url_parts(getattr(request, "url", None))
        if parts is None:
            return
        _mark(request, _RESPONDED_ATTR)
        _, request_body, names = _requests_request_sizes(request, parts)
        _events.emit(
            _request_event(
                source="requests",
                parts=parts,
                ts=ts,
                method=str(getattr(request, "method", "GET") or "GET"),
                status=None,
                failed=True,
                encoded_body=None,
                response_headers=None,
                request_headers=None,
                request_body=None,
                header_names=names,
            )
        )
    except Exception:
        pass


def instrument_requests(session: Any) -> Any:
    """Record one event per response of a ``requests.Session``; idempotent; returns the session.

    Appends a ``response`` hook (redirect hops included) and wraps
    ``session.send`` so that a request raising before any response (connection
    refused, proxy error, timeout) is recorded as failed; the exception is
    re-raised unchanged. Writes one ``attach`` event on install.
    """
    try:
        if session is None or getattr(session, _INSTRUMENTED_ATTR, False):
            return session
        if _events.events_path() is None:
            _events.warn_inactive()
            return session
        hooks = session.hooks.setdefault("response", [])
        if not isinstance(hooks, list):
            hooks = [hooks]
            session.hooks["response"] = hooks
        hooks.append(_requests_response_hook)
        original_send = session.send

        @functools.wraps(original_send)
        def send(request: Any, **kwargs: Any) -> Any:
            started = _events.now()
            try:
                return original_send(request, **kwargs)
            except Exception:
                _requests_failure(request, started)
                raise

        session.send = send
        _mark(session, _INSTRUMENTED_ATTR)
        _emit_attach("requests")
    except Exception:
        pass
    return session


# ---------------------------------------------------------------------------
# HTTPX
# ---------------------------------------------------------------------------


class _HttpxRecord:
    """Static fields of one HTTPX response; emitted once when its stream closes."""

    def __init__(self, parts: _events.UrlParts, ts: float, method: str, status: int | None,
                 response_headers: int | None, request_headers: int | None,
                 request_body: int | None, names: set[str]) -> None:
        self.parts = parts
        self.ts = ts
        self.method = method
        self.status = status
        self.response_headers = response_headers
        self.request_headers = request_headers
        self.request_body = request_body
        self.names = names
        self.body_bytes = 0
        self.failed = False
        self._done = False
        self._lock = threading.Lock()

    def add(self, chunk: Any) -> None:
        try:
            self.body_bytes += len(chunk)
        except Exception:
            pass

    def finish(self) -> None:
        with self._lock:
            if self._done:
                return
            self._done = True
        try:
            _events.emit(
                _request_event(
                    source="httpx",
                    parts=self.parts,
                    ts=self.ts,
                    method=self.method,
                    status=self.status,
                    failed=self.failed,
                    encoded_body=_events.count(self.body_bytes),
                    response_headers=self.response_headers,
                    request_headers=self.request_headers,
                    request_body=self.request_body,
                    header_names=self.names,
                )
            )
        except Exception:
            pass


@functools.cache
def _stream_classes() -> tuple[type, type]:
    """Byte-stream wrappers that count raw body bytes and emit on close (built lazily)."""
    import httpx

    class ObservedSyncStream(httpx.SyncByteStream):
        def __init__(self, inner: Any, record: _HttpxRecord) -> None:
            self._inner = inner
            self._record = record

        def __iter__(self) -> Any:
            try:
                for chunk in self._inner:
                    self._record.add(chunk)
                    yield chunk
            except Exception:
                self._record.failed = True
                raise

        def close(self) -> None:
            try:
                self._inner.close()
            finally:
                self._record.finish()

    class ObservedAsyncStream(httpx.AsyncByteStream):
        def __init__(self, inner: Any, record: _HttpxRecord) -> None:
            self._inner = inner
            self._record = record

        async def __aiter__(self) -> Any:
            try:
                async for chunk in self._inner:
                    self._record.add(chunk)
                    yield chunk
            except Exception:
                self._record.failed = True
                raise

        async def aclose(self) -> None:
            try:
                await self._inner.aclose()
            finally:
                self._record.finish()

    return ObservedSyncStream, ObservedAsyncStream


def _httpx_request_sizes(request: Any) -> tuple[int | None, int | None, set[str]]:
    headers = request.headers
    names = _names(headers)
    try:
        target_len = len(request.url.raw_path)
    except Exception:
        target_len = 1
    method = str(request.method)
    request_headers = _header_block_size(len(method) + 1 + target_len + len(" HTTP/1.1"), headers.raw)
    request_body = _int_header(headers, "content-length")
    if request_body is None:
        try:
            request_body = len(request.content)
        except Exception:  # streaming body not read
            request_body = None
    return _events.count(request_headers), request_body, names


def _httpx_record(response: Any) -> _HttpxRecord | None:
    request = response.request
    parts = _events.url_parts(str(request.url))
    if parts is None:
        return None
    started = getattr(request, _START_ATTR, None)
    ts = started if isinstance(started, float) else _events.now()
    status = response.status_code
    version = str(getattr(response, "http_version", "HTTP/1.1") or "HTTP/1.1")
    reason = str(getattr(response, "reason_phrase", "") or "")
    request_headers, request_body, names = _httpx_request_sizes(request)
    response_headers: int | None = None
    if version.upper() in _MULTIPLEXED_VERSIONS:
        request_headers = None  # HPACK/QPACK on the wire; the rebuilt HTTP/1.1 text is not what was sent
    else:
        response_headers = _events.count(
            _header_block_size(len(f"{version} {status} {reason}"), response.headers.raw)
        )
    _mark(request, _RESPONDED_ATTR)
    return _HttpxRecord(parts, ts, str(request.method), status, response_headers,
                        request_headers, request_body, names)


def _observe(response: Any, *, is_async: bool) -> None:
    record = _httpx_record(response)
    if record is None:
        return
    if getattr(response, "is_closed", False):
        record.body_bytes = int(getattr(response, "num_bytes_downloaded", 0) or 0)
        record.finish()
        return
    sync_cls, async_cls = _stream_classes()
    cls = async_cls if is_async else sync_cls
    response.stream = cls(response.stream, record)
    # Fallback for streamed responses that are never closed: record at garbage collection.
    weakref.finalize(response, record.finish)


def _httpx_request_hook(request: Any) -> None:
    try:
        _mark(request, _START_ATTR, _events.now())
        if _current_httpx_request.get() is not None:
            _current_httpx_request.set(request)
    except Exception:
        pass


def _httpx_response_hook(response: Any) -> None:
    try:
        _observe(response, is_async=False)
    except Exception:
        pass


async def _async_httpx_request_hook(request: Any) -> None:
    _httpx_request_hook(request)


async def _async_httpx_response_hook(response: Any) -> None:
    try:
        _observe(response, is_async=True)
    except Exception:
        pass


def _httpx_failure(request: Any, started: float) -> None:
    try:
        hop = _current_httpx_request.get()
        if hop is None or hop is _IN_SEND:
            hop = request
        if getattr(hop, _RESPONDED_ATTR, False):
            return
        parts = _events.url_parts(str(hop.url))
        if parts is None:
            return
        _mark(hop, _RESPONDED_ATTR)
        ts = getattr(hop, _START_ATTR, None)
        _events.emit(
            _request_event(
                source="httpx",
                parts=parts,
                ts=ts if isinstance(ts, float) else started,
                method=str(hop.method),
                status=None,
                failed=True,
                encoded_body=None,
                response_headers=None,
                request_headers=None,
                request_body=None,
                header_names=_names(hop.headers),
            )
        )
    except Exception:
        pass


def httpx_event_hooks() -> dict[str, list[Any]]:
    """``event_hooks`` for ``httpx.Client(event_hooks=...)``; writes one ``attach`` event.

    Returns empty hook lists (with the single warning) when
    ``SCRAPESCOPE_EVENTS`` is unset. Cannot see requests that fail before a
    response; use :func:`instrument_httpx` for that.
    """
    if _events.events_path() is None:
        _events.warn_inactive()
        return {"request": [], "response": []}
    _emit_attach("httpx")
    return {"request": [_httpx_request_hook], "response": [_httpx_response_hook]}


def async_httpx_event_hooks() -> dict[str, list[Any]]:
    """``event_hooks`` for ``httpx.AsyncClient(event_hooks=...)`` (async hook functions)."""
    if _events.events_path() is None:
        _events.warn_inactive()
        return {"request": [], "response": []}
    _emit_attach("httpx")
    return {"request": [_async_httpx_request_hook], "response": [_async_httpx_response_hook]}


def instrument_httpx(client: Any) -> Any:
    """Instrument an ``httpx.Client`` or ``httpx.AsyncClient`` in place; idempotent; returns it.

    Appends request and response hooks (async ones for ``AsyncClient``) and
    wraps ``client.send`` so a request that raises before any response is
    recorded as failed (the exception is re-raised unchanged). Writes one
    ``attach`` event on install.
    """
    try:
        if client is None or getattr(client, _INSTRUMENTED_ATTR, False):
            return client
        if _events.events_path() is None:
            _events.warn_inactive()
            return client
        import httpx

        is_async = isinstance(client, httpx.AsyncClient)
        hooks = client.event_hooks
        request_hooks = list(hooks.get("request", []))
        response_hooks = list(hooks.get("response", []))
        if is_async:
            request_hooks.append(_async_httpx_request_hook)
            response_hooks.append(_async_httpx_response_hook)
        else:
            request_hooks.append(_httpx_request_hook)
            response_hooks.append(_httpx_response_hook)
        client.event_hooks = {"request": request_hooks, "response": response_hooks}
        original_send = client.send
        if is_async:

            @functools.wraps(original_send)
            async def send(request: Any, **kwargs: Any) -> Any:
                started = _events.now()
                token = _current_httpx_request.set(_IN_SEND)
                try:
                    return await original_send(request, **kwargs)
                except Exception:
                    _httpx_failure(request, started)
                    raise
                finally:
                    _current_httpx_request.reset(token)

        else:

            @functools.wraps(original_send)
            def send(request: Any, **kwargs: Any) -> Any:  # type: ignore[misc]
                started = _events.now()
                token = _current_httpx_request.set(_IN_SEND)
                try:
                    return original_send(request, **kwargs)
                except Exception:
                    _httpx_failure(request, started)
                    raise
                finally:
                    _current_httpx_request.reset(token)

        client.send = send
        _mark(client, _INSTRUMENTED_ATTR)
        _emit_attach("httpx")
    except Exception:
        pass
    return client


__all__ = ["async_httpx_event_hooks", "httpx_event_hooks", "instrument_httpx", "instrument_requests"]
