"""Loopback listeners, request-form checks, credentials and HTTP/1.1 framing.

Contract: docs/dev/contracts.md sections 3.1-3.5 and 3.9.

The forwarder is an HTTP proxy on 127.0.0.1 that the user's job talks to
instead of its real proxy. It accepts only ``CONNECT host:port`` and
absolute-form ``http://`` requests, chains each client connection to exactly
one upstream connection (HTTP CONNECT proxy, SOCKS5 proxy with remote DNS, or
the target itself in direct/sizing mode), never terminates TLS, and counts
every byte on the upstream socket (see :mod:`scrapescope.forwarder.meter`).

Accuracy and limits, stated plainly:

- Counts are "tunnel-measured": exact for the socket the meter owns, but a
  provider may meter differently (for example its own error replies or the
  CONNECT line). They are not a bill.
- The meter stops at its own count: when the budget trips, bytes already in
  flight at the provider can add roughly (open tunnels x a few MB) to what it
  bills.
- Plain HTTP is re-framed by h11 (chunk sizes may differ from the client's), so
  upstream byte counts for plain HTTP can differ slightly from the client's own
  socket counts. CONNECT tunnels are relayed byte for byte.
- Sizing mode (direct route) sends plain-HTTP requests to the target in
  origin form without ``Proxy-Authorization``. A provider would receive the
  absolute-form target (``http://host[:port]`` more per request) and the
  credentials line on every request; no estimate is added for that, and
  ``with_connect_estimated`` reflects CONNECT tunnels only (meas3-9, documented
  in docs/accuracy.md).
- Plain HTTP over an HTTP CONNECT upstream keeps its provider connection when a
  keep-alive client switches host, as the client itself would (round 3,
  meas3-3): the meter starts a new TunnelRecord at the request boundary
  (``continued_from``) instead of a new provider connection, so providers that
  rotate exits or bind sessions per connection see the job's own pattern.

Logging goes to the ``scrapescope.forwarder`` logger (DEBUG, off by default)
and never contains headers, paths, queries, credentials or anything about the
upstream proxy (host, port, username, password). OS exception messages are
never logged because they can contain socket addresses.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import logging
import re
import socket
import struct
import threading
import time
import traceback
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

import h11

from ..config import (
    METER_HOST,
    PROXY_REALM,
    SYNTHETIC_CONNECT_RESPONSE,
    TOKEN_PREFIX,
    TOKEN_SEPARATOR,
    ConnectMap,
    ForwarderConfig,
    basic_auth_value,
    parse_basic_auth,
    split_authority,
)
from ..types import (
    TUNNEL_OK,
    AuthUse,
    BudgetEvent,
    Listener,
    MeterSnapshot,
    Route,
    canonical_host,
    embedded_ipv4,
    host_glob_match,
)
from . import upstream as _up
from .meter import Meter, Tunnel, TunnelAborted
from .upstream import UpstreamConnection, UpstreamError

logger = logging.getLogger("scrapescope.forwarder")

#: Relay read size.
CHUNK = 256 * 1024
#: Largest request head (and response head) accepted.
MAX_HEAD = 256 * 1024
#: StreamReader limit on client sockets.
CLIENT_READ_LIMIT = 256 * 1024
#: After a refusal, how long the meter keeps reading so the reply is not lost to a TCP reset.
LINGER_S = 1.0
#: A client connection that has not delivered one complete request head this many seconds after it
#: was accepted is closed (sec2-6). Real clients send CONNECT or a request as soon as they connect.
#: The 600 s idle timeout applies once a request arrived.
FIRST_REQUEST_TIMEOUT_S = 60.0
LINGER_MAX_BYTES = 256 * 1024

_REASONS = {
    400: "Bad Request",
    403: "Forbidden",
    407: "Proxy Authentication Required",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
}

#: Fixed one-line bodies for the meter's own replies; they never echo request content.
_MESSAGES = {
    "bad-request": "malformed proxy request",
    "https-absolute-form": "absolute-form https:// is not supported; use CONNECT (no TLS origination)",
    "self-loop": "refusing a request to the meter itself",
    "token-required": "proxy token required",
    "bad-token": "wrong proxy token",
    "auth-challenge": "proxy credentials required",
    "budget": "byte budget tripped; new requests are refused",
    "denied": "host denied by a scrapescope deny rule",
    "upstream-unreachable": "upstream proxy unreachable",
    "upstream-timeout": "upstream proxy timed out",
    "upstream-closed": "upstream closed the connection",
    "upstream-protocol-error": "upstream sent an invalid reply",
    "socks-auth-failed": "SOCKS5 authentication failed",
    "socks-no-method": "SOCKS5 upstream accepted no offered method",
    "socks-auth-unsupported": "these proxy credentials cannot be sent over SOCKS5",
    "dns-failed": "target name did not resolve",
    "connect-refused": "target refused the connection",
    "connect-timeout": "target connection timed out",
    "private-address": "refusing a direct connection to this machine or a loopback, private, link-local "
    "or same-link address (--allow-private-targets permits it)",
    "local-limit": "the meter ran out of file descriptors (open-files limit); raise it with ulimit -n",
    "internal-error": "scrapescope internal error",
}

_BARE_403 = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"


def meter_response(
    status: int,
    error_code: str | None,
    *,
    extra_headers: tuple[tuple[str, str], ...] = (),
    head_only: bool = False,
) -> bytes:
    """The meter's own reply: fixed headers, ``X-Scrapescope-Error`` and a one-line body.

    ``error_code=None`` gives the bare origin-form 403 (no body, no scrapescope
    headers), which is the DNS-rebinding defence: the meter serves no readable
    page to anything that is not a proxy request.
    """
    if error_code is None:
        return _BARE_403
    message = _MESSAGES.get(error_code)
    if message is None:
        if error_code.startswith("socks-reply-"):
            message = "SOCKS5 upstream refused the connection"
        else:
            message = "request refused"
    body = f"scrapescope: {message}\n".encode("ascii")
    lines = [
        f"HTTP/1.1 {status} {_REASONS.get(status, 'Error')}",
        "Content-Type: text/plain; charset=utf-8",
        f"Content-Length: {len(body)}",
        "Connection: close",
        f"X-Scrapescope-Error: {error_code}",
    ]
    lines.extend(f"{name}: {value}" for name, value in extra_headers)
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")
    return head if head_only else head + body


class ForwarderError(Exception):
    """The forwarder failed to start (port in use, bad config) or crashed. CLI exit 88."""


# ---------------------------------------------------------------------------- request decisions


@dataclass(frozen=True)
class _Refusal:
    status: int
    #: Key in MeterSnapshot.refused (None for deny-rule refusals, which become TunnelRecords).
    reason: str | None
    #: X-Scrapescope-Error value, or None for the bare 403.
    error_code: str | None
    extra_headers: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class _Creds:
    """What to present upstream for one request."""

    auth: AuthUse
    #: HTTP upstream: Proxy-Authorization value to send (None = send none).
    header_value: bytes | None
    #: SOCKS5 upstream: RFC 1929 credentials (None = no-auth method).
    socks: tuple[str, str] | None
    #: The client sent a non-Basic Proxy-Authorization we pass through (HTTP upstream only).
    non_basic: bool = False


@dataclass(frozen=True)
class _Route:
    host: str
    port: int
    kind: str  # "connect" | "http"
    route: Route
    creds: _Creds
    rule: str | None
    #: Plain HTTP only: origin-form target for SOCKS5/direct routes.
    origin_target: bytes | None = None
    #: Plain HTTP only: authority text for an added Host header.
    authority: bytes = b""


class _BadRequest(Exception):
    pass


class _ClientGone(Exception):
    pass


class _UpstreamGone(Exception):
    """The upstream closed, reset or broke framing during a plain-HTTP exchange.

    ``received`` says whether any byte of the response to the current request
    arrived before that; see :meth:`_ClientConn._handle_http` for the
    keep-alive race it decides.
    """

    def __init__(self, head_sent: bool, protocol: bool = False, reset: bool = False, *, received: bool = True) -> None:
        super().__init__("upstream closed")
        self.head_sent = head_sent
        self.protocol = protocol
        self.reset = reset
        self.received = received


class _UpstreamReset(Exception):
    """The upstream connection was reset (not closed) during a raw relay."""


class _ClientReset(Exception):
    """The client connection was reset (not closed) during a raw relay."""


def _reset_transport(transport: asyncio.BaseTransport) -> None:
    """Close ``transport`` with a TCP reset (SO_LINGER 0) instead of a FIN.

    Used to pass a reset on: a clean close would tell the other side that a
    close-delimited body ended normally.
    """
    with contextlib.suppress(Exception):
        sock = transport.get_extra_info("socket")
        if sock is not None:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    with contextlib.suppress(Exception):
        transport.abort()  # type: ignore[attr-defined]


#: Request headers that are never removed as hop-by-hop: h11 re-frames the body
#: from the framing headers, Host is set from the target, Proxy-Authorization
#: follows the credential table, and Upgrade/TE are forwarded with their option.
_NEVER_STRIPPED = frozenset({b"host", b"content-length", b"transfer-encoding", b"proxy-authorization", b"upgrade", b"te"})
#: Hop-by-hop request headers removed even when Connection does not list them.
_ALWAYS_STRIPPED = frozenset({b"keep-alive", b"proxy-connection"})
#: Connection options that still apply to the forwarded request.
_KEPT_OPTIONS = frozenset({b"close", b"upgrade", b"te"})


def _strip_hop_by_hop(headers: list[tuple[bytes, bytes]]) -> list[tuple[bytes, bytes]]:
    """Remove hop-by-hop request headers before forwarding (RFC 9110 section 7.6.1).

    Drops Keep-Alive, Proxy-Connection and every header the Connection field
    names, except the framing, Host, credential, Upgrade and TE headers, and
    rewrites Connection to the options that still apply (close, upgrade, te).
    """
    options: list[bytes] = []
    for name, value in headers:
        if name.lower() == b"connection":
            for token in value.split(b","):
                token = token.strip()
                if token and token.lower() not in (o.lower() for o in options):
                    options.append(token)
    drop = set(_ALWAYS_STRIPPED)
    drop.update(o.lower() for o in options if o.lower() not in _NEVER_STRIPPED)
    kept = [o for o in options if o.lower() in _KEPT_OPTIONS]
    out: list[tuple[bytes, bytes]] = []
    placed = False
    for name, value in headers:
        lname = name.lower()
        if lname == b"connection":
            if kept and not placed:
                out.append((name, b", ".join(kept)))
                placed = True
            continue
        if lname in drop:
            continue
        out.append((name, value))
    return out


def _set_host(headers: list[tuple[bytes, bytes]], authority: bytes) -> list[tuple[bytes, bytes]]:
    """Make the Host header the request target's authority (RFC 9112 section 3.2.2).

    Routing, deny rules and attribution use the absolute-form target, so the
    forwarded Host must name the same host; a foreign Host could otherwise
    reach a denied site on a shared address.
    """
    out: list[tuple[bytes, bytes]] = []
    placed = False
    for name, value in headers:
        if name.lower() == b"host":
            if not placed:
                out.append((name, authority))
                placed = True
            continue
        out.append((name, value))
    if not placed:
        out.insert(0, (b"Host", authority))
    return out


_AUTHORITY_SAFE = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:[]")


def _inject_host(raw: bytes) -> bytes | None:
    """Add a ``Host`` header (as the LAST header) to a head that lacks one.

    Some clients (for example Python 3.11's http.client) send ``CONNECT``
    without ``Host``, which h11 rejects for HTTP/1.1. The authority comes from
    the request target and is restricted to a safe character set.
    """
    line_end = raw.find(b"\r\n")
    head_end = raw.find(b"\r\n\r\n")
    if line_end < 0 or head_end < 0:
        return None
    parts = raw[:line_end].split(b" ")
    if len(parts) != 3:
        return None
    method, target = parts[0], parts[1]
    if method == b"CONNECT":
        authority = target
    elif target[:7].lower() == b"http://":
        rest = target[7:]
        cut = len(rest)
        for sep in (b"/", b"?", b"#"):
            idx = rest.find(sep)
            if idx >= 0:
                cut = min(cut, idx)
        authority = rest[:cut]
    else:
        return None
    if not authority or not all(c in _AUTHORITY_SAFE for c in authority):
        return None
    insert_at = head_end + 2
    return raw[:insert_at] + b"Host: " + authority + b"\r\n" + raw[insert_at:]


def _origin_form(target: bytes) -> bytes:
    """``http://host:port/p?q`` -> ``/p?q`` (fragment dropped)."""
    rest = target[7:]
    rest = rest.split(b"#", 1)[0]
    idx = len(rest)
    for sep in (b"/", b"?"):
        pos = rest.find(sep)
        if pos >= 0:
            idx = min(idx, pos)
    path = rest[idx:]
    if not path:
        return b"/"
    if path.startswith(b"?"):
        return b"/" + path
    return path


#: End of a message head as h11 finds it (it accepts bare LF line ends too).
_HEAD_END_RE = re.compile(rb"\n\r?\n")
_STATUS_CODE_RE = re.compile(rb"HTTP/\d\.\d[ \t]+(\d{3})")


def _normalize_response_head(head: bytes, *, keep_transfer_coding: bool) -> tuple[bytes, bytes | None]:
    """A response head as h11 accepts it, changed only where RFC 9112 lets a proxy change it (meas4-4).

    - Whitespace between a field name and its colon (``X-Bad : v``,
      ``X-A\t: b``) is removed: RFC 9112 section 5.1 says a proxy MUST remove
      it from a response before forwarding, where h11 would reject the head.
    - With ``keep_transfer_coding``, a single ``Transfer-Encoding`` whose last
      coding is ``chunked`` after other codings (``gzip, chunked``) becomes
      ``chunked`` for h11, which frames the body; the original value is
      returned so the head relayed to the client carries it again (the body
      stays transfer-coded, chunk framing added by h11). The caller passes
      False for HTTP/1.0 clients, which cannot receive a transfer coding.

    Returns ``(head, original Transfer-Encoding value or None)``. Anything else
    stays as it was; h11 still rejects what it rejects.
    """
    lines = head.split(b"\n")
    te_lines = []
    for i in range(1, len(lines)):
        line = lines[i]
        cr = line.endswith(b"\r")
        body = line[:-1] if cr else line
        if not body or body[:1] in (b" ", b"\t"):
            continue  # the blank end line, or an obs-fold continuation
        name, sep, value = body.partition(b":")
        if not sep:
            continue
        stripped = name.rstrip(b" \t")
        if stripped != name and stripped:
            body = stripped + b":" + value
            lines[i] = body + (b"\r" if cr else b"")
        if stripped.lower() == b"transfer-encoding":
            te_lines.append((i, stripped, value, cr))
    original: bytes | None = None
    if keep_transfer_coding and len(te_lines) == 1:
        i, name, value, cr = te_lines[0]
        codings = [c.split(b";", 1)[0].strip().lower() for c in value.split(b",") if c.strip()]
        if len(codings) > 1 and codings[-1] == b"chunked" and b"chunked" not in codings[:-1]:
            original = value.strip()
            lines[i] = name + b": chunked" + (b"\r" if cr else b"")
    return b"\n".join(lines), original


def _restore_transfer_coding(head: bytes, value: bytes) -> bytes:
    """Put ``value`` back as the Transfer-Encoding of a head h11 wrote with ``chunked``."""
    lines = head.split(b"\r\n")
    for i in range(len(lines) - 1, 0, -1):
        name, sep, current = lines[i].partition(b":")
        if sep and name.strip().lower() == b"transfer-encoding" and current.strip().lower() == b"chunked":
            lines[i] = name + b": " + value
            break
    return b"\r\n".join(lines)


def _take_response_heads(buf: bytearray, *, keep_transfer_coding: bool) -> tuple[bytes, bool, bytes | None]:
    """Normalise the complete response heads at the start of ``buf`` (consumed) for h11.

    Heads are taken up to and including the first final one (not 1xx, or 101
    Switching Protocols); after it the rest of ``buf`` is body and is handed
    over unchanged. Returns ``(bytes for h11, final head seen, original
    Transfer-Encoding of the final head)``; an incomplete head stays in ``buf``.
    """
    out = bytearray()
    while True:
        match = _HEAD_END_RE.search(buf)
        if match is None:
            return bytes(out), False, None
        end = match.end()
        head = bytes(buf[:end])
        del buf[:end]
        status = _STATUS_CODE_RE.match(head.lstrip(b"\r\n"))
        code = int(status.group(1)) if status else 0
        final = not (100 <= code < 200) or code == 101
        fixed, original = _normalize_response_head(head, keep_transfer_coding=keep_transfer_coding and final)
        out += fixed
        if final:
            out += buf
            buf.clear()
            return bytes(out), True, original


def _is_self_host(host: str) -> bool:
    """True when ``host`` names this machine: ``localhost`` or a loopback/unspecified literal.

    Literals are parsed like ``getaddrinfo`` parses them, legacy IPv4 spellings
    included (``127.1``, ``0x7f.0.0.1``, ``2130706433``), so no spelling of a
    loopback address slips past the self-loop check.
    """
    if host == "localhost" or host.endswith(".localhost"):
        return True
    ip = _up.ip_literal(host)
    return ip is not None and _up.is_self_address(ip)


def _replace_proxy_authorization(
    headers: list[tuple[bytes, bytes]], value: bytes | None
) -> tuple[list[tuple[bytes, bytes]], int]:
    """Remove every Proxy-Authorization and put ``value`` (if any) where the first one was.

    Returns the new header list and the byte size of the line that will be sent
    (``len(b"Proxy-Authorization: " + value + b"\\r\\n")``) or 0.
    """
    out: list[tuple[bytes, bytes]] = []
    placed = False
    for name, val in headers:
        if name.lower() == b"proxy-authorization":
            if value is not None and not placed:
                out.append((name, value))
                placed = True
            continue
        out.append((name, val))
    if value is not None and not placed:
        out.append((b"Proxy-Authorization", value))
    size = len(b"Proxy-Authorization: ") + len(value) + 2 if value is not None else 0
    return out, size


def _connect_head(req: h11.Request, value: bytes | None, host_injected: bool) -> tuple[bytes, int]:
    """The CONNECT head sent upstream: the client's, with Proxy-Authorization rewritten."""
    headers = list(req.headers.raw_items())
    if host_injected and headers:
        headers = headers[:-1]  # the Host header we added is always last
    headers, pa_size = _replace_proxy_authorization(headers, value)
    lines = [b"CONNECT " + req.target + b" HTTP/" + req.http_version]
    lines.extend(name + b": " + val for name, val in headers)
    return b"\r\n".join(lines) + b"\r\n\r\n", pa_size


# ---------------------------------------------------------------------------- client connection


class _HttpSession:
    """The current upstream connection of a keep-alive plain-HTTP client connection.

    On the HTTP CONNECT route the connection outlives an authority switch
    (meas3-3): ``key`` and ``tunnel`` then change to the new authority's record
    while ``up`` and ``conn`` stay.
    """

    def __init__(self, key: tuple, tunnel: Tunnel, up: UpstreamConnection) -> None:
        self.key = key
        self.tunnel = tunnel
        self.up = up
        self.conn = h11.Connection(h11.CLIENT, max_incomplete_event_size=MAX_HEAD)
        #: Requests whose response completed on this upstream connection (> 0: the connection is reused).
        self.completed = 0
        #: HTTP CONNECT route: a final response other than 407 was relayed on the current record.
        self.passed_proxy_auth = False


class _ClientConn:
    """One accepted client connection and everything it opened upstream."""

    def __init__(
        self,
        fw: Forwarder,
        listener: Listener,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self.fw = fw
        self.meter = fw._meter
        self.config = fw.config
        self.listener: Listener = listener
        self.reader = reader
        self.writer = writer
        self.h11 = h11.Connection(h11.SERVER, max_incomplete_event_size=MAX_HEAD)
        self.accepted_at = self.last_activity = time.monotonic()
        #: Complete request heads read on this connection (0: still waiting for the first one).
        self.requests_seen = 0
        self.tunnel: Tunnel | None = None
        self.session: _HttpSession | None = None
        #: True once bytes of the current response (or the CONNECT reply) went to the client.
        self.response_started = False
        #: Plain HTTP: a final response went out while the client waited for 100-continue.
        self._body_abandoned = False
        #: Plain HTTP, current exchange: the response head went to the client / any response byte arrived.
        self._resp_head_sent = False
        self._resp_received = False
        #: Plain HTTP: the upstream stopped taking the request body after its whole response arrived.
        self._upload_cut = False
        #: CONNECT: client bytes that arrived while the tunnel was being set up (relayed first),
        #: and whether the client half-closed after them.
        self._early = bytearray()
        self._early_eof = False
        #: Plain HTTP: the final response's Transfer-Encoding before h11 saw it as ``chunked`` (meas4-4).
        self._resp_te: bytes | None = None

    # ------------------------------------------------------------------ small helpers
    def touch(self) -> None:
        self.last_activity = time.monotonic()

    def abort(self) -> None:
        """Force-close the client socket and whatever it has open upstream."""
        self.abort_client()
        self.abort_upstream()

    def abort_upstream(self) -> None:
        """Force-close only the upstream side (the client socket is left alone)."""
        if self.session is not None:
            self.session.up.abort()
        if self.tunnel is not None:
            self.tunnel.abort_transports(exclude=self.abort_client)

    async def _client_read(self) -> bytes:
        try:
            data = await self.reader.read(CHUNK)
        except (ConnectionError, OSError):
            data = b""
        if data:
            self.touch()
            if self.tunnel is not None:
                self.meter.add_client(self.tunnel, received=len(data))
        return data

    async def _client_write(self, data: bytes) -> None:
        if not data:
            return
        self.response_started = True
        try:
            self.writer.write(data)
            await self.writer.drain()
        except (ConnectionError, OSError, RuntimeError):
            raise _ClientGone from None
        self.touch()
        if self.tunnel is not None:
            self.meter.add_client(self.tunnel, sent=len(data))

    async def _reply_and_close(self, data: bytes) -> None:
        """Send a final reply, then read briefly so it is not lost to a TCP reset."""
        with contextlib.suppress(Exception):
            self.writer.write(data)
            await self.writer.drain()
        with contextlib.suppress(Exception):
            if self.writer.can_write_eof():
                self.writer.write_eof()
        loop = asyncio.get_running_loop()
        deadline = loop.time() + LINGER_S
        total = 0
        with contextlib.suppress(Exception):
            while total < LINGER_MAX_BYTES:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    break
                chunk = await asyncio.wait_for(self.reader.read(65536), remaining)
                if not chunk:
                    break
                total += len(chunk)

    async def _refuse(self, refusal: _Refusal, *, head_only: bool) -> None:
        if refusal.reason is not None:
            self.meter.refuse(refusal.reason)
        await self._reply_and_close(
            meter_response(refusal.status, refusal.error_code, extra_headers=refusal.extra_headers, head_only=head_only)
        )

    # ------------------------------------------------------------------ main loop
    async def run(self) -> None:
        """Serve the connection; unexpected exceptions become ``failed:internal`` + 502."""
        try:
            await self._serve()
        except Exception as exc:  # never let one connection take the loop down
            self.meter.internal_error()
            logger.debug("forwarder: internal error %s at %s", type(exc).__name__, _where(exc))
            for tunnel in (self.tunnel, self.session.tunnel if self.session else None):
                if tunnel is not None:
                    self.meter.finish(tunnel, "failed:internal")
            if not self.response_started:  # "when still possible": nothing sent for this request yet
                with contextlib.suppress(Exception):
                    self.writer.write(meter_response(502, "internal-error"))
            self.abort_upstream()
        finally:
            await self._close_session()
            with contextlib.suppress(Exception):
                self.writer.close()  # graceful: flushes a pending reply

    async def _serve(self) -> None:
        """Read requests and dispatch them until the connection is done."""
        while True:
            try:
                req, host_injected = await self._read_request()
            except _BadRequest:
                await self._refuse(_Refusal(400, "bad_request", "bad-request"), head_only=False)
                return
            if req is None:
                return
            self.response_started = False
            head_only = req.method == b"HEAD"
            decision = self._decide(req)
            if isinstance(decision, _Refusal):
                await self._close_session()
                await self._refuse(decision, head_only=head_only)
                return
            if decision.kind == "connect":
                await self._close_session()
                await self._handle_connect(req, decision, host_injected)
                return
            keep = await self._handle_http(req, decision)
            if not keep:
                return
            if self.h11.our_state is h11.DONE and self.h11.their_state is h11.DONE:
                self.h11.start_next_cycle()
            else:
                return

    async def _read_request(self) -> tuple[h11.Request | None, bool]:
        """Read one request head; returns (None, False) when the client closed cleanly."""
        raw = bytearray(self.h11.trailing_data[0])
        injected = False
        eof = False
        while True:
            try:
                event = self.h11.next_event()
            except h11.RemoteProtocolError as exc:
                if eof:
                    return None, False
                if not injected and "Missing mandatory Host" in str(exc):
                    fixed = _inject_host(bytes(raw))
                    if fixed is not None:
                        self.h11 = h11.Connection(h11.SERVER, max_incomplete_event_size=MAX_HEAD)
                        self.h11.receive_data(fixed)
                        injected = True
                        continue
                raise _BadRequest from None
            if event is h11.NEED_DATA:
                data = await self._client_read()
                if not data:
                    eof = True
                elif len(raw) <= MAX_HEAD + CHUNK:
                    raw += data
                self.h11.receive_data(data)
                continue
            if isinstance(event, h11.Request):
                self.requests_seen += 1
                return event, injected
            if isinstance(event, h11.ConnectionClosed):
                return None, False
            raise _BadRequest

    # ------------------------------------------------------------------ checks
    def _decide(self, req: h11.Request) -> _Refusal | _Route:
        """Request form, authority, self-loop, credentials, budget, deny, routing (in that order)."""
        method = req.method
        target = req.target
        origin_target: bytes | None = None
        authority = b""
        if method == b"CONNECT":
            kind = "connect"
            try:
                host, port = split_authority(target.decode("ascii"), None)
            except (ValueError, UnicodeDecodeError):
                return _Refusal(400, "bad_request", "bad-request")
        else:
            prefix = target[:8].lower()
            if prefix.startswith(b"https://"):
                return _Refusal(400, "https_absolute_form", "https-absolute-form")
            if not prefix.startswith(b"http://"):
                return _Refusal(403, "origin_form", None)
            kind = "http"
            try:
                text = target.decode("ascii")
                parts = urlsplit(text)
                if parts.username is not None or parts.password is not None or not parts.netloc:
                    raise ValueError("userinfo or empty authority")
                host, port = split_authority(parts.netloc, 80)
            except (ValueError, UnicodeDecodeError):
                return _Refusal(400, "bad_request", "bad-request")
            origin_target = _origin_form(target)
            authority = parts.netloc.encode("ascii")
            names = {n.lower() for n, _ in req.headers.raw_items()}
            if b"transfer-encoding" in names and b"content-length" in names:
                # RFC 9112 section 6.3: a request smuggling vector; refuse and close.
                return _Refusal(400, "bad_request", "bad-request")

        # One spelling per address (sec3-5): deny and routing rules, records and
        # reports see 1.2.3.4 for 1.2.3.04, 0x01020304, 16909060 or ::ffff:1.2.3.4,
        # as getaddrinfo would. What is sent upstream on the HTTP CONNECT route
        # (the CONNECT line, the absolute-form target and Host) stays the client's.
        host = canonical_host(host)

        if port in self.fw._own_ports and _is_self_host(host):
            return _Refusal(403, "self_loop", "self-loop")

        creds = self._credentials(req)
        if isinstance(creds, _Refusal):
            return creds

        if self.meter.budget_tripped:
            return _Refusal(
                403, "budget", "budget", extra_headers=(("X-Scrapescope-Budget", "tripped"),)
            )

        # Round 4 (sec4-1): an IPv6 literal that stands for an IPv4 address (NAT64 64:ff9b::/96,
        # IPv4-translated or IPv4-compatible) also matches rules on that IPv4 address. The host
        # itself is not rewritten: what the provider receives keeps the client's address.
        embedded = embedded_ipv4(_up.ip_literal(host))
        alias = str(embedded) if embedded is not None else None
        for rule in self.config.deny_rules:
            if host_glob_match(rule.pattern, host) or (alias is not None and host_glob_match(rule.pattern, alias)):
                self.meter.record_denied(host=host, port=port, kind=kind, listener=self.listener, rule=rule.label)
                return _Refusal(403, None, "denied")

        route: Route
        rule_label: str | None = None
        for direct_rule in self.config.direct_rules:
            if host_glob_match(direct_rule.pattern, host):
                route = "non-target"
                rule_label = direct_rule.label
                break
        else:
            route = self.config.upstream.kind if self.config.upstream is not None else "direct"
        if route in ("direct", "non-target"):
            creds = _Creds(auth="none", header_value=None, socks=None)
        return _Route(
            host=host,
            port=port,
            kind=kind,
            route=route,
            creds=creds,
            rule=rule_label,
            origin_target=origin_target,
            authority=authority,
        )

    def _credentials(self, req: h11.Request) -> _Creds | _Refusal:
        """Apply the credential table of contracts section 3.3 to one request."""
        values = [v for n, v in req.headers.raw_items() if n.lower() == b"proxy-authorization"]
        presented = values[0] if values else None
        config = self.config
        upstream = config.upstream
        token = config.token

        def inject() -> _Creds:
            if upstream is not None and upstream.has_credentials:
                value = upstream.proxy_authorization()
                assert value is not None
                return _Creds(
                    auth="injected",
                    header_value=value.encode("latin-1"),
                    socks=(upstream.username or "", upstream.password or ""),
                )
            return _Creds(auth="none", header_value=None, socks=None)

        challenge = (("Proxy-Authenticate", f'Basic realm="{PROXY_REALM}"'),)
        if presented is None:
            if self.listener == "auth":
                return _Refusal(407, "auth_challenge", "auth-challenge", challenge)
            if config.require_token:
                return _Refusal(407, "token_required", "token-required", challenge)
            return inject()
        parsed = parse_basic_auth(presented.decode("latin-1"))
        if parsed is None:
            if config.require_token:
                return _Refusal(407, "token_required", "token-required", challenge)
            return _Creds(auth="passthrough", header_value=presented, socks=None, non_basic=True)
        username, password = parsed
        if token is not None and username.startswith(TOKEN_PREFIX):
            expected = (TOKEN_PREFIX + token).encode("utf-8")
            head, sep, upstream_user = username.partition(TOKEN_SEPARATOR)
            if not hmac.compare_digest(head.encode("utf-8"), expected):
                return _Refusal(407, "bad_token", "bad-token", challenge)
            if not sep:
                return inject()
            value = basic_auth_value(upstream_user, password)
            return _Creds(
                auth="token-mapped",
                header_value=value.encode("utf-8"),
                socks=(upstream_user, password),
            )
        if config.require_token:
            return _Refusal(407, "token_required", "token-required", challenge)
        return _Creds(auth="passthrough", header_value=presented, socks=(username, password))

    # ------------------------------------------------------------------ upstream legs
    async def _open_upstream(self, tunnel: Tunnel, decision: _Route) -> UpstreamConnection:
        """TCP connect (and SOCKS5 negotiation) for ``decision``; raises UpstreamError.

        ``connect_timeout_s`` (30 s) bounds name resolution and the TCP connect
        only. The SOCKS5 exchange, whose CONNECT reply waits for the provider
        to reach the target, may take up to the idle timeout (round 4,
        meas4-3), like the HTTP CONNECT reply in :meth:`_handle_connect`.
        """
        config = self.config
        timeout = config.connect_timeout_s
        if decision.route in ("direct", "non-target"):
            # The meter connects by itself: resolve once, refuse the meter's own
            # listeners and (sizing mode, unless opted in) non-global addresses,
            # then connect to the checked address. Non-target hosts are catalog
            # globs under the API providers' own DNS zones, which a page cannot
            # point at a private address; private answers there come from the
            # user's resolver (cloud private endpoints) and stay allowed.
            return await _up.open_direct(
                decision.host,
                decision.port,
                meter=self.meter,
                tunnel=tunnel,
                timeout=timeout,
                connect_map=self.fw._connect_map,
                allow_private=config.allow_private_targets or decision.route == "non-target",
                own_ports=self.fw._own_ports,
            )
        upstream = config.upstream
        assert upstream is not None
        if decision.route == "socks5":
            if decision.creds.non_basic:
                raise UpstreamError("socks_auth_unsupported", 502, "socks-auth-unsupported")
            _up.check_socks_credentials(decision.creds.socks)
        conn = await _up.open_counted(
            upstream.host, upstream.port, meter=self.meter, tunnel=tunnel, timeout=timeout, direct=False
        )
        # An upstream name that resolves to this meter would recurse until file descriptors run out.
        _up.check_not_self(conn, self.fw._own_ports)
        if decision.route == "socks5":
            try:
                await _up.socks5_connect(
                    conn, decision.host, decision.port, decision.creds.socks, timeout=self.fw._reply_timeout_s
                )
            except BaseException:
                conn.abort()
                raise
        return conn

    def _open_tunnel(self, decision: _Route, *, continued_from: int | None = None) -> Tunnel:
        tunnel = self.meter.open_tunnel(
            host=decision.host,
            port=decision.port,
            kind=decision.kind,  # type: ignore[arg-type]
            route=decision.route,
            listener=self.listener,
            auth=decision.creds.auth,
            rule=decision.rule,
            continued_from=continued_from,
        )
        tunnel.add_aborter(self.abort_client)
        return tunnel

    def abort_client(self) -> None:
        with contextlib.suppress(Exception):
            self.writer.transport.abort()

    async def _reset_client(self) -> None:
        """Pass an upstream reset on: flush what was already relayed (briefly), then reset the client."""
        transport = self.writer.transport
        loop = asyncio.get_running_loop()
        deadline = loop.time() + LINGER_S
        with contextlib.suppress(Exception):
            while transport.get_write_buffer_size() > 0 and not transport.is_closing() and loop.time() < deadline:
                await asyncio.sleep(0.01)
        _reset_transport(transport)

    # ------------------------------------------------------------------ CONNECT
    async def _establish(
        self,
        tunnel: Tunnel,
        decision: _Route,
        req: h11.Request,
        host_injected: bool,
        holder: list[UpstreamConnection],
    ) -> _up.ConnectReply | None:
        """Open the upstream leg of a CONNECT tunnel; the connection goes into ``holder`` as soon as it exists.

        Returns the provider's CONNECT reply on the HTTP CONNECT route, else None.
        """
        holder.append(await self._open_upstream(tunnel, decision))
        if decision.route != "http-connect":
            return None
        head, pa_size = _connect_head(req, decision.creds.header_value, host_injected)
        self.meter.set_connect_sizes(tunnel, len(head), pa_size)
        # meas4-3: the provider may hold CONNECT while it finds a peer or retries the
        # target; wait as long as an idle connection may last, not the 30 s connect timeout.
        return await _up.http_connect(
            holder[0], head, timeout=self.fw._reply_timeout_s, body_timeout=self.config.connect_timeout_s
        )

    async def _while_client_waits(self, awaitable: object) -> object:
        """Await ``awaitable`` (setting up a tunnel) while watching the client connection.

        The provider may take minutes to answer CONNECT (meas4-3), and a client
        that gives up closes its connection: a reset, or an end of stream
        before the client sent any byte of its own, ends the wait at once with
        :class:`_ClientGone`, as closing would end the client's own pending
        CONNECT at the provider (Squid's default ``half_closed_clients off``
        does the same). A client that sent early bytes and then half-closed
        (a scripted pipe) keeps waiting; ``self._early_eof`` passes the
        half-close on once the tunnel is up. Early bytes are kept in
        ``self._early`` and relayed first; after ``MAX_HEAD`` of them the meter
        stops reading (TCP backpressure).
        """
        work = asyncio.ensure_future(awaitable)  # type: ignore[arg-type]
        watch = asyncio.ensure_future(self._watch_client())
        try:
            done, _ = await asyncio.wait({work, watch}, return_when=asyncio.FIRST_COMPLETED)
            if work not in done:
                if not watch.result():
                    raise _ClientGone
                self._early_eof = True
                return await work
            return work.result()
        finally:
            for task in (work, watch):
                if not task.done():
                    task.cancel()
            await asyncio.gather(work, watch, return_exceptions=True)

    async def _watch_client(self) -> bool:
        """Wait for the client to end its side; True for a half-close after it sent bytes, False otherwise.

        Early bytes go to ``self._early``.
        """
        while True:
            if len(self._early) >= MAX_HEAD:
                await asyncio.get_running_loop().create_future()  # stop reading until cancelled
            try:
                data = await self.reader.read(CHUNK)
            except (ConnectionError, OSError):
                return False
            if not data:
                return bool(self._early) or bool(self.h11.trailing_data[0])
            self.touch()
            self._early += data

    async def _handle_connect(self, req: h11.Request, decision: _Route, host_injected: bool) -> None:
        meter = self.meter
        tunnel = self._open_tunnel(decision)
        self.tunnel = tunnel
        if decision.route == "direct":
            # Sizing mode: the estimated CONNECT request is the head this client sent (Host,
            # User-Agent, Proxy-Connection...), as a provider would receive it, minus credentials.
            meter.set_synthetic_request_bytes(tunnel, len(_connect_head(req, None, host_injected)[0]))
        holder: list[UpstreamConnection] = []
        established = False
        try:
            reply = await self._while_client_waits(self._establish(tunnel, decision, req, host_injected, holder))
            up = holder[0]
            if isinstance(reply, _up.ConnectReply):
                meter.update(tunnel, upstream_status=reply.status)
                if not reply.ok:
                    meter.mark_all_negotiation(tunnel)
                    meter.finish(tunnel, "failed:upstream_status")
                    with contextlib.suppress(_ClientGone):
                        await self._client_write(reply.head + reply.body)
                    return
                await self._client_write(reply.head)
            else:
                await self._client_write(SYNTHETIC_CONNECT_RESPONSE)
            established = True
            trailing, client_closed = self.h11.trailing_data
            client_closed = client_closed or self._early_eof
            early = bytes(trailing) + bytes(self._early)
            self._early.clear()
            if early:
                meter.add_client(tunnel, received=len(early))
                up.write(early)
            if client_closed:
                up.write_eof()
            await self._splice(tunnel, up, client_eof=client_closed)
            meter.finish(tunnel, TUNNEL_OK)
        except _UpstreamReset:
            # A reset must reach the client as a reset: a clean close could make a
            # truncated close-delimited body look complete.
            meter.finish(tunnel, "failed:upstream_reset")
            await self._reset_client()
        except _ClientReset:
            meter.finish(tunnel, TUNNEL_OK)
            if holder:
                holder[0].reset()
        except UpstreamError as exc:
            meter.mark_all_negotiation(tunnel)
            if exc.socks_reply is not None:
                meter.update(tunnel, socks_reply=exc.socks_reply)
            if meter.finish(tunnel, f"failed:{exc.reason}"):
                await self._reply_and_close(meter_response(exc.status, exc.error_code))
        except TunnelAborted:
            pass
        except (_ClientGone, ConnectionError, OSError):
            if not established:
                meter.mark_all_negotiation(tunnel)
            meter.finish(tunnel, TUNNEL_OK if established else "failed:client_closed")
        except Exception:
            meter.finish(tunnel, "failed:internal")
            raise
        finally:
            if holder:
                await holder[0].close()
            self.tunnel = None

    async def _splice(
        self,
        tunnel: Tunnel,
        up: UpstreamConnection,
        *,
        client_eof: bool = False,
    ) -> None:
        """Relay raw bytes both ways with half-close propagation until both sides end."""
        meter = self.meter
        reader, writer = self.reader, self.writer

        def gone(side: type[Exception]) -> Exception:
            # Aborts by the meter itself (budget, cap, stop) are not resets of either side.
            return TunnelAborted() if tunnel.closing else side()

        async def client_to_upstream() -> None:
            if client_eof:
                return
            while True:
                # A reset tears both sides down and is passed on as a reset; only a
                # clean EOF half-closes.
                try:
                    data = await reader.read(CHUNK)
                except (ConnectionError, OSError):
                    raise gone(_ClientReset) from None
                if not data:
                    break
                self.last_activity = time.monotonic()
                meter.add_client(tunnel, received=len(data))
                up.write(data)
                try:
                    await up.drain()
                except (ConnectionError, OSError):
                    raise gone(_UpstreamReset) from None
            up.write_eof()

        async def upstream_to_client() -> None:
            up_reader = up.reader
            while True:
                try:
                    data = await up_reader.read(CHUNK)
                except (ConnectionError, OSError):
                    raise gone(_UpstreamReset) from None
                if not data:
                    break
                self.last_activity = time.monotonic()
                writer.write(data)
                meter.add_client(tunnel, sent=len(data))
                try:
                    await writer.drain()
                except (ConnectionError, OSError):
                    raise gone(_ClientReset) from None
            with contextlib.suppress(Exception):
                if not writer.is_closing() and writer.can_write_eof():
                    writer.write_eof()

        await _run_pair(client_to_upstream(), upstream_to_client())

    # ------------------------------------------------------------------ plain HTTP
    async def _close_session(self, status: str = TUNNEL_OK) -> None:
        session = self.session
        if session is None:
            return
        self.session = None
        self.tunnel = None
        self.meter.finish(session.tunnel, status)
        await session.up.close()

    async def _handle_http(self, req: h11.Request, decision: _Route) -> bool:
        """Forward one plain-HTTP request; True when the client connection may continue."""
        meter = self.meter
        head_only = req.method == b"HEAD"
        key = (decision.route, decision.host, decision.port, decision.creds.socks if decision.route == "socks5" else None)
        if self.session is not None and (
            self.session.tunnel.closing
            # The upstream closed (or reset) this idle keep-alive connection: open a new one instead of failing.
            or self.session.up.reader.at_eof()
            or self.session.up.reader.exception() is not None
            or self.session.up.writer.is_closing()
        ):
            await self._close_session()
        elif self.session is not None and self.session.key != key:
            if self.session.key[0] == "http-connect" and decision.route == "http-connect":
                # The upstream connection goes to the provider, which serves every
                # authority: keep it, as the client kept its proxy connection, and
                # start a new record at this request boundary (meas3-3).
                self._continue_session(self.session, decision, key)
            else:
                await self._close_session()
        if self.session is None:
            tunnel = self._open_tunnel(decision)
            self.tunnel = tunnel
            try:
                up = await self._open_upstream(tunnel, decision)
            except UpstreamError as exc:
                meter.mark_all_negotiation(tunnel)
                if exc.socks_reply is not None:
                    meter.update(tunnel, socks_reply=exc.socks_reply)
                self.tunnel = None
                if meter.finish(tunnel, f"failed:{exc.reason}"):
                    await self._reply_and_close(meter_response(exc.status, exc.error_code, head_only=head_only))
                return False
            except TunnelAborted:
                self.tunnel = None
                return False
            self.session = _HttpSession(key, tunnel, up)
        session = self.session
        tunnel = session.tunnel
        self.tunnel = tunnel
        if tunnel.record.auth != decision.creds.auth:
            meter.update(tunnel, auth=decision.creds.auth)

        headers = _strip_hop_by_hop(list(req.headers.raw_items()))
        if decision.route == "http-connect":
            # Rebuilt from the authority that routing, deny rules and attribution
            # used, never the raw target: in "http://allowed.example#@denied.example/"
            # urlsplit sees allowed.example, while a proxy that takes the last "@"
            # of the authority would fetch denied.example. The fragment is dropped.
            target = b"http://" + decision.authority + (decision.origin_target or b"/")
            headers, pa_size = _replace_proxy_authorization(headers, decision.creds.header_value)
        else:
            target = decision.origin_target or b"/"
            headers = [(n, v) for n, v in headers if n.lower() != b"proxy-authorization"]
            pa_size = 0
        headers = _set_host(headers, decision.authority)

        try:
            data = session.conn.send(h11.Request(method=req.method, target=target, headers=headers))
            session.up.write(data or b"")
            meter.count_request(tunnel, pa_size)
            outcome = await self._exchange(session)
        except TunnelAborted:
            self.abort_client()
            return False
        except _UpstreamGone as exc:
            if session.completed > 0 and not exc.received and not exc.head_sent:
                # The keep-alive race: a reused upstream connection closed (its idle
                # timeout, say) after this request went out but before any byte of a
                # reply. Without the meter the client would see its own reused
                # connection close and retry an idempotent request on a new one, so
                # pass the close (or reset) on instead of answering 502. The tunnel
                # carried complete exchanges and ended normally.
                meter.finish(tunnel, TUNNEL_OK)
                self.session = None
                self.tunnel = None
                session.up.abort()
                if exc.reset:
                    await self._reset_client()
                else:
                    await self._reply_and_close(b"")
                return False
            if exc.reset:
                reason = "failed:upstream_reset"
            else:
                reason = "failed:upstream_protocol" if exc.protocol else "failed:upstream_closed"
            meter.finish(tunnel, reason)
            self.session = None
            self.tunnel = None
            session.up.abort()
            if exc.head_sent:
                if exc.reset:
                    await self._reset_client()
                else:
                    self.abort_client()
            else:
                code = "upstream-protocol-error" if exc.protocol else "upstream-closed"
                await self._reply_and_close(meter_response(502, code, head_only=head_only))
            return False
        except (_ClientGone, h11.RemoteProtocolError, ConnectionError, OSError):
            await self._close_session()
            return False

        if outcome == "switched":
            self.session = None
            try:
                client_trailing, client_closed = self.h11.trailing_data
                up_trailing, _ = session.conn.trailing_data
                if up_trailing:
                    await self._client_write(up_trailing)
                if client_trailing:
                    meter.add_client(tunnel, received=len(client_trailing))
                    session.up.write(client_trailing)
                if client_closed:
                    session.up.write_eof()
                await self._splice(tunnel, session.up, client_eof=client_closed)
                meter.finish(tunnel, TUNNEL_OK)
            except _UpstreamReset:
                meter.finish(tunnel, "failed:upstream_reset")
                await self._reset_client()
            except _ClientReset:
                meter.finish(tunnel, TUNNEL_OK)
                session.up.reset()
            except (TunnelAborted, _ClientGone, ConnectionError, OSError):
                meter.finish(tunnel, TUNNEL_OK)
            finally:
                await session.up.close()
                self.tunnel = None
            return False
        if outcome == "abandoned":
            # The client will not send (the rest of) this request body, or one side
            # closes after this response: end the connection instead of waiting for
            # a body that never comes. Linger so the relayed response is not lost to a reset.
            await self._close_session()
            await self._reply_and_close(b"")
            return False

        if session.conn.our_state is h11.DONE and session.conn.their_state is h11.DONE:
            session.conn.start_next_cycle()
            session.completed += 1
        else:
            await self._close_session()
        return True

    def _continue_session(self, session: _HttpSession, decision: _Route, key: tuple) -> None:
        """Charge the kept HTTP CONNECT upstream connection to a new record for ``decision``'s authority.

        Called between two exchanges (h11 delimits each one and the meter never
        pipelines upstream), so every byte of the next exchange lands on the
        new record. The previous record closes ``ok`` (or its 407 status).
        """
        old = session.tunnel
        new = self._open_tunnel(decision, continued_from=old.id)
        self.meter.continue_connection(old, new)  # the per-tunnel cap follows the connection (meas4-6)
        session.up.rebind(new)
        session.key = key
        session.tunnel = new
        session.passed_proxy_auth = False
        self.tunnel = new
        self.meter.finish(old, TUNNEL_OK)

    async def _exchange(self, session: _HttpSession) -> str:
        """Run the request-body and response pumps concurrently.

        Returns "done", "switched" (101) or "abandoned" (the client connection
        cannot be reused, e.g. a final response arrived while the client was
        still waiting for 100-continue).
        """
        self._body_abandoned = False
        self._resp_head_sent = False
        self._resp_received = False
        self._upload_cut = False
        req_task = asyncio.ensure_future(self._pump_request(session))
        resp_task = asyncio.ensure_future(self._pump_response(session))
        try:
            done, _pending = await asyncio.wait({req_task, resp_task}, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                exc = task.exception()
                if exc is not None:
                    raise exc
            if resp_task in done and req_task not in done and resp_task.result() == "done":
                # h11 clears they_are_waiting_for_100_continue as soon as a final
                # response is sent, so _pump_response records it just before.
                upstream_done = session.conn.their_state in (h11.MUST_CLOSE, h11.CLOSED)
                if self._body_abandoned or upstream_done or self.h11.our_state is h11.MUST_CLOSE:
                    return "abandoned"
                await req_task
            elif req_task in done and resp_task not in done:
                await resp_task
            result = resp_task.result()
            if result == "done" and self._upload_cut:
                return "abandoned"  # the rest of the body never went out: end the client connection
            return result
        finally:
            for task in (req_task, resp_task):
                if not task.done():
                    task.cancel()
            await asyncio.gather(req_task, resp_task, return_exceptions=True)

    async def _next_client_event(self) -> object:
        while True:
            event = self.h11.next_event()
            if event is h11.NEED_DATA:
                self.h11.receive_data(await self._client_read())
                continue
            return event

    async def _pump_request(self, session: _HttpSession) -> None:
        while True:
            event = await self._next_client_event()
            if isinstance(event, h11.Data):
                session.up.write(session.conn.send(h11.Data(data=event.data)) or b"")
                if not await self._drain_upstream(session):
                    return
            elif isinstance(event, h11.EndOfMessage):
                # Trailers come only with a chunked body, which is forwarded chunked too.
                trailers = list(event.headers.raw_items())
                session.up.write(session.conn.send(h11.EndOfMessage(headers=trailers)) or b"")
                await self._drain_upstream(session)
                return
            else:
                raise _ClientGone

    async def _drain_upstream(self, session: _HttpSession) -> bool:
        """Wait for the request body to leave; False when the upstream stopped taking it after its response.

        A failure while the response is still incomplete is the upstream going
        away mid-exchange (meas3-6): ``failed:upstream_reset``, like a reset
        during the response, never a normal close. A failure after the whole
        response arrived (a server that answers 413 and then resets the rest of
        an upload) truncates nothing the client is owed: the response is still
        relayed and the client connection then ends with a lingering close.
        """
        try:
            await session.up.drain()
        except (ConnectionError, OSError):
            if session.tunnel.closing:
                raise TunnelAborted from None
            if session.conn.their_state in (h11.DONE, h11.MUST_CLOSE, h11.CLOSED):
                self._upload_cut = True
                return False
            raise _UpstreamGone(self._resp_head_sent, reset=True, received=self._resp_received) from None
        return True

    async def _pump_response(self, session: _HttpSession) -> str:
        meter = self.meter
        head_sent = False
        eof = False
        #: Any byte of this request's response read from the upstream (h11 may still hold them).
        received = False
        #: Response head bytes not yet handed to h11 (normalised first, meas4-4).
        pending = bytearray()
        self._resp_te = None
        while True:
            try:
                event = session.conn.next_event()
            except h11.RemoteProtocolError:
                if session.tunnel.closing:
                    raise TunnelAborted from None
                # h11 reports an EOF mid-message as a protocol error; that is a close.
                raise _UpstreamGone(head_sent, protocol=not eof, received=received) from None
            if event is h11.NEED_DATA:
                try:
                    data = await session.up.reader.read(CHUNK)
                except (ConnectionError, OSError):
                    if session.tunnel.closing:
                        raise TunnelAborted from None
                    # A reset is not an end of message, even for a close-delimited body.
                    raise _UpstreamGone(head_sent, reset=True, received=received) from None
                if not data:
                    if session.tunnel.closing:
                        raise TunnelAborted
                    eof = True
                else:
                    received = self._resp_received = True
                    self.touch()
                if session.conn.their_state is h11.SEND_RESPONSE and (data or pending):
                    # Still before the final response head: normalise heads the way RFC 9112
                    # asks a proxy to before h11 (stricter than clients) parses them.
                    pending += data
                    ready, final, original_te = _take_response_heads(
                        pending, keep_transfer_coding=self.h11.their_http_version not in (None, b"1.0")
                    )
                    if final:
                        self._resp_te = original_te
                    if eof or len(pending) > MAX_HEAD or pending[:1] < b"!":
                        # h11 reports what is wrong with it (at once for bytes that cannot start a
                        # status line, such as a TLS alert, as before this buffering).
                        ready += bytes(pending)
                        pending.clear()
                    if ready:
                        session.conn.receive_data(ready)
                    if eof:
                        session.conn.receive_data(b"")
                    continue
                session.conn.receive_data(data)
                continue
            if isinstance(event, h11.InformationalResponse):
                if event.status_code != 101 and self.h11.their_http_version == b"1.0":
                    # RFC 9110 section 15.2: never send 1xx to an HTTP/1.0 client. The
                    # meter speaks HTTP/1.1 upstream, so the origin may send them (meas3-10).
                    continue
                out = h11.InformationalResponse(
                    status_code=event.status_code, headers=list(event.headers.raw_items()), reason=event.reason
                )
                await self._client_write(self.h11.send(out) or b"")
                if event.status_code == 101:
                    meter.update(session.tunnel, upstream_status=101)
                    return "switched"
                continue
            if isinstance(event, h11.Response):
                meter.update(session.tunnel, upstream_status=event.status_code)
                if session.key[0] == "http-connect":
                    # A 407 to a plain-HTTP request comes from the provider: a record that
                    # got nothing else ends failed:upstream_status, like a CONNECT answered
                    # 407, so the credential hint and tunnel_failures see it (meas3-7).
                    if event.status_code != 407:
                        session.passed_proxy_auth = True
                        session.tunnel.ok_status = TUNNEL_OK
                    elif not session.passed_proxy_auth:
                        session.tunnel.ok_status = "failed:upstream_status"
                out_response = h11.Response(
                    status_code=event.status_code, headers=list(event.headers.raw_items()), reason=event.reason
                )
                if self.h11.they_are_waiting_for_100_continue:
                    # A final response before 100: the client may never send the body.
                    self._body_abandoned = True
                head_bytes = self.h11.send(out_response) or b""
                if self._resp_te is not None:
                    head_bytes = _restore_transfer_coding(head_bytes, self._resp_te)
                    self._resp_te = None
                await self._client_write(head_bytes)
                head_sent = self._resp_head_sent = True
                continue
            if isinstance(event, h11.Data):
                await self._client_write(self.h11.send(h11.Data(data=event.data)) or b"")
                continue
            if isinstance(event, h11.EndOfMessage):
                trailers = list(event.headers.raw_items())
                if trailers and self.h11.their_http_version in (None, b"1.0"):
                    trailers = []  # an HTTP/1.0 client gets a close-delimited body: no place for trailers
                await self._client_write(self.h11.send(h11.EndOfMessage(headers=trailers)) or b"")
                return "done"
            if session.tunnel.closing:
                raise TunnelAborted
            raise _UpstreamGone(head_sent, received=received)


async def _run_pair(first: object, second: object) -> None:
    """Run two relay coroutines; if one fails, cancel the other and re-raise."""
    t1 = asyncio.ensure_future(first)  # type: ignore[arg-type]
    t2 = asyncio.ensure_future(second)  # type: ignore[arg-type]
    try:
        done, pending = await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_EXCEPTION)
        for task in done:
            exc = task.exception()
            if exc is not None:
                raise exc
    finally:
        for task in (t1, t2):
            if not task.done():
                task.cancel()
        await asyncio.gather(t1, t2, return_exceptions=True)


def _where(exc: BaseException) -> str:
    """``file:line`` of the innermost frame, for internal-error logs (no messages)."""
    tb = traceback.extract_tb(exc.__traceback__)
    if not tb:
        return "?"
    frame = tb[-1]
    return f"{frame.filename.rsplit('/', 1)[-1]}:{frame.lineno}"


# ---------------------------------------------------------------------------- the forwarder


class Forwarder:
    """Asyncio loopback forwarder that counts bytes per tunnel and enforces the budget.

    Binds 127.0.0.1 only; chains to the configured upstream (HTTP CONNECT or
    SOCKS5 with remote DNS) or connects directly (sizing mode); never
    terminates TLS; one upstream connection per client connection, never
    pooled. ``connect_map`` (tests only) replaces DNS for the meter's own
    direct connections; it never affects the connection to the upstream proxy.
    """

    def __init__(
        self,
        config: ForwarderConfig,
        *,
        connect_map: ConnectMap | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.config = config
        self._connect_map = connect_map
        self._clock = clock
        self._meter = Meter(
            mode=config.mode,
            budget_bytes=config.budget_bytes,
            max_tunnel_bytes=config.max_tunnel_bytes,
            warn_fraction=config.budget_warn_fraction,
            timeline_resolution_s=config.timeline_resolution_s,
            clock=clock,
            record_timeline=config.record_timeline,
        )
        self._servers: list[asyncio.base_events.Server] = []
        self._port: int | None = None
        self._auth_port: int | None = None
        self._own_ports: frozenset[int] = frozenset()
        self._conns: set[_ClientConn] = set()
        self._tasks: set[asyncio.Task] = set()
        self._watchdog: asyncio.Task | None = None
        self._started = False
        self._stopped = False
        #: Idle timeout for tunnels and keep-alive connections (never below 600 s in config).
        self._idle_timeout_s = config.idle_timeout_s
        #: Deadline for a connection's first complete request head, counted from accept (sec2-6).
        self._first_request_timeout_s = FIRST_REQUEST_TIMEOUT_S
        #: Wait for an upstream's CONNECT reply or SOCKS5 negotiation (meas4-3): the idle timeout,
        #: not the connect timeout, which bounds only name resolution and the TCP connect.
        self._reply_timeout_s = config.idle_timeout_s
        self._watchdog_interval_s = min(15.0, config.idle_timeout_s / 20)

    def __repr__(self) -> str:
        return f"Forwarder(mode={self.config.mode!r}, port={self._port!r})"

    # ------------------------------------------------------------------ lifecycle
    async def start(self) -> None:
        """Bind 127.0.0.1:config.port (plus a random-port auth listener when configured)."""
        if self._started:
            raise ForwarderError("forwarder already started")
        self._started = True
        try:
            main = await asyncio.start_server(
                lambda r, w: self._on_client("main", r, w),
                METER_HOST,
                self.config.port,
                limit=CLIENT_READ_LIMIT,
                backlog=512,
            )
        except OSError as exc:
            raise ForwarderError(
                f"could not listen on {METER_HOST}:{self.config.port}: {exc.strerror or type(exc).__name__}"
            ) from None
        self._servers.append(main)
        self._port = main.sockets[0].getsockname()[1]
        if self.config.auth_listener:
            try:
                auth = await asyncio.start_server(
                    lambda r, w: self._on_client("auth", r, w),
                    METER_HOST,
                    0,
                    limit=CLIENT_READ_LIMIT,
                    backlog=512,
                )
            except OSError as exc:
                main.close()
                raise ForwarderError(
                    f"could not open the credential listener: {exc.strerror or type(exc).__name__}"
                ) from None
            self._servers.append(auth)
            self._auth_port = auth.sockets[0].getsockname()[1]
        self._own_ports = frozenset(p for p in (self._port, self._auth_port) if p)
        upstream = self.config.upstream
        if upstream is not None and upstream.port in self._own_ports and _is_self_host(upstream.host):
            for server in self._servers:
                server.close()
            self._servers.clear()
            raise ForwarderError("the upstream proxy URL points at this meter's own listening port")
        self._meter.port = self._port
        self._meter.auth_port = self._auth_port
        self._meter.started_at = self._clock()
        self._watchdog = asyncio.ensure_future(self._watch_idle())
        logger.debug("forwarder listening on %s:%d mode=%s", METER_HOST, self._port, self.config.mode)

    async def stop(self) -> None:
        """Close the listeners and every tunnel (status "ok"); idempotent."""
        if self._stopped or not self._started:
            self._stopped = True
            return
        self._stopped = True
        for server in self._servers:
            server.close()
        if self._watchdog is not None:
            self._watchdog.cancel()
        self._meter.close_all(TUNNEL_OK)
        for conn in list(self._conns):
            conn.abort()
        tasks = [t for t in self._tasks if not t.done()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.wait(tasks, timeout=5)
        if self._watchdog is not None:
            await asyncio.gather(self._watchdog, return_exceptions=True)
        for server in self._servers:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(server.wait_closed(), timeout=1.0)
        logger.debug("forwarder stopped")

    # ------------------------------------------------------------------ properties
    @property
    def port(self) -> int:
        if self._port is None:
            raise RuntimeError("forwarder not started")
        return self._port

    @property
    def auth_port(self) -> int | None:
        return self._auth_port

    @property
    def url(self) -> str:
        return f"http://{METER_HOST}:{self.port}"

    @property
    def auth_url(self) -> str | None:
        return f"http://{METER_HOST}:{self._auth_port}" if self._auth_port else None

    @property
    def budget_tripped(self) -> bool:
        return self._meter.budget_tripped

    @property
    def meter(self) -> Meter:
        return self._meter

    def snapshot(self) -> MeterSnapshot:
        """Everything measured so far, as deep copies (safe from any thread)."""
        return self._meter.snapshot()

    def open_tunnel_count(self) -> int:
        """Open tunnels right now (cheap, thread-safe; no snapshot)."""
        return self._meter.open_count()

    def on_budget(self, callback: Callable[[BudgetEvent], None]) -> None:
        """Called on the loop thread for warn_80, tripped and tunnel_cap events."""
        self._meter.on_budget(callback)

    # ------------------------------------------------------------------ connections
    async def _on_client(self, listener: Listener, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
        conn = _ClientConn(self, listener, reader, writer)
        self._conns.add(conn)
        try:
            if self._stopped:
                return
            await conn.run()
        except asyncio.CancelledError:
            pass
        except Exception as exc:  # run() handles its own errors; this is a last resort
            self._meter.internal_error()
            logger.debug("forwarder: internal error %s at %s", type(exc).__name__, _where(exc))
            conn.abort()
        finally:
            with contextlib.suppress(Exception):
                if conn.tunnel is not None:
                    self._meter.finish(conn.tunnel, TUNNEL_OK)
            with contextlib.suppress(Exception):
                writer.close()
            self._conns.discard(conn)
            if task is not None:
                self._tasks.discard(task)

    async def _watch_idle(self) -> None:
        """Close connections idle (no bytes either way) for longer than the idle timeout.

        A connection that has not delivered a complete first request head within
        ``FIRST_REQUEST_TIMEOUT_S`` of being accepted is closed too, however
        slowly it keeps sending: accepted-but-silent connections would
        otherwise each hold one of the meter's file descriptors for 600 s.
        """
        while True:
            await asyncio.sleep(self._watchdog_interval_s)
            now = time.monotonic()
            for conn in list(self._conns):
                silent = conn.requests_seen == 0 and now - conn.accepted_at > self._first_request_timeout_s
                if silent or now - conn.last_activity > self._idle_timeout_s:
                    logger.debug("forwarder: closing %s connection", "silent" if silent else "idle")
                    if conn.tunnel is not None:
                        self._meter.finish(conn.tunnel, TUNNEL_OK)
                    conn.abort()


def _quiet_exception_handler(loop: asyncio.AbstractEventLoop, context: dict) -> None:
    """Loop exception handler that never logs messages (they can contain addresses)."""
    exc = context.get("exception")
    logger.debug("forwarder loop: %s", type(exc).__name__ if exc is not None else "error without exception")


def _is_accept_limit(context: dict) -> bool:
    """asyncio's report that a listener's accept() failed for lack of file descriptors.

    asyncio then stops accepting on that listener for about one second; waiting
    clients stay in the kernel's backlog (and may time out or be reset).
    """
    exc = context.get("exception")
    return (
        str(context.get("message", "")).startswith("socket.accept() out of system resource")
        and isinstance(exc, OSError)
        and _up.is_local_limit(exc)
    )


class ForwarderThread:
    """Runs a :class:`Forwarder` on its own event loop in a daemon thread."""

    def __init__(self, config: ForwarderConfig, *, connect_map: ConnectMap | None = None) -> None:
        self.config = config
        self.connect_map = connect_map
        self.budget_tripped = threading.Event()
        self.error: BaseException | None = None
        self._forwarder = Forwarder(config, connect_map=connect_map)
        self._forwarder.on_budget(self._note_budget)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._final: MeterSnapshot | None = None
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return f"ForwarderThread(mode={self.config.mode!r})"

    def _note_budget(self, event: BudgetEvent) -> None:
        if event.kind == "tripped":
            self.budget_tripped.set()

    def _on_loop_exception(self, loop: asyncio.AbstractEventLoop, context: dict) -> None:
        """Count accept() failures for lack of descriptors; log everything else quietly."""
        if _is_accept_limit(context):
            self._forwarder.meter.accept_limit_error()
        _quiet_exception_handler(loop, context)

    @property
    def forwarder(self) -> Forwarder:
        return self._forwarder

    def start(self, timeout: float = 10.0) -> None:
        """Start listening; returns once bound. Startup errors raise :class:`ForwarderError`."""
        with self._lock:
            if self._loop is not None:
                raise ForwarderError("forwarder thread already started")
            loop = asyncio.new_event_loop()
            loop.set_exception_handler(self._on_loop_exception)
            self._loop = loop
            self._thread = threading.Thread(target=self._run, args=(loop,), name="scrapescope-forwarder", daemon=True)
            self._thread.start()
            future = asyncio.run_coroutine_threadsafe(self._forwarder.start(), loop)
            try:
                future.result(timeout)
            except ForwarderError:
                self._shutdown_loop()
                raise
            except BaseException as exc:
                self._shutdown_loop()
                raise ForwarderError(f"forwarder failed to start ({type(exc).__name__})") from None

    def _run(self, loop: asyncio.AbstractEventLoop) -> None:
        asyncio.set_event_loop(loop)
        try:
            loop.run_forever()
        except BaseException as exc:  # the loop died: the runner exits 88
            self.error = exc

    def _shutdown_loop(self) -> None:
        loop, thread = self._loop, self._thread
        if loop is None:
            return
        with contextlib.suppress(RuntimeError):
            loop.call_soon_threadsafe(loop.stop)
        if thread is not None:
            thread.join(5)
        if thread is None or not thread.is_alive():
            with contextlib.suppress(Exception):
                loop.close()

    def stop(self, timeout: float = 10.0) -> MeterSnapshot:
        """Stop and return the final snapshot; idempotent."""
        with self._lock:
            if self._final is not None:
                return self._final
            loop = self._loop
            if loop is not None and self._thread is not None and self._thread.is_alive():
                future = asyncio.run_coroutine_threadsafe(self._forwarder.stop(), loop)
                try:
                    future.result(timeout)
                except BaseException as exc:
                    self._forwarder.meter.internal_error()
                    logger.debug("forwarder stop failed: %s", type(exc).__name__)
            self._final = self._forwarder.snapshot()
            self._shutdown_loop()
            return self._final

    def __enter__(self) -> ForwarderThread:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    @property
    def port(self) -> int:
        return self._forwarder.port

    @property
    def auth_port(self) -> int | None:
        return self._forwarder.auth_port

    @property
    def url(self) -> str:
        return self._forwarder.url

    @property
    def auth_url(self) -> str | None:
        return self._forwarder.auth_url

    def snapshot(self, timeout: float = 5.0) -> MeterSnapshot:
        """Thread-safe snapshot (the meter's counters are guarded by a lock)."""
        if self._final is not None:
            return self._final
        return self._forwarder.snapshot()

    def open_tunnel_count(self) -> int:
        """Open tunnels right now (thread-safe and cheap, unlike a full snapshot)."""
        if self._final is not None:
            return 0
        return self._forwarder.open_tunnel_count()

    def on_budget(self, callback: Callable[[BudgetEvent], None]) -> None:
        """Register a callback; it runs on the forwarder thread: keep it short and thread-safe."""
        self._forwarder.on_budget(callback)


__all__ = ["Forwarder", "ForwarderError", "ForwarderThread", "meter_response"]
