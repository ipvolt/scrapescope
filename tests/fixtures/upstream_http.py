"""Authenticated HTTP proxy fixture: CONNECT tunnels and absolute-form plain HTTP.

Behaviour (a stand-in for a commercial proxy provider):
- ``CONNECT host:port`` opens a tunnel after Basic proxy authentication. The
  hostname is resolved through the hosts map ("remote DNS"); unknown names get
  ``502`` with the vendor-style header ``X-Fixture-Proxy-Error: host_unknown``.
- Absolute-form ``http://`` requests are forwarded with h11, keeping the
  client connection alive; ``https://`` absolute-form and origin-form requests
  get ``400``.
- Missing or wrong credentials get ``407`` with ``Proxy-Authenticate`` and
  ``X-Fixture-Proxy-Error: auth_required|bad_auth``; the connection stays open
  so a client can retry on it (Chromium does this).

Counting: every client connection gets one :class:`HTTPProxyRecord` with the
bytes consumed from and written to the CLIENT-side socket, the pre-tunnel
negotiation part of those (CONNECT request(s), 407 exchanges and the 200 line),
and the bytes exchanged with the origin. Counts are exact once the connection
has closed (see ``_aio`` for the counting rule while it is open).
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from dataclasses import dataclass, field
from urllib.parse import quote, urlsplit

import h11

from ._aio import PUMP_CHUNK, BackgroundLoop, close_writer, splice, wait_until
from .common import (
    UPSTREAM_PASSWORD,
    UPSTREAM_REALM,
    UPSTREAM_USERNAME,
    VENDOR_ERROR_HEADER,
    AuthPolicy,
    HostsMap,
    Registry,
    parse_basic_proxy_auth,
    resolve,
    split_authority,
)

#: The exact status line the fixture sends when a tunnel is established.
CONNECT_OK = b"HTTP/1.1 200 Connection established\r\n\r\n"

_HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authorization",
    "proxy-authenticate",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
    "expect",
}

_REASONS = {
    400: b"Bad Request",
    407: b"Proxy Authentication Required",
    502: b"Bad Gateway",
}


@dataclass
class HTTPProxyRecord:
    """Everything the HTTP upstream saw on one client connection."""

    id: int = 0
    client_port: int = 0
    started_at: float = 0.0
    ended_at: float | None = None
    #: "connect" or "http" (from the first request), "none" if no request arrived.
    kind: str = "none"
    methods: list[str] = field(default_factory=list)
    #: "host:port" per request (never paths or queries).
    targets: list[str] = field(default_factory=list)
    #: Username presented per request (None when no usable Proxy-Authorization).
    usernames: list[str | None] = field(default_factory=list)
    auth_ok: list[bool] = field(default_factory=list)
    #: Status sent to the client per request (origin status for plain HTTP).
    statuses: list[int] = field(default_factory=list)
    #: Request headers per request, Proxy-Authorization value replaced by "<redacted>".
    request_headers: list[list[tuple[str, str]]] = field(default_factory=list)
    #: Vendor error codes sent (e.g. "bad_auth", "host_unknown", "connect_failed").
    errors: list[str] = field(default_factory=list)
    tunnel_established: bool = False
    bytes_from_client: int = 0
    bytes_to_client: int = 0
    bytes_to_origin: int = 0
    bytes_from_origin: int = 0
    origin_connections: int = 0
    closed: bool = False
    # Internal accumulators used to derive the negotiation figures.
    pre_tunnel_from_client: int = 0
    pre_tunnel_to_client: int = 0
    trailing_len: int = 0

    @property
    def negotiation_from_client(self) -> int:
        """Client->proxy bytes of the CONNECT exchange(s); 0 for plain HTTP."""
        if self.kind != "connect":
            return 0
        return self.pre_tunnel_from_client - self.trailing_len

    @property
    def negotiation_to_client(self) -> int:
        """Proxy->client bytes of the CONNECT exchange(s) incl. 407s and the 200 line."""
        if self.kind != "connect":
            return 0
        return self.pre_tunnel_to_client

    @property
    def payload_from_client(self) -> int:
        return self.bytes_from_client - self.negotiation_from_client

    @property
    def payload_to_client(self) -> int:
        return self.bytes_to_client - self.negotiation_to_client

    @property
    def target(self) -> str | None:
        return self.targets[-1] if self.targets else None

    @property
    def username(self) -> str | None:
        """The last accepted username, else the last presented one."""
        for name, ok in zip(reversed(self.usernames), reversed(self.auth_ok)):
            if ok:
                return name
        return self.usernames[-1] if self.usernames else None


@dataclass
class _OriginState:
    key: tuple[str, int] | None = None
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None
    conn: h11.Connection | None = None


class UpstreamHTTPProxy:
    """HTTP CONNECT / absolute-form proxy on 127.0.0.1 with its own loop thread."""

    def __init__(self, hosts: HostsMap, policy: AuthPolicy | None = None, name: str = "http-upstream") -> None:
        self.hosts = hosts
        self.policy = policy if policy is not None else AuthPolicy.default()
        self.name = name
        self.host = "127.0.0.1"
        self.port = 0
        self._registry = Registry()
        self._loop: BackgroundLoop | None = None
        self._server: asyncio.base_events.Server | None = None
        self._tasks: set[asyncio.Task] = set()

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> UpstreamHTTPProxy:
        self._loop = BackgroundLoop(self.name)
        self._server = self._loop.run(asyncio.start_server(self._handle, self.host, 0))
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    def stop(self) -> None:
        if self._loop is None:
            return

        async def _shutdown() -> None:
            if self._server is not None:
                self._server.close()
            for task in list(self._tasks):
                task.cancel()
            if self._tasks:
                await asyncio.wait(list(self._tasks), timeout=5)

        with contextlib.suppress(Exception):
            self._loop.run(_shutdown(), timeout=10)
        self._loop.stop()
        self._loop = None

    # ------------------------------------------------------------------ public API
    @property
    def server(self) -> str:
        """``http://127.0.0.1:PORT`` without credentials (Playwright ``proxy.server``)."""
        return f"http://{self.host}:{self.port}"

    def proxy_url(self, username: str | None = UPSTREAM_USERNAME, password: str | None = UPSTREAM_PASSWORD) -> str:
        """Proxy URL with (percent-encoded) credentials; pass None to omit them."""
        if username is None:
            return self.server
        userinfo = quote(username, safe="")
        if password is not None:
            userinfo += ":" + quote(password, safe="")
        return f"http://{userinfo}@{self.host}:{self.port}"

    @property
    def url(self) -> str:
        """Default proxy URL: with the fixture credentials when auth is required."""
        return self.proxy_url() if self.policy.required else self.server

    def records(self) -> list[HTTPProxyRecord]:
        """Snapshot copies of all connection records since the last reset."""
        return self._registry.snapshot()

    def open_connections(self) -> int:
        return self._registry.open_count()

    def wait_idle(self, timeout: float = 5.0) -> bool:
        """Wait until no client connection is open; True if that happened in time."""
        return wait_until(lambda: self._registry.open_count() == 0, timeout)

    def reset(self, wait: bool = True, timeout: float = 5.0) -> None:
        """Forget all records (optionally waiting for open connections first)."""
        if wait:
            self.wait_idle(timeout)
        self._registry.clear()

    def totals(self) -> dict[str, int]:
        recs = self.records()
        return {
            "connections": len(recs),
            "bytes_from_client": sum(r.bytes_from_client for r in recs),
            "bytes_to_client": sum(r.bytes_to_client for r in recs),
            "negotiation_from_client": sum(r.negotiation_from_client for r in recs),
            "negotiation_to_client": sum(r.negotiation_to_client for r in recs),
            "bytes_to_origin": sum(r.bytes_to_origin for r in recs),
            "bytes_from_origin": sum(r.bytes_from_origin for r in recs),
        }

    # ------------------------------------------------------------------ counting
    def _count_in(self, rec: HTTPProxyRecord, n: int) -> None:
        with self._registry.lock:
            rec.bytes_from_client += n
            if not rec.tunnel_established:
                rec.pre_tunnel_from_client += n

    async def _send(self, writer: asyncio.StreamWriter, rec: HTTPProxyRecord, data: bytes) -> None:
        if not data:
            return
        with self._registry.lock:
            rec.bytes_to_client += len(data)
            if not rec.tunnel_established:
                rec.pre_tunnel_to_client += len(data)
        writer.write(data)
        await writer.drain()

    async def _next_event(self, conn: h11.Connection, reader: asyncio.StreamReader, rec: HTTPProxyRecord):
        while True:
            event = conn.next_event()
            if event is h11.NEED_DATA:
                data = await reader.read(PUMP_CHUNK)
                if data:
                    self._count_in(rec, len(data))
                conn.receive_data(data)
                continue
            return event

    async def _next_origin_event(self, st: _OriginState, rec: HTTPProxyRecord):
        assert st.conn is not None and st.reader is not None
        while True:
            event = st.conn.next_event()
            if event is h11.NEED_DATA:
                data = await st.reader.read(PUMP_CHUNK)
                if data:
                    with self._registry.lock:
                        rec.bytes_from_origin += len(data)
                st.conn.receive_data(data)
                continue
            return event

    async def _to_origin(self, st: _OriginState, rec: HTTPProxyRecord, data: bytes) -> None:
        assert st.writer is not None
        if not data:
            return
        with self._registry.lock:
            rec.bytes_to_origin += len(data)
        st.writer.write(data)
        await st.writer.drain()

    # ------------------------------------------------------------------ handling
    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
        peer = writer.get_extra_info("peername") or ("", 0)
        rec = HTTPProxyRecord(client_port=peer[1] if len(peer) > 1 else 0, started_at=time.time())
        self._registry.add(rec)
        conn = h11.Connection(h11.SERVER, max_incomplete_event_size=64 * 1024)
        origin = _OriginState()
        try:
            while True:
                event = await self._next_event(conn, reader, rec)
                if not isinstance(event, h11.Request):
                    break
                keep = await self._handle_request(event, conn, reader, writer, rec, origin)
                if not keep:
                    break
                if conn.our_state is h11.DONE and conn.their_state is h11.DONE:
                    conn.start_next_cycle()
                else:
                    break
        except h11.RemoteProtocolError:
            recorded = len(rec.errors)
            with contextlib.suppress(Exception):
                if conn.our_state in (h11.IDLE, h11.SEND_RESPONSE):
                    await self._error(conn, writer, rec, 400, "bad_request", head_only=False)
            if len(rec.errors) == recorded:  # _error records the code itself; record it once
                rec.errors.append("bad_request")
        except (ConnectionError, OSError, asyncio.IncompleteReadError, h11.LocalProtocolError):
            rec.errors.append("connection_error")
        except Exception as exc:  # a fixture bug must not kill the loop silently
            rec.errors.append(f"internal:{type(exc).__name__}")
        finally:
            await close_writer(origin.writer)
            await close_writer(writer)
            with self._registry.lock:
                rec.ended_at = time.time()
                rec.closed = True
            self._registry.closed(rec)
            if task is not None:
                self._tasks.discard(task)

    async def _drain_body(self, conn: h11.Connection, reader: asyncio.StreamReader, rec: HTTPProxyRecord) -> None:
        while True:
            event = await self._next_event(conn, reader, rec)
            if isinstance(event, h11.EndOfMessage):
                return
            if not isinstance(event, h11.Data):
                raise ConnectionError("client went away mid-request")

    async def _error(
        self,
        conn: h11.Connection,
        writer: asyncio.StreamWriter,
        rec: HTTPProxyRecord,
        status: int,
        code: str,
        *,
        head_only: bool,
    ) -> None:
        body = b"" if head_only else f"{status} {code}\n".encode("ascii")
        headers = [
            ("Content-Type", "text/plain"),
            ("Content-Length", str(len(body)) if not head_only else "0"),
            (VENDOR_ERROR_HEADER, code),
        ]
        if status == 407:
            headers.append(("Proxy-Authenticate", f'Basic realm="{UPSTREAM_REALM}"'))
        data = conn.send(h11.Response(status_code=status, headers=headers, reason=_REASONS.get(status, b"")))
        if body:
            data += conn.send(h11.Data(data=body))
        data += conn.send(h11.EndOfMessage())
        rec.statuses.append(status)
        rec.errors.append(code)
        await self._send(writer, rec, data)

    async def _handle_request(
        self,
        req: h11.Request,
        conn: h11.Connection,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        rec: HTTPProxyRecord,
        origin: _OriginState,
    ) -> bool:
        """Serve one request; return True to keep the client connection."""
        method = req.method.decode("ascii", "replace").upper()
        target = req.target.decode("latin-1")
        raw_headers = [(n.decode("latin-1"), v.decode("latin-1")) for n, v in req.headers.raw_items()]
        auth_value = next((v for n, v in raw_headers if n.lower() == "proxy-authorization"), None)
        username, password = parse_basic_proxy_auth(auth_value)
        redacted = [(n, "<redacted>" if n.lower() == "proxy-authorization" else v) for n, v in raw_headers]
        ok = self.policy.check(username, password)
        head_only = method == "HEAD"
        with self._registry.lock:
            if rec.kind == "none":
                rec.kind = "connect" if method == "CONNECT" else "http"
            rec.methods.append(method)
            rec.usernames.append(username)
            rec.auth_ok.append(ok)
            rec.request_headers.append(redacted)

        if method == "CONNECT":
            await self._drain_body(conn, reader, rec)
            hp = split_authority(target)
            rec.targets.append(f"{hp[0]}:{hp[1]}" if hp else target[:200])
            if not ok:
                await self._error(conn, writer, rec, 407, "bad_auth" if auth_value else "auth_required", head_only=False)
                return True
            if hp is None:
                await self._error(conn, writer, rec, 400, "bad_target", head_only=False)
                return True
            dest = resolve(self.hosts, *hp)
            if dest is None:
                await self._error(conn, writer, rec, 502, "host_unknown", head_only=False)
                return True
            try:
                o_reader, o_writer = await asyncio.wait_for(asyncio.open_connection(*dest), 10)
            except (OSError, asyncio.TimeoutError):
                await self._error(conn, writer, rec, 502, "connect_failed", head_only=False)
                return True
            try:
                rec.origin_connections += 1
                rec.statuses.append(200)
                await self._send(writer, rec, CONNECT_OK)
                trailing, client_closed = conn.trailing_data
                with self._registry.lock:
                    rec.tunnel_established = True
                    rec.trailing_len = len(trailing)
                if trailing:
                    with self._registry.lock:
                        rec.bytes_to_origin += len(trailing)
                    o_writer.write(trailing)
                    await o_writer.drain()
                if client_closed and o_writer.can_write_eof():
                    o_writer.write_eof()

                def on_client(n: int) -> None:
                    with self._registry.lock:
                        rec.bytes_from_client += n
                        rec.bytes_to_origin += n

                def on_origin(n: int) -> None:
                    with self._registry.lock:
                        rec.bytes_from_origin += n
                        rec.bytes_to_client += n

                await splice(reader, writer, o_reader, o_writer, on_client, on_origin)
            finally:
                await close_writer(o_writer)
            return False

        # ---- absolute-form plain HTTP
        split = urlsplit(target)
        scheme = split.scheme.lower()
        host = (split.hostname or "").lower()
        try:
            port = split.port or 80
        except ValueError:
            port = 0
        rec.targets.append(f"{host}:{port}" if host else "(origin-form)")
        if not ok:
            await self._drain_body(conn, reader, rec)
            await self._error(conn, writer, rec, 407, "bad_auth" if auth_value else "auth_required", head_only=head_only)
            return True
        if scheme != "http" or not host or not port:
            await self._drain_body(conn, reader, rec)
            code = "https_absolute_form_unsupported" if scheme == "https" else "not_a_proxy_request"
            await self._error(conn, writer, rec, 400, code, head_only=head_only)
            return True
        dest = resolve(self.hosts, host, port)
        if dest is None:
            await self._drain_body(conn, reader, rec)
            await self._error(conn, writer, rec, 502, "host_unknown", head_only=head_only)
            return True
        if origin.key != (host, port) or origin.writer is None:
            await close_writer(origin.writer)
            origin.writer = None
            try:
                origin.reader, origin.writer = await asyncio.wait_for(asyncio.open_connection(*dest), 10)
            except (OSError, asyncio.TimeoutError):
                await self._drain_body(conn, reader, rec)
                await self._error(conn, writer, rec, 502, "connect_failed", head_only=head_only)
                return True
            origin.key = (host, port)
            origin.conn = h11.Connection(h11.CLIENT)
            rec.origin_connections += 1
        assert origin.conn is not None

        path = split.path or "/"
        if split.query:
            path += "?" + split.query
        out_headers = [(n, v) for n, v in raw_headers if n.lower() not in _HOP_BY_HOP]
        if not any(n.lower() == "host" for n, _ in out_headers):
            out_headers.insert(0, ("Host", split.netloc))
        if conn.they_are_waiting_for_100_continue:
            await self._send(writer, rec, conn.send(h11.InformationalResponse(status_code=100, headers=[])))
        await self._to_origin(
            origin, rec, origin.conn.send(h11.Request(method=req.method, target=path.encode("latin-1"), headers=out_headers))
        )
        while True:
            event = await self._next_event(conn, reader, rec)
            if isinstance(event, h11.Data):
                await self._to_origin(origin, rec, origin.conn.send(h11.Data(data=event.data)))
            elif isinstance(event, h11.EndOfMessage):
                await self._to_origin(origin, rec, origin.conn.send(h11.EndOfMessage()))
                break
            else:
                raise ConnectionError("client went away mid-request")

        while True:
            event = await self._next_origin_event(origin, rec)
            if isinstance(event, h11.InformationalResponse):
                continue
            if isinstance(event, h11.Response):
                headers = [
                    (n.decode("latin-1"), v.decode("latin-1"))
                    for n, v in event.headers.raw_items()
                    if n.decode("latin-1").lower() not in _HOP_BY_HOP
                ]
                rec.statuses.append(event.status_code)
                await self._send(
                    writer,
                    rec,
                    conn.send(h11.Response(status_code=event.status_code, headers=headers, reason=event.reason)),
                )
            elif isinstance(event, h11.Data):
                await self._send(writer, rec, conn.send(h11.Data(data=event.data)))
            elif isinstance(event, h11.EndOfMessage):
                await self._send(writer, rec, conn.send(h11.EndOfMessage()))
                break
            else:
                rec.errors.append("origin_closed")
                return False

        if origin.conn.our_state is h11.DONE and origin.conn.their_state is h11.DONE:
            origin.conn.start_next_cycle()
        else:
            await close_writer(origin.writer)
            origin.writer = None
            origin.key = None
        return True
