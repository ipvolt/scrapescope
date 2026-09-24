"""Fixture origins: a counting TCP relay in front of a threaded HTTP(S) server.

Each :class:`OriginServer` serves one fake hostname over one scheme. Its public
port is an asyncio relay that counts the exact wire bytes of every client
connection (TLS records included) and forwards them to an internal
``ThreadingHTTPServer`` on another loopback port, which terminates TLS
(trustme certificate, HTTP/1.1 via ALPN) and serves :mod:`.site`.

Per connection the origin records bytes in/out, completed TLS handshakes, the
SNI name and the requests served on it (method, path, query, headers, status,
body sizes). Keep-alive, ``Expect: 100-continue``, HEAD, chunked request and
response bodies, close-delimited responses and ETag/304 are supported.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import select
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from . import site
from ._aio import BackgroundLoop, close_writer, splice, wait_until
from .common import Registry

HANDLER_IDLE_TIMEOUT = 900.0
#: Longest a ``stall_after`` response waits for the client to go away before closing on its own.
STALL_LIMIT_S = 60.0


@dataclass
class OriginRequestRecord:
    conn_id: int | None
    site: str
    scheme: str
    method: str
    path: str
    query: str
    #: Request headers as received (names in original case).
    headers: list[tuple[str, str]]
    status: int
    request_body_bytes: int
    #: Body bytes written (after compression; 0 for HEAD/204/304).
    response_body_bytes: int
    content_encoding: str | None
    ts: float

    def header(self, name: str) -> str | None:
        name = name.lower()
        for key, value in self.headers:
            if key.lower() == name:
                return value
        return None


@dataclass
class OriginConnRecord:
    id: int = 0
    host: str = ""
    scheme: str = ""
    client_port: int = 0
    started_at: float = 0.0
    ended_at: float | None = None
    #: Wire bytes read from the client (TLS included).
    bytes_in: int = 0
    #: Wire bytes written to the client (TLS included).
    bytes_out: int = 0
    tls_handshakes: int = 0
    tls_failures: int = 0
    sni: str | None = None
    requests: list[OriginRequestRecord] = field(default_factory=list)
    closed: bool = False


class _InternalServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128

    def __init__(self, origin: OriginServer, ssl_ctx: ssl.SSLContext | None) -> None:
        self.origin = origin
        self.ssl_ctx = ssl_ctx
        self._sni = threading.local()
        if ssl_ctx is not None:
            ssl_ctx.sni_callback = self._on_sni
        super().__init__(("127.0.0.1", 0), _Handler)

    def _on_sni(self, _sslobj, server_name, _ctx):  # noqa: ANN001
        self._sni.name = server_name
        return None

    def finish_request(self, request, client_address):  # noqa: ANN001
        port = client_address[1]
        if self.ssl_ctx is None:
            self.RequestHandlerClass(request, client_address, self)
            return
        self._sni.name = None
        request.settimeout(30)
        try:
            tls_sock = self.ssl_ctx.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError) as exc:
            self.origin._note_tls(port, ok=False, sni=getattr(self._sni, "name", None), error=type(exc).__name__)
            return
        self.origin._note_tls(port, ok=True, sni=getattr(self._sni, "name", None))
        try:
            tls_sock.settimeout(None)
            self.RequestHandlerClass(tls_sock, client_address, self)
        finally:
            with contextlib.suppress(OSError):
                tls_sock.close()

    def handle_error(self, request, client_address):  # noqa: ANN001
        # Client disconnects are normal in tests; stay quiet.
        return


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = HANDLER_IDLE_TIMEOUT
    server: _InternalServer
    _server_header = "fixture-origin"

    def version_string(self) -> str:
        return self._server_header

    def log_message(self, format, *args):  # noqa: A002, ANN001
        return

    # Every method goes through one dispatcher.
    def do_GET(self) -> None:
        self._dispatch()

    do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_GET

    def _read_body(self) -> bytes:
        te = (self.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in te:
            chunks = []
            while True:
                line = self.rfile.readline(65537)
                size = int(line.split(b";", 1)[0].strip() or b"0", 16)
                if size == 0:
                    while self.rfile.readline(65537) not in (b"\r\n", b"\n", b""):
                        pass
                    break
                chunks.append(self.rfile.read(size))
                self.rfile.readline(3)
            return b"".join(chunks)
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length > 0 else b""

    def _dispatch(self) -> None:
        origin = self.server.origin
        split = urlsplit(self.path)
        path = split.path or "/"
        body = self._read_body()
        header_items = list(self.headers.items())
        req = site.Request(
            site=origin.site,
            scheme=origin.scheme,
            method=self.command,
            path=path,
            query=split.query,
            headers={k.lower(): v for k, v in header_items},
            body=body,
        )
        resp = site.handle(req)
        head_only = self.command == "HEAD"
        status = resp.status
        encoding: str | None = None
        payload = resp.body
        extra: list[tuple[str, str]] = []
        if isinstance(payload, bytes) and resp.compressible:
            extra.append(("Vary", "Accept-Encoding"))
            if "gzip" in (self.headers.get("Accept-Encoding") or "").lower():
                payload = site.gzip_body(payload)
                encoding = "gzip"
        etag = None
        if isinstance(payload, bytes) and status == 200 and resp.cache.startswith("public"):
            etag = '"' + hashlib.sha256(payload).hexdigest()[:24] + ('-gz"' if encoding else '"')
            inm = self.headers.get("If-None-Match")
            if inm and etag in [t.strip() for t in inm.split(",")]:
                status, payload = 304, b""
        no_body = head_only or status in (204, 304) or 100 <= status < 200

        self._server_header = resp.server or "fixture-origin"
        self.send_response(status)
        if resp.content_type and status != 304:
            self.send_header("Content-Type", resp.content_type)
        self.send_header("Cache-Control", resp.cache)
        if etag:
            self.send_header("ETag", etag)
        if encoding and status != 304:
            self.send_header("Content-Encoding", encoding)
        for name, value in extra + resp.headers:
            self.send_header(name, value)

        if isinstance(payload, bytes):
            expected = 0 if no_body else len(payload)
        else:
            expected = 0 if no_body or resp.framing != "length" else (resp.length or 0)
        record = OriginRequestRecord(
            conn_id=None,
            site=origin.site,
            scheme=origin.scheme,
            method=self.command,
            path=path,
            query=split.query,
            headers=header_items,
            status=status,
            request_body_bytes=len(body),
            response_body_bytes=expected,
            content_encoding=encoding,
            ts=time.time(),
        )
        # Recorded before the body is written so a client never sees a response
        # that the origin has not recorded yet.
        origin._note_request(self.client_address[1], record)

        written = 0
        try:
            if isinstance(payload, bytes):
                if status not in (204, 304):
                    self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if not no_body and payload:
                    self.wfile.write(payload)
                    written = len(payload)
            elif resp.framing == "chunked":
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                if not no_body:
                    for piece in payload():
                        self.wfile.write(b"%x\r\n" % len(piece) + piece + b"\r\n")
                        written += len(piece)
                    self.wfile.write(b"0\r\n\r\n")
            elif resp.framing == "close":
                self.send_header("Connection", "close")
                self.close_connection = True
                self.end_headers()
                if not no_body:
                    for piece in payload():
                        self.wfile.write(piece)
                        written += len(piece)
            else:
                self.send_header("Content-Length", str(resp.length or 0))
                self.end_headers()
                if not no_body:
                    for piece in payload():
                        if resp.stall_after is not None and written + len(piece) >= resp.stall_after:
                            piece = piece[: resp.stall_after - written]
                            self.wfile.write(piece)
                            written += len(piece)
                            self._stall_until_peer_closes()
                            break
                        self.wfile.write(piece)
                        written += len(piece)
            with contextlib.suppress(Exception):
                self.wfile.flush()
        finally:
            origin._update_request(record, written)

    def _stall_until_peer_closes(self, limit_s: float = STALL_LIMIT_S) -> None:
        """Stop writing mid-body and wait until the client goes away (or ``limit_s`` passes), then close.

        The handler's socket is the plain TCP leg behind the relay (TLS ends there), and
        the client never sends more on a connection with a response in flight, so the
        socket turning readable means EOF: the client, or the relay on its behalf, closed.
        The response stays incomplete and ``close_connection`` ends the connection.
        """
        with contextlib.suppress(Exception):
            self.wfile.flush()
        self.close_connection = True
        deadline = time.monotonic() + limit_s
        while (remaining := deadline - time.monotonic()) > 0:
            readable, _, _ = select.select([self.connection], [], [], min(remaining, 1.0))
            if readable:
                return


class OriginServer:
    """One fake hostname over one scheme, with byte counting per connection."""

    def __init__(
        self,
        host: str,
        scheme: str,
        ssl_ctx: ssl.SSLContext | None = None,
        loop: BackgroundLoop | None = None,
        site_id: str | None = None,
    ) -> None:
        if scheme == "https" and ssl_ctx is None:
            raise ValueError("https origin needs an SSL context")
        self.host = host
        self.scheme = scheme
        self.site = site_id or site.SITE_OF_HOST.get(host, "c")
        self.default_port = 443 if scheme == "https" else 80
        self.port = 0
        self._ssl_ctx = ssl_ctx if scheme == "https" else None
        self._own_loop = loop is None
        self._loop = loop
        self._registry = Registry()
        self._port_to_conn: dict[int, OriginConnRecord] = {}
        self._internal: _InternalServer | None = None
        self._internal_thread: threading.Thread | None = None
        self._relay: asyncio.base_events.Server | None = None
        self._tasks: set[asyncio.Task] = set()
        self._orphans: list[OriginRequestRecord] = []

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> OriginServer:
        self._internal = _InternalServer(self, self._ssl_ctx)
        self._internal_thread = threading.Thread(
            target=self._internal.serve_forever, kwargs={"poll_interval": 0.2}, name=f"origin-{self.host}-{self.scheme}", daemon=True
        )
        self._internal_thread.start()
        if self._loop is None:
            self._loop = BackgroundLoop(f"origin-{self.host}-{self.scheme}")
        self._relay = self._loop.run(asyncio.start_server(self._on_client, "127.0.0.1", 0))
        self.port = self._relay.sockets[0].getsockname()[1]
        return self

    def stop(self) -> None:
        if self._loop is not None and self._relay is not None:

            async def _shutdown() -> None:
                assert self._relay is not None
                self._relay.close()
                for task in list(self._tasks):
                    task.cancel()
                if self._tasks:
                    await asyncio.wait(list(self._tasks), timeout=5)

            with contextlib.suppress(Exception):
                self._loop.run(_shutdown(), timeout=10)
            self._relay = None
            if self._own_loop:
                self._loop.stop()
        if self._internal is not None:
            self._internal.shutdown()
            self._internal.server_close()
            self._internal = None

    # ------------------------------------------------------------------ public API
    @property
    def address(self) -> tuple[str, int]:
        return ("127.0.0.1", self.port)

    def url(self, path: str = "/") -> str:
        """The public URL of this origin (by fake hostname, default port)."""
        return f"{self.scheme}://{self.host}{path}"

    def connections(self) -> list[OriginConnRecord]:
        return self._registry.snapshot()

    def requests(self) -> list[OriginRequestRecord]:
        """All requests served since the last reset, in arrival order."""
        reqs = [r for c in self.connections() for r in c.requests]
        with self._registry.lock:
            reqs.extend(list(self._orphans))
        return sorted(reqs, key=lambda r: r.ts)

    def paths(self) -> list[str]:
        return [r.path for r in self.requests()]

    def open_connections(self) -> int:
        return self._registry.open_count()

    def wait_idle(self, timeout: float = 5.0) -> bool:
        return wait_until(lambda: self._registry.open_count() == 0, timeout)

    def wait_for_path(self, path: str, timeout: float = 10.0) -> bool:
        return wait_until(lambda: path in self.paths(), timeout, interval=0.05)

    def reset(self, wait: bool = True, timeout: float = 5.0) -> None:
        if wait:
            self.wait_idle(timeout)
        self._registry.clear()
        with self._registry.lock:
            self._orphans = []

    def totals(self) -> dict[str, int]:
        conns = self.connections()
        return {
            "connections": len(conns),
            "bytes_in": sum(c.bytes_in for c in conns),
            "bytes_out": sum(c.bytes_out for c in conns),
            "tls_handshakes": sum(c.tls_handshakes for c in conns),
            "tls_failures": sum(c.tls_failures for c in conns),
            "requests": sum(len(c.requests) for c in conns),
        }

    # ------------------------------------------------------------------ internal hooks
    def _note_tls(self, port: int, *, ok: bool, sni: str | None, error: str | None = None) -> None:
        with self._registry.lock:
            rec = self._port_to_conn.get(port)
            if rec is None:
                return
            if ok:
                rec.tls_handshakes += 1
            else:
                rec.tls_failures += 1
            if sni:
                rec.sni = sni

    def _note_request(self, port: int, record: OriginRequestRecord) -> None:
        with self._registry.lock:
            rec = self._port_to_conn.get(port)
            if rec is None:
                self._orphans.append(record)
                return
            record.conn_id = rec.id
            rec.requests.append(record)

    def _update_request(self, record: OriginRequestRecord, written: int) -> None:
        with self._registry.lock:
            record.response_body_bytes = written

    async def _on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
        peer = writer.get_extra_info("peername") or ("", 0)
        rec = OriginConnRecord(host=self.host, scheme=self.scheme, client_port=peer[1], started_at=time.time())
        self._registry.add(rec)
        o_writer: asyncio.StreamWriter | None = None
        local_port = None
        try:
            assert self._internal is not None
            o_reader, o_writer = await asyncio.open_connection(*self._internal.server_address[:2])
            sock = o_writer.get_extra_info("socket")
            if sock is not None:
                with contextlib.suppress(OSError):
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            local_port = o_writer.get_extra_info("sockname")[1]
            with self._registry.lock:
                self._port_to_conn[local_port] = rec

            def on_in(n: int) -> None:
                with self._registry.lock:
                    rec.bytes_in += n

            def on_out(n: int) -> None:
                with self._registry.lock:
                    rec.bytes_out += n

            await splice(reader, writer, o_reader, o_writer, on_in, on_out)
        except (ConnectionError, OSError):
            pass
        finally:
            await close_writer(o_writer)
            await close_writer(writer)
            with self._registry.lock:
                rec.ended_at = time.time()
                rec.closed = True
                if local_port is not None:
                    self._port_to_conn.pop(local_port, None)
            self._registry.closed(rec)
            if task is not None:
                self._tasks.discard(task)
