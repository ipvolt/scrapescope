"""SOCKS5 proxy fixture (RFC 1928) with optional RFC 1929 username/password auth.

- Domain-name targets (ATYP 3) are resolved through the hosts map (remote
  DNS); unknown names get reply ``0x04`` (host unreachable).
- IPv4/IPv6 literal targets are accepted only for loopback addresses, and the
  ATYP used is recorded so tests can assert that clients sent the hostname.
- Only CONNECT (CMD 1) is supported; other commands get ``0x07``.
- A wrong username/password gets sub-negotiation status ``0x01`` and the
  connection is closed, as RFC 1929 requires.

Counting: per client connection, the bytes consumed from and written to the
CLIENT-side socket, the negotiation portion (greeting, method selection,
auth, request and reply) and the bytes exchanged with the origin.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import socket
import struct
import time
from dataclasses import dataclass, field
from urllib.parse import quote

from ._aio import BackgroundLoop, close_writer, splice, wait_until
from .common import (
    UPSTREAM_PASSWORD,
    UPSTREAM_USERNAME,
    AuthPolicy,
    HostsMap,
    Registry,
    resolve,
)

REP_SUCCEEDED = 0x00
REP_GENERAL_FAILURE = 0x01
REP_NOT_ALLOWED = 0x02
REP_HOST_UNREACHABLE = 0x04
REP_CONNECTION_REFUSED = 0x05
REP_COMMAND_NOT_SUPPORTED = 0x07
REP_ATYP_NOT_SUPPORTED = 0x08

METHOD_NO_AUTH = 0x00
METHOD_USERPASS = 0x02
METHOD_NONE_ACCEPTABLE = 0xFF


class _Closed(Exception):
    """The client closed the connection during negotiation."""


@dataclass
class SocksRecord:
    """Everything the SOCKS5 upstream saw on one client connection."""

    id: int = 0
    client_port: int = 0
    started_at: float = 0.0
    ended_at: float | None = None
    methods_offered: list[int] = field(default_factory=list)
    method_selected: int | None = None
    username: str | None = None
    #: None when no RFC 1929 sub-negotiation took place.
    auth_ok: bool | None = None
    #: "ipv4", "domain" or "ipv6".
    atyp: str | None = None
    target_host: str | None = None
    target_port: int | None = None
    reply_code: int | None = None
    tunnel_established: bool = False
    greeting_bytes: int = 0
    method_reply_bytes: int = 0
    auth_request_bytes: int = 0
    auth_reply_bytes: int = 0
    request_bytes: int = 0
    reply_bytes: int = 0
    bytes_from_client: int = 0
    bytes_to_client: int = 0
    bytes_to_origin: int = 0
    bytes_from_origin: int = 0
    error: str | None = None
    closed: bool = False

    @property
    def target(self) -> str | None:
        if self.target_host is None:
            return None
        return f"{self.target_host}:{self.target_port}"

    @property
    def negotiation_from_client(self) -> int:
        return self.greeting_bytes + self.auth_request_bytes + self.request_bytes

    @property
    def negotiation_to_client(self) -> int:
        return self.method_reply_bytes + self.auth_reply_bytes + self.reply_bytes

    @property
    def payload_from_client(self) -> int:
        return self.bytes_from_client - self.negotiation_from_client

    @property
    def payload_to_client(self) -> int:
        return self.bytes_to_client - self.negotiation_to_client


class UpstreamSocks5Proxy:
    """SOCKS5 proxy on 127.0.0.1 with its own loop thread."""

    def __init__(self, hosts: HostsMap, policy: AuthPolicy | None = None, name: str = "socks-upstream") -> None:
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
    def start(self) -> UpstreamSocks5Proxy:
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
    def proxy_url(
        self,
        username: str | None = UPSTREAM_USERNAME,
        password: str | None = UPSTREAM_PASSWORD,
        scheme: str = "socks5",
    ) -> str:
        """Proxy URL; ``scheme="socks5h"`` for clients (requests/curl) that need it for remote DNS."""
        if username is None:
            return f"{scheme}://{self.host}:{self.port}"
        userinfo = quote(username, safe="")
        if password is not None:
            userinfo += ":" + quote(password, safe="")
        return f"{scheme}://{userinfo}@{self.host}:{self.port}"

    @property
    def url(self) -> str:
        """``socks5://`` URL, with the fixture credentials when auth is required."""
        return self.proxy_url() if self.policy.required else self.proxy_url(None)

    @property
    def url_h(self) -> str:
        """Same as :attr:`url` with the ``socks5h`` scheme (remote DNS in requests/curl)."""
        if self.policy.required:
            return self.proxy_url(scheme="socks5h")
        return self.proxy_url(None, scheme="socks5h")

    def records(self) -> list[SocksRecord]:
        return self._registry.snapshot()

    def open_connections(self) -> int:
        return self._registry.open_count()

    def wait_idle(self, timeout: float = 5.0) -> bool:
        return wait_until(lambda: self._registry.open_count() == 0, timeout)

    def reset(self, wait: bool = True, timeout: float = 5.0) -> None:
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

    # ------------------------------------------------------------------ handling
    async def _read(self, reader: asyncio.StreamReader, rec: SocksRecord, n: int, part: str) -> bytes:
        try:
            data = await reader.readexactly(n)
        except asyncio.IncompleteReadError as exc:
            with self._registry.lock:
                rec.bytes_from_client += len(exc.partial)
                setattr(rec, part, getattr(rec, part) + len(exc.partial))
            raise _Closed from exc
        with self._registry.lock:
            rec.bytes_from_client += n
            setattr(rec, part, getattr(rec, part) + n)
        return data

    async def _write(self, writer: asyncio.StreamWriter, rec: SocksRecord, data: bytes, part: str) -> None:
        with self._registry.lock:
            rec.bytes_to_client += len(data)
            setattr(rec, part, getattr(rec, part) + len(data))
        writer.write(data)
        await writer.drain()

    @staticmethod
    def _reply(code: int, bind: tuple[str, int] | None = None) -> bytes:
        host, port = bind if bind is not None else ("0.0.0.0", 0)
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = ipaddress.ip_address("0.0.0.0")
        if ip.version == 4:
            return bytes([5, code, 0, 1]) + ip.packed + struct.pack(">H", port)
        return bytes([5, code, 0, 4]) + ip.packed + struct.pack(">H", port)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
        peer = writer.get_extra_info("peername") or ("", 0)
        rec = SocksRecord(client_port=peer[1] if len(peer) > 1 else 0, started_at=time.time())
        self._registry.add(rec)
        o_writer: asyncio.StreamWriter | None = None
        try:
            ver, nmethods = await self._read(reader, rec, 2, "greeting_bytes")
            if ver != 5:
                rec.error = "bad_version"
                return
            methods = list(await self._read(reader, rec, nmethods, "greeting_bytes"))
            rec.methods_offered = methods
            if self.policy.required:
                chosen = METHOD_USERPASS if METHOD_USERPASS in methods else METHOD_NONE_ACCEPTABLE
            elif METHOD_NO_AUTH in methods:
                chosen = METHOD_NO_AUTH
            elif METHOD_USERPASS in methods:
                chosen = METHOD_USERPASS
            else:
                chosen = METHOD_NONE_ACCEPTABLE
            rec.method_selected = chosen
            await self._write(writer, rec, bytes([5, chosen]), "method_reply_bytes")
            if chosen == METHOD_NONE_ACCEPTABLE:
                rec.error = "no_acceptable_method"
                return
            if chosen == METHOD_USERPASS:
                (sub_ver,) = await self._read(reader, rec, 1, "auth_request_bytes")
                (ulen,) = await self._read(reader, rec, 1, "auth_request_bytes")
                uname = await self._read(reader, rec, ulen, "auth_request_bytes")
                (plen,) = await self._read(reader, rec, 1, "auth_request_bytes")
                passwd = await self._read(reader, rec, plen, "auth_request_bytes")
                username = uname.decode("utf-8", "replace")
                password = passwd.decode("utf-8", "replace")
                ok = sub_ver == 1 and self.policy.check(username, password)
                rec.username = username
                rec.auth_ok = ok
                await self._write(writer, rec, bytes([1, 0 if ok else 1]), "auth_reply_bytes")
                if not ok:
                    rec.error = "auth_failed"
                    return

            ver, cmd, _rsv, atyp = await self._read(reader, rec, 4, "request_bytes")
            if atyp == 1:
                host = str(ipaddress.IPv4Address(await self._read(reader, rec, 4, "request_bytes")))
                rec.atyp = "ipv4"
            elif atyp == 3:
                (dlen,) = await self._read(reader, rec, 1, "request_bytes")
                host = (await self._read(reader, rec, dlen, "request_bytes")).decode("ascii", "replace").lower()
                rec.atyp = "domain"
            elif atyp == 4:
                host = str(ipaddress.IPv6Address(await self._read(reader, rec, 16, "request_bytes")))
                rec.atyp = "ipv6"
            else:
                rec.reply_code = REP_ATYP_NOT_SUPPORTED
                rec.error = "bad_atyp"
                await self._write(writer, rec, self._reply(REP_ATYP_NOT_SUPPORTED), "reply_bytes")
                return
            (port,) = struct.unpack(">H", await self._read(reader, rec, 2, "request_bytes"))
            rec.target_host, rec.target_port = host, port
            if ver != 5 or cmd != 1:
                rec.reply_code = REP_COMMAND_NOT_SUPPORTED
                rec.error = "command_not_supported"
                await self._write(writer, rec, self._reply(REP_COMMAND_NOT_SUPPORTED), "reply_bytes")
                return
            dest = resolve(self.hosts, host, port)
            if dest is None:
                code = REP_HOST_UNREACHABLE if rec.atyp == "domain" else REP_NOT_ALLOWED
                rec.reply_code = code
                rec.error = "host_unknown" if rec.atyp == "domain" else "not_allowed"
                await self._write(writer, rec, self._reply(code), "reply_bytes")
                return
            try:
                o_reader, o_writer = await asyncio.wait_for(asyncio.open_connection(*dest), 10)
            except (OSError, asyncio.TimeoutError):
                rec.reply_code = REP_CONNECTION_REFUSED
                rec.error = "connect_failed"
                await self._write(writer, rec, self._reply(REP_CONNECTION_REFUSED), "reply_bytes")
                return
            bind = o_writer.get_extra_info("sockname")
            rec.reply_code = REP_SUCCEEDED
            await self._write(writer, rec, self._reply(REP_SUCCEEDED, (bind[0], bind[1]) if bind else None), "reply_bytes")
            with self._registry.lock:
                rec.tunnel_established = True

            def on_client(n: int) -> None:
                with self._registry.lock:
                    rec.bytes_from_client += n
                    rec.bytes_to_origin += n

            def on_origin(n: int) -> None:
                with self._registry.lock:
                    rec.bytes_from_origin += n
                    rec.bytes_to_client += n

            await splice(reader, writer, o_reader, o_writer, on_client, on_origin)
        except _Closed:
            rec.error = rec.error or "client_closed"
        except (ConnectionError, OSError, socket.error):
            rec.error = rec.error or "connection_error"
        except Exception as exc:  # a fixture bug must not kill the loop silently
            rec.error = rec.error or f"internal:{type(exc).__name__}"
        finally:
            await close_writer(o_writer)
            await close_writer(writer)
            with self._registry.lock:
                rec.ended_at = time.time()
                rec.closed = True
            self._registry.closed(rec)
            if task is not None:
                self._tasks.discard(task)
