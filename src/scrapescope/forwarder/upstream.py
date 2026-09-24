"""Upstream connectors: HTTP CONNECT (Basic), SOCKS5 (remote DNS, RFC 1929), direct.

Contract: docs/dev/contracts.md sections 3.3, 3.4 and 3.6.

- Target hostnames are never resolved locally on the routes that go to an
  upstream proxy: HTTP CONNECT forwards the client's own request target, and
  SOCKS5 sends names as ATYP 0x03 (only IP literals use 0x01/0x04). For those
  routes the only local lookup is of the upstream proxy's own hostname, which
  the operating system needs to open the socket.
- The meter connects by itself, and therefore resolves the name locally and
  uses this machine's own IP address, on two routes only: ``direct`` (sizing
  mode, no upstream) and ``non-target`` (direct.json hosts under
  ``run --env-all``, also when an upstream is configured).
- On those two routes :func:`open_direct` resolves the name once, refuses the
  meter's own listeners, and connects to the very address it checked, so a
  DNS answer cannot change between the check and the connection. On the
  ``direct`` route it also refuses destinations that are not globally
  routable (loopback, private, link-local, CGNAT, unspecified, multicast)
  unless the user opted in (``--allow-private-targets``). Otherwise a page
  loaded through the meter could reach services on this machine or its
  network: browsers treat anything fetched through a proxy as coming from the
  proxy's own (loopback) address, so their private-network protections do not
  apply. Round 3 (sec3-1): a globally routable address can still be this
  machine's own (a service bound to all interfaces) or, for IPv6, a host on
  its own /64, so after connecting and before writing a byte the meter also
  refuses a connection whose peer is its own source address or shares that
  address's /64 (:func:`check_not_own_address`). IPv4 netmasks are not
  visible, so IPv4 LAN hosts with public addresses are not caught.
  ``non-target`` hosts are exempt from those checks (the server decides):
  they match catalog globs under the API providers' own DNS zones, and a
  private answer there comes from the user's resolver, such as a cloud
  private endpoint.
- Every upstream socket is opened with :func:`open_counted`, whose protocol
  counts received bytes in ``data_received`` (before anything is relayed) and
  whose :class:`UpstreamConnection.write` counts sent bytes as they are handed
  to the transport. When the meter aborts a connection (budget, tunnel cap,
  stop), bytes still queued in the transport are discarded and uncounted
  again, so ``upstream_bytes_sent`` holds only bytes handed to the kernel. See
  :mod:`scrapescope.forwarder.meter` for what that means.
- On the two routes where the meter connects by itself, the checked addresses
  are tried Happy-Eyeballs style (RFC 8305): families interleaved, a new
  attempt every :data:`HAPPY_EYEBALLS_DELAY_S` or as soon as one fails, all
  within one connect deadline. A blackholed first address (a broken IPv6 path)
  therefore costs about 250 ms, as it does for a browser on its own, instead
  of the whole timeout.
- Running out of file descriptors (EMFILE/ENFILE) is reported as
  ``failed:local_limit`` (``503 local-limit``), never as the target or the
  provider refusing: each tunnel costs the meter two descriptors (client and
  upstream socket).
- Error messages and exceptions raised here never contain the upstream host,
  port, username or password: :class:`UpstreamError` carries only fixed
  vocabulary, and OS exceptions are mapped, never echoed.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import ipaddress
import os
import re
import socket
import struct
from dataclasses import dataclass

from ..config import ConnectMap
from ..types import embedded_ipv4, ip_literal
from .meter import Meter, Tunnel, TunnelAborted

#: StreamReader limit for upstream sockets (also bounds reply heads).
READ_LIMIT = 256 * 1024
#: Largest CONNECT reply head accepted from an upstream proxy.
MAX_REPLY_HEAD = 64 * 1024
#: Largest error body relayed from a non-2xx CONNECT reply.
MAX_ERROR_BODY = 1024 * 1024
#: Idle wait while reading a close-delimited error body.
ERROR_BODY_IDLE_S = 2.0
#: Happy Eyeballs connection attempt delay (RFC 8305 section 5 recommends 250 ms).
HAPPY_EYEBALLS_DELAY_S = 0.25
#: errno values meaning "this process or system is out of file descriptors".
_LOCAL_LIMIT_ERRNOS = frozenset(e for e in (getattr(errno, "EMFILE", None), getattr(errno, "ENFILE", None)) if e)

_STATUS_RE = re.compile(rb"HTTP/\d\.\d[ \t]+(\d{3})(?:[ \t]|\r\n)")


class UpstreamError(Exception):
    """Establishing the upstream leg failed.

    ``reason`` becomes the tunnel status ``failed:<reason>``; ``status`` and
    ``error_code`` are the meter's own reply to the client (``X-Scrapescope-Error``).
    """

    def __init__(self, reason: str, status: int, error_code: str, *, socks_reply: int | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status
        self.error_code = error_code
        self.socks_reply = socks_reply


def _unreachable(direct: bool) -> UpstreamError:
    if direct:
        return UpstreamError("connect_refused", 502, "connect-refused")
    return UpstreamError("upstream_unreachable", 502, "upstream-unreachable")


def _timeout(direct: bool) -> UpstreamError:
    if direct:
        return UpstreamError("connect_timeout", 504, "connect-timeout")
    return UpstreamError("upstream_timeout", 504, "upstream-timeout")


def local_limit_error() -> UpstreamError:
    """The meter itself ran out of file descriptors (not the target's or the provider's fault)."""
    return UpstreamError("local_limit", 503, "local-limit")


def is_local_limit(exc: BaseException) -> bool:
    """True for an OS error that means "out of file descriptors" (EMFILE or ENFILE).

    ``loop.create_connection`` folds different per-address errors into one
    ``OSError("Multiple exceptions: ...")`` without an errno; its text still
    carries each ``[Errno N]``.
    """
    if not isinstance(exc, OSError):
        return False
    if exc.errno in _LOCAL_LIMIT_ERRNOS:
        return True
    if exc.errno is None:
        text = str(exc)
        return any(f"[Errno {n}]" in text for n in _LOCAL_LIMIT_ERRNOS)
    return False


def descriptors_exhausted() -> bool:
    """Probe whether this process can open one more file descriptor right now.

    Used only on failure paths whose error does not say why (a resolver
    failure can be a missing descriptor for its own socket).
    """
    try:
        fd = os.open(os.devnull, os.O_RDONLY)
    except OSError as exc:
        return exc.errno in _LOCAL_LIMIT_ERRNOS
    os.close(fd)
    return False


class _CountingProtocol(asyncio.StreamReaderProtocol):
    """StreamReaderProtocol that counts every received byte at the socket."""

    def __init__(self, reader: asyncio.StreamReader, meter: Meter, tunnel: Tunnel, loop: asyncio.AbstractEventLoop) -> None:
        super().__init__(reader, loop=loop)
        self._meter = meter
        self._tunnel = tunnel

    def data_received(self, data: bytes) -> None:
        self._meter.add_received(self._tunnel, len(data))
        super().data_received(data)


class UpstreamConnection:
    """One counted upstream socket bound to one tunnel (never pooled or shared)."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        meter: Meter,
        tunnel: Tunnel,
        protocol: _CountingProtocol | None = None,
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.meter = meter
        self.tunnel = tunnel
        self._protocol = protocol

    def rebind(self, tunnel: Tunnel) -> None:
        """Charge this connection's bytes to ``tunnel`` from now on.

        Only for plain HTTP over an HTTP CONNECT upstream, at a request
        boundary: the connection goes to the provider, which serves every
        authority, so a keep-alive client that switches authority keeps it
        (meas3-3) and only the record changes. The new tunnel can abort it.
        """
        if self._protocol is not None:
            self._protocol._tunnel = tunnel
        self.tunnel = tunnel
        tunnel.add_aborter(self.abort)

    def write(self, data: bytes, *, negotiation: bool = False) -> None:
        """Hand ``data`` to the transport, then count it; raises :class:`TunnelAborted` if the meter closed the tunnel.

        Writing first means the slice that trips the budget or the tunnel cap is
        really handed over; the abort that follows discards whatever is still
        queued in the transport and uncounts it (:meth:`abort`), so sent bytes
        are those handed to the kernel (contracts section 3.6, "when written").
        A transport that is already closing drops writes, so they are not counted.
        """
        if not data:
            return
        if self.tunnel.closing:
            raise TunnelAborted
        if self.writer.transport.is_closing():
            return  # dropped by asyncio; the next drain() reports the lost connection
        self.writer.write(data)
        self.meter.add_sent(self.tunnel, len(data), negotiation=len(data) if negotiation else 0)
        if self.tunnel.closing:  # this write tripped the budget or the tunnel cap
            raise TunnelAborted

    async def drain(self) -> None:
        await self.writer.drain()

    def write_eof(self) -> None:
        with contextlib.suppress(Exception):
            if not self.writer.is_closing() and self.writer.can_write_eof():
                self.writer.write_eof()

    def abort(self) -> None:
        """Close at once; bytes still queued in the transport never leave, so they are uncounted."""
        unsent = 0
        with contextlib.suppress(Exception):
            transport = self.writer.transport
            unsent = transport.get_write_buffer_size()  # 0 after an earlier abort (the buffer is cleared)
            transport.abort()
        if unsent > 0:
            self.meter.discard_sent(self.tunnel, unsent)

    def reset(self) -> None:
        """Close with a TCP reset (SO_LINGER 0), to pass a client's reset on to the upstream."""
        with contextlib.suppress(Exception):
            sock = self.writer.transport.get_extra_info("socket")
            if sock is not None:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        self.abort()

    async def close(self) -> None:
        with contextlib.suppress(Exception):
            self.writer.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(self.writer.wait_closed(), timeout=2.0)


IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def is_loopback_literal(host: str) -> bool:
    ip = ip_literal(host)
    return ip is not None and ip.is_loopback


def is_self_address(ip: IPAddress) -> bool:
    """True for addresses that reach this machine's own listeners (loopback or unspecified).

    IPv6 forms that stand for an IPv4 address (:func:`scrapescope.types.embedded_ipv4`)
    are judged by that address.
    """
    embedded = embedded_ipv4(ip)
    if embedded is not None:
        ip = embedded
    return ip.is_loopback or ip.is_unspecified


#: IPv6 ranges refused on direct routes whatever the Python version's ``is_global`` says:
#: deprecated site-local (RFC 3879), 6to4 (RFC 3056, carries an IPv4 address and is not
#: globally reachable per the IANA special-purpose registry) and the local-use NAT64
#: prefix (RFC 8215). Python 3.11 treats the last two as global.
_NON_GLOBAL_V6 = (
    ipaddress.IPv6Network("fec0::/10"),
    ipaddress.IPv6Network("2002::/16"),
    ipaddress.IPv6Network("64:ff9b:1::/48"),
)


def is_private_destination(ip: IPAddress) -> bool:
    """True for destinations the meter refuses on direct routes without ``--allow-private-targets``.

    Everything that is not globally routable: loopback, RFC 1918 private,
    link-local, CGNAT (100.64.0.0/10), unique-local and site-local IPv6,
    unspecified, documentation and reserved ranges, 6to4 and local-use NAT64,
    plus multicast. Round 4 (sec4-1): an IPv6 address that stands for an IPv4
    address (IPv4-mapped, the NAT64 well-known prefix ``64:ff9b::/96``,
    IPv4-translated or IPv4-compatible; :func:`scrapescope.types.embedded_ipv4`)
    is judged by that IPv4 address as well, so ``64:ff9b::a00:5`` is refused
    like ``10.0.0.5`` (on a NAT64 network it reaches that host through the
    gateway). NAT64 with a network-specific prefix cannot be recognised.
    """
    embedded = embedded_ipv4(ip)
    if embedded is not None:
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = embedded  # the same address: judge it as IPv4 only
        elif not embedded.is_global or embedded.is_multicast:
            return True
    if isinstance(ip, ipaddress.IPv6Address) and any(ip in net for net in _NON_GLOBAL_V6):
        return True
    return not ip.is_global or ip.is_multicast


def _sockaddr_ip(sockaddr: object) -> IPAddress | None:
    try:
        text = str(sockaddr[0]).split("%", 1)[0]  # type: ignore[index]
        return ipaddress.ip_address(text)
    except (ValueError, TypeError, IndexError):
        return None


def private_address_error() -> UpstreamError:
    return UpstreamError("private_address", 403, "private-address")


def _unmapped(ip: IPAddress | None) -> IPAddress | None:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def is_own_or_on_link(local: IPAddress | None, peer: IPAddress | None) -> bool:
    """True when a connection from ``local`` to ``peer`` reaches this machine or its own IPv6 link.

    ``local`` is the connected socket's own address. A connection to one of
    this machine's addresses gets that same address as its source (the kernel
    routes it over loopback), so ``local == peer`` is a self-connection even
    for a globally routable address (sec3-1). For IPv6, a peer in the same /64
    as the source address is on this machine's own link (a router, NAS or
    printer with a global address). IPv4 netmasks are not visible to the
    meter, so for IPv4 only this machine's own address is caught.
    """
    local, peer = _unmapped(local), _unmapped(peer)
    if local is None or peer is None:
        return False
    if local == peer:
        return True
    if isinstance(local, ipaddress.IPv6Address) and isinstance(peer, ipaddress.IPv6Address):
        return int(local) >> 64 == int(peer) >> 64
    return False


def check_not_own_address(conn: UpstreamConnection) -> None:
    """Refuse (``private-address``) a direct connection that reached this machine or its IPv6 link.

    Runs after the TCP connect and before any byte is written. The resolved
    address passed the non-global check, but a global address can still be
    this machine's own (a service bound to all interfaces) or a host on its
    own /64; a hostile page could reach those through a rebinding name.
    """
    own = True
    with contextlib.suppress(Exception):
        transport = conn.writer.transport
        own = is_own_or_on_link(
            _sockaddr_ip(transport.get_extra_info("sockname")), _sockaddr_ip(transport.get_extra_info("peername"))
        )
    if own:
        conn.abort()
        raise private_address_error()


def self_loop_error() -> UpstreamError:
    return UpstreamError("self_loop", 403, "self-loop")


def direct_address(host: str, port: int, connect_map: ConnectMap | None) -> tuple[str, int]:
    """Where the meter itself connects for a direct or non-target tunnel.

    Without a connect map: the target as given (the OS resolves the name). With
    a (test-only) connect map: mapped names, loopback IP literals as given, and
    ``failed:dns`` for everything else, without touching DNS. The address
    checks live in :func:`open_direct`.
    """
    if connect_map is None:
        return host, port
    mapped = connect_map.get((host, port))
    if mapped is not None:
        return mapped
    if is_loopback_literal(host):
        return host, port
    raise UpstreamError("dns", 502, "dns-failed")


async def direct_candidates(
    host: str,
    port: int,
    *,
    connect_map: ConnectMap | None,
    allow_private: bool,
    own_ports: frozenset[int],
    timeout: float,
) -> list[tuple[str, int]]:
    """The checked ``(ip, port)`` addresses the meter may connect to for a direct route.

    Resolves the name once (or reads the test connect map), then drops
    addresses that would reach the meter's own listeners (``self-loop``) and,
    unless ``allow_private``, addresses that are not globally routable
    (``private-address``). The caller connects to these literal addresses
    only, so the check and the connection use the same DNS answer.

    Test connect-map entries are the test's explicit declaration of where a
    fake name lives, so they are exempt from the private-address check (they
    all point at loopback fixtures); the self-loop check still applies.
    """
    if connect_map is not None:
        mapped = connect_map.get((host, port))
        if mapped is not None:
            ip = ip_literal(mapped[0])
            if ip is not None and is_self_address(ip) and mapped[1] in own_ports:
                raise self_loop_error()
            return [mapped]
        literal = ip_literal(host)
        if literal is None or not literal.is_loopback:
            raise UpstreamError("dns", 502, "dns-failed")
        addresses: list[IPAddress] = [literal]
    else:
        literal = ip_literal(host)
        if literal is not None:
            addresses = [literal]
        else:
            loop = asyncio.get_running_loop()
            try:
                infos = await asyncio.wait_for(
                    loop.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP), timeout
                )
            except TimeoutError:
                raise _timeout(True) from None
            except (socket.gaierror, UnicodeError, OSError) as exc:
                if is_local_limit(exc) or descriptors_exhausted():
                    raise local_limit_error() from None
                raise UpstreamError("dns", 502, "dns-failed") from None
            addresses = []
            for info in infos:
                ip = _sockaddr_ip(info[4])
                if ip is not None and ip not in addresses:
                    addresses.append(ip)
            if not addresses:
                raise UpstreamError("dns", 502, "dns-failed")
    allowed: list[tuple[str, int]] = []
    refused_private = False
    for ip in addresses:
        if is_self_address(ip) and port in own_ports:
            raise self_loop_error()
        if not allow_private and is_private_destination(ip):
            refused_private = True
            continue
        allowed.append((str(ip), port))
    if not allowed:
        if refused_private:
            raise private_address_error()
        raise UpstreamError("dns", 502, "dns-failed")
    return allowed


def interleave_families(candidates: list[tuple[str, int]]) -> list[tuple[str, int]]:
    """Alternate address families, starting with the resolver's first (RFC 8305 section 4)."""
    first: list[tuple[str, int]] = []
    other: list[tuple[str, int]] = []
    first_v6: bool | None = None
    for cand in candidates:
        is_v6 = ":" in cand[0]
        if first_v6 is None:
            first_v6 = is_v6
        (first if is_v6 == first_v6 else other).append(cand)
    out: list[tuple[str, int]] = []
    for i in range(max(len(first), len(other))):
        if i < len(first):
            out.append(first[i])
        if i < len(other):
            out.append(other[i])
    return out


async def open_direct(
    host: str,
    port: int,
    *,
    meter: Meter,
    tunnel: Tunnel,
    timeout: float,
    connect_map: ConnectMap | None,
    allow_private: bool,
    own_ports: frozenset[int],
    attempt_delay: float = HAPPY_EYEBALLS_DELAY_S,
) -> UpstreamConnection:
    """Open the meter's own connection for a ``direct`` or ``non-target`` route.

    See :func:`direct_candidates` for the address checks. With one address it
    gets the whole ``timeout``. With several, attempts are staggered Happy
    Eyeballs style: families interleaved, the next address starts after
    ``attempt_delay`` or as soon as an attempt fails, and every attempt runs
    until the one overall deadline. The first connection wins; the others are
    cancelled or closed before a byte is written. A deadline with an attempt
    still pending gives ``connect_timeout``; otherwise the last failure is
    reported.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    candidates = await direct_candidates(
        host, port, connect_map=connect_map, allow_private=allow_private, own_ports=own_ports, timeout=timeout
    )
    remaining = deadline - loop.time()
    if remaining <= 0:
        raise _timeout(True)
    # Connect-map entries are the tests' explicit declarations (loopback fixtures), exempt like above.
    check_own = not allow_private and not (connect_map is not None and (host, port) in connect_map)
    if len(candidates) == 1:
        ip, cport = candidates[0]
        conn = await _open_direct_socket(ip, cport, meter=meter, tunnel=tunnel, timeout=remaining, check_own=check_own)
        return _adopt(conn)
    conn = await _race_connect(interleave_families(candidates), meter, tunnel, deadline, attempt_delay, check_own)
    return _adopt(conn)


async def _open_direct_socket(
    ip: str,
    port: int,
    *,
    meter: Meter,
    tunnel: Tunnel,
    timeout: float,
    check_own: bool,
) -> UpstreamConnection:
    """One direct connection attempt; with ``check_own``, refuse this machine and its IPv6 link."""
    conn = await _open_socket(ip, port, meter=meter, tunnel=tunnel, timeout=timeout, direct=True)
    if check_own:
        check_not_own_address(conn)
    return conn


async def _race_connect(
    candidates: list[tuple[str, int]],
    meter: Meter,
    tunnel: Tunnel,
    deadline: float,
    delay: float,
    check_own: bool = False,
) -> UpstreamConnection:
    """Staggered connection attempts to ``candidates``; returns the first that connects (not yet adopted).

    With ``check_own`` an attempt that reached this machine or its IPv6 link
    fails with ``private-address`` (see :func:`check_not_own_address`) and the
    next address is tried at once.
    """
    loop = asyncio.get_running_loop()
    queue = list(candidates)
    attempts: list[asyncio.Task[UpstreamConnection]] = []
    last: UpstreamError | None = None
    next_start = loop.time()
    winner: asyncio.Task[UpstreamConnection] | None = None
    try:
        while True:
            now = loop.time()
            if now >= deadline:
                raise _timeout(True)
            if queue and (now >= next_start or all(t.done() for t in attempts)):
                ip, cport = queue.pop(0)
                attempt = _open_direct_socket(
                    ip, cport, meter=meter, tunnel=tunnel, timeout=deadline - now, check_own=check_own
                )
                attempts.append(asyncio.ensure_future(attempt))
                next_start = now + delay
            running = [t for t in attempts if not t.done()]
            if not running:
                if not queue:
                    break
                continue
            wake = deadline if not queue else min(deadline, next_start)
            done, _ = await asyncio.wait(running, timeout=max(0.0, wake - loop.time()), return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                exc = task.exception()
                if exc is None:
                    winner = task
                    return task.result()
                if not isinstance(exc, UpstreamError):
                    raise exc
                last = exc
                next_start = loop.time()  # a failed attempt starts the next one at once
        assert last is not None
        raise last
    finally:
        losers = [t for t in attempts if t is not winner]
        for task in losers:
            task.cancel()
        if losers:
            await asyncio.gather(*losers, return_exceptions=True)
        for task in losers:
            if task.done() and not task.cancelled() and task.exception() is None:
                task.result().abort()  # connected too late: closed before anything was written


def check_not_self(conn: UpstreamConnection, own_ports: frozenset[int]) -> None:
    """Refuse (``self-loop``) a connection whose peer is one of the meter's own listeners.

    Catches upstream proxy names that resolve to the meter itself, which the
    start-time check on the URL cannot see. Nothing has been written yet.
    """
    is_self = False
    with contextlib.suppress(Exception):
        peer = conn.writer.transport.get_extra_info("peername")
        ip = _sockaddr_ip(peer)
        is_self = ip is not None and is_self_address(ip) and int(peer[1]) in own_ports
    if is_self:
        conn.abort()
        raise self_loop_error()


async def open_counted(
    host: str,
    port: int,
    *,
    meter: Meter,
    tunnel: Tunnel,
    timeout: float,
    direct: bool,
) -> UpstreamConnection:
    """Open a TCP connection whose bytes are counted on ``tunnel``.

    ``direct`` selects the failure vocabulary: direct/non-target connections
    report ``dns``/``connect_refused``/``connect_timeout``; connections to the
    upstream proxy report ``upstream_unreachable``/``upstream_timeout``. Either
    way, running out of file descriptors reports ``local_limit``.
    """
    conn = await _open_socket(host, port, meter=meter, tunnel=tunnel, timeout=timeout, direct=direct)
    return _adopt(conn)


async def _open_socket(
    host: str,
    port: int,
    *,
    meter: Meter,
    tunnel: Tunnel,
    timeout: float,
    direct: bool,
) -> UpstreamConnection:
    """The TCP connect of :func:`open_counted`, without registering the connection on the tunnel."""
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=READ_LIMIT, loop=loop)
    protocol = _CountingProtocol(reader, meter, tunnel, loop)
    try:
        transport, _ = await asyncio.wait_for(loop.create_connection(lambda: protocol, host, port), timeout)
    except TimeoutError:  # asyncio.TimeoutError is TimeoutError (an OSError) on 3.11+
        raise _timeout(direct) from None
    except socket.gaierror as exc:
        if is_local_limit(exc) or descriptors_exhausted():
            raise local_limit_error() from None
        if direct:
            raise UpstreamError("dns", 502, "dns-failed") from None
        raise _unreachable(False) from None
    except OSError as exc:
        if is_local_limit(exc):
            raise local_limit_error() from None
        raise _unreachable(direct) from None
    writer = asyncio.StreamWriter(transport, protocol, reader, loop)
    return UpstreamConnection(reader, writer, meter, tunnel, protocol)


def _adopt(conn: UpstreamConnection) -> UpstreamConnection:
    """Register a freshly connected socket on its tunnel (so budget trips and stop() abort it)."""
    if conn.tunnel.closing:  # budget tripped or forwarder stopped while connecting
        conn.abort()
        raise TunnelAborted
    conn.tunnel.add_aborter(conn.abort)
    return conn


# ---------------------------------------------------------------------------- HTTP CONNECT


@dataclass
class ConnectReply:
    """The upstream's reply to CONNECT: status plus the raw bytes to relay verbatim."""

    status: int
    head: bytes
    body: bytes = b""

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


def _header_value(head: bytes, name: bytes) -> bytes | None:
    lname = name.lower()
    for line in head.split(b"\r\n")[1:]:
        key, sep, value = line.partition(b":")
        if sep and key.strip().lower() == lname:
            return value.strip()
    return None


async def _read_chunked_raw(reader: asyncio.StreamReader, cap: int) -> bytes:
    out = bytearray()
    while len(out) <= cap:
        line = await reader.readuntil(b"\r\n")
        out += line
        size_text = line.split(b";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError:
            return bytes(out)
        if size == 0:
            while True:
                trailer = await reader.readuntil(b"\r\n")
                out += trailer
                if trailer == b"\r\n" or len(out) > cap:
                    return bytes(out)
        out += await reader.readexactly(min(size, cap) + 2)
    return bytes(out)


async def _read_until_idle(reader: asyncio.StreamReader, cap: int) -> bytes:
    out = bytearray()
    while len(out) < cap:
        try:
            data = await asyncio.wait_for(reader.read(min(65536, cap - len(out))), ERROR_BODY_IDLE_S)
        except TimeoutError:
            break
        if not data:
            break
        out += data
    return bytes(out)


async def _read_error_body(reader: asyncio.StreamReader, head: bytes, status: int) -> bytes:
    """Read the body of a non-2xx CONNECT reply (Content-Length, chunked or close-delimited)."""
    if 100 <= status < 200 or status in (204, 304):
        return b""
    te = _header_value(head, b"transfer-encoding")
    if te is not None and b"chunked" in te.lower():
        return await _read_chunked_raw(reader, MAX_ERROR_BODY)
    cl = _header_value(head, b"content-length")
    if cl is not None:
        try:
            length = int(cl.split(b",")[0].strip())
        except ValueError:
            length = 0
        length = max(0, min(length, MAX_ERROR_BODY))
        if length == 0:
            return b""
        try:
            return await reader.readexactly(length)
        except asyncio.IncompleteReadError as exc:
            return exc.partial
    return await _read_until_idle(reader, MAX_ERROR_BODY)


async def http_connect(
    conn: UpstreamConnection, head: bytes, *, timeout: float, body_timeout: float | None = None
) -> ConnectReply:
    """Send the CONNECT head and read the upstream's reply.

    A 2xx reply returns only the head; bytes after it stay in the reader as
    tunnel payload. A non-2xx reply also reads its body (bounded) so the caller
    can relay the whole reply verbatim before closing.

    ``timeout`` bounds the wait for the reply head. Round 4 (meas4-3): the
    server passes the idle timeout (at least 600 s), not the 30 s connect
    timeout, because a provider may hold CONNECT while it finds a peer or
    retries the target, and the job's own client would keep waiting too.
    ``body_timeout`` (default ``timeout``) bounds reading a non-2xx reply's body.
    """
    tunnel = conn.tunnel
    conn.write(head, negotiation=True)
    try:
        await conn.drain()
        raw = await asyncio.wait_for(conn.reader.readuntil(b"\r\n\r\n"), timeout)
    except TimeoutError:
        raise UpstreamError("upstream_timeout", 504, "upstream-timeout") from None
    except asyncio.IncompleteReadError:
        if tunnel.closing:
            raise TunnelAborted from None
        raise UpstreamError("upstream_closed", 502, "upstream-closed") from None
    except asyncio.LimitOverrunError:
        raise UpstreamError("upstream_protocol", 502, "upstream-protocol-error") from None
    except (ConnectionError, OSError):
        if tunnel.closing:
            raise TunnelAborted from None
        raise UpstreamError("upstream_closed", 502, "upstream-closed") from None
    if len(raw) > MAX_REPLY_HEAD:
        raise UpstreamError("upstream_protocol", 502, "upstream-protocol-error")
    conn.meter.mark_negotiation_received(tunnel, len(raw))
    match = _STATUS_RE.match(raw)
    if match is None:
        raise UpstreamError("upstream_protocol", 502, "upstream-protocol-error")
    status = int(match.group(1))
    if 200 <= status < 300:
        return ConnectReply(status=status, head=raw)
    try:
        body = await asyncio.wait_for(
            _read_error_body(conn.reader, raw, status), timeout if body_timeout is None else body_timeout
        )
    except (TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError, OSError, ValueError):
        body = b""
    conn.meter.mark_negotiation_received(tunnel, len(body))
    return ConnectReply(status=status, head=raw, body=body)


# ---------------------------------------------------------------------------- SOCKS5

SOCKS_VERSION = 5
METHOD_NO_AUTH = 0x00
METHOD_USERPASS = 0x02
METHOD_NONE_ACCEPTABLE = 0xFF


def socks_address(host: str) -> bytes:
    """ATYP + address: 0x01/0x04 for IP literals, 0x03 (remote DNS) for names."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        name = host.encode("idna") if not host.isascii() else host.encode("ascii")
        if not 0 < len(name) <= 255:
            raise UpstreamError("bad_request", 400, "bad-request") from None
        return b"\x03" + bytes([len(name)]) + name
    if ip.version == 4:
        return b"\x01" + ip.packed
    return b"\x04" + ip.packed


def check_socks_credentials(creds: tuple[str, str] | None) -> tuple[bytes, bytes] | None:
    """Encode RFC 1929 credentials; raises when they cannot be represented."""
    if creds is None:
        return None
    user = creds[0].encode("utf-8")
    password = creds[1].encode("utf-8")
    if len(user) > 255 or len(password) > 255:
        raise UpstreamError("socks_auth_unsupported", 502, "socks-auth-unsupported")
    return user, password


async def socks5_connect(
    conn: UpstreamConnection,
    host: str,
    port: int,
    creds: tuple[str, str] | None,
    *,
    timeout: float,
) -> int:
    """RFC 1928 CONNECT with optional RFC 1929 auth. Returns REP (0) or raises.

    Offers method 0x02 when credentials exist, else 0x00. Every byte of the
    exchange is negotiation. Failures raise :class:`UpstreamError` with the
    contract's reasons (``socks_method``, ``socks_auth``, ``socks_reply_<n>``).
    ``timeout`` bounds the whole exchange; the server passes the idle timeout
    (round 4, meas4-3), since the CONNECT reply waits for the provider to
    reach the target.
    """
    encoded = check_socks_credentials(creds)
    address = socks_address(host) + struct.pack(">H", port)
    try:
        return await asyncio.wait_for(_socks5_exchange(conn, encoded, address), timeout)
    except TimeoutError:
        raise UpstreamError("upstream_timeout", 504, "upstream-timeout") from None


async def _socks5_exchange(conn: UpstreamConnection, encoded: tuple[bytes, bytes] | None, address: bytes) -> int:
    tunnel = conn.tunnel
    meter = conn.meter

    async def read(n: int) -> bytes:
        try:
            data = await conn.reader.readexactly(n)
        except asyncio.IncompleteReadError:
            if tunnel.closing:
                raise TunnelAborted from None
            raise UpstreamError("upstream_closed", 502, "upstream-closed") from None
        except (ConnectionError, OSError):
            if tunnel.closing:
                raise TunnelAborted from None
            raise UpstreamError("upstream_closed", 502, "upstream-closed") from None
        meter.mark_negotiation_received(tunnel, n)
        return data

    method_offer = METHOD_USERPASS if encoded is not None else METHOD_NO_AUTH
    conn.write(bytes([SOCKS_VERSION, 1, method_offer]), negotiation=True)
    await conn.drain()
    version, method = await read(2)
    if version != SOCKS_VERSION:
        raise UpstreamError("upstream_protocol", 502, "upstream-protocol-error")
    if method == METHOD_NONE_ACCEPTABLE or method != method_offer:
        raise UpstreamError("socks_method", 502, "socks-no-method")
    if method == METHOD_USERPASS:
        assert encoded is not None
        user, password = encoded
        conn.write(b"\x01" + bytes([len(user)]) + user + bytes([len(password)]) + password, negotiation=True)
        await conn.drain()
        _sub_version, status = await read(2)
        if status != 0:
            raise UpstreamError("socks_auth", 502, "socks-auth-failed")
    conn.write(b"\x05\x01\x00" + address, negotiation=True)
    await conn.drain()
    _ver, rep, _rsv, atyp = await read(4)
    meter.update(tunnel, socks_reply=rep)
    try:
        if atyp == 0x01:
            await read(4 + 2)
        elif atyp == 0x04:
            await read(16 + 2)
        elif atyp == 0x03:
            (length,) = await read(1)
            await read(length + 2)
        elif rep == 0:
            raise UpstreamError("upstream_protocol", 502, "upstream-protocol-error")
    except UpstreamError:
        if rep == 0:
            raise
        # A failure reply with a truncated address: the REP code is what matters.
    if rep != 0:
        raise UpstreamError(f"socks_reply_{rep}", 502, f"socks-reply-{rep}", socks_reply=rep)
    return rep


__all__ = [
    "ConnectReply",
    "HAPPY_EYEBALLS_DELAY_S",
    "READ_LIMIT",
    "UpstreamConnection",
    "UpstreamError",
    "check_not_own_address",
    "check_not_self",
    "check_socks_credentials",
    "direct_address",
    "descriptors_exhausted",
    "direct_candidates",
    "http_connect",
    "interleave_families",
    "ip_literal",
    "is_local_limit",
    "is_loopback_literal",
    "is_own_or_on_link",
    "is_private_destination",
    "is_self_address",
    "local_limit_error",
    "open_counted",
    "open_direct",
    "socks5_connect",
    "socks_address",
]
