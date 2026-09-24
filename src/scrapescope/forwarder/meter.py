"""Per-tunnel counters, count-on-read budget, tunnel cap and timeline.

Contract: docs/dev/contracts.md sections 3.6 and 3.7.

What is counted, and where
--------------------------
Every byte is counted on the meter's side of the *upstream* socket (the
connection to the upstream proxy, or to the target in direct/sizing mode):

- received bytes are counted in the socket protocol's ``data_received``, i.e.
  as soon as the kernel hands them to the meter and before they are relayed;
- sent bytes are counted when they are handed to the socket transport. When
  the meter aborts a connection (budget trip, tunnel cap, stop, idle timeout),
  whatever is still queued in the transport is discarded and uncounted again
  (:meth:`Meter.discard_sent`), so sent bytes are the bytes handed to the
  kernel. Bytes already in the kernel's send buffer stay counted.

Those are the "tunnel-measured" figures. They include the CONNECT or SOCKS
negotiation, which is additionally recorded as a sub-count so reports can show
totals with and without it. They are complete for this hop, but a provider may
meter at a different point (for example it may not bill its own error replies
or may count the CONNECT line differently), so they are never "a bill".

Budget
------
The budget counter is the sum of upstream socket bytes, both directions,
negotiation included, over target tunnels (routes http-connect, socks5,
direct). It is checked on every count, including the read that crosses the
limit; that slice is counted because the provider has already sent (and billed)
it. The meter stops at its own count: when the budget trips, bytes already in
flight at the provider or in kernel buffers can add roughly (open tunnels x a
few MB) to what the provider bills, and a local meter cannot see them.

Thread safety: counting happens on the forwarder's event-loop thread; every
mutation that a snapshot reads is done under one lock, so :meth:`Meter.snapshot`
may be called from any thread. Budget callbacks and tunnel aborts run on the
calling (loop) thread, outside the lock.

Snapshot cost: the loop thread needs the lock for every count, so a snapshot
must not hold it for long. The meter keeps a private copy of every record and
refreshes, under the lock, only the copies of open tunnels and of records
changed since the previous snapshot; the per-record copies handed to the
caller are made after the lock is released. Memory still grows with every
tunnel record for the forwarder's lifetime, with no cap: measured with
tracemalloc (round 3, sec3-9), about 0.4 kB per record in the meter and about
0.8 kB once the snapshot cache holds its copy (``serve`` snapshots every 60 s),
about 1.1 kB while a snapshot is alive. A long ``serve`` session keeps every
record, because the report needs them. Requests refused by a deny rule also
create records (route ``refused``, status ``denied``) before any provider
contact and count no bytes, so ``--budget`` does not bound them.

Timeline: one slot per ``timeline_resolution_s`` step with target traffic. It
is bounded: when it would exceed :data:`MAX_TIMELINE_SLOTS` slots, adjacent
slots are merged and the resolution doubles (0.25 s, 0.5 s, 1 s, ...), so a
long run keeps at most that many slots at a coarser step; the snapshot reports
the step in use. A snapshot copies the slots as plain numbers under the lock
and builds the points after releasing it. ``record_timeline=False`` (``serve``,
whose report has no helper events to align it with) keeps no timeline at all.
"""

from __future__ import annotations

import contextlib
import copy
import logging
import math
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field

from ..config import BUDGET_WARN_FRACTION, TIMELINE_RESOLUTION_S, TOP_HOSTS_WINDOW_S, synthetic_connect_sizes
from ..types import (
    TARGET_ROUTES,
    TUNNEL_BUDGET,
    TUNNEL_CAP,
    TUNNEL_DENIED,
    TUNNEL_OK,
    TUNNEL_OPEN,
    AuthUse,
    BudgetEvent,
    HostBytes,
    Listener,
    MeterSnapshot,
    Mode,
    Route,
    TimelinePoint,
    TunnelKind,
    TunnelRecord,
)

logger = logging.getLogger("scrapescope.forwarder")

#: Maximum number of hosts listed in a trip event's ``top_hosts``.
TOP_HOSTS_LIMIT = 10
#: Timeline slots kept before adjacent slots are merged and the resolution doubles
#: (16,384 slots = about 68 minutes of continuous traffic at 0.25 s).
MAX_TIMELINE_SLOTS = 16384
#: How far back (in slots) :meth:`Meter.discard_sent` looks for the slots to correct.
_DISCARD_LOOKBACK_SLOTS = 4096

BudgetCallback = Callable[[BudgetEvent], None]


def _copy_record(rec: TunnelRecord) -> TunnelRecord:
    """A fast shallow copy (every TunnelRecord field is an immutable scalar, so it is a full copy)."""
    try:
        new = object.__new__(TunnelRecord)
        new.__dict__.update(rec.__dict__)
        return new
    except AttributeError:  # pragma: no cover - only if TunnelRecord ever gains __slots__
        return copy.copy(rec)


class TunnelAborted(Exception):
    """The meter closed this tunnel (budget trip, tunnel cap or forwarder stop)."""


class Tunnel:
    """Live state of one tunnel: its :class:`TunnelRecord` plus the means to abort it.

    ``record`` is owned by the :class:`Meter`; mutate counters only through the
    meter's methods so snapshots stay consistent. ``closing`` becomes True when
    the tunnel was finished or aborted; I/O code checks it to stop relaying.
    ``ok_status`` is the status a normal close (``finish(tunnel, "ok")``, also
    at stop or idle timeout) records: the server sets it to
    ``failed:upstream_status`` for a plain-HTTP tunnel whose only responses
    were the provider's 407. ``connection_base`` is what earlier records of the
    same upstream connection counted (:meth:`Meter.continue_connection`), so
    the per-tunnel cap applies to the connection (round 4, meas4-6).
    """

    __slots__ = ("record", "target", "closing", "ok_status", "connection_base", "_aborters")

    def __init__(self, record: TunnelRecord) -> None:
        self.record = record
        self.target = record.route in TARGET_ROUTES
        self.closing = False
        self.ok_status = TUNNEL_OK
        self.connection_base = 0
        self._aborters: list[Callable[[], None]] = []

    @property
    def connection_bytes(self) -> int:
        """Bytes counted on this tunnel's upstream connection so far, earlier continued records included."""
        return self.connection_base + self.record.counted_bytes

    @property
    def id(self) -> int:
        return self.record.id

    def add_aborter(self, fn: Callable[[], None]) -> None:
        """Register a callable that force-closes a transport of this tunnel."""
        self._aborters.append(fn)

    def abort_transports(self, *, exclude: Callable[[], None] | None = None) -> None:
        """Force-close every registered transport (except ``exclude``)."""
        for fn in list(self._aborters):
            if exclude is not None and fn == exclude:
                continue
            with contextlib.suppress(Exception):
                fn()


@dataclass
class _Pending:
    """Actions decided under the lock, executed after it is released."""

    events: list[BudgetEvent] = field(default_factory=list)
    abort: list[Tunnel] = field(default_factory=list)


class Meter:
    """Counters for every tunnel of one forwarder, plus budget, cap and timeline."""

    def __init__(
        self,
        *,
        mode: Mode,
        budget_bytes: int | None = None,
        max_tunnel_bytes: int | None = None,
        warn_fraction: float = BUDGET_WARN_FRACTION,
        timeline_resolution_s: float = TIMELINE_RESOLUTION_S,
        clock: Callable[[], float] = time.time,
        top_hosts_window_s: float = TOP_HOSTS_WINDOW_S,
        record_timeline: bool = True,
        max_timeline_slots: int = MAX_TIMELINE_SLOTS,
    ) -> None:
        if budget_bytes is not None and budget_bytes <= 0:
            raise ValueError("budget_bytes must be positive")
        if max_tunnel_bytes is not None and max_tunnel_bytes <= 0:
            raise ValueError("max_tunnel_bytes must be positive")
        if timeline_resolution_s <= 0:
            raise ValueError("timeline_resolution_s must be positive")
        if max_timeline_slots < 2:
            raise ValueError("max_timeline_slots must be at least 2")
        self.mode: Mode = mode
        self.budget_bytes = budget_bytes
        self.max_tunnel_bytes = max_tunnel_bytes
        self.warn_fraction = warn_fraction
        self.resolution = float(timeline_resolution_s)
        self.clock = clock
        self.window_s = float(top_hosts_window_s)
        self.port = 0
        self.auth_port: int | None = None
        self.started_at = clock()

        self._lock = threading.Lock()
        self._records: list[TunnelRecord] = []
        #: Private copies of ``_records`` (same order) as of the last snapshot; never mutated in place.
        self._copies: list[TunnelRecord | None] = []
        #: Ids of records changed since the last snapshot (open tunnels are always refreshed).
        self._dirty: set[int] = set()
        self._open: dict[int, Tunnel] = {}
        self._next_id = 1
        self._counted = 0
        self._warned = False
        self._tripped = False
        self._events: list[BudgetEvent] = []
        self._refused: dict[str, int] = {}
        self._timeline: dict[int, list[int]] = {}
        self._record_timeline = record_timeline
        self._max_slots = max_timeline_slots
        #: Index of the newest timeline slot (for discard_sent's corrections).
        self._timeline_last: int | None = None
        self._accept_limit_errors = 0
        #: (whole second, {host: bytes}) for the heaviest-hosts window.
        self._recent: deque[tuple[int, dict[str, int]]] = deque()
        self._internal_errors = 0
        self._callbacks: list[BudgetCallback] = []

    # ------------------------------------------------------------------ properties
    @property
    def budget_tripped(self) -> bool:
        return self._tripped

    @property
    def counted_bytes(self) -> int:
        return self._counted

    def on_budget(self, callback: BudgetCallback) -> None:
        """Register a callback for warn_80, tripped and tunnel_cap events (loop thread)."""
        self._callbacks.append(callback)

    def internal_error(self) -> None:
        with self._lock:
            self._internal_errors += 1

    def refuse(self, reason: str) -> None:
        """Count a client request refused before any tunnel existed."""
        with self._lock:
            self._refused[reason] = self._refused.get(reason, 0) + 1

    def accept_limit_error(self) -> None:
        """A listener could not accept a connection: this process is out of file descriptors."""
        with self._lock:
            self._accept_limit_errors += 1

    # ------------------------------------------------------------------ tunnels
    def open_tunnel(
        self,
        *,
        host: str,
        port: int,
        kind: TunnelKind,
        route: Route,
        listener: Listener = "main",
        auth: AuthUse = "none",
        rule: str | None = None,
        continued_from: int | None = None,
    ) -> Tunnel:
        """Create and register a new open tunnel.

        ``continued_from``: the record whose upstream connection this one keeps
        (plain HTTP over an HTTP CONNECT upstream after an authority switch).

        Direct (sizing) mode CONNECT tunnels get the synthetic CONNECT sizes,
        which make their "with CONNECT" figure an estimate; they are not added
        to the upstream bytes or the budget. The server then replaces the
        request size with the client's own CONNECT head
        (:meth:`set_synthetic_request_bytes`).
        """
        with self._lock:
            record = TunnelRecord(
                id=self._next_id,
                host=host,
                port=port,
                kind=kind,
                route=route,
                opened_at=self.clock(),
                auth=auth,
                rule=rule,
                listener=listener,
                continued_from=continued_from,
            )
            if route == "direct" and kind == "connect":
                sent, received = synthetic_connect_sizes(host, port)
                record.synthetic_negotiation_bytes_sent = sent
                record.synthetic_negotiation_bytes_received = received
            self._next_id += 1
            self._append_locked(record)
            tunnel = Tunnel(record)
            self._open[record.id] = tunnel
        return tunnel

    def _append_locked(self, record: TunnelRecord) -> None:
        # Record ids are 1, 2, 3, ... in append order: index = id - 1.
        self._records.append(record)
        self._copies.append(None)
        self._dirty.add(record.id)

    def record_denied(
        self,
        *,
        host: str,
        port: int,
        kind: TunnelKind,
        listener: Listener,
        rule: str,
    ) -> TunnelRecord:
        """Record a request refused by a deny rule (route "refused", status "denied")."""
        with self._lock:
            now = self.clock()
            record = TunnelRecord(
                id=self._next_id,
                host=host,
                port=port,
                kind=kind,
                route="refused",
                opened_at=now,
                closed_at=now,
                status=TUNNEL_DENIED,
                rule=rule,
                listener=listener,
            )
            self._next_id += 1
            self._append_locked(record)
        logger.debug("tunnel %d %s:%d %s denied", record.id, host, port, kind)
        return record

    def continue_connection(self, previous: Tunnel, tunnel: Tunnel) -> None:
        """``tunnel`` continues ``previous``'s upstream connection: carry its count for the per-tunnel cap.

        ``--max-tunnel-mb`` limits one upstream connection (round 4, meas4-6);
        without this, every authority switch on a kept provider connection
        would restart the count at zero. Budget and totals are unaffected.
        """
        with self._lock:
            tunnel.connection_base = previous.connection_base + previous.record.counted_bytes

    def update(self, tunnel: Tunnel, **fields: object) -> None:
        """Set record fields (upstream_status, socks_reply, auth, ...) consistently."""
        with self._lock:
            for name, value in fields.items():
                setattr(tunnel.record, name, value)
            self._dirty.add(tunnel.record.id)

    def count_request(self, tunnel: Tunnel, proxy_authorization_bytes: int = 0) -> None:
        """One plain-HTTP request forwarded on this tunnel."""
        with self._lock:
            tunnel.record.requests += 1
            tunnel.record.proxy_authorization_bytes += proxy_authorization_bytes
            self._dirty.add(tunnel.record.id)

    def set_connect_sizes(self, tunnel: Tunnel, connect_request_bytes: int, proxy_authorization_bytes: int) -> None:
        with self._lock:
            tunnel.record.connect_request_bytes = connect_request_bytes
            tunnel.record.proxy_authorization_bytes = proxy_authorization_bytes
            self._dirty.add(tunnel.record.id)

    def set_synthetic_request_bytes(self, tunnel: Tunnel, request_bytes: int) -> None:
        """Direct mode: size the estimated CONNECT request from the head the client actually sent.

        ``request_bytes`` is the client's CONNECT head as an HTTP CONNECT
        provider would receive it, without any ``Proxy-Authorization`` (real
        clients send ``User-Agent`` and ``Proxy-Connection`` too, which the
        minimal ``synthetic_connect_sizes`` estimate leaves out). Only tunnels
        that carry a synthetic estimate (direct-route CONNECT tunnels) change.
        """
        with self._lock:
            rec = tunnel.record
            if rec.synthetic_negotiation_bytes_sent > 0 and request_bytes > 0:
                rec.synthetic_negotiation_bytes_sent = int(request_bytes)
                self._dirty.add(rec.id)

    def mark_negotiation_received(self, tunnel: Tunnel, n: int) -> None:
        """Classify ``n`` already-counted received bytes as negotiation."""
        if n <= 0:
            return
        with self._lock:
            rec = tunnel.record
            rec.negotiation_bytes_received = min(rec.upstream_bytes_received, rec.negotiation_bytes_received + n)
            self._dirty.add(rec.id)

    def mark_all_negotiation(self, tunnel: Tunnel) -> None:
        """A tunnel whose negotiation failed: every byte it moved was negotiation."""
        with self._lock:
            rec = tunnel.record
            rec.negotiation_bytes_sent = rec.upstream_bytes_sent
            rec.negotiation_bytes_received = rec.upstream_bytes_received
            self._dirty.add(rec.id)

    def add_client(self, tunnel: Tunnel, *, received: int = 0, sent: int = 0) -> None:
        """Client-socket diagnostics (never used for totals or the budget)."""
        with self._lock:
            rec = tunnel.record
            rec.client_bytes_received += received
            rec.client_bytes_sent += sent
            self._dirty.add(rec.id)

    def add_sent(self, tunnel: Tunnel, n: int, *, negotiation: int = 0) -> None:
        """Count ``n`` bytes handed to the upstream socket (``negotiation`` of them)."""
        self._add(tunnel, n, negotiation, received=False)

    def add_received(self, tunnel: Tunnel, n: int, *, negotiation: int = 0) -> None:
        """Count ``n`` bytes read from the upstream socket (``negotiation`` of them)."""
        self._add(tunnel, n, negotiation, received=True)

    def discard_sent(self, tunnel: Tunnel, n: int) -> None:
        """Uncount ``n`` sent bytes that an abort discarded before they reached the kernel.

        Corrects the tunnel, the budget counter and the newest timeline slots.
        A budget trip or tunnel cap that these bytes caused stays in force: the
        meter decided on its count at that moment. The heaviest-hosts window of
        a trip event is not corrected.
        """
        if n <= 0:
            return
        try:
            with self._lock:
                rec = tunnel.record
                n = min(n, rec.upstream_bytes_sent)
                if n <= 0:
                    return
                rec.upstream_bytes_sent -= n
                rec.negotiation_bytes_sent = min(rec.negotiation_bytes_sent, rec.upstream_bytes_sent)
                self._dirty.add(rec.id)
                if tunnel.target:
                    self._counted = max(0, self._counted - n)
                    self._untimeline_sent_locked(n)
        except Exception as exc:  # counting must never break the relay
            self.internal_error()
            logger.debug("meter: discard error %s", type(exc).__name__)

    def _untimeline_sent_locked(self, n: int) -> None:
        idx = self._timeline_last
        if idx is None:
            return
        timeline = self._timeline
        for _ in range(_DISCARD_LOOKBACK_SLOTS):
            if n <= 0 or not timeline:
                return
            slot = timeline.get(idx)
            if slot is not None:
                take = min(slot[0], n)
                slot[0] -= take
                n -= take
                if not slot[0] and not slot[1]:
                    del timeline[idx]
            idx -= 1

    def _add(self, tunnel: Tunnel, n: int, negotiation: int, *, received: bool) -> None:
        if n <= 0:
            return
        pending: _Pending | None = None
        try:
            with self._lock:
                rec = tunnel.record
                self._dirty.add(rec.id)
                if received:
                    rec.upstream_bytes_received += n
                    if negotiation:
                        rec.negotiation_bytes_received += min(n, negotiation)
                else:
                    rec.upstream_bytes_sent += n
                    if negotiation:
                        rec.negotiation_bytes_sent += min(n, negotiation)
                if tunnel.target:
                    pending = self._count_target_locked(tunnel, n, received)
        except Exception as exc:  # counting must never break the relay
            self.internal_error()
            logger.debug("meter: counting error %s", type(exc).__name__)
            return
        if pending is not None:
            self._run_pending(pending)

    def _count_target_locked(self, tunnel: Tunnel, n: int, received: bool) -> _Pending | None:
        now = self.clock()
        self._counted += n
        if self._record_timeline:
            self._timeline_add_locked(now, n, received)
        sec = int(now)
        recent = self._recent
        if not recent or recent[-1][0] != sec:
            recent.append((sec, {}))
            horizon = sec - int(math.ceil(self.window_s)) - 1
            while recent and recent[0][0] < horizon:
                recent.popleft()
        hosts = recent[-1][1]
        host = tunnel.record.host
        hosts[host] = hosts.get(host, 0) + n

        pending: _Pending | None = None
        budget = self.budget_bytes
        if budget is not None:
            if not self._warned and self._counted >= self.warn_fraction * budget:
                self._warned = True
                event = BudgetEvent(ts=now, kind="warn_80", counted_bytes=self._counted, limit_bytes=budget)
                self._events.append(event)
                pending = _Pending(events=[event])
            if not self._tripped and self._counted >= budget:
                self._tripped = True
                closed = self._close_all_locked(TUNNEL_BUDGET, now)
                event = BudgetEvent(
                    ts=now,
                    kind="tripped",
                    counted_bytes=self._counted,
                    limit_bytes=budget,
                    top_hosts=self._top_hosts_locked(now),
                    closed_tunnels=len(closed),
                )
                self._events.append(event)
                pending = pending or _Pending()
                pending.events.append(event)
                pending.abort.extend(closed)
                return pending
        cap = self.max_tunnel_bytes
        if cap is not None and not tunnel.closing and tunnel.connection_bytes >= cap:
            rec = tunnel.record
            self._finish_locked(tunnel, TUNNEL_CAP, now)
            event = BudgetEvent(
                ts=now,
                kind="tunnel_cap",
                # The upstream connection's count, continued records included (meas4-6).
                counted_bytes=tunnel.connection_bytes,
                limit_bytes=cap,
                tunnel_id=rec.id,
                host=rec.host,
                closed_tunnels=1,
            )
            self._events.append(event)
            pending = pending or _Pending()
            pending.events.append(event)
            pending.abort.append(tunnel)
        return pending

    def _timeline_add_locked(self, now: float, n: int, received: bool) -> None:
        idx = math.floor(now / self.resolution)
        timeline = self._timeline
        slot = timeline.get(idx)
        if slot is None:
            slot = timeline[idx] = [0, 0]
            if self._timeline_last is None or idx > self._timeline_last:
                self._timeline_last = idx
        slot[1 if received else 0] += n
        if len(timeline) > self._max_slots:
            self._coarsen_timeline_locked()

    def _coarsen_timeline_locked(self) -> None:
        """Merge adjacent slots and double the resolution (floor(t / 2r) == floor(t / r) // 2)."""
        while len(self._timeline) > self._max_slots:
            merged: dict[int, list[int]] = {}
            for idx, (sent, received) in self._timeline.items():
                slot = merged.get(idx // 2)
                if slot is None:
                    merged[idx // 2] = [sent, received]
                else:
                    slot[0] += sent
                    slot[1] += received
            self._timeline = merged
            self.resolution *= 2
            if self._timeline_last is not None:
                self._timeline_last //= 2

    def _top_hosts_locked(self, now: float) -> list[HostBytes]:
        cutoff = now - self.window_s
        totals: dict[str, int] = {}
        for sec, hosts in self._recent:
            if sec + 1 <= cutoff:
                continue
            for host, n in hosts.items():
                totals[host] = totals.get(host, 0) + n
        ranked = sorted(totals.items(), key=lambda kv: (-kv[1], kv[0]))[:TOP_HOSTS_LIMIT]
        return [HostBytes(host=h, bytes=b) for h, b in ranked]

    def _close_all_locked(self, status: str, now: float) -> list[Tunnel]:
        closed = list(self._open.values())
        for tunnel in closed:
            self._finish_locked(tunnel, status, now)
        return closed

    def _finish_locked(self, tunnel: Tunnel, status: str, now: float) -> bool:
        rec = tunnel.record
        tunnel.closing = True
        if rec.status != TUNNEL_OPEN:
            return False
        if status == TUNNEL_OK:
            status = tunnel.ok_status
        rec.status = status
        rec.closed_at = now
        self._open.pop(rec.id, None)
        self._dirty.add(rec.id)
        return True

    def _run_pending(self, pending: _Pending) -> None:
        for tunnel in pending.abort:
            tunnel.abort_transports()
            self._log_close(tunnel.record)
        for event in pending.events:
            for callback in list(self._callbacks):
                try:
                    callback(event)
                except Exception as exc:  # a callback bug must not break the meter
                    with self._lock:
                        self._internal_errors += 1
                    logger.debug("meter: budget callback raised %s", type(exc).__name__)

    def finish(self, tunnel: Tunnel, status: str = TUNNEL_OK) -> bool:
        """Close a tunnel with ``status`` unless it is already closed (first status wins)."""
        with self._lock:
            changed = self._finish_locked(tunnel, status, self.clock())
        if changed:
            self._log_close(tunnel.record)
        return changed

    def close_all(self, status: str = TUNNEL_OK) -> int:
        """Close every open tunnel (forwarder stop) and abort its transports."""
        with self._lock:
            closed = self._close_all_locked(status, self.clock())
        for tunnel in closed:
            tunnel.abort_transports()
            self._log_close(tunnel.record)
        return len(closed)

    def open_tunnels(self) -> list[Tunnel]:
        with self._lock:
            return list(self._open.values())

    def open_count(self) -> int:
        """Number of open tunnels (cheap; for drain loops that would otherwise snapshot)."""
        with self._lock:
            return len(self._open)

    @staticmethod
    def _log_close(rec: TunnelRecord) -> None:
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "tunnel %d %s:%d kind=%s route=%s status=%s sent=%d received=%d",
                rec.id,
                rec.host,
                rec.port,
                rec.kind,
                rec.route,
                rec.status,
                rec.upstream_bytes_sent,
                rec.upstream_bytes_received,
            )

    # ------------------------------------------------------------------ snapshot
    def snapshot(self) -> MeterSnapshot:
        """A deep copy of everything measured so far (safe from any thread)."""
        with self._lock:
            # Refresh only what can have changed; everything else is reused from
            # the previous snapshot, so the lock is held for O(open + changed).
            records, copies = self._records, self._copies
            for rid in self._dirty.union(self._open):
                copies[rid - 1] = _copy_record(records[rid - 1])
            self._dirty.clear()
            cached = list(copies)
            events = copy.deepcopy(self._events)
            refused = dict(self._refused)
            # Plain numbers only (the slot lists are mutated in place by the loop thread);
            # at most MAX_TIMELINE_SLOTS of them. The points are built after the lock.
            slots = [(idx, slot[0], slot[1]) for idx, slot in self._timeline.items()]
            resolution = self.resolution
            counted = self._counted
            tripped = self._tripped
            internal = self._internal_errors
            accept_limit = self._accept_limit_errors
        # Fresh objects for the caller, made outside the lock (cached copies are never mutated).
        slots.sort()
        timeline = [TimelinePoint(t=idx * resolution, sent=sent, received=rec) for idx, sent, rec in slots if sent or rec]
        tunnels = [_copy_record(c) for c in cached if c is not None]
        return MeterSnapshot(
            taken_at=self.clock(),
            started_at=self.started_at,
            mode=self.mode,
            port=self.port,
            auth_port=self.auth_port,
            tunnels=tunnels,
            counted_bytes=counted,
            budget_bytes=self.budget_bytes,
            max_tunnel_bytes=self.max_tunnel_bytes,
            budget_tripped=tripped,
            budget_events=events,
            refused=refused,
            timeline=timeline,
            timeline_resolution_s=resolution,
            internal_errors=internal,
            accept_limit_errors=accept_limit,
        )


__all__ = ["BudgetCallback", "MAX_TIMELINE_SLOTS", "Meter", "Tunnel", "TunnelAborted", "TOP_HOSTS_LIMIT"]
