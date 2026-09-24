"""Loopback metering forwarder (owner: forwarder role).

Contract: docs/dev/contracts.md section 3. Public names: :class:`Forwarder`
(asyncio), :class:`ForwarderThread` (its own loop in a daemon thread) and
:class:`ForwarderError` (startup failure or crash; CLI exit 88).

Modules: ``server`` (listeners, request checks, credentials, CONNECT and h11
plain-HTTP relay), ``upstream`` (HTTP CONNECT, SOCKS5 with remote DNS, direct;
counted sockets), ``meter`` (per-tunnel counters, count-on-read budget, tunnel
cap, timeline), ``limits`` (the process's open-file limit; two descriptors
per tunnel). Counts are "tunnel-measured" on the meter's upstream socket;
the meter stops at its own count, and bytes already in flight when the budget
trips can add roughly (open tunnels x a few MB) at the provider.
"""

from .limits import raise_open_file_limit
from .server import Forwarder, ForwarderError, ForwarderThread

__all__ = ["Forwarder", "ForwarderError", "ForwarderThread", "raise_open_file_limit"]
