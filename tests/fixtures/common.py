"""Shared constants and small helpers for the fixture proxies.

The credentials below are deliberately distinctive so credential-sentinel
tests can grep every output for them. They are fake and grant nothing outside
the local test world.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field

#: Username accepted by the authenticated fixture upstreams.
UPSTREAM_USERNAME = "sentinel-user-Q7xK2m"
#: Password for :data:`UPSTREAM_USERNAME`.
UPSTREAM_PASSWORD = "sentinel-pass-Z9vB4wLp"
#: Any username is accepted with this password (models provider session usernames).
SESSION_PASSWORD = "sentinel-session-pass-R3tY8"

#: Vendor-style error header the HTTP upstream adds to its own error responses.
VENDOR_ERROR_HEADER = "X-Fixture-Proxy-Error"

#: Realm in the upstream's ``Proxy-Authenticate`` challenge.
UPSTREAM_REALM = "fixture-upstream"

HostPort = tuple[str, int]
#: {(hostname, port): (ip, port)} used by the fixture upstreams for remote DNS.
HostsMap = dict[HostPort, HostPort]


@dataclass
class AuthPolicy:
    """Which proxy credentials an upstream accepts.

    ``required=False`` accepts every connection (credentials, if any, are still
    recorded). Otherwise a (username, password) pair is accepted when it is in
    ``credentials`` or when ``any_user_password`` is set and equals the password.
    """

    required: bool = True
    credentials: dict[str, str] = field(default_factory=dict)
    any_user_password: str | None = None

    def check(self, username: str | None, password: str | None) -> bool:
        if not self.required:
            return True
        if username is None or password is None:
            return False
        if self.credentials.get(username) == password:
            return True
        return self.any_user_password is not None and password == self.any_user_password

    @classmethod
    def default(cls) -> AuthPolicy:
        """The policy of the authenticated fixture upstreams."""
        return cls(
            required=True,
            credentials={UPSTREAM_USERNAME: UPSTREAM_PASSWORD},
            any_user_password=SESSION_PASSWORD,
        )

    @classmethod
    def open(cls) -> AuthPolicy:
        """No authentication required."""
        return cls(required=False)


def parse_basic_proxy_auth(value: str | None) -> tuple[str | None, str | None]:
    """Return (username, password) from a ``Proxy-Authorization: Basic`` value.

    Malformed or non-Basic values yield ``(None, None)``.
    """
    if not value:
        return None, None
    scheme, _, token = value.strip().partition(" ")
    if scheme.lower() != "basic" or not token:
        return None, None
    try:
        decoded = base64.b64decode(token.strip(), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None, None
    username, sep, password = decoded.partition(":")
    if not sep:
        return username, None
    return username, password


def split_authority(authority: str, default_port: int | None = None) -> HostPort | None:
    """Split ``host:port`` (IPv6 in brackets) into (lowercased host, port)."""
    authority = authority.strip()
    if not authority:
        return None
    if authority.startswith("["):
        end = authority.find("]")
        if end < 0:
            return None
        host = authority[1:end]
        rest = authority[end + 1 :]
        if rest.startswith(":"):
            port_s = rest[1:]
        elif rest == "" and default_port is not None:
            return host.lower(), default_port
        else:
            return None
    else:
        host, sep, port_s = authority.rpartition(":")
        if not sep:
            if default_port is None:
                return None
            return authority.lower(), default_port
    if not port_s.isdigit():
        return None
    port = int(port_s)
    if not 0 < port < 65536 or not host:
        return None
    return host.lower(), port


def is_loopback_literal(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def resolve(hosts: Mapping[HostPort, HostPort], host: str, port: int) -> HostPort | None:
    """Remote-DNS lookup used by the upstreams.

    Only mapped names and loopback IP literals are reachable, so a fixture
    upstream can never reach the internet.
    """
    mapped = hosts.get((host.lower(), port))
    if mapped is not None:
        return mapped
    if is_loopback_literal(host):
        return host, port
    return None


def connect_map_json(hosts: Mapping[HostPort, HostPort]) -> str:
    """Serialise a hosts map as ``SCRAPESCOPE_TEST_CONNECT_MAP`` JSON.

    Format: a JSON object ``{"host:port": "ip:port"}``; keys use lowercase
    hostnames. Example: ``{"origin-a.test:443": "127.0.0.1:52011"}``.
    """
    return json.dumps(
        {f"{h}:{p}": f"{ip}:{ip_port}" for (h, p), (ip, ip_port) in sorted(hosts.items())},
        sort_keys=True,
    )


class Registry:
    """Thread-safe list of connection records with snapshot copies."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self._records: list = []
        self._next_id = 1
        self._open = 0

    def add(self, record) -> None:
        with self.lock:
            record.id = self._next_id
            self._next_id += 1
            self._records.append(record)
            self._open += 1

    def closed(self, record) -> None:
        with self.lock:
            self._open -= 1

    def snapshot(self) -> list:
        from copy import deepcopy

        with self.lock:
            return [deepcopy(r) for r in self._records]

    def open_count(self) -> int:
        with self.lock:
            return self._open

    def clear(self) -> None:
        with self.lock:
            self._records = []
