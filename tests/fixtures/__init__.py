"""Local test world for scrapescope: fake origins and counting upstream proxies.

Nothing here imports scrapescope and nothing reaches the internet: fake
hostnames resolve only through the hosts map, and the upstream fixtures refuse
every name that is not in it. See ``tests/fixtures/README.md``.

Import from ``tests.fixtures`` (the repository root is put on ``sys.path`` by
``tests/conftest.py``).
"""

from . import site
from .common import (
    SESSION_PASSWORD,
    UPSTREAM_PASSWORD,
    UPSTREAM_REALM,
    UPSTREAM_USERNAME,
    VENDOR_ERROR_HEADER,
    AuthPolicy,
    HostsMap,
    connect_map_json,
    parse_basic_proxy_auth,
)
from .origin import OriginConnRecord, OriginRequestRecord, OriginServer
from .tls import BAD_CERT_NAME, TRUSTED_NAMES, TestCA
from .upstream_http import CONNECT_OK, HTTPProxyRecord, UpstreamHTTPProxy
from .upstream_socks import SocksRecord, UpstreamSocks5Proxy
from .world import BACKGROUND_HOSTS, HTTP_HOSTS, HTTPS_HOSTS, PROXY_ENV_VARS, TestWorld, free_port

__all__ = [
    "AuthPolicy",
    "BACKGROUND_HOSTS",
    "BAD_CERT_NAME",
    "CONNECT_OK",
    "HTTPProxyRecord",
    "HTTPS_HOSTS",
    "HTTP_HOSTS",
    "HostsMap",
    "OriginConnRecord",
    "OriginRequestRecord",
    "OriginServer",
    "PROXY_ENV_VARS",
    "SESSION_PASSWORD",
    "SocksRecord",
    "TRUSTED_NAMES",
    "TestCA",
    "TestWorld",
    "UPSTREAM_PASSWORD",
    "UPSTREAM_REALM",
    "UPSTREAM_USERNAME",
    "UpstreamHTTPProxy",
    "UpstreamSocks5Proxy",
    "VENDOR_ERROR_HEADER",
    "connect_map_json",
    "free_port",
    "parse_basic_proxy_auth",
    "site",
]
