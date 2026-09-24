"""Tests for scrapescope.config: upstream parsing, sizes, child env, test hooks."""

from __future__ import annotations

import argparse
import base64
import os
import stat

import pytest

from scrapescope import config
from scrapescope.config import (
    ConfigError,
    ForwarderConfig,
    HostRule,
    PrivateEventsFile,
    UpstreamConfig,
)

SENTINEL_USER = "sentinel-cfg-user-9Qa"
SENTINEL_PASS = "sentinel-cfg-pass-7Zk"
SENTINEL_HOST = "sentinel-proxy-host.example"
UPSTREAM_URL = f"http://{SENTINEL_USER}:{SENTINEL_PASS}@{SENTINEL_HOST}:8000"


def _secrets_absent(text: str) -> None:
    for secret in (SENTINEL_USER, SENTINEL_PASS, SENTINEL_HOST, "8000"):
        assert secret not in text
    b64 = base64.b64encode(f"{SENTINEL_USER}:{SENTINEL_PASS}".encode()).decode()
    assert b64 not in text


# ---------------------------------------------------------------------------- upstream URL


def test_parse_http_upstream_with_credentials() -> None:
    up = config.parse_upstream_url(UPSTREAM_URL)
    assert up.kind == "http-connect" and up.mode == "http-connect"
    assert up.host == SENTINEL_HOST and up.port == 8000
    assert up.username == SENTINEL_USER and up.password == SENTINEL_PASS
    assert up.proxy_authorization() == config.basic_auth_value(SENTINEL_USER, SENTINEL_PASS)


@pytest.mark.parametrize(
    ("url", "kind", "host", "port"),
    [
        ("http://proxy.example", "http-connect", "proxy.example", 80),
        ("proxy.example:3128", "http-connect", "proxy.example", 3128),
        ("socks5://proxy.example", "socks5", "proxy.example", 1080),
        ("socks5h://u:p@[::1]:1081", "socks5", "::1", 1081),
        ("HTTP://Proxy.EXAMPLE:8080/", "http-connect", "proxy.example", 8080),
    ],
)
def test_parse_upstream_variants(url: str, kind: str, host: str, port: int) -> None:
    up = config.parse_upstream_url(url)
    assert (up.kind, up.host, up.port) == (kind, host, port)


def test_parse_upstream_percent_decodes_userinfo() -> None:
    up = config.parse_upstream_url("http://us%40er:p%3Ass%2Fw@proxy.example:1")
    assert up.username == "us@er" and up.password == "p:ss/w"


def test_parse_upstream_without_credentials() -> None:
    up = config.parse_upstream_url("http://proxy.example:1")
    assert up.username is None and up.password is None
    assert not up.has_credentials and up.proxy_authorization() is None


@pytest.mark.parametrize(
    "url",
    [
        f"https://{SENTINEL_USER}:{SENTINEL_PASS}@{SENTINEL_HOST}:8000",
        f"socks4://{SENTINEL_USER}:{SENTINEL_PASS}@{SENTINEL_HOST}:8000",
        f"http://{SENTINEL_USER}:{SENTINEL_PASS}@{SENTINEL_HOST}:8000/path",
        f"http://{SENTINEL_USER}:{SENTINEL_PASS}@{SENTINEL_HOST}:8000?x=1",
        f"http://{SENTINEL_USER}:{SENTINEL_PASS}@{SENTINEL_HOST}:99999",
        f"http://{SENTINEL_USER}:{SENTINEL_PASS}@:8000",
        "",
    ],
)
def test_parse_upstream_rejects_without_echoing_secrets(url: str) -> None:
    with pytest.raises(ConfigError) as info:
        config.parse_upstream_url(url, source="HTTPS_PROXY")
    assert info.value.exit_code == 89
    _secrets_absent(str(info.value))
    _secrets_absent(repr(info.value))


def test_socks_credentials_length_limit() -> None:
    with pytest.raises(ConfigError):
        config.parse_upstream_url("socks5://" + "u" * 256 + ":p@proxy.example:1080")


def test_upstream_repr_hides_everything_secret() -> None:
    up = config.parse_upstream_url(UPSTREAM_URL)
    for text in (repr(up), str(up), f"{up}", repr([up])):
        _secrets_absent(text)
    assert "credentials=yes" in repr(up)


def test_forwarder_config_repr_hides_token_and_upstream() -> None:
    up = config.parse_upstream_url(UPSTREAM_URL)
    cfg = ForwarderConfig(upstream=up, token="TOKENSENTINEL123", require_token=True)
    text = repr(cfg)
    _secrets_absent(text)
    assert "TOKENSENTINEL123" not in text
    assert cfg.mode == "http-connect"
    assert ForwarderConfig().mode == "direct"


def test_forwarder_config_validation() -> None:
    with pytest.raises(ValueError):
        ForwarderConfig(idle_timeout_s=30)
    with pytest.raises(ValueError):
        ForwarderConfig(require_token=True)
    with pytest.raises(ValueError):
        ForwarderConfig(port=70000)


def test_host_rule_normalises_and_validates() -> None:
    assert HostRule("*.Example.COM.", "deny-host:x").pattern == "*.example.com"
    for bad in ("exa?mple.com", "[ab].com", "a b.com", ""):
        with pytest.raises(ValueError):
            HostRule(bad, "deny-host:x")


# ---------------------------------------------------------------------------- resolve_upstream


def test_resolve_upstream_direct() -> None:
    assert config.resolve_upstream(direct=True, upstream_var=None, environ={"HTTPS_PROXY": UPSTREAM_URL}) == (None, None)


def test_resolve_upstream_named_variable() -> None:
    up, var = config.resolve_upstream(direct=False, upstream_var="MY_PROXY", environ={"MY_PROXY": UPSTREAM_URL})
    assert var == "MY_PROXY" and isinstance(up, UpstreamConfig) and up.host == SENTINEL_HOST


def test_resolve_upstream_falls_back_to_https_proxy() -> None:
    up, var = config.resolve_upstream(direct=False, upstream_var=None, environ={"HTTPS_PROXY": UPSTREAM_URL})
    assert var == "HTTPS_PROXY" and up is not None


def test_resolve_upstream_missing_suggests_direct() -> None:
    with pytest.raises(ConfigError) as info:
        config.resolve_upstream(direct=False, upstream_var=None, environ={})
    assert "--direct" in str(info.value)
    with pytest.raises(ConfigError) as info:
        config.resolve_upstream(direct=False, upstream_var="NOPE", environ={})
    assert "NOPE" in str(info.value) and "--direct" in str(info.value)


def test_resolve_upstream_conflicting_flags() -> None:
    with pytest.raises(ConfigError):
        config.resolve_upstream(direct=True, upstream_var="HTTPS_PROXY", environ={"HTTPS_PROXY": UPSTREAM_URL})


def test_upstream_from_env_rejects_bad_variable_name() -> None:
    with pytest.raises(ConfigError):
        config.upstream_from_env("NOT A NAME", {"NOT A NAME": UPSTREAM_URL})


# ---------------------------------------------------------------------------- sizes


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("2GB", 2_000_000_000),
        ("2gb", 2_000_000_000),
        ("500MB", 500_000_000),
        ("500 mb", 500_000_000),
        ("1.5GiB", 1_610_612_736),
        ("750kB", 750_000),
        ("1KiB", 1024),
        ("1TB", 10**12),
        ("1000", 1000),
        ("1000B", 1000),
        ("2G", 2 * 10**9),
    ],
)
def test_parse_size(text: str, expected: int) -> None:
    assert config.parse_size(text) == expected


@pytest.mark.parametrize("text", ["", "abc", "-1GB", "0", "0MB", "2XB", "1e9", "1.5.5GB"])
def test_parse_size_rejects(text: str) -> None:
    with pytest.raises(ValueError):
        config.parse_size(text)


def test_size_arg_raises_argparse_error() -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        config.size_arg("lots")


def test_units_and_formatting() -> None:
    assert config.unit_bytes("GB") == 10**9 and config.unit_bytes("GiB") == 2**30
    assert config.to_unit(2 * 10**9, "GB") == 2.0
    assert config.to_unit(2**30, "GiB") == 1.0
    assert config.format_size(999) == "999 B"
    assert config.format_size(1_234_567) == "1.23 MB"
    assert config.format_size(1_234_567, "GiB") == "1.18 MiB"
    assert config.format_size(2 * 10**9) == "2.00 GB"


# ---------------------------------------------------------------------------- auth helpers


def test_basic_auth_round_trip_and_malformed() -> None:
    value = config.basic_auth_value("ss-tok~user", "p:w")
    assert config.parse_basic_auth(value) == ("ss-tok~user", "p:w")
    assert config.parse_basic_auth(None) is None
    assert config.parse_basic_auth("Bearer abc") is None
    assert config.parse_basic_auth("Basic !!!") is None
    assert config.parse_basic_auth("Basic " + base64.b64encode(b"onlyuser").decode()) == ("onlyuser", "")


def test_token_helpers() -> None:
    token = config.new_token()
    assert len(token) == 24 and "~" not in token and ":" not in token
    assert token != config.new_token()
    assert config.token_username("abc") == "ss-abc"
    assert config.token_username("abc", "user-1") == "ss-abc~user-1"


def test_authority_helpers() -> None:
    assert config.split_authority("Origin-A.test:443") == ("origin-a.test", 443)
    assert config.split_authority("[::1]:8080") == ("::1", 8080)
    assert config.split_authority("example.com", 80) == ("example.com", 80)
    for bad in ("example.com", "example.com:0", "example.com:65536", "::1:80", "[::1", "exa mple.com:1", ":80"):
        with pytest.raises(ValueError):
            config.split_authority(bad)
    assert config.format_authority("::1", 443) == "[::1]:443"
    assert config.format_authority("origin-a.test", 443) == "origin-a.test:443"


def test_synthetic_connect_sizes_match_bytes() -> None:
    req = b"CONNECT origin-a.test:443 HTTP/1.1\r\nHost: origin-a.test:443\r\n\r\n"
    assert config.synthetic_connect_sizes("origin-a.test", 443) == (len(req), len(config.SYNTHETIC_CONNECT_RESPONSE))


# ---------------------------------------------------------------------------- child env


def test_child_env_topology_preserving_default() -> None:
    base = {
        "HTTPS_PROXY": UPSTREAM_URL,
        "https_proxy": UPSTREAM_URL + "/",
        "HTTP_PROXY": "http://other-proxy.example:1",
        "NO_PROXY": "corp.local",
        "PATH": "/usr/bin",
        "SCRAPESCOPE_KEEP_URLS": "1",
    }
    env = config.build_child_env(
        base,
        meter_url="http://127.0.0.1:5555",
        events_path="/tmp/ev/events.jsonl",
        upstream_var="HTTPS_PROXY",
        auth_meter_url="http://127.0.0.1:5556",
    )
    assert env["HTTPS_PROXY"] == "http://127.0.0.1:5555"
    assert env["https_proxy"] == "http://127.0.0.1:5555"  # duplicate of the upstream URL replaced
    assert env["HTTP_PROXY"] == "http://other-proxy.example:1"  # other variables untouched
    assert env["NO_PROXY"] == "corp.local"
    assert env["PATH"] == "/usr/bin"
    assert "ALL_PROXY" not in env and "NODE_USE_ENV_PROXY" not in env
    assert env["SCRAPESCOPE_PROXY_URL"] == "http://127.0.0.1:5555"
    assert env["SCRAPESCOPE_AUTH_PROXY_URL"] == "http://127.0.0.1:5556"
    assert env["SCRAPESCOPE_EVENTS"] == "/tmp/ev/events.jsonl"
    assert "SCRAPESCOPE_KEEP_URLS" not in env
    _secrets_absent("\n".join(f"{k}={v}" for k, v in env.items()))
    assert base["HTTPS_PROXY"] == UPSTREAM_URL  # input not mutated


def test_child_env_env_all() -> None:
    base = {"HTTPS_PROXY": UPSTREAM_URL, "NO_PROXY": "corp.local,localhost", "no_proxy": "internal.test"}
    env = config.build_child_env(
        base,
        meter_url="http://127.0.0.1:5555",
        events_path="/tmp/e",
        upstream_var="HTTPS_PROXY",
        env_all=True,
        keep_urls=True,
    )
    for name in config.PROXY_ENV_VARS:
        assert env[name] == "http://127.0.0.1:5555"
    assert env["NODE_USE_ENV_PROXY"] == "1"
    assert env["NO_PROXY"] == env["no_proxy"] == "corp.local,localhost,internal.test,127.0.0.1,::1"
    assert env["SCRAPESCOPE_KEEP_URLS"] == "1"
    assert "SCRAPESCOPE_AUTH_PROXY_URL" not in env
    _secrets_absent("\n".join(f"{k}={v}" for k, v in env.items()))


def test_child_env_direct_mode_touches_no_proxy_variables() -> None:
    base = {"HTTP_PROXY": "http://job-proxy.example:1"}
    env = config.build_child_env(base, meter_url="http://127.0.0.1:1", events_path=None, upstream_var=None)
    assert env["HTTP_PROXY"] == "http://job-proxy.example:1"
    assert "SCRAPESCOPE_EVENTS" not in env
    assert env["SCRAPESCOPE_PROXY_URL"] == "http://127.0.0.1:1"


def test_merge_no_proxy() -> None:
    assert config.merge_no_proxy(None) == "127.0.0.1,localhost,::1"
    assert config.merge_no_proxy(" a , b ", "b,c") == "a,b,c,127.0.0.1,localhost,::1"


# ---------------------------------------------------------------------------- test hooks


def test_connect_map_parsing_and_gating() -> None:
    text = '{"Origin-A.test:443": "127.0.0.1:5000", "[::1]:80": "127.0.0.1:5001"}'
    assert config.parse_connect_map(text) == {
        ("origin-a.test", 443): ("127.0.0.1", 5000),
        ("::1", 80): ("127.0.0.1", 5001),
    }
    env = {"SCRAPESCOPE_TEST_CONNECT_MAP": text, "SCRAPESCOPE_TEST_CA": "/tmp/ca.pem"}
    assert config.connect_map_from_env(env) is None  # ignored without SCRAPESCOPE_TESTING=1
    assert config.test_ca_from_env(env) is None
    env["SCRAPESCOPE_TESTING"] = "1"
    assert config.connect_map_from_env(env) == config.parse_connect_map(text)
    assert config.test_ca_from_env(env) == "/tmp/ca.pem"
    for bad in ("[]", '{"a:1": 5}', '{"nohostport": "127.0.0.1:1"}', "not json"):
        with pytest.raises(ValueError):
            config.parse_connect_map(bad)


def test_private_events_file_permissions_and_cleanup() -> None:
    events = PrivateEventsFile.create()
    try:
        assert stat.S_IMODE(os.stat(events.directory).st_mode) == 0o700
        assert stat.S_IMODE(os.stat(events.path).st_mode) == 0o600
        assert events.path.read_bytes() == b""
    finally:
        events.cleanup()
    assert not events.directory.exists()
    events.cleanup()  # idempotent


def test_exit_codes_are_distinct() -> None:
    codes = [
        config.EXIT_OK,
        config.EXIT_NOT_FOUND,
        config.EXIT_USAGE,
        config.EXIT_BROWSER_UNAVAILABLE,
        config.EXIT_BLOCKED,
        config.EXIT_LOAD_ERROR,
        config.EXIT_BUDGET,
        config.EXIT_BYPASS,
        config.EXIT_INTERNAL,
        config.EXIT_UPSTREAM_CONFIG,
    ]
    assert codes == [0, 1, 2, 3, 4, 5, 86, 87, 88, 89]


def test_user_agent_is_honest() -> None:
    from scrapescope import __version__

    # The tool, its version and the project's contact URL (the public repository),
    # nothing else: no browser impersonation, no operating-system details (docs-1).
    assert config.USER_AGENT == f"scrapescope/{__version__} (+https://github.com/ipvolt/scrapescope)"
    assert "Mozilla" not in config.USER_AGENT
    assert config.USER_AGENT.count("http") == 1


# ---------------------------------------------------------------------------- semantic duplicates (sec2-10)
def test_child_env_replaces_semantic_duplicates_of_the_upstream(monkeypatch: pytest.MonkeyPatch) -> None:
    """Spelling differences must not leave the provider URL (and its credentials) in the child."""
    import os
    import urllib.request

    upstream = "http://custA:s3cret@gw.provider.example:8000"
    base = {
        "HTTPS_PROXY": upstream,
        "https_proxy": "http://custA:s3cret@GW.provider.example:8000",  # host case
        "HTTP_PROXY": "custA:s3cret@gw.provider.example:8000",  # scheme-less form scrapescope accepts
        "http_proxy": "http://custA:s3cret@gw.provider.example:8000/",
        "ALL_PROXY": "http://custA:s3cret@gw.provider.example:8000",
        "all_proxy": "HTTP://custA:s3cret@gw.provider.example:08000",
        "FTP_PROXY": "http://other.example:8000",  # another proxy: untouched
        "NO_PROXY": "gw.provider.example:8000",  # never a proxy setting
        "PROVIDER_HOST": "gw.provider.example:8000",  # not a proxy variable and not an exact duplicate
    }
    env = config.build_child_env(base, meter_url="http://127.0.0.1:5555", events_path=None, upstream_var="HTTPS_PROXY")
    for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        assert env[name] == "http://127.0.0.1:5555", name
    assert env["FTP_PROXY"] == "http://other.example:8000"
    assert env["NO_PROXY"] == "gw.provider.example:8000"
    assert env["PROVIDER_HOST"] == "gw.provider.example:8000"
    child = {k: v for k, v in env.items() if k.lower().endswith("proxy")}
    assert not any("s3cret" in v for v in child.values())
    # What urllib (and requests) in the child would use: the meter, never the provider.
    monkeypatch.setattr(os, "environ", dict(env))
    proxies = urllib.request.getproxies_environment()
    assert proxies["https"] == proxies["http"] == "http://127.0.0.1:5555"


def test_child_env_socks5_and_socks5h_are_the_same_endpoint() -> None:
    base = {"HTTPS_PROXY": "socks5://u:p@gw.provider.example:1080", "https_proxy": "socks5h://u:p@gw.provider.example"}
    env = config.build_child_env(base, meter_url="http://127.0.0.1:1", events_path=None, upstream_var="HTTPS_PROXY")
    assert env["https_proxy"] == "http://127.0.0.1:1"


def test_child_env_other_credentials_stay_and_are_named_for_a_warning() -> None:
    base = {
        "HTTPS_PROXY": "http://custA:s3cret@gw.provider.example:8000",
        "http_proxy": "http://custB:other@gw.provider.example:8000",  # another account: not a duplicate
        "ws_proxy": "http://gw.provider.example:9000",  # another port of the gateway: named (sec3-7)
        "ftp_proxy": "http://custA:s3cret@other.example:3128",  # another proxy: left alone and not named
    }
    env = config.build_child_env(base, meter_url="http://127.0.0.1:5555", events_path=None, upstream_var="HTTPS_PROXY")
    assert env["http_proxy"] == base["http_proxy"]
    upstream = config.parse_upstream_url(base["HTTPS_PROXY"])
    assert config.unmetered_proxy_variables(env, upstream) == ["ftp_proxy", "http_proxy", "ws_proxy"]
    assert config.unmetered_proxy_variables(env, None) == []
    # A local upstream on 127.0.0.1 is not confused with the meter's own URL.
    local = config.parse_upstream_url("http://127.0.0.1:8000")
    env2 = config.build_child_env({"HTTPS_PROXY": "http://127.0.0.1:8000"}, meter_url="http://127.0.0.1:5555",
                                  events_path=None, upstream_var="HTTPS_PROXY")
    assert config.unmetered_proxy_variables(env2, local) == []


def test_child_env_names_the_provider_gateway_on_another_port_or_scheme() -> None:
    """sec3-7: one gateway, HTTP CONNECT on 8080 (metered) and SOCKS5 on 1080 with the same password."""
    sentinel = "SENTPASS"
    base = {
        "HTTPS_PROXY": f"http://cust-U1:{sentinel}@gw.provider.test:8080",
        "HTTP_PROXY": f"http://cust-U1:{sentinel}@gw.provider.test:8080",
        "all_proxy": f"socks5h://cust-U1:{sentinel}@gw.provider.test:1080",
        "no_proxy": "gw.provider.test",
    }
    env = config.build_child_env(base, meter_url="http://127.0.0.1:5555", events_path=None, upstream_var="HTTPS_PROXY")
    assert env["HTTPS_PROXY"] == env["HTTP_PROXY"] == "http://127.0.0.1:5555"
    # Another port can select another session or country: rerouting it would change the job, so it
    # stays, and the runner names it at start and in the report.
    assert env["all_proxy"] == base["all_proxy"]
    upstream = config.parse_upstream_url(base["HTTPS_PROXY"])
    names = config.unmetered_proxy_variables(env, upstream)
    assert names == ["all_proxy"]
    assert not any(sentinel in name for name in names)


def test_unmetered_variables_never_name_the_meter_or_other_local_programs() -> None:
    local = config.parse_upstream_url("http://127.0.0.1:8000")
    base = {"HTTPS_PROXY": "http://127.0.0.1:8000", "ALL_PROXY": "socks5://127.0.0.1:9050"}  # e.g. Tor, not the relay
    env = config.build_child_env(base, meter_url="http://127.0.0.1:5555", events_path=None, upstream_var="HTTPS_PROXY",
                                 env_all=True)
    assert config.unmetered_proxy_variables(env, local) == []
    env2 = config.build_child_env(base, meter_url="http://127.0.0.1:5555", events_path=None, upstream_var="HTTPS_PROXY")
    assert config.unmetered_proxy_variables(env2, local) == []
    # The local relay's own port with other credentials still bypasses the meter.
    assert config.unmetered_proxy_variables(dict(env2, http_proxy="http://other:x@127.0.0.1:8000"), local) == [
        "http_proxy"
    ]


def test_unmetered_variables_parse_other_schemes_and_paths_leniently() -> None:
    """sec4-4 (a): a TLS proxy port (https://), socks4:// or a path still names the provider's gateway."""
    upstream = config.parse_upstream_url("http://user:secret@gw.provider.com:8000")
    base = {
        "HTTPS_PROXY": "http://user:secret@gw.provider.com:8000",
        "https_proxy": "https://user:secret@gw.provider.com:8443",
        "HTTP_PROXY": "socks4://gw.provider.com:1080",
        "ALL_PROXY": "http://user:secret@gw.provider.com:8000/route",
        "ftp_proxy": "socks5h://gw.provider.com:1080",
        "npm_config_https_proxy": "https://user:secret@relay.example:443",  # its credentials on another host
        "GIT_PROXY": "https://other.example:3128/x",  # another proxy without the credentials: not named
        "NODE_USE_ENV_PROXY": "1",  # not a URL: never named
    }
    env = config.build_child_env(base, meter_url="http://127.0.0.1:5555", events_path=None, upstream_var="HTTPS_PROXY")
    assert config.unmetered_proxy_variables(env, upstream) == [
        "ALL_PROXY", "HTTP_PROXY", "ftp_proxy", "https_proxy", "npm_config_https_proxy"
    ]
    # A loopback relay: another scheme on its own port counts, other local ports do not.
    local = config.parse_upstream_url("http://127.0.0.1:8000")
    env2 = {"https_proxy": "https://127.0.0.1:8000", "ALL_PROXY": "socks4://127.0.0.1:9050", "X_PROXY": "https://[::1"}
    assert config.unmetered_proxy_variables(env2, local) == ["https_proxy"]


def test_case_twin_of_the_metered_variable_is_named_as_another_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """sec4-4 (b): urllib/requests/curl/Node read https_proxy before HTTPS_PROXY, so a twin shadows the meter."""
    import urllib.request

    upstream = config.parse_upstream_url("http://user:secret@gw.provider-a.com:8000")
    base = {
        "HTTPS_PROXY": "http://user:secret@gw.provider-a.com:8000",
        "https_proxy": "http://other:pw@gw.provider-b.com:9000",
        "ALL_PROXY": "socks5://127.0.0.1:9050",
        "http_proxy": "",  # empty: clients treat it as unset
    }
    env = config.build_child_env(base, meter_url="http://127.0.0.1:5555", events_path=None, upstream_var="HTTPS_PROXY")
    assert env["https_proxy"] == base["https_proxy"]  # left unchanged, but named
    assert config.unmetered_proxy_variables(env, upstream) == []
    assert config.other_proxy_variables(env, "HTTPS_PROXY") == ["https_proxy", "ALL_PROXY"]
    monkeypatch.setattr(os, "environ", dict(env))
    assert urllib.request.getproxies_environment()["https"] == base["https_proxy"]  # the shadow is real
    # The meter's own URLs, the metered variable itself and --env-all never produce a name.
    env_all = config.build_child_env(base, meter_url="http://127.0.0.1:5555", events_path=None,
                                     upstream_var="HTTPS_PROXY", env_all=True)
    assert config.other_proxy_variables(env_all, "HTTPS_PROXY") == []
    # A lowercase metered variable: the uppercase twin (read first by Go) comes first.
    env3 = config.build_child_env({"https_proxy": base["HTTPS_PROXY"], "HTTPS_PROXY": base["https_proxy"]},
                                  meter_url="http://127.0.0.1:5555", events_path=None, upstream_var="https_proxy")
    assert config.other_proxy_variables(env3, "https_proxy") == ["HTTPS_PROXY"]
    assert config.case_twin("HTTPS_PROXY") == "https_proxy" and config.case_twin("all_proxy") == "ALL_PROXY"
    assert config.case_twin("Https_Proxy") is None and config.case_twin("MY_PROXY") is None


def test_missing_upstream_names_http_proxy_too() -> None:
    """ux4-4: an http:// scraper often sets only HTTP_PROXY; the hint names it."""
    for name in ("HTTP_PROXY", "http_proxy"):
        with pytest.raises(config.ConfigError) as exc:
            config.resolve_upstream(direct=False, upstream_var=None, environ={name: "http://u:SENT@proxy.example.net:8000"})
        text = str(exc.value)
        assert f"but {name} is" in text and f"--upstream-from-env {name}" in text and "SENT" not in text
    with pytest.raises(config.ConfigError) as exc:
        config.resolve_upstream(direct=False, upstream_var=None, environ={"https_proxy": "x", "HTTP_PROXY": "y"})
    assert "but https_proxy is" in str(exc.value)


def test_proxy_variable_names() -> None:
    for name in ("HTTPS_PROXY", "http_proxy", "ALL_PROXY", "ftp_proxy", "SCRAPER_PROXY"):
        assert config.is_proxy_variable_name(name), name
    for name in ("NO_PROXY", "no_proxy", "PROXY_URL", "PATH"):
        assert not config.is_proxy_variable_name(name), name
