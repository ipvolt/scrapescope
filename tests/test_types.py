"""Tests for scrapescope.types: arithmetic, round trips, the events parser, sanitisers,
catalog validation, and the structural consistency of report/schema.json."""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

import pytest

from scrapescope import types as T
from scrapescope.types import (
    AttachEvent,
    AttributionResult,
    BucketTally,
    BudgetEvent,
    Catalogs,
    ChallengeResult,
    Coverage,
    FindResult,
    HostAttribution,
    HostBytes,
    LaunchEvent,
    MeterSnapshot,
    RequestEvent,
    StarterCode,
    TunnelRecord,
)

ROOT = Path(__file__).resolve().parents[1]


def _tunnel(**kw) -> TunnelRecord:
    base = dict(id=1, host="origin-a.test", port=443, kind="connect", route="http-connect", opened_at=100.0)
    base.update(kw)
    return TunnelRecord(**base)


def _snapshot(tunnels: list[TunnelRecord], mode: str = "http-connect") -> MeterSnapshot:
    return MeterSnapshot(
        taken_at=200.0,
        started_at=100.0,
        mode=mode,  # type: ignore[arg-type]
        port=5555,
        auth_port=5556,
        tunnels=tunnels,
        counted_bytes=sum(t.counted_bytes for t in tunnels if t.is_target),
        budget_bytes=None,
        max_tunnel_bytes=None,
        budget_tripped=False,
    )


# ---------------------------------------------------------------------------- tunnel arithmetic


def test_tunnel_bytes_upstream_mode() -> None:
    t = _tunnel(upstream_bytes_sent=1000, upstream_bytes_received=9000, negotiation_bytes_sent=150, negotiation_bytes_received=39)
    assert t.counted_bytes == 10_000
    assert t.bytes_with_connect == 10_000
    assert t.bytes_without_connect == 10_000 - 189
    assert t.payload_bytes_sent == 850 and t.payload_bytes_received == 8961
    assert not t.negotiation_estimated and t.is_target and not t.failed


def test_tunnel_bytes_direct_mode_estimate() -> None:
    t = _tunnel(route="direct", upstream_bytes_sent=1000, upstream_bytes_received=9000,
                synthetic_negotiation_bytes_sent=63, synthetic_negotiation_bytes_received=39)
    assert t.counted_bytes == 10_000  # budget never counts synthetic bytes
    assert t.bytes_with_connect == 10_102
    assert t.bytes_without_connect == 10_000
    assert t.negotiation_estimated


def test_snapshot_totals_include_failed_exclude_denied_and_non_target() -> None:
    ok = _tunnel(id=1, upstream_bytes_sent=100, upstream_bytes_received=900, negotiation_bytes_sent=60, negotiation_bytes_received=39)
    failed = _tunnel(id=2, status="failed:upstream_status", upstream_status=407,
                     upstream_bytes_sent=60, upstream_bytes_received=120, negotiation_bytes_sent=60, negotiation_bytes_received=120)
    denied = _tunnel(id=3, route="refused", status="denied", rule="deny-host:*.test")
    non_target = _tunnel(id=4, host="api.openai.com", route="non-target", upstream_bytes_sent=5000, upstream_bytes_received=5000)
    totals = _snapshot([ok, failed, denied, non_target]).totals()
    assert totals.with_connect == 1000 + 180
    assert totals.without_connect == (1000 - 99) + 0
    assert totals.bytes_sent == 160 and totals.bytes_received == 1020
    assert totals.tunnels == 2 and totals.failed_tunnels == 1 and totals.denied_tunnels == 1
    assert totals.with_connect_estimated is False


def test_snapshot_totals_direct_mode_flags_estimate() -> None:
    t = _tunnel(route="direct", upstream_bytes_sent=10, upstream_bytes_received=10,
                synthetic_negotiation_bytes_sent=63, synthetic_negotiation_bytes_received=39)
    assert _snapshot([t], mode="direct").totals().with_connect_estimated is True


# ---------------------------------------------------------------------------- round trips


def test_snapshot_round_trip() -> None:
    snap = _snapshot([_tunnel(upstream_bytes_sent=5)])
    snap.budget_events.append(BudgetEvent(ts=150.0, kind="tripped", counted_bytes=5, limit_bytes=4,
                                          top_hosts=[HostBytes("origin-a.test", 5)], closed_tunnels=1))
    snap.timeline.append(T.TimelinePoint(t=100.0, sent=5, received=0))
    snap.refused["origin_form"] = 2
    data = json.loads(json.dumps(snap.to_dict()))
    assert MeterSnapshot.from_dict(data) == snap


def test_attribution_round_trip() -> None:
    result = AttributionResult(
        hosts=[
            HostAttribution(
                host="origin-a.test", ports=[443], tunnels=1, failed_tunnels=0, denied_tunnels=0,
                bytes_sent=1, bytes_received=2, bytes_with_connect=3, bytes_without_connect=3, requests=1,
                buckets={"attributed": BucketTally(1, 3)}, allocated_by_type={"document": 3},
                paths=[T.PathBytes("/", 1, 3)],
            )
        ],
        buckets=T.Buckets(attributed=3, background={"optimization-guide": 0}),
        per_unit=T.PerUnitBytes(first_unit_bytes=1, rest_units=0, rest_bytes=0, rest_mean_bytes=None, resolution_s=0.25),
        success=T.SuccessInfo(count=1, basis="navigations", rate=1.0),
    )
    assert AttributionResult.from_dict(json.loads(json.dumps(result.to_dict()))) == result


def test_find_result_terminal_only_fields_never_serialised() -> None:
    result = FindResult(
        status="found", target_host="origin-a.test", target_path="/p", values_count=1,
        short_value_warning=False, challenge=ChallengeResult(blocked=False),
        target_url="https://origin-a.test/p?secret=1",
        starter_code=[StarterCode(1, "curl --compressed 'https://origin-a.test/p?secret=1'", "httpx.get(...)")],
        match_urls={"1": "https://origin-a.test/api?secret=1"},
    )
    text = json.dumps(result.to_dict())
    assert "secret" not in text and "starter_code" not in text and "match_urls" not in text
    back = FindResult.from_dict(json.loads(text))
    assert back.target_url == "" and back.starter_code == [] and back.match_urls == {}


def test_from_dict_rejects_wrong_types() -> None:
    good = _tunnel().to_dict()
    for key, value in (("port", True), ("port", "443"), ("kind", "socks"), ("opened_at", "x")):
        bad = dict(good, **{key: value})
        with pytest.raises(ValueError):
            TunnelRecord.from_dict(bad)
    missing = dict(good)
    del missing["host"]
    with pytest.raises(ValueError):
        TunnelRecord.from_dict(missing)
    assert TunnelRecord.from_dict(dict(good, unknown_future_key=1)) == _tunnel()


# ---------------------------------------------------------------------------- events


def _request(**kw) -> dict:
    base = {"v": 1, "kind": "request", "ts": 1.5, "source": "playwright", "host": "origin-a.test", "port": 443,
            "scheme": "https", "method": "GET", "resource_type": "document", "status": 200, "frame": "main",
            "is_navigation": True, "encoded_body_bytes": 100, "response_header_bytes": 20,
            "request_header_bytes": 30, "request_body_bytes": 0}
    base.update(kw)
    return base


def test_parse_request_event() -> None:
    ev = T.parse_event(_request(host="Origin-A.TEST.", path="/p?q=secret#frag", extra_future_field=1))
    assert isinstance(ev, RequestEvent)
    assert ev.host == "origin-a.test" and ev.path == "/p"
    assert ev.reported_bytes == 150 and ev.hit_network


def test_parse_attach_and_launch_events() -> None:
    assert isinstance(T.parse_event({"v": 1, "kind": "attach", "ts": 1, "source": "httpx"}), AttachEvent)
    launch = T.parse_event({"v": 1, "kind": "launch", "ts": 1, "source": "playwright", "browser": "weird"})
    assert isinstance(launch, LaunchEvent) and launch.browser == "other"


@pytest.mark.parametrize(
    "bad",
    [
        _request(v=2),
        _request(v=True),
        _request(kind="nope"),
        _request(source="curl"),
        _request(host="a b"),
        _request(host=""),
        _request(scheme="data"),
        _request(scheme="blob"),
        _request(method="get"),
        _request(resource_type="Doc Type"),
        _request(status=1000),
        _request(status=True),
        _request(encoded_body_bytes=-1),
        _request(encoded_body_bytes=True),
        _request(frame="top"),
        _request(failed="yes"),
        _request(ts=float("nan")),
        _request(port=0),
        _request(context="bad context!"),
        [],
    ],
)
def test_parse_event_rejects(bad: object) -> None:
    with pytest.raises(ValueError):
        T.parse_event(bad)


def test_event_line_round_trip() -> None:
    ev = T.parse_event(_request())
    line = T.event_to_json_line(ev)
    assert line.endswith("\n") and "\n" not in line[:-1]
    assert '"path"' not in line  # omitted when no path was kept
    assert len(line.encode()) <= T.MAX_EVENT_LINE_BYTES
    assert T.parse_event(json.loads(line)) == ev


# ---------------------------------------------------------------------------- sanitisers


def test_clean_host() -> None:
    assert T.clean_host("Example.COM.") == "example.com"
    assert T.clean_host("[::1]") == "::1"
    assert T.clean_host("b\u00fccher.de") == "xn--bcher-kva.de"
    for bad in (None, "", "a b", "evil<script>", "x" * 254, "fe80::1%en0", 5):
        assert T.clean_host(bad) is None


def test_clean_path_strips_query_and_escapes() -> None:
    assert T.clean_path("/a/b?token=secret#x") == "/a/b"
    assert T.clean_path("/p\u00e4 th") == "/p%C3%A4%20th"
    assert T.clean_path("relative") is None
    long = T.clean_path("/" + "a" * 2000)
    assert long is not None and len(long) == T.MAX_PATH_LEN and long.endswith("...")


@pytest.mark.parametrize(
    "char",
    [
        "\u200e",  # LEFT-TO-RIGHT MARK (Cf)
        "\u200f",  # RIGHT-TO-LEFT MARK (Cf)
        "\u061c",  # ARABIC LETTER MARK (Cf)
        "\u2028",  # LINE SEPARATOR (Zl)
        "\u2029",  # PARAGRAPH SEPARATOR (Zp)
        "\u200b",  # ZERO WIDTH SPACE (Cf)
        "\u2060",  # WORD JOINER (Cf)
        "\U000e0041",  # TAG LATIN CAPITAL LETTER A (Cf, astral)
        "\ud800",  # lone surrogate (Cs)
        "\u2066",  # isolate (already escaped before)
        "\x1b",
    ],
)
def test_safe_text_escapes_every_control_format_and_separator_character(char: str) -> None:
    """sec-15: categories Cc, Cf, Zl, Zp (and Cs) never reach a terminal raw."""
    for fn in (T.safe_text, T.safe_code):
        out = fn(f"a{char}b")
        assert char not in out and out.startswith("a\\") and out.endswith("b"), (fn.__name__, out)
        out.encode("utf-8")  # always printable, even for lone surrogates
    assert T.safe_text("a\U000e0041b") == "a\\U000e0041b"


def test_safe_text_keeps_ordinary_unicode() -> None:
    assert T.safe_text("caf\u00e9 \u65e5\u672c \u05e2\u05d1\u05e8\u05d9\u05ea \U0001f600") == (
        "caf\u00e9 \u65e5\u672c \u05e2\u05d1\u05e8\u05d9\u05ea \U0001f600"
    )
    assert T.safe_code("x\n\ty\u2028") == "x\n\ty\\u2028"


def test_safe_text_neutralises_terminal_and_bidi_tricks() -> None:
    out = T.safe_text("ok\x1b[31mred\u202eevil\r\nx\ufeff")
    assert "\x1b" not in out and "\u202e" not in out and "\r" not in out and "\n" not in out and "\ufeff" not in out
    assert "\\x1b" in out and "\\u202e" in out
    assert len(T.safe_text("x" * 1000)) == T.MAX_TEXT_LEN
    code = T.safe_code("a\nb\x1b")
    assert "\n" in code and "\x1b" not in code


def test_host_globs() -> None:
    assert T.host_glob_match("*.openai.azure.com", "x.openai.azure.com")
    assert T.host_glob_match("*.openai.azure.com", "a.b.openai.azure.com")
    assert not T.host_glob_match("*.openai.azure.com", "openai.azure.com")
    assert T.host_glob_match("s3.*.amazonaws.com", "s3.us-east-1.amazonaws.com")
    assert T.host_glob_match("API.OpenAI.com", "api.openai.com")
    assert not T.host_glob_match("api.openai.com", "api.openai.com.evil.test")
    assert not T.host_glob_match("exa?ple.com", "example.com")  # invalid globs never match
    with pytest.raises(ValueError):
        T.validate_host_glob("[a-z].com")


def test_ip_literal_globs_and_hosts_are_canonical() -> None:
    """sec3-5: an address has one spelling for rules and records; hostnames are untouched."""
    for spelling in ("1.2.3.04", "0x01020304", "16909060", "1.2.772", "::ffff:1.2.3.4", "[::FFFF:1.2.3.4]"):
        assert T.canonical_host(spelling) == "1.2.3.4", spelling
    assert T.canonical_host("2001:DB8:0::1") == "2001:db8::1"
    for name in ("example.com", "1password.com", "deadbeef", "123abc", "1e100.net"):
        assert T.canonical_host(name) == name
    assert T.validate_host_glob("1.2.3.04") == "1.2.3.4"
    assert T.validate_host_glob("2001:DB8:0::1") == "2001:db8::1"
    assert T.validate_host_glob("10.*") == "10.*"  # globs with a wildcard are kept as written
    assert T.validate_host_glob("1password.com") == "1password.com"
    assert T.host_glob_match("16909060", "1.2.3.4")
    assert str(T.ip_literal("127.1")) == "127.0.0.1" and T.ip_literal("example.com") is None


def test_embedded_ipv4_forms() -> None:
    """sec4-1: IPv6 spellings that stand for an IPv4 address expose it; others do not."""
    import ipaddress

    cases = {
        "::ffff:10.0.0.5": "10.0.0.5",  # IPv4-mapped
        "64:ff9b::a00:5": "10.0.0.5",  # NAT64 well-known prefix (RFC 6052)
        "64:ff9b::a9fe:a9fe": "169.254.169.254",
        "::ffff:0:a00:5": "10.0.0.5",  # IPv4-translated
        "::a9fe:a9fe": "169.254.169.254",  # IPv4-compatible (deprecated)
        "::": None,
        "::1": None,
        "2001:db8::1": None,
        "64:ff9b:1::a00:5": None,  # local-use NAT64 prefix: no fixed embedding position
    }
    for text, expected in cases.items():
        got = T.embedded_ipv4(ipaddress.ip_address(text))
        assert (str(got) if got is not None else None) == expected, text
    assert T.embedded_ipv4(ipaddress.ip_address("10.0.0.5")) is None
    assert T.embedded_ipv4(None) is None


def test_coverage_summary() -> None:
    cov = Coverage(inspected=41, skipped={"binary": 2, "over_cap": 1, "evicted": 0})
    assert cov.summary(False) == "not found in 41 inspected responses; skipped: 2 binary, 1 over the size cap"
    assert Coverage(inspected=1).summary(True) == "searched 1 inspected response; skipped: none"


# ---------------------------------------------------------------------------- catalogs


def _catalog_docs():
    background = {"version": "2026.09.23", "entries": [
        {"id": "optimization-guide", "hosts": ["optimizationguide-pa.googleapis.com"], "component": "c",
         "evidence": ["https://news.ycombinator.com/item?id=41593410"], "security_tradeoff": "s", "last_verified": "2026-09-23"}]}
    challenges = {"version": "2026.09.23", "attribution": "x", "vendors": [
        {"id": "cloudflare", "name": "Cloudflare", "docs": ["https://developers.cloudflare.com/"],
         "signals": [{"type": "header", "name": "cf-mitigated", "pattern": "^challenge$"},
                     {"type": "body", "pattern": "Just a moment\\.\\.\\.", "statuses": [403, 503]}]}]}
    direct = {"version": "2026.09.23", "entries": [
        {"id": "openai", "hosts": ["api.openai.com", "*.openai.azure.com"], "reason": "LLM API"}]}
    return background, challenges, direct


def test_catalogs_from_documents_and_lookups() -> None:
    cats = Catalogs.from_documents(*_catalog_docs())
    assert cats.versions() == {"background": "2026.09.23", "challenges": "2026.09.23", "direct": "2026.09.23"}
    assert cats.background_id_for("OptimizationGuide-PA.googleapis.com") == "optimization-guide"
    assert cats.background_id_for("origin-a.test") is None
    assert cats.direct_id_for("x.openai.azure.com") == "openai"
    assert cats.vendor("cloudflare").signals[1].statuses == (403, 503)
    assert Catalogs.from_dict(json.loads(json.dumps(cats.to_dict()))) == cats


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b, c, d: b.update(version=3),
        lambda b, c, d: b["entries"].append(dict(b["entries"][0])),
        lambda b, c, d: d["entries"][0]["hosts"].append("bad glob?"),
        lambda b, c, d: c["vendors"][0]["signals"].append({"type": "body", "pattern": "("}),
        lambda b, c, d: c["vendors"][0]["signals"].append({"type": "smell"}),
        lambda b, c, d: d["entries"][0].update(id="Bad Id"),
    ],
)
def test_catalogs_reject_invalid(mutate) -> None:
    b, c, d = _catalog_docs()
    mutate(b, c, d)
    with pytest.raises(Exception):
        Catalogs.from_documents(b, c, d)


# ---------------------------------------------------------------------------- schema structure

_SUBSET = {
    "$schema", "$id", "$ref", "$defs", "title", "description", "type", "const", "enum", "properties",
    "required", "additionalProperties", "propertyNames", "items", "maxItems", "minimum", "maximum",
    "minLength", "maxLength", "pattern",
}


def _schema() -> dict:
    return json.loads(resources.files("scrapescope.report").joinpath("schema.json").read_text(encoding="utf-8"))


def _walk(node, keywords: set[str], refs: set[str]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            keywords.add(key)
            if key == "$ref":
                refs.add(value)
            if key in ("properties", "$defs"):
                for sub in value.values():
                    _walk(sub, keywords, refs)
            elif isinstance(value, dict):
                _walk(value, keywords, refs)


def test_schema_uses_documented_subset_and_refs_resolve() -> None:
    schema = _schema()
    keywords: set[str] = set()
    refs: set[str] = set()
    _walk(schema, keywords, refs)
    assert keywords <= _SUBSET, keywords - _SUBSET
    for ref in refs:
        assert ref.startswith("#/$defs/") and ref.split("/")[-1] in schema["$defs"]


#: Top-level fields added in round 2 (docs-2): optional, so reports written before them still validate.
OPTIONAL_TOP_LEVEL = {"tunnel_failures", "accept_limit_errors"}


def test_schema_top_level_is_closed_and_complete() -> None:
    schema = _schema()
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(schema["properties"]) - OPTIONAL_TOP_LEVEL
    assert OPTIONAL_TOP_LEVEL <= set(schema["properties"])
    for forbidden in ("upstream", "upstream_host", "command_line", "argv", "env", "values", "cookies", "headers", "bodies"):
        assert forbidden not in schema["properties"]


@pytest.mark.parametrize("name", ["example-report.json", "example-report-find.json"])
def test_example_reports_match_schema_shape(name: str) -> None:
    schema = _schema()
    report = json.loads((ROOT / "docs" / "dev" / name).read_text(encoding="utf-8"))
    assert set(report) == set(schema["required"]) | OPTIONAL_TOP_LEVEL  # the builders always write them
    assert report["schema_version"] == T.REPORT_SCHEMA_VERSION
    totals = report["totals"]
    buckets = report["buckets"]
    assert (
        buckets["attributed"] + buckets["preconnect_idle"] + buckets["before_attach"] + buckets["unattributed"]
        + sum(buckets["background"].values())
    ) == totals["with_connect"]
    assert sum(h["bytes_with_connect"] for h in report["hosts"]) == totals["with_connect"]
    assert sum(t["allocated_bytes"] for t in report["types"]) == buckets["attributed"]


# ---------------------------------------------------------------------------- kept paths without session tokens (sec2-12)
@pytest.mark.parametrize(
    "raw,expected",
    [
        ("/cart;jsessionid=8F3A2B9C1D4E5F60718293A4B5C6D7E8?x=1", "/cart"),
        ("/a;x=1/b;v=2", "/a/b"),
        ("/api/v1/session/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.abcdefghijk/items", "/api/v1/session/{token}/items"),
        ("/orders/123e4567-e89b-12d3-a456-426614174000", "/orders/{token}"),
        ("/o/inv-123E4567-E89B-12D3-A456-426614174000.pdf", "/o/inv-{token}.pdf"),
        ("/reset/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b", "/reset/{token}"),
        ("/static/a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6.js", "/static/{token}.js"),
        ("/s/Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MEFCQ0RFRg/view", "/s/{token}/view"),
        # Ordinary paths stay as they are.
        ("/catalogue/a-light-in-the-attic_1000/index.html", "/catalogue/a-light-in-the-attic_1000/index.html"),
        ("/wiki/Samsung_Galaxy_S24_Ultra_512GB_Black_Edition", "/wiki/Samsung_Galaxy_S24_Ultra_512GB_Black_Edition"),
        ("/product/B08N5WRWNW", "/product/B08N5WRWNW"),
        ("/static/app.3f9a1c2b.js", "/static/app.3f9a1c2b.js"),
        ("/2026/09/23/summer-sale-2026-v2", "/2026/09/23/summer-sale-2026-v2"),
        ("/", "/"),
        ("/{token}/x", "/{token}/x"),  # idempotent
    ],
)
def test_clean_path_drops_path_parameters_and_token_segments(raw: str, expected: str) -> None:
    assert T.clean_path(raw) == expected
    assert T.clean_path(expected) == expected


def test_clean_path_token_placeholder_fits_the_report_schema() -> None:
    import re

    schema = json.loads(resources.files("scrapescope.report").joinpath("schema.json").read_text(encoding="utf-8"))
    pattern = schema["$defs"]["path"]["pattern"]
    cleaned = T.clean_path("/a/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.abcdefghijk;x=1/b")
    assert cleaned == "/a/" + T.PATH_TOKEN_PLACEHOLDER + "/b"
    assert re.search(pattern, cleaned)
