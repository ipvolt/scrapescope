"""Catalog tests: shape, evidence, required hosts, glob matching, loader, and
the challenge signals classified with the contract's semantics (section 8)."""

from __future__ import annotations

import copy
import fnmatch
import json
import os
import re
from pathlib import Path

import pytest

from scrapescope import catalog as cat
from scrapescope.catalog import (
    CatalogError,
    background_deny_rules,
    background_hosts_seen,
    catalog_versions,
    check_documents,
    direct_rules,
    load_catalogs,
    load_documents,
    match_host,
)
from scrapescope.types import Catalogs, host_glob_match
from tests.fixtures import BACKGROUND_HOSTS, site

ROOT = Path(__file__).resolve().parents[1]
CATALOG_DIR = ROOT / "src" / "scrapescope" / "catalog"


def _write_docs(tmp_path: Path, background: dict, challenges: dict, direct: dict) -> Path:
    for name, doc in (("background.json", background), ("challenges.json", challenges), ("direct.json", direct)):
        (tmp_path / name).write_text(json.dumps(doc), encoding="utf-8")
    return tmp_path


# ---------------------------------------------------------------------------- loading and shape


def test_packaged_catalogs_load_and_are_cached() -> None:
    first = load_catalogs()
    assert isinstance(first, Catalogs)
    assert load_catalogs() is first
    assert first.background and first.challenges and first.direct


def test_versions_are_reported_and_not_stubs() -> None:
    versions = catalog_versions()
    assert set(versions) == {"background", "challenges", "direct"}
    for value in versions.values():
        assert re.fullmatch(r"[0-9]{4}\.[0-9]{2}\.[0-9]{2}", value), value
    assert load_catalogs().versions() == versions


def test_packaged_documents_pass_strict_checks() -> None:
    assert check_documents(*load_documents()) == []


def test_files_are_ascii_json_objects() -> None:
    for name in ("background.json", "challenges.json", "direct.json"):
        raw = (CATALOG_DIR / name).read_bytes()
        assert raw.isascii(), name
        assert isinstance(json.loads(raw), dict)


def test_every_entry_cites_evidence_or_docs() -> None:
    background, challenges, direct = load_documents()
    for entry in background["entries"]:
        assert entry["evidence"], entry["id"]
        assert all(u.startswith("https://") for u in entry["evidence"])
        assert entry["security_tradeoff"].strip()
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", entry["last_verified"])
    for vendor in challenges["vendors"]:
        assert vendor["docs"], vendor["id"]
        assert all(u.startswith("https://") for u in vendor["docs"])
    for entry in direct["entries"]:
        assert entry["docs"], entry["id"]
        assert all(u.startswith("https://") for u in entry["docs"])


def test_ids_do_not_collide_across_background_and_direct() -> None:
    cats = load_catalogs()
    bg = {e.id for e in cats.background}
    di = {e.id for e in cats.direct}
    assert not bg & di


# ---------------------------------------------------------------------------- required content


def test_background_required_hosts_and_credits() -> None:
    cats = load_catalogs()
    background, _, _ = load_documents()
    assert cats.background_id_for("optimizationguide-pa.googleapis.com") == "optimization-guide"
    og = next(e for e in background["entries"] if e["id"] == "optimization-guide")
    assert "https://news.ycombinator.com/item?id=41593410" in og["evidence"]
    assert any("NodeMaven" in c and "2026-08-19" in c for c in og["credits"])
    for host in ("clients2.google.com", "update.googleapis.com", "edgedl.me.gvt1.com", "clients2.googleusercontent.com"):
        assert cats.background_entry_for(host) is not None, host
    assert cats.background_id_for("safebrowsing.googleapis.com") == "safe-browsing"


NODEMAVEN = ("https://github.com/nodemaven/proxy-benchmark/blob/main/NOTEBOOK.md"
             "#chrome-pays-its-vendor-43-mb-per-profile-and-the-pool-was-billed-for-it")
PUPPETEER_7042 = "https://github.com/puppeteer/puppeteer/issues/7042"


def _host_evidence(host: str) -> list[str]:
    background, _, _ = load_documents()
    cats = load_catalogs()
    entry = cats.background_entry_for(host)
    assert entry is not None, host
    raw = next(e for e in background["entries"] if e["id"] == entry.id)
    glob = next(g for g in raw["hosts"] if host_glob_match(g, host))
    return raw["host_evidence"][glob]


def test_background_evidence_names_each_host() -> None:
    # data-4: evidence must support exactly the hosts listed. Checked by hand on 2026-09-23: Puppeteer
    # #7042 names redirector.gvt1.com and dl.google.com; Google's Chrome update documentation names
    # update.googleapis.com, *.gvt1.com, dl.google.com, clients2.google.com and
    # clients2.googleusercontent.com/crx/blobs; Chromium source names update.googleapis.com
    # (component updater), clients2.google.com (extension updates, network time),
    # safebrowsing.googleapis.com (IsSafeBrowsingUrl) and optimizationguide-pa.googleapis.com.
    assert PUPPETEER_7042 in _host_evidence("redirector.gvt1.com")
    assert PUPPETEER_7042 in _host_evidence("dl.google.com")
    assert NODEMAVEN in _host_evidence("optimizationguide-pa.googleapis.com")
    assert NODEMAVEN in _host_evidence("r4---sn-4g5e6nzl.gvt1.com")  # NodeMaven's r*.gvt1.com CDN node
    for host in ("update.googleapis.com", "clients2.google.com", "clients2.googleusercontent.com",
                 "safebrowsing.googleapis.com"):
        assert all(PUPPETEER_7042 != url for url in _host_evidence(host)), host  # #7042 does not name these


def test_credits_cite_their_sources_and_every_host_has_evidence() -> None:
    background, challenges, direct = load_documents()
    og = next(e for e in background["entries"] if e["id"] == "optimization-guide")
    assert NODEMAVEN in og["evidence"]
    for entry in background["entries"]:
        assert set(entry["host_evidence"]) == set(entry["hosts"]), entry["id"]
        for urls in entry["host_evidence"].values():
            assert urls and set(urls) <= set(entry["evidence"]), entry["id"]
    broken = json.loads(json.dumps(background))
    broken["entries"][0]["host_evidence"] = {}
    assert any("host_evidence" in p for p in check_documents(broken, challenges, direct))


def test_every_fixture_background_host_is_catalogued() -> None:
    cats = load_catalogs()
    for host in BACKGROUND_HOSTS:
        assert cats.background_id_for(host) is not None, host


@pytest.mark.parametrize(
    "host",
    [
        "www.google.com",
        "accounts.google.com",
        "android.clients.google.com",
        "origin-a.test",
        "origin-b.test",
        "origin-c.test",
        "googleapis.com",
        "example.com",
    ],
)
def test_uncatalogued_hosts_are_never_background(host: str) -> None:
    assert load_catalogs().background_id_for(host) is None


def test_component_update_tradeoff_mentions_revocation_and_safe_browsing() -> None:
    entry = next(e for e in load_catalogs().background if e.id == "component-updater")
    text = entry.security_tradeoff.lower()
    assert "revocation" in text and "safe browsing" in text


@pytest.mark.parametrize(
    "host, expected",
    [
        ("api.openai.com", "openai"),
        ("api.anthropic.com", "anthropic"),
        ("generativelanguage.googleapis.com", "google-gemini"),
        ("myres.openai.azure.com", "azure-openai"),
        ("api.mistral.ai", "mistral"),
        ("api.groq.com", "groq"),
        ("api.together.ai", "together"),  # data-1: the current SDKs and docs use api.together.ai
        ("api.together.xyz", "together"),  # the deprecated v1 Python SDK
        ("openrouter.ai", "openrouter"),
    ],
)
def test_direct_required_hosts(host: str, expected: str) -> None:
    assert load_catalogs().direct_id_for(host) == expected


@pytest.mark.parametrize(
    "host",
    [
        # Cloud-storage buckets are often scrape targets; carrying them direct under
        # --env-all would expose the user's own IP address to the bucket owner (sec-1).
        "my-private-bucket.s3.amazonaws.com",
        "s3.eu-west-1.amazonaws.com",
        "bucket.s3.eu-west-1.amazonaws.com",
        "s3.amazonaws.com",
        "storage.googleapis.com",
        "acct.blob.core.windows.net",
        "acct.r2.cloudflarestorage.com",
    ],
)
def test_direct_catalog_never_carries_cloud_storage_hosts(host: str) -> None:
    assert load_catalogs().direct_id_for(host) is None
    assert all("storage" not in e.reason.lower() for e in load_catalogs().direct)


@pytest.mark.parametrize("host", ["openai.com", "origin-a.test", "www.anthropic.com", "blob.core.windows.net", "googleapis.com"])
def test_direct_does_not_overreach(host: str) -> None:
    assert load_catalogs().direct_id_for(host) is None


def test_direct_notes_state_the_openrouter_trade_off() -> None:
    # data-1: openrouter.ai serves the API and the website on one host; host rules cannot split them.
    direct = json.loads((CATALOG_DIR / "direct.json").read_text())
    assert "OpenRouter serves its API (openrouter.ai/api/v1) on the same host as its website" in direct["notes"]
    together = next(e for e in direct["entries"] if e["id"] == "together")
    assert together["docs"][0] == "https://docs.together.ai/docs/inference/openai-compatibility"


def _host_literal(glob: str) -> str:
    """The part of a host glob a documentation page must contain (``*.gvt1.com`` -> ``gvt1.com``)."""
    return glob.rsplit("*", 1)[-1].lstrip(".")


@pytest.mark.skipif(os.environ.get("SCRAPESCOPE_CHECK_CATALOG_URLS") != "1",
                    reason="release step (network): set SCRAPESCOPE_CHECK_CATALOG_URLS=1 to fetch every catalog URL")
@pytest.mark.timeout(600)
def test_catalog_urls_still_name_their_hosts() -> None:
    """data-1: every direct.json host is named by one of its entry's docs pages, and every background.json
    host glob by one of its host_evidence pages, as fetched today (docs move: Together's reference page
    stopped naming api.together.xyz). Opt-in, because tests never touch the network by default."""
    import urllib.request

    background, _challenges, direct = cat.load_documents()
    pages: dict[str, str] = {}

    def page(url: str) -> str:
        if url not in pages:
            request = urllib.request.Request(url, headers={"User-Agent": "scrapescope-catalog-check"})
            try:
                with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 (https only)
                    pages[url] = response.read(8 * 1024 * 1024).decode("utf-8", "replace").lower()
            except Exception as exc:  # reported below, per URL
                pages[url] = f"\0fetch failed: {type(exc).__name__}"
        return pages[url]

    problems = []
    checks = [(f"direct {e['id']}", host, e["docs"]) for e in direct["entries"] for host in e["hosts"]]
    checks += [(f"background {e['id']}", glob, urls) for e in background["entries"]
               for glob, urls in e["host_evidence"].items()]
    for where, glob, urls in checks:
        literal = _host_literal(glob).lower()
        if not any(literal in page(url) for url in urls):
            failed = [url for url in urls if page(url).startswith("\0")]
            problems.append(f"{where}: {glob} not named by {urls}" + (f" (fetch failed: {failed})" if failed else ""))
    assert problems == []


def test_challenge_vendors_present_and_attributed() -> None:
    cats = load_catalogs()
    ids = {v.id for v in cats.challenges}
    for required in ("cloudflare", "aws-waf", "datadome", "human", "akamai", "imperva", "kasada", "recaptcha", "hcaptcha", "turnstile"):
        assert required in ids
    _, challenges, _ = load_documents()
    assert "https://github.com/microlinkhq/is-antibot" in challenges["attribution"]
    assert "MIT" in challenges["attribution"]
    cf = cats.vendor("cloudflare")
    assert cf is not None
    assert "https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/" in cf.docs
    aws = cats.vendor("aws-waf")
    assert aws is not None
    assert "https://docs.aws.amazon.com/waf/latest/developerguide/waf-captcha-and-challenge-actions.html" in aws.docs
    for vendor in cats.challenges:
        if vendor.source and "is-antibot" in vendor.source:
            assert "MIT" in vendor.source


def test_notice_credits_is_antibot() -> None:
    notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
    assert "is-antibot" in notice and "MIT" in notice


def test_is_antibot_copyright_and_permission_notice_are_verbatim() -> None:
    """docs-6: the MIT licence asks for its copyright and permission notice with substantial portions."""
    notice = " ".join((ROOT / "NOTICE").read_text(encoding="utf-8").split())
    copyright_line = "Copyright \u00a9 2025 Microlink <hello@microlink.io> (https://microlink.io)"
    assert copyright_line in notice
    assert "Copyright (c) microlink.io" not in notice
    assert (
        "The above copyright notice and this permission notice shall be included in all copies or "
        "substantial portions of the Software."
    ) in notice
    assert copyright_line in load_documents()[1]["attribution"]


# ---------------------------------------------------------------------------- glob matching


@pytest.mark.parametrize(
    "pattern, host, expected",
    [
        ("*.example.com", "a.example.com", True),
        ("*.example.com", "a.b.example.com", True),
        ("*.example.com", "example.com", False),
        ("s3.*.amazonaws.com", "s3.us-east-1.amazonaws.com", True),
        ("s3.*.amazonaws.com", "s3.amazonaws.com", False),
        ("api.openai.com", "API.OpenAI.com.", True),
        ("api.openai.com", "api.openai.com.evil.test", False),
        ("*.openai.azure.com", "evil-openai.azure.com", False),
        ("a?c.test", "abc.test", False),
        ("[ab].test", "a.test", False),
        ("*.example.com", "<script>.example.com", False),
    ],
)
def test_match_host(pattern: str, host: str, expected: bool) -> None:
    assert match_host(pattern, host) is expected


def test_background_hosts_seen_groups_by_entry() -> None:
    cats = load_catalogs()
    seen = background_hosts_seen(cats, ["edgedl.me.gvt1.com", "origin-a.test", "update.googleapis.com", "update.googleapis.com"])
    assert seen == {"component-updater": ["edgedl.me.gvt1.com", "update.googleapis.com"]}


def test_rule_helpers_cover_every_glob_with_contract_labels() -> None:
    cats = load_catalogs()
    deny = background_deny_rules(cats)
    assert len(deny) == sum(len(e.hosts) for e in cats.background)
    assert all(r.label.startswith("catalog:background:") for r in deny)
    assert any(r.pattern == "optimizationguide-pa.googleapis.com" and r.label == "catalog:background:optimization-guide" for r in deny)
    direct = direct_rules(cats)
    assert len(direct) == sum(len(e.hosts) for e in cats.direct)
    assert any(r.pattern == "api.openai.com" and r.label == "openai" for r in direct)


# ---------------------------------------------------------------------------- override path and strict checks


def test_override_directory_loads_without_touching_the_cache(tmp_path: Path) -> None:
    background, challenges, direct = copy.deepcopy(load_documents())
    background["version"] = "9.9.9-test"
    background["entries"] = background["entries"][:1]
    d = _write_docs(tmp_path, background, challenges, direct)
    custom = load_catalogs(d)
    assert custom.background_version == "9.9.9-test"
    assert len(custom.background) == 1
    assert load_catalogs().background_version != "9.9.9-test"


@pytest.mark.parametrize(
    "mutate, fragment",
    [
        (lambda b, c, d: b["entries"][0].update(evidence=[]), "evidence"),
        (lambda b, c, d: b["entries"][0].update(evidence=["http://insecure.example/"]), "evidence"),
        (lambda b, c, d: b["entries"][0].update(last_verified="yesterday"), "last_verified"),
        (lambda b, c, d: b["entries"][0].update(security_tradeoff=" "), "security_tradeoff"),
        (lambda b, c, d: c["vendors"][0].update(docs=[]), "docs"),
        (lambda b, c, d: c["vendors"][0]["signals"].append({"type": "header", "name": None, "statuses": [], "strength": "vendor"}), "header"),
        (lambda b, c, d: c["vendors"][0]["signals"].append({"type": "body", "pattern": None, "statuses": [], "strength": "vendor"}), "pattern"),
        (lambda b, c, d: c["vendors"][0]["signals"].append({"type": "status", "statuses": [], "strength": "vendor"}), "statuses"),
        (lambda b, c, d: c["vendors"][0]["signals"].append({"type": "header", "name": "x", "statuses": [99], "strength": "vendor"}), "status"),
        (lambda b, c, d: c["vendors"][0].update(signals=[s for s in c["vendors"][0]["signals"] if s["strength"] == "vendor"]), "challenge-strength"),
        (lambda b, c, d: d["entries"][0].update(docs=[]), "docs"),
        (lambda b, c, d: d["entries"][0].update(id=b["entries"][0]["id"]), "both"),
    ],
)
def test_strict_checks_reject_bad_documents(tmp_path: Path, mutate, fragment: str) -> None:
    docs = copy.deepcopy(load_documents())
    mutate(*docs)
    assert any(fragment in p for p in check_documents(*docs))
    with pytest.raises(CatalogError):
        load_catalogs(_write_docs(tmp_path, *docs))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b, c, d: b["entries"].append(dict(b["entries"][0])),  # duplicate id
        lambda b, c, d: b["entries"][0].update(hosts=["bad host"]),
        lambda b, c, d: c["vendors"][0]["signals"][0].update(pattern="(unclosed"),
        lambda b, c, d: d.update(version=""),
    ],
)
def test_structural_errors_raise_catalog_error(tmp_path: Path, mutate) -> None:
    docs = copy.deepcopy(load_documents())
    mutate(*docs)
    with pytest.raises(CatalogError):
        load_catalogs(_write_docs(tmp_path, *docs))


def test_bad_json_raises_catalog_error_without_content(tmp_path: Path) -> None:
    b, c, d = load_documents()
    directory = _write_docs(tmp_path, b, c, d)
    (directory / "direct.json").write_text("{not json sentinel-XYZ", encoding="utf-8")
    with pytest.raises(CatalogError) as info:
        load_catalogs(directory)
    assert "sentinel-XYZ" not in str(info.value)


def test_cache_is_module_level_and_resettable() -> None:
    cat._packaged.cache_clear()
    assert load_catalogs() is load_catalogs()


# ---------------------------------------------------------------------------- challenge signals (reference classifier)


def _classify(status: int, headers: list[tuple[str, str]], body: str, cookies: list[tuple[str, str]] = ()):
    """Reference implementation of the section 8 signal semantics (tests only)."""
    blocked_by: list[str] = []
    vendors: list[str] = []
    for vendor in load_catalogs().challenges:
        for sig in vendor.signals:
            if sig.statuses and status not in sig.statuses:
                continue
            if sig.type == "header":
                values = [v for n, v in headers if n.lower() == sig.name]
                fired = bool(values) and (sig.pattern is None or any(re.search(sig.pattern, v, re.I) for v in values))
            elif sig.type == "cookie":
                fired = any(
                    fnmatch.fnmatchcase(n, sig.name) and (sig.pattern is None or re.search(sig.pattern, v, re.I))
                    for n, v in cookies
                )
            elif sig.type == "status":
                fired = status in sig.statuses
            else:
                fired = re.search(sig.pattern, body[:65536], re.I) is not None
            if fired:
                (blocked_by if sig.strength == "challenge" else vendors).append(vendor.id)
    return bool(blocked_by), (blocked_by or vendors or [None])[0]


ORDINARY_HTML = "<!doctype html><html><head><title>Shop</title></head><body><h1>Widget</h1></body></html>"


@pytest.mark.parametrize(
    "status, headers, body, cookies, blocked, vendor",
    [
        # Cloudflare: the documented header (every challenge page carries it), the challenge options
        # object (is-antibot) on an error status. Page titles alone are not sourced signals.
        (403, [("cf-mitigated", "challenge"), ("server", "cloudflare")], site.CF_CHALLENGE_HTML, [], True, "cloudflare"),
        (503, [("server", "cloudflare")], "<script>window._cf_chl_opt={}</script>", [], True, "cloudflare"),
        (503, [("server", "cloudflare")], "<html><head><title>Just a moment...</title></head></html>", [], False, None),
        (403, [], "<title>Attention Required! | Cloudflare</title>", [], False, None),
        # An ordinary Cloudflare-fronted page with bot-management cookie and JS detection script.
        (200, [("server", "cloudflare"), ("cf-ray", "8f-AMS")],
         '<script src="/cdn-cgi/challenge-platform/scripts/jsd/main.js"></script>' + ORDINARY_HTML,
         [("__cf_bm", "x")], False, "cloudflare"),
        # A 200 page that merely mentions the phrase.
        (200, [], "<p>Just a moment... we are loading your cart</p>", [], False, None),
        # AWS WAF, per the AWS documentation and the fixture pages.
        (202, [("x-amzn-waf-action", "challenge")], site.AWS_CHALLENGE_HTML, [], True, "aws-waf"),
        (405, [("x-amzn-waf-action", "captcha")], site.AWS_CHALLENGE_HTML, [], True, "aws-waf"),
        (200, [("x-amzn-waf-action", "challenge")], ORDINARY_HTML, [], False, "aws-waf"),
        (200, [], ORDINARY_HTML, [("aws-waf-token", "t")], False, "aws-waf"),
        # Vercel.
        (429, [("x-vercel-mitigated", "challenge")], ORDINARY_HTML, [], True, "vercel"),
        # DataDome.
        (403, [("x-datadome", "protected")], "<script src=\"https://ct.captcha-delivery.com/c.js\"></script>", [], True, "datadome"),
        (200, [], ORDINARY_HTML, [("datadome", "abc")], False, "datadome"),
        # HUMAN / PerimeterX: is-antibot's block-page rule needs the app id and a captcha marker.
        (403, [], "<script>window._pxAppId='PX1';</script><div id=\"px-captcha\"></div>", [], True, "human"),
        # find3-9: ... and an error status; a 200 tutorial quoting both (escaped or not) is not blocked.
        (200, [], "<pre>&lt;script&gt;window._pxAppId = \"PXabc123\";&lt;/script&gt; &lt;div id=\"px-captcha\"&gt;</pre>",
         [], False, "human"),
        (200, [], "<script>window._pxAppId='PX1';</script><div id=\"px-captcha\"></div>", [], False, "human"),
        (200, [], "<p>How we met the px-captcha wall</p>", [], False, None),
        (200, [], "<script>window._pxAppId='PXabc';</script>" + ORDINARY_HTML, [("_px3", "v")], False, "human"),
        # Akamai: the bot-manager cookie on an error status (is-antibot).
        (403, [("server", "AkamaiGHost")], "<H1>Access Denied</H1>", [("_abck", "x")], True, "akamai"),
        # find3-8: Akamai's deny page with its edge reference string (Akamai's documentation), entity-escaped
        # as served, on a 403 only; a 200 support article quoting a reference is not blocked.
        (403, [("server", "AkamaiGHost")],
         "<H1>Access Denied</H1> Reference&#32;&#35;18&#46;4f2e1a17&#46;1790000000&#46;1a2b3c", [], True, "akamai"),
        (403, [], "<p>Reference #9.6f64d440.1318965461.2f2b078</p>", [], True, "akamai"),
        (200, [], "<p>Seeing Access Denied, Reference #9.6f64d440.1318965461.2f2b078? Clear cookies.</p>", [], False, None),
        (403, [], "<h1>Access Denied</h1><p>Reference #12</p>", [], False, None),
        # find3-8: Cloudflare's own 1xxx block pages (Error 1020 "Access denied"), 403 only.
        (403, [("server", "cloudflare"), ("cf-ray", "8f-AMS")],
         '<title>Access denied | example.com used Cloudflare to restrict access</title>'
         '<h1><span class="cf-error-type">Error</span> <span class="cf-error-code">1020</span></h1>', [], True,
         "cloudflare"),
        (200, [], "<p>How to fix Cloudflare Error 1020: Access denied</p>", [], False, None),
        (403, [], "<h1>Access denied</h1><p>Error 403</p>", [], False, None),
        (200, [], "<p>The page used /_sec/cp_challenge/ and a sec-if-cpt-container div.</p>", [], False, None),
        (200, [], ORDINARY_HTML, [("_abck", "x"), ("bm_sz", "y")], False, "akamai"),
        # Imperva: its headers on an error status block; the "incident ID" text alone does not.
        (403, [("x-iinfo", "1-2-3")], "<html>Request unsuccessful. Incapsula incident ID: 123-456</html>", [], True, "imperva"),
        (200, [], "<p>Seeing 'Request unsuccessful. Incapsula incident ID'? Here is why.</p>", [], False, None),
        (200, [("x-cdn", "Imperva")], ORDINARY_HTML, [("visid_incap_123", "v"), ("incap_ses_1_2", "s")], False, "imperva"),
        # Kasada.
        (429, [("x-kasada-challenge", "1")], "<script src=\"/ips.js\"></script>", [], True, "kasada"),
        (200, [("x-kasada", "1")], ORDINARY_HTML, [], False, "kasada"),
        # CAPTCHA widgets: a 200 login form is not a challenge; a 403 page embedding one is.
        (200, [], '<script src="https://www.google.com/recaptcha/api.js"></script><div class="g-recaptcha"></div>', [], False, "recaptcha"),
        # find3-9: a 200 contact form with id="captcha-form" and a reCAPTCHA widget is not a challenge; Google's
        # /sorry/ page (429) is.
        (200, [], '<form id="captcha-form" action="/contact"><div class="g-recaptcha" data-sitekey="k"></div></form>',
         [], False, "recaptcha"),
        (429, [], '<form id="captcha-form" action="index"><div class="g-recaptcha" data-sitekey="k"></div></form>',
         [], True, "recaptcha"),
        (403, [], '<script src="https://www.google.com/recaptcha/api.js"></script><div class="g-recaptcha"></div>', [], True, "recaptcha"),
        (503, [], '<h1>Down for maintenance</h1><script src="https://www.google.com/recaptcha/api.js"></script>', [], False, "recaptcha"),
        (200, [], '<script src="https://js.hcaptcha.com/1/api.js"></script>', [], False, "hcaptcha"),
        (429, [], '<script src="https://hcaptcha.com/1/api.js"></script>', [], True, "hcaptcha"),
        (200, [], '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>', [], False, "turnstile"),
        # Nothing at all.
        (200, [("server", "nginx")], ORDINARY_HTML, [("session", "x")], False, None),
        (404, [], "<h1>Not found</h1>", [], False, None),
        (429, [("retry-after", "5")], "Too many requests", [], False, None),
    ],
)
def test_challenge_signals_classify(status, headers, body, cookies, blocked, vendor) -> None:
    assert _classify(status, headers, body, cookies) == (blocked, vendor)


def test_fixture_product_page_is_not_a_challenge() -> None:
    blocked, _ = _classify(200, [("server", "fixture")], site.product_html("https"))
    assert blocked is False


def test_signal_labels_fit_the_report_schema() -> None:
    label_re = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}:(header|cookie|status|body):[\x21-\x7e]{1,128}")
    for vendor in load_catalogs().challenges:
        for i, sig in enumerate(vendor.signals):
            label = f"{vendor.id}:{sig.type}:{sig.name if sig.name is not None else i}"
            assert label_re.fullmatch(label), label
        assert re.fullmatch(r"[\x20-\x7e]{1,64}", vendor.name)


def test_every_challenge_signal_cites_its_own_sources() -> None:
    # data-5: provenance per signal; is-antibot only where its providers.json has the rule.
    _, challenges, _ = load_documents()
    ia = "https://github.com/microlinkhq/is-antibot/blob/HEAD/src/providers.json"
    for vendor in challenges["vendors"]:
        for sig in vendor["signals"]:
            assert sig["sources"] and all(u.startswith("https://") for u in sig["sources"]), (vendor["id"], sig)
        uses_ia = any(ia in sig["sources"] for sig in vendor["signals"])
        assert ("is-antibot" in (vendor.get("source") or "")) == uses_ia, vendor["id"]
    problems = check_documents(*load_documents()[:1], {**challenges, "vendors": [
        {**challenges["vendors"][0], "signals": [{**challenges["vendors"][0]["signals"][0], "sources": []}]}
    ]}, load_documents()[2])
    assert any("source URL" in p for p in problems)


IS_ANTIBOT_MARKERS = {
    # (vendor, signal name) -> a literal that is-antibot's providers.json contains for that rule.
    ("cloudflare", "challenge-options"): "_cf_chl_opt",
    ("vercel", "x-vercel-mitigated"): "x-vercel-mitigated",
    ("datadome", "captcha-delivery"): "captcha-delivery.com",
    ("akamai", "_abck"): "_abck=",
    ("akamai", "sensor-data"): "bmak.sensor_data",
    ("imperva", "x-iinfo"): "x-iinfo",
    ("imperva", "reese84"): "reese84=",
    ("kasada", "x-kasada-challenge"): "x-kasada-challenge",
    ("human", "px-action"): "_pxAction",
}


def test_is_antibot_attributions_name_rules_it_has() -> None:
    # The literals above were checked against is-antibot's providers.json (2026-09-23); a signal
    # attributed to it must be one of the rules listed here or a pattern built from them.
    _, challenges, _ = load_documents()
    ia = "https://github.com/microlinkhq/is-antibot/blob/HEAD/src/providers.json"
    names = {(v["id"], s["name"]) for v in challenges["vendors"] for s in v["signals"] if ia in s["sources"]}
    for key in IS_ANTIBOT_MARKERS:
        assert key in names, key
    # ("akamai", "edge-reference") came back in round 3 (find3-8), sourced from Akamai's own documentation of
    # the reference string instead of being attributed to is-antibot, which does not have it.
    removed = {("kasada", "x-kpsdk-ct"), ("akamai", "sec-cpt"),
               ("imperva", "incident-id"), ("human", "px-captcha-cdn"), ("akamai", "ak_bmsc"), ("akamai", "bm_sz")}
    for vendor in challenges["vendors"]:
        for sig in vendor["signals"]:
            if (vendor["id"], sig["name"]) == ("akamai", "edge-reference"):
                assert ia not in sig["sources"] and sig["statuses"] == [403], sig
    all_names = {(v["id"], s["name"]) for v in challenges["vendors"] for s in v["signals"]}
    assert not removed & all_names
