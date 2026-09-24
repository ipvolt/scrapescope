"""classify_challenge: signal semantics (contracts.md section 8) against a test catalog and the shipped one."""

from __future__ import annotations

import pytest

from scrapescope.find import classify_challenge
from scrapescope.find.challenge import BODY_WINDOW_CHARS, parse_set_cookie_names
from scrapescope.types import Catalogs
from tests.fixtures import site
from tests.test_find_support import TEST_CHALLENGES, make_test_catalogs, shipped_catalogs_or_none, validate_subset, load_report_schema

CF_HEADERS = [("cf-mitigated", "challenge"), ("Server", "cloudflare"), ("Content-Type", "text/html; charset=UTF-8")]


@pytest.fixture(scope="module")
def cat() -> Catalogs:
    return make_test_catalogs()


def _schema_errors(result) -> list[str]:
    schema = load_report_schema()
    return validate_subset(result.to_dict(), schema["$defs"]["challenge"], schema)


def test_cloudflare_header_blocks(cat: Catalogs) -> None:
    result = classify_challenge(403, CF_HEADERS, site.CF_CHALLENGE_HTML, cat)
    assert result.blocked is True
    assert result.vendor_id == "cloudflare"
    assert result.vendor_name == "Cloudflare"
    assert result.status == 403
    assert "cloudflare:header:cf-mitigated" in result.signals
    assert "cloudflare:body:just-a-moment" in result.signals
    # a body signal without a name is labelled by its index
    assert "cloudflare:body:2" in result.signals
    assert _schema_errors(result) == []


def test_header_name_is_case_insensitive_and_pattern_applies(cat: Catalogs) -> None:
    assert classify_challenge(403, [("CF-Mitigated", "Challenge")], None, cat).blocked
    # the header without the challenge value does not block
    assert not classify_challenge(200, [("cf-mitigated", "managed")], None, cat).blocked


def test_body_signal_needs_its_statuses(cat: Catalogs) -> None:
    # "Just a moment..." is restricted to 403/503: a 200 article quoting it is not a challenge
    result = classify_challenge(200, [], site.CF_CHALLENGE_HTML, cat)
    assert result.blocked is False
    # the vendor-strength challenge-platform script still names the vendor
    assert result.vendor_id == "cloudflare"
    assert result.signals == ["cloudflare:body:2"]
    blocked = classify_challenge(503, [], site.CF_CHALLENGE_HTML, cat)
    assert blocked.blocked and blocked.vendor_id == "cloudflare"


def test_body_window_is_64_kib(cat: Catalogs) -> None:
    padding = "x" * BODY_WINDOW_CHARS
    late = padding + "<title>Just a moment...</title>"
    assert not classify_challenge(403, [], late, cat).blocked
    early = "<title>Just a moment...</title>" + padding
    assert classify_challenge(403, [], early, cat).blocked


@pytest.mark.parametrize(
    ("status", "action", "blocked"),
    [(202, "challenge", True), (405, "captcha", True), (200, "challenge", False), (202, "captcha", False), (403, "block", False)],
)
def test_aws_waf_action_with_status(cat: Catalogs, status: int, action: str, blocked: bool) -> None:
    result = classify_challenge(status, [("x-amzn-waf-action", action)], site.AWS_CHALLENGE_HTML, cat)
    assert result.blocked is blocked
    assert result.vendor_id == ("aws-waf" if blocked else None)


def test_cookie_signal_uses_set_cookie_names_and_statuses(cat: Catalogs) -> None:
    headers = [("Set-Cookie", "datadome=abc123; Path=/; Secure"), ("Set-Cookie", "other=1")]
    assert classify_challenge(403, headers, "", cat).vendor_id == "datadome"
    assert classify_challenge(403, headers, "", cat).blocked
    # the same cookie on a 200 page only names nobody (statuses restrict it)
    assert not classify_challenge(200, headers, "", cat).blocked
    # a cookie value never matters without a pattern, and names are matched exactly (case-sensitive)
    assert not classify_challenge(403, [("Set-Cookie", "DataDome=1")], "", cat).blocked


def test_vendor_signal_only_names_vendor(cat: Catalogs) -> None:
    result = classify_challenge(200, [("Set-Cookie", "__cf_bm=zzz; HttpOnly")], "<html>ok</html>", cat)
    assert result.blocked is False
    assert result.vendor_id == "cloudflare"
    assert result.signals == ["cloudflare:cookie:__cf_bm"]


def test_challenge_vendor_wins_over_earlier_vendor_signal(cat: Catalogs) -> None:
    headers = [("x-datadome", "protected"), ("x-amzn-waf-action", "challenge"), ("Set-Cookie", "__cf_bm=1")]
    result = classify_challenge(202, headers, "", cat)
    assert result.blocked is True
    assert result.vendor_id == "aws-waf"  # first firing *challenge* signal
    assert result.signals[0] == "cloudflare:cookie:__cf_bm"  # signals keep catalog order


def test_status_signal(cat: Catalogs) -> None:
    result = classify_challenge(418, [], None, cat)
    assert result.blocked and result.vendor_id == "teapot"
    assert result.signals == ["teapot:status:0"]
    assert not classify_challenge(200, [], None, cat).blocked


def test_ordinary_pages_are_not_blocked(cat: Catalogs) -> None:
    for status, body in [(200, site.product_html("https")), (404, "not found"), (None, None), (500, "")]:
        result = classify_challenge(status, [("Content-Type", "text/html")], body, cat)
        assert result.blocked is False
        assert result.vendor_id is None
        assert result.signals == []


def test_signals_never_contain_page_content(cat: Catalogs) -> None:
    hostile = "<title>Just a moment...</title><script>alert('\u202e')</script>"
    result = classify_challenge(403, [("cf-mitigated", "challenge\u202e\x1b[31m")], hostile, cat)
    joined = " ".join(result.signals)
    assert "alert" not in joined and "\u202e" not in joined and "\x1b" not in joined
    assert _schema_errors(result) == []


def test_unusable_signal_names_fall_back_to_index() -> None:
    doc = {
        "version": "t",
        "vendors": [
            {
                "id": "weird",
                "name": "Weird \u202e Vendor with a very long name that goes on and on and on and on and on",
                "signals": [{"type": "header", "name": "x-has space", "pattern": None, "statuses": [], "strength": "challenge"}],
                "docs": [],
            }
        ],
    }
    cat = Catalogs.from_documents({"version": "t", "entries": []}, doc, {"version": "t", "entries": []})
    result = classify_challenge(200, [("x-has space", "1")], None, cat)
    assert result.blocked
    assert result.signals == ["weird:header:0"]
    assert result.vendor_name is not None and "\u202e" not in result.vendor_name and len(result.vendor_name) <= 64
    assert _schema_errors(result) == []


def test_parse_set_cookie_names() -> None:
    values = ["a=1; Path=/", "b=two=2; HttpOnly\nc=3", "=novalue", "junk", " d = 4 ;x"]
    assert parse_set_cookie_names(values) == [("a", "1"), ("b", "two=2"), ("c", "3"), ("d", "4")]


def test_test_catalog_is_valid() -> None:
    cat = make_test_catalogs()
    assert cat.challenges_version == TEST_CHALLENGES["version"]
    assert [v.id for v in cat.challenges] == ["cloudflare", "aws-waf", "datadome", "teapot"]


# --------------------------------------------------------------------------- shipped catalog


@pytest.fixture(scope="module")
def shipped() -> Catalogs:
    cat = shipped_catalogs_or_none()
    if cat is None:
        pytest.skip("challenges.json is still the architect stub")
    return cat


@pytest.mark.parametrize(
    ("status", "headers", "body", "vendor"),
    [
        (403, CF_HEADERS, site.CF_CHALLENGE_HTML, "cloudflare"),
        (202, [("x-amzn-waf-action", "challenge")], site.AWS_CHALLENGE_HTML, "aws-waf"),
        (405, [("x-amzn-waf-action", "captcha")], site.AWS_CHALLENGE_HTML, "aws-waf"),
    ],
)
def test_shipped_catalog_classifies_fixture_challenges(shipped: Catalogs, status, headers, body, vendor) -> None:
    result = classify_challenge(status, headers, body, shipped)
    assert result.blocked is True
    assert result.vendor_id == vendor
    assert _schema_errors(result) == []


def test_shipped_catalog_leaves_the_product_page_alone(shipped: Catalogs) -> None:
    headers = [("Content-Type", "text/html; charset=utf-8"), ("Set-Cookie", "ss_session=x; Path=/api/session-product.json")]
    result = classify_challenge(200, headers, site.product_html("https"), shipped)
    assert result.blocked is False


# --------------------------------------------------------------------------- shipped catalog: ordinary pages (find-6)

_ARTICLE = "<!doctype html><html><head><title>{title}</title></head><body><article><p>{text}</p>{pad}</article></body></html>"


def _article(title: str, text: str) -> str:
    return _ARTICLE.format(title=title, text=text, pad="<p>" + "Lorem ipsum dolor sit amet. " * 400 + "</p>")


@pytest.mark.parametrize(
    ("name", "status", "headers", "body"),
    [
        ("incapsula-blog", 200, [("Server", "nginx")],
         _article("Scraping behind Imperva", "If you see 'Request unsuccessful. Incapsula incident ID: 0-123', "
                  "the iframe id=\"main-iframe\" loads /_Incapsula_Resource?SWUDNSAI=31")),
        ("akamai-blog", 200, [("Server", "nginx")],
         _article("Akamai sec-cpt explained", "The interstitial has a sec-if-cpt-container div and posts to "
                  "/_sec/cp_challenge/verify; the edge answers with Reference #18.4f2e1a17.1790000000.1a2b3c")),
        ("kasada-forum", 200, [], _article("Kasada", "the x-kpsdk-ct header and window.KPSDK")),
        ("cloudflare-tutorial", 200, [], _article("Just a moment...", "<code>&lt;title&gt;Attention Required! | "
                                                  "Cloudflare&lt;/title&gt;</code> and _cf_chl_opt")),
        ("turnstile-login", 200, [],
         '<form><script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>'
         '<div class="cf-turnstile" data-sitekey="x"></div><button>Sign in</button></form>'),
        ("recaptcha-login", 200, [],
         '<form><script src="https://www.google.com/recaptcha/api.js"></script>'
         '<div class="g-recaptcha" data-sitekey="x"></div></form>'),
        ("hcaptcha-login", 200, [],
         '<form><script src="https://js.hcaptcha.com/1/api.js"></script><div class="h-captcha" data-sitekey="x"></div></form>'),
        ("maintenance-503-recaptcha", 503, [("Retry-After", "120")],
         '<h1>Back soon</h1><p>Contact us:</p><script src="https://www.google.com/recaptcha/api.js"></script>'
         '<div class="g-recaptcha" data-sitekey="x"></div>'),
        # find3-9: a 200 contact form with id="captcha-form", and a 200 tutorial quoting HUMAN's markup
        ("recaptcha-captcha-form-200", 200, [],
         '<form id="captcha-form" action="/contact"><input name="email"><div class="g-recaptcha" '
         'data-sitekey="x"></div><button>Send</button></form><p>Widget Pro costs 49.00</p>'),
        ("human-tutorial-200", 200, [],
         _article("Scraping behind HUMAN", "<pre>&lt;script&gt;window._pxAppId = \"PXabc123\";&lt;/script&gt; "
                  "&lt;div id=\"px-captcha\"&gt;</pre>")),
        ("human-tutorial-unescaped-200", 200, [],
         _article("HUMAN", '<script>window._pxAppId = "PXabc123";</script><div id="px-captcha"></div>')),
        # find3-8: the new hard-block rules need a 403
        ("cloudflare-1020-article-200", 200, [], _article("Error 1020", "Error 1020: Access denied, explained")),
    ],
    ids=lambda value: value if isinstance(value, str) and len(value) < 40 and "<" not in value else "",
)
def test_shipped_catalog_does_not_block_pages_that_only_mention_or_embed_vendors(
    shipped: Catalogs, name: str, status: int, headers: list[tuple[str, str]], body: str
) -> None:
    result = classify_challenge(status, headers, body, shipped)
    assert result.blocked is False, (name, result.signals)


@pytest.mark.parametrize(
    ("status", "headers", "body", "vendor"),
    [
        (403, [("X-Iinfo", "12-345-0 0NNN RT(1790000000 1) q(0 -1 -1 -1) r(0 -1)")], "<html>Request unsuccessful.</html>",
         "imperva"),
        (403, [("Set-Cookie", "_abck=abc; Path=/")], "<H1>Access Denied</H1>", "akamai"),
        (429, [("x-kasada-challenge", "1")], "", "kasada"),
        (403, [], '<div class="g-recaptcha" data-sitekey="x"></div>', "recaptcha"),
        # round 2 (find-r2-6): the verify page is a challenge at a challenge status; the same
        # markup on a 200 page can be a contact form (see the xfail cases below)
        (403, [], '<div class="cf-turnstile"></div><h1>Verify you are human</h1>', "turnstile"),
        # find3-9: the status-restricted rules still fire at a challenge status
        (429, [], '<form id="captcha-form"><div class="g-recaptcha" data-sitekey="x"></div></form>', "recaptcha"),
        (403, [], '<script>window._pxAppId = "PXabc123";</script><div id="px-captcha"></div>', "human"),
        # find3-8: hard WAF block pages (sourced from the vendors' documentation)
        (403, [("Server", "cloudflare")],
         '<title>Access denied | shop.example used Cloudflare to restrict access</title>'
         '<h1><span class="cf-error-type" data-translate="error">Error</span><span class="cf-error-code">1020</span></h1>',
         "cloudflare"),
        (403, [("Server", "AkamaiGHost")],
         "<HTML><HEAD><TITLE>Access Denied</TITLE></HEAD><BODY><H1>Access Denied</H1>You don't have permission. "
         "<P>Reference&#32;&#35;18&#46;4f2e1a17&#46;1790000000&#46;1a2b3c</BODY></HTML>", "akamai"),
    ],
    ids=["imperva-403", "akamai-403-abck", "kasada-429", "recaptcha-403", "turnstile-verify-403",
         "recaptcha-sorry-429", "human-block-403", "cloudflare-1020-403", "akamai-access-denied-403"],
)
def test_shipped_catalog_still_blocks_sourced_challenge_pages(shipped: Catalogs, status, headers, body, vendor) -> None:
    result = classify_challenge(status, headers, body, shipped)
    assert result.blocked is True and result.vendor_id == vendor, result.signals


# --------------------------------------------------------------------------- round 2: find-r2-6


@pytest.mark.parametrize(
    ("status", "headers", "body"),
    [
        (200, [], '<form><label>Verify you are human</label><div class="cf-turnstile" data-sitekey="x"></div></form>'
                  "<p>Widget Pro costs 49.00</p>"),
        (200, [], '<form><p>Verify you are human</p><div class="h-captcha" data-sitekey="x"></div></form>'),
        (200, [], "<article><h1>Just a moment...</h1><pre><code>&lt;div class=&quot;cf-turnstile&quot;&gt;"
                  '</code></pre><div class="cf-turnstile"></div></article>'),
        (503, [("Set-Cookie", "visid_incap_123=abc; path=/"), ("Set-Cookie", "incap_ses_1_2=x")], "<h1>Maintenance</h1>"),
        (503, [("Set-Cookie", "datadome=abc")], "<h1>Maintenance</h1>"),
        (503, [("Set-Cookie", "_abck=abc")], "<h1>Maintenance</h1>"),
        (503, [("Set-Cookie", "_pxhd=abc")], "<h1>Maintenance</h1>"),
        # Imperva also sends X-Iinfo and X-CDN on every response, so a real maintenance page carries them
        (503, [("X-Iinfo", "12-345-0 0NNN RT(1790000000 1) q(0 -1 -1 -1) r(0 -1)"), ("X-CDN", "Incapsula"),
               ("Set-Cookie", "visid_incap_123=abc; path=/")], "<h1>Maintenance</h1>"),
    ],
    ids=["turnstile-contact-200", "hcaptcha-signup-200", "turnstile-tutorial-200", "imperva-503-cookies",
         "datadome-503-cookie", "akamai-503-cookie", "human-503-cookie", "imperva-503-headers"],
)
def test_shipped_catalog_does_not_block_forms_or_maintenance_pages(shipped: Catalogs, status, headers, body) -> None:
    """find-r2-6: verify-page rules need a challenge status; cookie- or header-only rules leave out 503."""
    result = classify_challenge(status, headers, body, shipped)
    assert result.blocked is False, result.signals
