"""Value search for ``find``: variants, match kinds and match locations.

Bodies are searched in memory and then discarded; nothing here keeps a body,
and nothing returned here contains a searched value. What comes back is, per
value, a match kind (``"exact"``, ``"variant:<id>"`` or ``"none"``) and, per
response, a list of location labels such as ``json-key:offers.price``.

A value that starts or ends with a digit is matched with digit boundaries
on that side: ``51.77`` is not ``exact`` inside ``151.77``, ``51.775`` or
``51,775``, and ``22 available`` is not ``exact`` inside ``122 available``.
A value that starts with an ASCII ``-`` or ``+`` and a digit is not matched
where that character follows a letter, digit or underscore (a hyphen:
``-42`` is not in ``ABC-42`` or ``1e-42``); the ``number-format`` variant
reads a leading ``+`` as no sign, so ``+42`` matches wherever ``42`` does.
In a parsed JSON body the number
tokens of a numeric value are compared as numbers for every kind, the exact
one included (``1,299`` is not in the list ``[1,299]``).
Other values use plain substring search. Numeric values (a number,
optionally with one currency symbol such as ``\u00a3`` ``$`` ``\u20ac`` or a
three-letter code such as ``EUR`` before or after it) also get the
``number-format`` variant.

Variant ids, tried in this order (the first that matches is reported):

``json-escape``
    the value as it appears inside a JSON/JavaScript string literal: found
    after decoding ``\\uXXXX``, ``\\u{X}``, ``\\xXX``, ``\\/``, ``\\'``,
    ``\\"`` and the other backslash escapes of the body, once or twice (for
    double-escaped strings such as Next.js flight data). This covers JSON
    bodies, JavaScript, and JSON or scripts embedded in HTML with HTML-safe
    escaping (``\\u0026`` for ``&``, ``\\u003c`` for ``<``, ``\\u00a0``...).
``html-entity``
    found after decoding HTML/XML character references (``&amp;``,
    ``&#8239;``, ``&nbsp;``), also inside decoded JSON/JavaScript strings.
``space-normalized``
    found after mapping U+00A0, U+202F and every other Unicode space to an
    ASCII space, dropping zero-width characters and soft hyphens, and
    collapsing whitespace runs (in both the value and the body).
``tag-stripped``
    HTML only: found in the visible text, where inline tags are removed
    without a separator (``<span>129</span>.<span>99</span>`` reads
    ``129.99``) and block tags separate words. Script, style, template and
    noscript content is not visible text.
``number-format``
    numeric values only: the same number with other thousands separators
    (``,`` ``.`` ``'`` or a space, one kind per number), a decimal comma or
    point (not the thousands separator: ``1,234.567`` is not 1234567),
    trailing zeros (``129.9`` matches ``129,90``), and without the currency
    symbol or code (``\u00a351.77`` matches the JSON number ``51.77``). Digits
    around the number must not continue it, nor may a thousands group
    (``1000`` is not in ``1,000,000``, ``12345`` not in ``12 345 678``);
    trailing zeros never form a three-digit group (``4.5`` is not ``4,500``);
    ``1,000`` is only a thousand, never 1; a minus sign and leading zeros are
    kept (``-42`` is not ``42``, ``007`` not ``7``), and a value without a
    sign is not found right after a minus sign (``42`` is not in ``-42`` or
    ``1e-42``; ``ABC-42`` and ``2020-2024`` hold hyphens, not signs, so ``-42``
    is not found there either). A single
    thousands dot (``1.994``) reads as a whole number only next to a currency
    (``1.994 \u20ac``), since it is as often a decimal point (CSS, SVG path
    data, version numbers). In a parsed JSON body the number tokens are
    compared as numbers (``.`` is a decimal point, ``,`` separates array
    elements), never read as formatted text.
``case-insensitive``
    found after Unicode case folding of the normalised value and body.
``substring``
    values that start or end with a digit, the weakest kind: the value
    occurs only inside a longer number (``51.77`` in ``151.77``, ``12`` in
    ``122``). It is reported but never counts as found (:data:`WEAK_KINDS`).

Accuracy limits: in JavaScript, CSS and JSON embedded in HTML, number
tokens are still read as text: a comma between a one-to-three-digit element
and a three-digit one (``[1,994]``) reads as a thousands group, and ``1.994``
next to a currency sign as one. Apart from the digit boundaries this is substring search,
like DevTools' search, so short values match inside longer tokens; callers
warn about short or numeric-only values. Variants can produce
matches a human would not call the same value (a tag-stripped match can join
adjacent inline elements; decoding escapes everywhere in a script can decode
a backslash sequence that was not in a string). Every non-exact match is
labelled as a variant so the reader can judge. Values computed by page
scripts from other data (for example a price stored in cents and formatted by
JavaScript) are not found unless the final string appears in some response;
``find`` never claims a page computed a value.
"""

from __future__ import annotations

import html
import json
import math
import re
import unicodedata
import urllib.parse
from collections.abc import Callable, Sequence
from decimal import Decimal, InvalidOperation
from dataclasses import dataclass, field
from functools import cached_property, lru_cache
from html.parser import HTMLParser

#: Variant ids in the order they are tried after an exact match fails.
VARIANT_IDS: tuple[str, ...] = (
    "json-escape",
    "html-entity",
    "space-normalized",
    "tag-stripped",
    "number-format",
    "case-insensitive",
    "substring",
)
#: Match kinds that only say a value occurs inside a longer number; they never count as found.
WEAK_KINDS: frozenset[str] = frozenset({"variant:substring"})


def counts_as_match(kind: str) -> bool:
    """True for a match kind that counts as found: not ``none`` and not a weak kind."""
    return kind != "none" and kind not in WEAK_KINDS

#: Body kinds understood by :func:`search_body`.
BODY_KINDS: tuple[str, ...] = ("html", "json", "js", "xml", "css", "text")

#: At most this many ``json-key:`` locations are reported per response.
MAX_JSON_KEY_LOCATIONS = 5
#: At most this many locations per response (report.json allows 20).
MAX_LOCATIONS = 20
#: At most this many locations per value of one response (report.json allows 10).
MAX_VALUE_LOCATIONS = 10
#: JSON documents with more nodes than this are only partly walked for key paths.
MAX_JSON_NODES = 200_000
#: Location name and detail charsets (report.json pattern) and lengths.
_LOCATION_NAME_RE = re.compile(r"[a-z][a-z0-9+_-]{0,31}")
_LOCATION_DETAIL_RE = re.compile(r"[A-Za-z0-9_.$@\[\]-]{1,128}")
_JSON_KEY_RE = re.compile(r"[A-Za-z0-9_$@-]{1,64}")

_ZERO_WIDTH_RE = re.compile("[\u00ad\u200b\u200c\u200d\u2060\ufeff]")
# Python's \s matches every Unicode space, including U+00A0 and U+202F.
_WS_RE = re.compile(r"\s+")
_GROUP_SEP = "[,.'\u00a0\u202f\u2009 ]"
_XSSI_PREFIX_RE = re.compile(r"^\s*(?:\)\]\}'|while\s*\(1\);|for\s*\(;;\);)\s*,?\s*")


def normalize_space(text: str) -> str:
    """Map every Unicode space to ' ', drop zero-width characters and collapse runs."""
    return _WS_RE.sub(" ", _ZERO_WIDTH_RE.sub("", text)).strip()


# ---------------------------------------------------------------------------
# JavaScript / JSON string escapes
# ---------------------------------------------------------------------------

_JS_ESCAPE_RE = re.compile(r"\\(?:u\{([0-9A-Fa-f]{1,6})\}|u([0-9A-Fa-f]{4})|x([0-9A-Fa-f]{2})|(.))", re.S)
_JS_SIMPLE_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}
_SURROGATE_RE = re.compile("[\ud800-\udfff]")


def _js_escape_char(m: re.Match[str]) -> str:
    hexa = m.group(1) or m.group(2) or m.group(3)
    if hexa is not None:
        cp = int(hexa, 16)
        return chr(cp) if cp <= 0x10FFFF else m.group(0)
    c = m.group(4)
    return _JS_SIMPLE_ESCAPES.get(c, c)


def js_unescape(text: str) -> str:
    """Decode JavaScript/JSON backslash escapes everywhere in ``text`` (search view only).

    ``\\uXXXX`` (surrogate pairs joined), ``\\u{X...}``, ``\\xXX``, the
    single-character escapes (``\\n``, ``\\t``...) and identity escapes
    (``\\/``, ``\\'``, ``\\"``, ``\\\\``). Text without a backslash is
    returned unchanged. One call removes one level of escaping.
    """
    if "\\" not in text:
        return text
    out = _JS_ESCAPE_RE.sub(_js_escape_char, text)
    if _SURROGATE_RE.search(out):
        out = out.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "replace")
    return out


# ---------------------------------------------------------------------------
# Values
# ---------------------------------------------------------------------------

_DIGITS = "0123456789"
_SIGNS = "+-\u2212"
#: ISO 4217 currency codes in circulation (funds, metals and test codes left out).
ISO_CURRENCY_CODES = frozenset(
    """AED AFN ALL AMD ANG AOA ARS AUD AWG AZN BAM BBD BDT BGN BHD BIF BMD BND BOB BRL BSD BTN BWP BYN BZD
    CAD CDF CHF CLP CNY COP CRC CUC CUP CVE CZK DJF DKK DOP DZD EGP ERN ETB EUR FJD FKP GBP GEL GHS GIP GMD
    GNF GTQ GYD HKD HNL HTG HUF IDR ILS INR IQD IRR ISK JMD JOD JPY KES KGS KHR KMF KPW KRW KWD KYD KZT LAK
    LBP LKR LRD LSL LYD MAD MDL MGA MKD MMK MNT MOP MRU MUR MVR MWK MXN MYR MZN NAD NGN NIO NOK NPR NZD OMR
    PAB PEN PGK PHP PKR PLN PYG QAR RON RSD RUB RWF SAR SBD SCR SDG SEK SGD SHP SLE SLL SOS SRD SSP STN SVC
    SYP SZL THB TJS TMT TND TOP TRY TTD TWD TZS UAH UGX USD UYU UZS VES VND VUV WST XAF XCD XCG XOF XPF YER
    ZAR ZMW ZWG ZWL""".split()
)
_ISO_PREFIX_RE = re.compile(r"([A-Z]{3})(?=[\s0-9+\-\u2212])\s*")
_ISO_SUFFIX_RE = re.compile(r"(?<=[\s0-9])\s*([A-Z]{3})$")
_SYMBOL_PREFIX_RE = re.compile(r"[A-Z]{0,3}([^\w\s])\s*")
_SYMBOL_SUFFIX_RE = re.compile(r"\s*([^\w\s])$")
#: Currency abbreviations written in letters (compared case-folded; a trailing dot is allowed):
#: z\u0142oty, kronor/kroner, koruna, forint, leu, rouble, hryvnia, lev, denar, dinar, kuna, rupee,
#: rand, ringgit, rupiah, Belarusian rouble, kwanza, lira, franc, shilling, taka, bol\u00edvar, guaran\u00ed.
LETTER_CURRENCY_TOKENS = frozenset(
    """z\u0142 zl kr k\u010d kc ft lei \u0440\u0443\u0431 \u0440 \u0433\u0440\u043d \u043b\u0432 \u0434\u0435\u043d \u0434\u0438\u043d din kn rs r rm rp br kz tl
    fr sfr chf ksh tk bs gs""".split()
)
_WORD_PREFIX_RE = re.compile(r"([^\W\d_]{1,4})\.?(?=[\s0-9+\-\u2212])\s*")
_WORD_SUFFIX_RE = re.compile(r"(?<=[\s0-9])\s*([^\W\d_]{1,4})\.?$")


def strip_currency(value: str) -> str | None:
    """The value without one currency affix, or None when it has none.

    An affix is a currency symbol (Unicode category Sc, optionally after up
    to three capital letters as in ``US$`` or ``R$``), an ISO 4217 code
    (``EUR``, ``USD``; ``SKU`` is not one) or a currency abbreviation written
    in letters (:data:`LETTER_CURRENCY_TOKENS`: ``z\u0142``, ``kr``,
    ``K\u010d``, ``Ft``, ``lei``, ``\u0440\u0443\u0431.``, ``Rs``, ``R``...; ``kg`` is not one),
    before or after the rest, with any spaces or no-break spaces next to it.
    A leading sign is kept. Used only to decide whether a value is numeric;
    the exact test keeps the value as typed.
    """
    s = value.strip()
    sign = ""
    if s[:1] in _SIGNS:
        sign, s = s[:1], s[1:].lstrip()
    changed = False
    m = _ISO_PREFIX_RE.match(s)
    if m is not None and m.group(1) not in ISO_CURRENCY_CODES:
        m = None
    if m is None:
        m = _SYMBOL_PREFIX_RE.match(s)
        if m is not None and unicodedata.category(m.group(1)) != "Sc":
            m = None
    if m is None:
        m = _WORD_PREFIX_RE.match(s)
        # a one-letter prefix needs a space or dot after it: "R 499" is rand, "R499" may be a code
        if m is not None and (m.group(1).casefold() not in LETTER_CURRENCY_TOKENS or m.end() == 1):
            m = None
    if m is not None:
        s, changed = s[m.end() :], True
        if not sign and s[:1] in _SIGNS:
            sign, s = s[:1], s[1:].lstrip()
    m = _ISO_SUFFIX_RE.search(s)
    if m is not None and m.group(1) not in ISO_CURRENCY_CODES:
        m = None
    if m is None:
        m = _SYMBOL_SUFFIX_RE.search(s)
        if m is not None and unicodedata.category(m.group(1)) != "Sc":
            m = None
    if m is None:
        m = _WORD_SUFFIX_RE.search(s)
        if m is not None and m.group(1).casefold() not in LETTER_CURRENCY_TOKENS:
            m = None
    if m is not None:
        s, changed = s[: m.start()], True
    s = s.strip()
    return sign + s if changed and s else None


def _number_readings(value: str) -> tuple[str, list[tuple[str, str]]]:
    """(sign, [(integer digits, fraction digits)]) of a numeric value, or ("", []) if not numeric.

    One currency symbol or code is ignored (:func:`strip_currency`). Spaces
    and apostrophes are thousands separators. With both ``.`` and ``,``
    present the last one is the decimal separator. A single separator followed
    by exactly three digits is ambiguous (``1,299`` is 1299 or 1.299), so both
    readings are returned, except when those three digits are zeros: ``1,000``
    is read only as a thousand, because its decimal reading (1) would match
    every bare ``1``. The sign is ``"-"`` for a minus sign (``-`` or U+2212)
    and ``""`` otherwise. Digits are returned as typed (leading zeros kept).
    """
    core = strip_currency(value)
    s = re.sub(r"[\s']", "", (core if core is not None else value).strip())
    sign = ""
    if s[:1] in _SIGNS:
        sign = "" if s[:1] == "+" else "-"
        s = s[1:]
    if not re.fullmatch(r"[0-9](?:[0-9.,]*[0-9])?", s):
        return "", []
    seps = [c for c in s if c in ".,"]

    def grouped(int_part: str, sep: str) -> str | None:
        groups = int_part.split(sep)
        if not 1 <= len(groups[0]) <= 3 or any(len(g) != 3 for g in groups[1:]):
            return None
        return "".join(groups)

    if not seps:
        readings = [(s, "")]
    elif len(set(seps)) == 2:
        dec = s[max(s.rfind("."), s.rfind(","))]
        thousands = "," if dec == "." else "."
        int_part, frac = s.rsplit(dec, 1)
        if dec in int_part:
            return "", []
        digits = grouped(int_part, thousands)
        if digits is None:
            return "", []
        readings = [(digits, frac)]
    elif len(seps) > 1:
        digits = grouped(s, seps[0])
        if digits is None:
            return "", []
        readings = [(digits, "")]
    else:
        int_part, frac = s.split(seps[0])
        readings = [(int_part, frac)]
        if len(frac) == 3 and 1 <= len(int_part) <= 3:
            readings = [(int_part + frac, "")] if frac == "000" else [(int_part + frac, ""), (int_part, frac)]
    return sign, readings


def _groups(digits: str) -> list[str]:
    head = len(digits) % 3 or 3
    return [digits[:head]] + [digits[i : i + 3] for i in range(head, len(digits), 3)]


def _int_pattern(digits: str) -> str:
    """Integer digits with any optional separator between groups (the privacy matcher only)."""
    if len(digits) <= 3:
        return digits
    groups = _groups(digits)
    return groups[0] + "".join(f"{_GROUP_SEP}?{g}" for g in groups[1:])


#: Thousands separators of one grouped form, each with the decimal separator it allows after it:
#: a dot group takes a decimal comma (1.299,50), a comma group a decimal point (1,299.50), and a
#: space or apostrophe group either.
_GROUPINGS: tuple[tuple[str, str], ...] = ((",", r"\."), (r"\.", ","), ("['\u00a0\u202f\u2009 ]", "[.,]"))


def _int_forms(digits: str) -> list[tuple[str, str]]:
    """(regex, decimal separator class) for integer digits written plainly or grouped with one separator.

    One separator per number (hon4-1): ``1,234.567`` is 1234.567, never 1234567.
    """
    if len(digits) <= 3:
        return [(digits, "[.,]")]
    groups = _groups(digits)
    return [(digits, "[.,]")] + [(sep.join(groups), dec) for sep, dec in _GROUPINGS]


#: A number whose only separator is one thousands dot (``1.994``, ``-5.000``): also a decimal number.
_SINGLE_DOT_GROUP_RE = re.compile("[-\u2212]?\\s?[0-9]{1,3}\\.[0-9]{3}")
_AFFIX_SPACES = " \u00a0\u202f\u2009"
_TRAILING_WORD_RE = re.compile(r"(?<![^\W\d_])([^\W\d_]{1,4})\.?$")
_LEADING_WORD_RE = re.compile(r"([^\W\d_]{1,4})(?![^\W\d_])")


def _is_currency_word(word: str) -> bool:
    return word in ISO_CURRENCY_CODES or word.casefold() in LETTER_CURRENCY_TOKENS


def currency_next_to(h: str, start: int, end: int) -> bool:
    """True when a currency symbol, ISO code or letter abbreviation sits right before or after ``h[start:end]``.

    Spaces may separate them (``1.299 \u20ac``, ``EUR 1.299``, ``kr 1.299``,
    ``\u20ac1.299``); so may nothing. A German price dash (``1.299,-``) counts too.
    """
    before = h[max(0, start - 8) : start].rstrip(_AFFIX_SPACES)
    if before:
        if unicodedata.category(before[-1]) == "Sc":
            return True
        m = _TRAILING_WORD_RE.search(before)
        if m is not None and _is_currency_word(m.group(1)):
            return True
    after = h[end : end + 8].lstrip(_AFFIX_SPACES)
    if after:
        if unicodedata.category(after[0]) == "Sc" or after.startswith((",-", ",\u2013", ",\u2014")):
            return True
        m = _LEADING_WORD_RE.match(after)
        if m is not None and _is_currency_word(m.group(1)):
            return True
    return False


def _dot_group_in_context(h: str, start: int, end: int) -> bool:
    """False for ``1.994`` read as 1994 with no currency next to it (hon4-1).

    Used for whole-number values. On the page a single dot group such as
    ``1.994`` is just as often a decimal (JSON, CSS,
    SVG path data, version numbers), so it counts as the same number only
    next to a currency. Two dot groups (``1.234.567``) or a decimal comma
    after the group (``1.299,00``) cannot be a decimal point and need no context.
    """
    return _SINGLE_DOT_GROUP_RE.fullmatch(h, start, end) is None or currency_next_to(h, start, end)


def _unsigned_whole_ok(h: str, start: int, end: int) -> bool:
    return not minus_before(h, start) and _dot_group_in_context(h, start, end)


def _frac_pattern(frac: str) -> str:
    """Fraction digits plus optional trailing zeros, never adding up to exactly three digits.

    Three digits after a separator read as a thousands group (``4,500``), so
    ``4.5`` may match ``4,50`` or ``4.5000`` but not ``4,500``.
    """
    if len(frac) == 1:
        return frac + "(?:0|0{3,})?"
    if len(frac) == 2:
        return frac + "(?:0{2,})?"
    return frac + "0*"


def number_pattern(value: str, *, loose: bool = False) -> NumberMatcher | None:
    """A matcher for the number in ``value`` in other common formats, or None.

    The match needs digit boundaries on both sides and may not continue a
    longer number across a joiner (:func:`_joins_number`: ``12345`` is not in
    ``12 345 678``, ``1000`` not in ``1,000,000``, but ``19.99`` is in the
    array ``[19.99,24.99]``); its optional decimal zeros never form a
    three-digit group. A minus sign and leading zeros in the value are
    required (``-42`` is not ``42``; ``007`` is not ``7``), and a value
    without a sign is not found right after a minus sign (:func:`minus_before`:
    ``42`` is not in ``-42``, ``\u221242`` or ``1e-42``; a hyphen after a
    letter or digit, as in ``ABC-42`` or ``2020-2024``, is not a minus
    sign). One number uses one thousands separator, and the decimal
    separator differs from it (``1,234.567`` is not 1234567). For a value
    that is a whole number in every reading (``1994``, ``1 994``, ``5,000``,
    ``1994.00``; not ``1,299``, which may mean 1.299) a single thousands dot
    (``1.994``) counts only next to a currency (:func:`_dot_group_in_context`).

    ``loose`` is for privacy checks only: the sign and leading zeros are
    dropped and only digit boundaries apply, so a path holding ``42`` counts
    as containing ``-42``.
    """
    sign, readings = _number_readings(value)
    if not readings:
        return None
    alts: list[str] = []
    seen: set[tuple[str, str]] = set()
    for int_digits, frac_digits in readings:
        digits = (int_digits.lstrip("0") or "0") if loose else (int_digits or "0")
        frac = frac_digits.rstrip("0")
        if (digits, frac) in seen:
            continue
        seen.add((digits, frac))
        forms = [(_int_pattern(digits), "[.,]")] if loose else _int_forms(digits)
        for ip, dec in forms:
            if frac:
                alts.append(f"{ip}{dec}{_frac_pattern(frac)}")
            else:
                alts.append(f"{ip}(?:{dec}(?:0{{1,2}}|0{{4,}}))?")
    prefix = "[-\u2212]\\s?" if sign and not loose else ""
    body = prefix + "(?:" + "|".join(alts) + ")"
    if loose:
        # privacy checks err on dropping: digit boundaries only, a decimal point may sit next to it
        return NumberMatcher(
            re.compile(_LEFT_BOUNDARY + body + _RIGHT_BOUNDARY),
            re.compile(_LEFT_SIGN + body + _RIGHT_DIGIT_ONLY),
            check_edges=False,
        )
    # a whole number in every reading (1994, 1 994, 5,000, 1994.00; not 1,299, which may be 1.299)
    whole = all(not frac.rstrip("0") for _int_digits, frac in readings)
    accept: MatchCheck | None
    if prefix:
        # find-r4-6: a hyphen after a letter or digit is no sign (``ABC-1,299``)
        accept = _signed_whole_ok if whole else sign_not_joined
    elif whole:
        accept = _unsigned_whole_ok
    else:
        accept = _not_after_minus
    return NumberMatcher(
        re.compile(_LEFT_BOUNDARY + body + _RIGHT_BOUNDARY),
        re.compile((_LEFT_SIGN if prefix else _LEFT_DIGIT) + body + _RIGHT_DIGIT),
        accept=accept,
        sign=sign,
        readings=tuple(readings),
    )


def _json_forms(value: str) -> tuple[str, ...]:
    """The value as JSON string content: ``\\uXXXX`` in both hex cases, ``\\/``, HTML-safe escapes.

    HTML-safe escaping (Next.js ``htmlEscapeJsonString``, Rails, PHP's
    ``JSON_HEX_*`` flags) writes ``&`` ``<`` ``>`` ``'`` as ``\\u0026``
    ``\\u003c`` ``\\u003e`` ``\\u0027``. These forms are a fast path; the
    decoded views of :class:`SearchText` catch every other escape.
    """
    forms = {json.dumps(value, ensure_ascii=False)[1:-1], json.dumps(value)[1:-1]}
    safe = {"&": "\\u0026", "<": "\\u003c", ">": "\\u003e", "'": "\\u0027"}
    forms |= {"".join(safe.get(c, c) for c in f) for f in forms}
    forms |= {re.sub(r"\\u([0-9a-f]{4})", lambda m: "\\u" + m.group(1).upper(), f) for f in forms}
    forms |= {f.replace("/", "\\/") for f in forms}
    forms.discard(value)
    return tuple(sorted(forms))


#: Characters that can join two digit runs into one number: decimal points, thousands separators.
_JOINERS = ".,'\u00a0\u202f\u2009 "
#: Joiners that are only ever thousands separators (spaces and the apostrophe).
_SPACE_JOINERS = "'\u00a0\u202f\u2009 "
_JOINER_CLASS = "[.,'\u00a0\u202f\u2009 ]"
#: Digit edges with nothing that could continue a number next to them (fast path).
_LEFT_BOUNDARY = rf"(?<![0-9])(?<![0-9]{_JOINER_CLASS})"
_RIGHT_BOUNDARY = rf"(?![0-9])(?!{_JOINER_CLASS}[0-9])"
#: Digit edges plus the decimal point, which always continues a number (:func:`_joins_number`);
#: a candidate next to another joiner is then judged by :func:`_edges_ok`. Leaving "." to the
#: regex keeps a body full of decimals (``1.5 2.5 3.5 ...``) from being walked match by match.
_LEFT_DIGIT = r"(?<![0-9])(?<![0-9]\.)"
_RIGHT_DIGIT = r"(?![0-9])(?!\.[0-9])"
#: The left edge of a match that starts with a sign (only no digit directly before it), and
#: the plain digit edges of the privacy matcher, which errs on dropping.
_LEFT_SIGN = r"(?<![0-9])"
_RIGHT_DIGIT_ONLY = r"(?![0-9])"
#: Longest digit run scanned next to a joiner (longer runs are never thousands groups).
_RUN_SCAN_MAX = 64


def _is_word_char(c: str) -> bool:
    return c.isalnum() or c == "_"


def minus_before(h: str, start: int) -> bool:
    """True when a minus sign sits directly before ``h[start]`` (hon4-1).

    U+2212 always is one, so is an exponent sign (``1e-42``, ``1E+42``), and
    so is ``-`` at the start or after a character that is not a letter,
    digit or underscore (``-42``, ``(-42)``, ``: -42``). A hyphen after a
    letter or digit (``ABC-42``, ``2020-2024``, ``1-42``) is a joiner, not a
    sign. Checked on candidate matches only, so a body full of digits is not
    slowed down position by position.
    """
    if start <= 0:
        return False
    c = h[start - 1]
    if c == "\u2212":
        return True
    if c in "-+" and start >= 3 and h[start - 2] in "eE" and _is_digit(h[start - 3]):
        return True
    return c == "-" and (start == 1 or not _is_word_char(h[start - 2]))


def _not_after_minus(h: str, start: int, end: int) -> bool:
    return not minus_before(h, start)


def sign_not_joined(h: str, start: int, end: int) -> bool:
    """False when ``h[start:end]`` starts with an ASCII ``-`` or ``+`` right after a letter, digit or underscore.

    Such a character is a hyphen or a joiner, not a sign (``ABC-42``,
    ``2020-2024``, ``1e-42``, ``v2-42``), so a signed value (``-42``) is not
    found there (find-r4-6); U+2212 is always a minus sign (:func:`minus_before`).
    """
    return not (0 < start < len(h) and h[start] in "+-" and _is_word_char(h[start - 1]))


def _signed_whole_ok(h: str, start: int, end: int) -> bool:
    return sign_not_joined(h, start, end) and _dot_group_in_context(h, start, end)


def _is_digit(c: str) -> bool:
    return "0" <= c <= "9"


def _run_before(h: str, end: int) -> tuple[int, int]:
    """(length, start) of the ASCII digit run that ends just before ``end`` (scan capped)."""
    a = end
    stop = max(0, end - _RUN_SCAN_MAX)
    while a > stop and _is_digit(h[a - 1]):
        a -= 1
    return end - a, a


def _run_after(h: str, start: int) -> tuple[int, int]:
    """(length, end) of the ASCII digit run that starts at ``start`` (scan capped)."""
    b = start
    stop = min(len(h), start + _RUN_SCAN_MAX)
    while b < stop and _is_digit(h[b]):
        b += 1
    return b - start, b


def _joins_number(h: str, i: int) -> bool:
    """True when ``h[i]``, a joiner between two digits, continues one number across it.

    - ``.`` always does (a decimal point, or a thousands dot as in ``1.500``).
    - A space, NBSP, NNBSP, thin space or apostrophe does when a three-digit
      group follows a run of one to three digits (``1 500``, ``1'299``,
      ``12 345 678``), never after a longer run (``2026 100``).
    - ``,`` does before a three-digit group after one to three digits
      (``1,500``, ``1,299.00``, ``1.234,567``); before one or two digits it is
      a decimal comma (``51,77``, ``1299,99``, ``1.299,99``) unless the digits
      after it continue with another joiner and digit (``1690000000,51.77``,
      ``38,39,40``: a list) or the digits before it are a decimal fraction or a
      list element (``19.99,24.99``); before four or more digits it separates
      list elements (``1299,1499``).
    """
    c = h[i]
    if c == ".":
        return True
    left, a = _run_before(h, i)
    right, b = _run_after(h, i + 1)
    # does the run before h[i] itself continue a number to its left? After "." or "," it is a
    # fraction, group or list element; after a space-like joiner only when it is a 3-digit group.
    before = h[a - 1] if a >= 2 and _is_digit(h[a - 2]) else ""
    grouped = before != "" and (before in ".," or (before in _SPACE_JOINERS and left == 3))
    if c in _SPACE_JOINERS:
        return right == 3 and (left == 3 if grouped else left <= 3)
    if right > 3:
        return False
    if right == 3:
        return left == 3 if grouped else left <= 3
    if b + 1 < len(h) and h[b] in ".," and _is_digit(h[b + 1]):
        return False
    return (left == 3 and before != ",") if grouped else True


def _edges_ok(h: str, start: int, end: int, left: bool, right: bool) -> bool:
    """True when ``h[start:end]`` does not continue a number on its digit edges.

    ``left``/``right`` say which edges are digit edges of the searched form.
    A match that starts with a sign only needs no digit before it.
    """
    if left and start > 0:
        if _is_digit(h[start - 1]):
            return False
        if (
            start > 1
            and _is_digit(h[start])
            and h[start - 1] in _JOINERS
            and _is_digit(h[start - 2])
            and _joins_number(h, start - 1)
        ):
            return False
    if right and end < len(h):
        if _is_digit(h[end]):
            return False
        if end + 1 < len(h) and h[end] in _JOINERS and _is_digit(h[end + 1]) and _joins_number(h, end):
            return False
    return True


#: ``(text, start, end) -> bool``: a last check on a candidate match (:func:`_dot_group_in_context`).
MatchCheck = Callable[[str, int, int], bool]


def _search_bounded(
    strict: re.Pattern[str],
    loose: re.Pattern[str],
    h: str,
    left: bool,
    right: bool,
    accept: MatchCheck | None = None,
) -> re.Match[str] | None:
    """The first match of ``strict``, else the first ``loose`` match whose edges pass :func:`_edges_ok`.

    With ``accept``, a candidate must also pass ``accept(h, start, end)``.
    """
    if accept is None:
        m = strict.search(h)
        if m is not None:
            return m
    else:
        for m in strict.finditer(h):
            if accept(h, m.start(), m.end()):
                return m
    pos = 0
    while True:
        m = loose.search(h, pos)
        if m is None:
            return None
        if _edges_ok(h, m.start(), m.end(), left, right) and (accept is None or accept(h, m.start(), m.end())):
            return m
        pos = m.start() + 1


@dataclass(frozen=True)
class Needle:
    """One form of a value; a form that starts or ends with a digit must not continue a number there.

    ``22 available`` is not found in ``122 available``, ``ABC-12`` not in
    ``ABC-123``, ``51.77`` not in ``151.77`` or ``51.775``, ``500 \u20ac`` not in
    ``1 500 \u20ac`` and ``12 345`` not in ``12 345 678``; ``19.99`` is found in the
    array ``[19.99,24.99]`` (:func:`_joins_number` decides what a joiner does).
    A form starting with a digit is not found right after a minus sign
    (:func:`minus_before`): ``42`` is not in ``-42``, but is in ``ABC-42``.
    A form starting with an ASCII sign and a digit (``signed``) is not found
    where that character follows a letter, digit or underscore
    (:func:`sign_not_joined`): ``-42`` is not in ``ABC-42`` or ``1e-42``.
    """

    text: str
    rx: re.Pattern[str] | None = None
    loose: re.Pattern[str] | None = None
    left: bool = False
    right: bool = False
    signed: bool = False

    @classmethod
    def of(cls, text: str, *, bounded: bool = True) -> Needle:
        left = bounded and text[:1] in _DIGITS
        right = bounded and text[-1:] in _DIGITS
        signed = bounded and len(text) > 1 and text[0] in "+-" and text[1] in _DIGITS
        if not (left or right or signed):
            return cls(text)
        body = re.escape(text)
        strict = (_LEFT_BOUNDARY if left else "") + body + (_RIGHT_BOUNDARY if right else "")
        loose = (_LEFT_DIGIT if left else "") + body + (_RIGHT_DIGIT if right else "")
        return cls(text, re.compile(strict), re.compile(loose), left, right, signed)

    def found(self, haystack: str) -> bool:
        if not self.text or not haystack or self.text not in haystack:
            return False
        if self.rx is None or self.loose is None:
            return True
        accept = _not_after_minus if self.left else sign_not_joined if self.signed else None
        return _search_bounded(self.rx, self.loose, haystack, self.left, self.right, accept) is not None


class NumberMatcher:
    """The ``number-format`` regex of a value plus the joiner rules at its edges.

    ``search`` returns a match whose edges do not continue a longer number
    (:func:`_edges_ok`); with ``check_edges=False`` (privacy checks, which err
    on dropping) only digit boundaries apply. ``fullmatch`` tests a whole
    string such as a bare digit run.
    """

    def __init__(
        self,
        strict: re.Pattern[str],
        loose: re.Pattern[str],
        *,
        check_edges: bool = True,
        accept: MatchCheck | None = None,
        sign: str = "",
        readings: tuple[tuple[str, str], ...] = (),
    ) -> None:
        self.strict = strict
        self.loose = loose
        self.check_edges = check_edges
        self.accept = accept
        #: The value's sign ("-" or "") and (integer digits, fraction digits) readings (:func:`_number_readings`).
        self.sign = sign
        self.readings = readings

    @property
    def pattern(self) -> str:
        return self.loose.pattern

    def search(self, text: str) -> re.Match[str] | None:
        if not text:
            return None
        if not self.check_edges:
            return self.loose.search(text)
        return _search_bounded(self.strict, self.loose, text, True, True, self.accept)

    def fullmatch(self, text: str) -> re.Match[str] | None:
        return self.loose.fullmatch(text)

    def equals_json_number(self, leaf: object) -> bool:
        """True when a parsed JSON number is this value's number (``.`` in JSON is always a decimal point).

        ``1994.0`` equals ``1994`` and ``51.77`` equals ``\u00a351.77``; ``1.994``
        does not equal ``1994`` (hon4-1), ``-42`` not ``42`` and ``7`` not ``007``.
        """
        parts = json_number_parts(leaf)
        if parts is None or parts[0] != self.sign:
            return False
        return any(int_digits == parts[1] and frac.rstrip("0") == parts[2] for int_digits, frac in self.readings)


def json_number_parts(leaf: object) -> tuple[str, str, str] | None:
    """(sign, integer digits, fraction digits without trailing zeros) of a parsed JSON number, else None."""
    if isinstance(leaf, bool) or not isinstance(leaf, (int, float)):
        return None
    try:
        if isinstance(leaf, float):
            if not math.isfinite(leaf):
                return None
            number = Decimal(repr(leaf))
        else:
            number = Decimal(leaf)
    except (InvalidOperation, ValueError):
        return None
    text = format(number, "f")
    sign = "-" if text.startswith("-") else ""
    int_part, _, frac = text.lstrip("-").partition(".")
    return sign, int_part, frac.rstrip("0")


@dataclass(frozen=True)
class PreparedValue:
    """A searched value with its precomputed variant forms (never serialised)."""

    raw: str
    norm: str
    fold: str
    json_forms: tuple[str, ...]
    number: NumberMatcher | None
    #: The forms above as needles, with digit boundaries wherever a form starts or ends with a digit.
    exact: Needle = field(default=Needle(""))
    norm_needle: Needle = field(default=Needle(""))
    fold_needle: Needle = field(default=Needle(""))
    json_needles: tuple[Needle, ...] = ()
    #: ``number`` without the sign or leading zeros: only for privacy checks, which err on dropping.
    number_loose: NumberMatcher | None = None

    @property
    def numeric(self) -> bool:
        """True when the value is a number (currency symbol or code allowed)."""
        return self.number is not None

    @property
    def digit_edged(self) -> bool:
        """True when the value starts or ends with a digit (its forms then have digit boundaries)."""
        return self.raw[:1] in _DIGITS or self.raw[-1:] in _DIGITS

    @classmethod
    def of(cls, value: str) -> PreparedValue:
        raw = value.strip()
        if not raw:
            raise ValueError("find values must not be empty")
        norm = normalize_space(raw)
        fold = norm.casefold()
        number = number_pattern(raw)
        forms = _json_forms(raw)
        return cls(
            raw=raw,
            norm=norm,
            fold=fold,
            json_forms=forms,
            number=number,
            exact=Needle.of(raw),
            norm_needle=Needle.of(norm),
            fold_needle=Needle.of(fold),
            json_needles=tuple(Needle.of(f) for f in forms),
            number_loose=number_pattern(raw, loose=True),
        )


def prepare_values(values: Sequence[str]) -> list[PreparedValue]:
    """Prepare every ``--value``; raises ``ValueError`` for empty values."""
    return [PreparedValue.of(v) for v in values]


def is_short_value(value: str) -> bool:
    """True when a value is shorter than 5 characters or only digits, spaces and ``.,``.

    A currency symbol or code does not count (``\u00a351.77`` is numeric-only),
    because its number is also matched on its own.
    """
    stripped = value.strip()
    core = strip_currency(stripped)
    return len(stripped) < 5 or re.fullmatch(r"[0-9\s.,'+\-\u2212]+", core if core is not None else stripped) is not None


#: Most decoded forms of a path examined by :func:`contains_any_value`.
_MAX_TEXT_FORMS = 32
_DIGIT_RUN_RE = re.compile(r"[0-9]+")


def _text_forms(text: str) -> list[str]:
    """``text`` plus its repeatedly percent-decoded (``%XX`` and ``+``) and entity-decoded forms."""
    forms = [text]
    seen = {text}
    queue = [text]
    while queue and len(forms) < _MAX_TEXT_FORMS:
        nxt: list[str] = []
        for form in queue:
            candidates = [urllib.parse.unquote(form), urllib.parse.unquote_plus(form)]
            if "&" in form:
                candidates.append(html.unescape(form))
            for cand in candidates:
                if cand not in seen and len(forms) < _MAX_TEXT_FORMS:
                    seen.add(cand)
                    forms.append(cand)
                    nxt.append(cand)
        queue = nxt
    return forms


@lru_cache(maxsize=512)
def _filter_value(value: str) -> PreparedValue | None:
    try:
        return PreparedValue.of(value)
    except ValueError:
        return None


def _form_leaks(form: str, pv: PreparedValue) -> bool:
    """True when ``form`` holds ``pv`` in any form the search itself would match (no boundaries)."""
    low = form.casefold()
    if pv.raw.casefold() in low or any(f.casefold() in low for f in pv.json_forms):
        return True
    norm = normalize_space(form)
    if pv.fold and pv.fold in norm.casefold():
        return True
    number = pv.number_loose or pv.number
    if number is not None:
        if number.search(form) or number.search(norm):
            return True
        # a digit run that is the number on its own (a map key "1299", an index [48213],
        # or "1299" inside "v1.1299" where the boundary rules would not see it)
        if any(number.fullmatch(run) for run in _DIGIT_RUN_RE.findall(form)):
            return True
    return False


def contains_any_value(text: str, values: Sequence[str]) -> bool:
    """True when ``text`` contains a value in any form ``find`` searches for.

    Used to drop paths and JSON key paths that would leak a searched value.
    ``text`` is checked as given and after repeated percent-decoding (``%XX``
    and ``+``) and HTML-entity decoding; each value with the same matchers as
    the search (raw, JSON-escaped, space-normalised and case-folded forms, and
    for numeric values the number in other formats, also as a bare digit
    run), without digit boundaries, so this errs on the side of dropping.
    """
    if not text:
        return False
    prepared = [pv for pv in (_filter_value(v.strip()) for v in values if v and v.strip()) if pv is not None]
    if not prepared:
        return False
    return any(_form_leaks(form, pv) for form in _text_forms(text) for pv in prepared)


# ---------------------------------------------------------------------------
# HTML scanning: visible text and embedded script blocks
# ---------------------------------------------------------------------------

_BLOCK_TAGS = frozenset(
    "address article aside blockquote body br dd details dialog div dl dt fieldset figcaption figure "
    "footer form h1 h2 h3 h4 h5 h6 head header hr html li main nav ol option p pre section select "
    "summary table tbody td textarea tfoot th thead title tr ul".split()
)
_HIDDEN_TAGS = frozenset({"script", "style", "template", "noscript"})
_JS_TYPES = frozenset({"", "text/javascript", "application/javascript", "module", "text/ecmascript"})


@dataclass
class EmbeddedBlock:
    """An inline ``<script>`` block: kind is next-data, ld-json, json-script or inline-script."""

    kind: str
    text: str


class _HTMLScan(HTMLParser):
    """Collects visible text (inline tags joined, block tags separated) and script blocks."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.blocks: list[EmbeddedBlock] = []
        self._hidden = 0
        self._script: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _BLOCK_TAGS:
            self.parts.append("\n")
        if tag == "script":
            a = {k.lower(): (v or "") for k, v in attrs}
            self._script = {
                "type": a.get("type", "").strip().lower(),
                "id": a.get("id", ""),
                "src": "src" in a,
                "data": [],
            }
        if tag in _HIDDEN_TAGS:
            self._hidden += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in _BLOCK_TAGS:
            self.parts.append("\n")
        if tag == "script" and self._script is not None:
            self._finish_script()
        if tag in _HIDDEN_TAGS and self._hidden:
            self._hidden -= 1

    def handle_data(self, data: str) -> None:
        if self._script is not None:
            self._script["data"].append(data)  # type: ignore[union-attr]
            return
        if not self._hidden:
            self.parts.append(data)

    def _finish_script(self) -> None:
        script = self._script
        self._script = None
        if script is None:
            return
        text = "".join(script["data"])  # type: ignore[arg-type]
        stype = str(script["type"])
        if script["id"] == "__NEXT_DATA__":
            kind = "next-data"
        elif stype == "application/ld+json":
            kind = "ld-json"
        elif "json" in stype:
            kind = "json-script"
        elif not script["src"] and stype in _JS_TYPES:
            kind = "inline-script"
        else:
            return
        if text.strip():
            self.blocks.append(EmbeddedBlock(kind, text))

    def close(self) -> None:
        super().close()
        if self._script is not None:
            self._finish_script()


# ---------------------------------------------------------------------------
# JSON walking
# ---------------------------------------------------------------------------


def parse_json_text(text: str) -> object | None:
    """Parse a JSON body (tolerating an anti-XSSI prefix such as ``)]}'``); None if not JSON."""
    stripped = _XSSI_PREFIX_RE.sub("", text, count=1).strip()
    if not stripped or stripped[0] not in "{[\"":
        return None
    try:
        return json.loads(stripped)
    except (ValueError, RecursionError):
        return None


def _format_json_path(segments: list[str | int]) -> str:
    out = ""
    for seg in segments:
        if isinstance(seg, int):
            out += f"[{seg}]"
        else:
            out += ("." if out else "") + seg
    return out or "$"


def _walk_json(obj: object):  # noqa: ANN202 - generator of (path segments, leaf)
    """Yield (path segments, leaf) for every scalar leaf, depth-first, bounded."""
    stack: list[tuple[list[str | int], object]] = [([], obj)]
    nodes = 0
    while stack and nodes < MAX_JSON_NODES:
        path, node = stack.pop()
        nodes += 1
        if isinstance(node, dict):
            items = list(node.items())
            for key, child in reversed(items):
                stack.append(([*path, str(key)], child))
        elif isinstance(node, list):
            for idx in range(len(node) - 1, -1, -1):
                stack.append(([*path, idx], node[idx]))
        else:
            yield path, node


def _leaf_text(leaf: object) -> str:
    if isinstance(leaf, str):
        return leaf
    if leaf is None:
        return "null"
    return json.dumps(leaf)


def _leaf_matches(leaf: str, pv: PreparedValue, *, strict: bool = True) -> bool:
    """Whether a JSON leaf holds the value, for location labels.

    ``strict`` (a value that counts as found) uses the same digit and joiner
    boundaries as the match kinds, so ``12.99`` is not located in a leaf
    ``112.99`` or ``12.990``; without it (a weak ``variant:substring`` value)
    any substring counts, which shows where the longer number sits. The leaf
    is also tried with its backslash escapes and HTML entities decoded
    (``"Tom &amp; Jerry"`` is a location of ``Tom & Jerry``).
    """
    forms = [leaf]
    if "\\" in leaf:
        forms.append(js_unescape(leaf))
    if "&" in leaf:
        forms.extend([html.unescape(f) for f in forms])
    for form in forms:
        norm = normalize_space(form)
        if strict:
            if pv.exact.found(form) or pv.norm_needle.found(norm) or pv.fold_needle.found(norm.casefold()):
                return True
            if pv.number is not None and pv.number.search(norm):
                return True
            continue
        if pv.raw in form:
            return True
        if pv.norm and pv.norm in norm:
            return True
        if pv.number is not None and pv.number.search(norm):
            return True
        if pv.fold and pv.fold in norm.casefold():
            return True
    return False


def _leaf_equal_kind(leaf: object, pv: PreparedValue) -> str | None:
    """``exact`` when a JSON leaf is the value itself, ``variant:number-format`` when it is the same number.

    A JSON number is compared as a decimal number (:meth:`NumberMatcher.equals_json_number`),
    never read with thousands separators.
    """
    if isinstance(leaf, (dict, list)):
        return None
    text = _leaf_text(leaf)
    if text == pv.raw:
        return "exact"
    if pv.number is not None and pv.number.equals_json_number(leaf):
        return "variant:number-format"
    return None


def json_key_paths(
    obj: object,
    values: Sequence[PreparedValue],
    raw_values: Sequence[str],
    strict: Sequence[bool] | None = None,
) -> list[list[str]]:
    """Per value, up to MAX_JSON_KEY_LOCATIONS dotted key paths whose leaf contains it.

    ``strict`` (per value, default all True) applies the match boundaries to
    each leaf (:func:`_leaf_matches`); pass False for a weak value.
    A JSON number leaf is located only where it equals the value
    (:func:`_leaf_equal_kind`). Paths use ``.`` between keys and ``[i]`` for array indices. A path is
    dropped when a key falls outside ``[A-Za-z0-9_$@-]`` or the path contains a
    searched value in any searched form (:func:`contains_any_value`: number
    formats, digit-run keys and indices, escapes). Only the first
    MAX_JSON_NODES nodes are walked; matching itself is not limited by that.
    """
    out: list[list[str]] = [[] for _ in values]
    strict_of = list(strict) if strict is not None else [True] * len(values)
    for segments, leaf in _walk_json(obj):
        text = _leaf_text(leaf)
        number_leaf = json_number_parts(leaf) is not None
        for i, pv in enumerate(values):
            if len(out[i]) >= MAX_JSON_KEY_LOCATIONS:
                continue
            if strict_of[i] and number_leaf:
                # a JSON number holds a value only when it is that number (hon4-1)
                hit = _leaf_equal_kind(leaf, pv) is not None
            else:
                hit = _leaf_matches(text, pv, strict=strict_of[i])
            if not hit:
                continue
            if any(isinstance(s, str) and not _JSON_KEY_RE.fullmatch(s) for s in segments):
                continue
            path = _format_json_path(segments)
            if len(path) > 128 or contains_any_value(path, raw_values):
                continue
            if path not in out[i]:
                out[i].append(path)
        if all(len(p) >= MAX_JSON_KEY_LOCATIONS for p in out):
            break
    return out


# ---------------------------------------------------------------------------
# Texts and matching
# ---------------------------------------------------------------------------


#: A JSON string (kept) or a JSON number token (masked) in a JSON text.
_JSON_TOKEN_RE = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"|-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?', re.S)


def mask_json_numbers(text: str) -> tuple[str, frozenset[str]]:
    """``text`` (a JSON document) with every number token outside strings replaced by ``#``, and those tokens."""
    tokens: set[str] = set()

    def mask(m: re.Match[str]) -> str:
        token = m.group(0)
        if token[:1] == '"':
            return token
        tokens.add(token)
        return "#"

    return _JSON_TOKEN_RE.sub(mask, text), frozenset(tokens)


def json_token_parts(token: str) -> tuple[str, str, str] | None:
    """(sign, integer digits, fraction digits without trailing zeros) of a JSON number token, else None."""
    sign = "-" if token.startswith("-") else ""
    body = token[len(sign) :]
    if "e" in body or "E" in body:
        try:
            text = format(Decimal(body), "f")
        except (InvalidOperation, ValueError):
            return None
    else:
        text = body
    int_part, _, frac = text.partition(".")
    if not int_part.isdigit():
        return None
    return sign, int_part, frac.rstrip("0")


class SearchText:
    """A decoded body with lazily computed search views (kept only while searching).

    Views: ``raw``; ``decoded``/``decoded2`` (JavaScript/JSON escapes removed
    once/twice, over the whole body, so JSON bodies of any size, scripts and
    JSON or scripts embedded in HTML are covered; empty when the body has no
    backslash); ``unescaped`` (HTML entities decoded, every kind but CSS, so
    ``"Tom &amp; Jerry"`` in a JSON body without any backslash is found);
    ``decoded_entities`` (entities decoded inside the decoded views); and the
    space-normalised and case-folded forms of those.
    """

    def __init__(self, raw: str, kind: str) -> None:
        if kind not in BODY_KINDS:
            raise ValueError(f"unknown body kind {kind!r}")
        self.raw = raw
        self.kind = kind

    @cached_property
    def unescaped(self) -> str:
        if self.kind != "css" and "&" in self.raw:
            return html.unescape(self.raw)
        return self.raw

    @cached_property
    def decoded(self) -> str:
        return js_unescape(self.raw) if "\\" in self.raw else ""

    @cached_property
    def decoded2(self) -> str:
        return js_unescape(self.decoded) if "\\" in self.decoded else ""

    @cached_property
    def decoded_entities(self) -> str:
        joined = "\n".join(p for p in (self.decoded, self.decoded2) if p)
        return html.unescape(joined) if "&" in joined else ""

    @cached_property
    def decoded_norm(self) -> str:
        parts = [p for p in (self.decoded, self.decoded2, self.decoded_entities) if p]
        return normalize_space("\n".join(parts)) if parts else ""

    @cached_property
    def decoded_fold(self) -> str:
        return self.decoded_norm.casefold()

    @cached_property
    def norm(self) -> str:
        return normalize_space(self.unescaped)

    @cached_property
    def fold(self) -> str:
        return self.norm.casefold()

    @cached_property
    def scan(self) -> _HTMLScan | None:
        if self.kind != "html":
            return None
        parser = _HTMLScan()
        try:
            parser.feed(self.raw)
            parser.close()
        except Exception:  # noqa: BLE001 - HTMLParser is lenient; never fail a search on markup
            pass
        return parser

    @cached_property
    def visible(self) -> str:
        scan = self.scan
        return normalize_space("".join(scan.parts)) if scan is not None else ""

    @cached_property
    def visible_fold(self) -> str:
        return self.visible.casefold()

    @cached_property
    def json_obj(self) -> object | None:
        if self.kind != "json":
            return None
        return parse_json_text(self.raw)

    @cached_property
    def number_view(self) -> SearchText:
        """The text the ``number-format`` variant searches (hon4-1).

        For a parsed JSON body, its number tokens outside strings are masked
        (:func:`mask_json_numbers`): ``.`` in them is always a decimal point
        and ``,`` between them separates array elements, so text search would
        read ``1.994`` or ``[1,994]`` as 1994. Those tokens are compared as
        numbers instead (:meth:`json_number_kind`). Other bodies search themselves.
        """
        masked = self._json_numbers[0]
        return SearchText(masked, "text") if masked is not None else self

    @cached_property
    def _json_numbers(self) -> tuple[str | None, frozenset[str], frozenset[tuple[str, str, str]]]:
        """(masked text or None, number tokens as written, their (sign, int, frac) parts) of a parsed JSON body."""
        if self.kind != "json" or self.json_obj is None:
            return None, frozenset(), frozenset()
        masked, tokens = mask_json_numbers(self.raw)
        if not tokens:
            return None, tokens, frozenset()
        parts = frozenset(p for p in (json_token_parts(t) for t in tokens) if p is not None)
        return masked, tokens, parts

    @property
    def json_number_tokens(self) -> frozenset[str]:
        """The number tokens (outside strings) of a parsed JSON body, as written; empty otherwise."""
        return self._json_numbers[1]

    def json_number_kind(self, pv: PreparedValue) -> str | None:
        """For a parsed JSON body: ``exact`` when a number token is the value as typed,
        ``variant:number-format`` when one is the same number (``.`` is a decimal point), else None.

        Tokens are read from the whole body (not the bounded leaf walk), so no
        number is missed in a large document.
        """
        _masked, tokens, parts = self._json_numbers
        if not tokens:
            return None
        if pv.raw in tokens:
            return "exact"
        number = pv.number
        if number is not None and any((number.sign, i, f.rstrip("0")) in parts for i, f in number.readings):
            return "variant:number-format"
        return None

    @cached_property
    def json_documents(self) -> list[object]:
        """The parsed JSON body, or the parsed JSON blocks embedded in an HTML body."""
        if self.json_obj is not None:
            return [self.json_obj]
        scan = self.scan
        if scan is None:
            return []
        docs = []
        for block in scan.blocks:
            if block.kind != "inline-script":
                parsed = parse_json_text(block.text)
                if parsed is not None:
                    docs.append(parsed)
        return docs


def _leaf_kind(text: SearchText, pv: PreparedValue) -> str | None:
    """The kind of a JSON leaf that equals the value (JSON bodies and embedded JSON blocks), or None.

    Text search cannot tell the list ``[1,2]`` from the decimal comma ``1,2``,
    so ``2`` is not found there as itself; a parsed leaf equal to the value is
    unambiguous. Tried only when the value's digits occur in the body at all.
    """
    if text.kind not in ("json", "html"):
        return None
    if pv.raw not in text.raw and (pv.number is None or pv.number.loose.search(text.raw) is None):
        return None
    for doc in text.json_documents:
        for _segments, leaf in _walk_json(doc):
            kind = _leaf_equal_kind(leaf, pv)
            if kind is not None:
                return kind
    return None


def match_kind(text: SearchText, pv: PreparedValue) -> str:
    """``"exact"``, ``"variant:<id>"`` or ``"none"`` for one value in one body.

    For a numeric value in a parsed JSON body, the text views search the body
    with its number tokens masked (:attr:`SearchText.number_view`): a token is
    compared as a number (:meth:`SearchText.json_number_kind`; ``exact`` when
    it is the value as typed), so the list ``[1,299]`` is not ``1,299``
    (find-r4-6).
    """
    view = text
    token_kind = None
    if pv.number is not None:
        token_kind = text.json_number_kind(pv)
        if token_kind == "exact":
            return "exact"
        view = text.number_view
    if pv.exact.found(view.raw):
        return "exact"
    html_kind = text.kind == "html"
    # json-escape: the value's own escaped forms, then the body's escapes decoded once or twice
    if any(n.found(view.raw) for n in pv.json_needles):
        return "variant:json-escape"
    if view.decoded and (pv.exact.found(view.decoded) or pv.exact.found(view.decoded2)):
        return "variant:json-escape"
    # html-entity (also inside decoded JSON/JavaScript strings)
    if (view.unescaped is not view.raw and pv.exact.found(view.unescaped)) or pv.exact.found(view.decoded_entities):
        return "variant:html-entity"
    # space-normalized
    if pv.norm_needle.found(view.norm) or pv.norm_needle.found(view.decoded_norm):
        return "variant:space-normalized"
    # tag-stripped
    if html_kind and pv.norm_needle.found(text.visible):
        return "variant:tag-stripped"
    # number-format (a JSON body's number tokens are compared as numbers, never read as text)
    if pv.number is not None:
        if token_kind is not None:
            return token_kind
        if pv.number.search(view.norm) or (view.decoded_norm and pv.number.search(view.decoded_norm)):
            return "variant:number-format"
        if html_kind and pv.number.search(text.visible):
            return "variant:tag-stripped"
    # case-insensitive
    if (
        pv.fold_needle.found(view.fold)
        or (html_kind and pv.fold_needle.found(text.visible_fold))
        or pv.fold_needle.found(view.decoded_fold)
    ):
        return "variant:case-insensitive"
    # a JSON leaf equal to the value (the list [1,2] reads like the decimal 1,2 in text)
    if pv.digit_edged or pv.number is not None:
        leaf = _leaf_kind(text, pv)
        if leaf is not None:
            return leaf
    # substring: a value starting or ending with a digit only inside a longer number
    if pv.digit_edged and (
        pv.raw in view.raw
        or pv.norm in view.norm
        or pv.norm in view.decoded_norm
        or (html_kind and pv.norm in text.visible)
        or (view is not text and any(pv.raw in token for token in text.json_number_tokens))
    ):
        return "variant:substring"
    return "none"


@dataclass
class BodyHits:
    """What one body search found: a kind per value and the match locations.

    ``locations`` are per response (base labels such as the resource type
    first); ``by_value`` holds, per value in order, the locations specific to
    that value (``json-key:...``, ``embedded:...``, ``html-text``,
    ``html-markup``), empty for a value that did not match or matched only in a
    body without finer locations.
    """

    kinds: list[str]
    locations: list[str] = field(default_factory=list)
    by_value: list[list[str]] = field(default_factory=list)

    @property
    def values_matched(self) -> int:
        """Values found as themselves (weak kinds, a value only inside a longer number, do not count)."""
        return sum(1 for k in self.kinds if counts_as_match(k))

    @property
    def weak_matches(self) -> int:
        """Values seen only as a substring of a longer number (not counted as matched)."""
        return sum(1 for k in self.kinds if k in WEAK_KINDS)

    @property
    def any(self) -> bool:
        return self.values_matched > 0

    @property
    def all(self) -> bool:
        return bool(self.kinds) and all(counts_as_match(k) for k in self.kinds)


def _add(locations: list[str], label: str, limit: int = 0) -> None:
    name, sep, detail = label.partition(":")
    if not _LOCATION_NAME_RE.fullmatch(name) or (sep and not _LOCATION_DETAIL_RE.fullmatch(detail)):
        return
    if label not in locations and len(locations) < (limit or MAX_LOCATIONS):
        locations.append(label)


#: Per-value location for bodies without finer locations (and JSON matched outside any leaf).
TEXT_LABELS: dict[str, str] = {
    "js": "script-text",
    "css": "css-text",
    "xml": "xml-text",
    "text": "plain-text",
    "json": "json-text",
}


def search_body(
    raw: str,
    kind: str,
    values: Sequence[PreparedValue],
    *,
    base_locations: Sequence[str] = (),
    raw_values: Sequence[str] | None = None,
    text_label: str | None = None,
) -> BodyHits:
    """Search one decoded body for every value; returns kinds and locations only.

    ``base_locations`` (for example the resource type and ``iframe``) come
    first. ``raw_values`` are the values as given, used only to drop JSON key
    paths that would contain one; they default to the prepared raw forms.
    Values matched in a body without finer locations get a label saying
    which text was searched (:data:`TEXT_LABELS`, or ``text_label`` such as
    ``svg-text``); so does a JSON value found outside every leaf (in a key).
    """
    text = SearchText(raw, kind)
    kinds = [match_kind(text, pv) for pv in values]
    locations: list[str] = []
    by_value: list[list[str]] = [[] for _ in values]
    for label in base_locations:
        _add(locations, label)
    matched_idx = [i for i, k in enumerate(kinds) if k != "none"]
    if not matched_idx:
        return BodyHits(kinds, locations, by_value)
    matched = [values[i] for i in matched_idx]
    raw_vals = list(raw_values) if raw_values is not None else [pv.raw for pv in values]
    strict = [counts_as_match(kinds[i]) for i in matched_idx]
    if kind == "json" and text.json_obj is not None:
        for i, paths in zip(matched_idx, json_key_paths(text.json_obj, matched, raw_vals, strict)):
            for path in paths:
                _add(locations, f"json-key:{path}")
                _add(by_value[i], f"json-key:{path}", MAX_VALUE_LOCATIONS)
    elif kind == "html":
        for i, pv, exact_only in zip(matched_idx, matched, strict):
            _html_locations(text, pv, raw_vals, locations, by_value[i], strict=exact_only)
    label = text_label or TEXT_LABELS.get(kind)
    if label is not None and kind != "html":
        for i in matched_idx:
            if not by_value[i]:
                _add(locations, label)
                _add(by_value[i], label, MAX_VALUE_LOCATIONS)
    return BodyHits(kinds, locations, by_value)


def _html_locations(
    text: SearchText,
    pv: PreparedValue,
    raw_values: Sequence[str],
    locations: list[str],
    mine: list[str],
    *,
    strict: bool = True,
) -> None:
    """Locations of one matched value in an HTML body, added to the response's and the value's lists.

    ``strict`` (a value that counts as found) places it only where it occurs
    as itself: an embedded block where it is only a weak hit, or visible text
    where it only sits inside a longer number, is not a location.
    """
    scan = text.scan
    blocks = scan.blocks if scan is not None else []

    def add(label: str) -> None:
        _add(locations, label)
        _add(mine, label, MAX_VALUE_LOCATIONS)

    placed = False
    for block in blocks:
        block_kind = "js" if block.kind == "inline-script" else "json"
        block_text = SearchText(block.text, block_kind)
        kind = match_kind(block_text, pv)
        if kind == "none" or (strict and not counts_as_match(kind)):
            continue
        placed = True
        add(f"embedded:{block.kind}")
        if block_kind == "json" and block_text.json_obj is not None:
            for path in json_key_paths(block_text.json_obj, [pv], raw_values, [strict])[0]:
                add(f"json-key:{path}")
    visible = text.visible
    if strict:
        in_text = (
            pv.norm_needle.found(visible)
            or (pv.number is not None and pv.number.search(visible) is not None)
            or pv.fold_needle.found(text.visible_fold)
        )
    else:
        in_text = pv.norm in visible or (pv.number is not None and pv.number.search(visible)) or pv.fold in text.visible_fold
    if in_text:
        placed = True
        add("html-text")
    if not placed:
        add("html-markup")


__all__ = [
    "BODY_KINDS",
    "BodyHits",
    "EmbeddedBlock",
    "Needle",
    "PreparedValue",
    "SearchText",
    "TEXT_LABELS",
    "VARIANT_IDS",
    "WEAK_KINDS",
    "contains_any_value",
    "counts_as_match",
    "currency_next_to",
    "is_short_value",
    "js_unescape",
    "json_number_parts",
    "json_token_parts",
    "mask_json_numbers",
    "json_key_paths",
    "match_kind",
    "normalize_space",
    "number_pattern",
    "parse_json_text",
    "prepare_values",
    "search_body",
    "sign_not_joined",
    "strip_currency",
]
