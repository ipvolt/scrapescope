"""Versioned catalogs: background.json, challenges.json, direct.json.

The three JSON files ship as package data and are loaded with
``importlib.resources`` (so they work from a wheel or a zip). Each has a string
``version`` that reports record in ``catalog_versions``.

- ``background.json``: Chromium background hosts (component updates, model
  downloads, Safe Browsing). Tunnel bytes are called "background" ONLY when the
  host matches an entry; an uncatalogued host is never called background.
- ``challenges.json``: challenge and block-page signals per vendor, used by
  ``find`` to classify a response. Classification only; scrapescope never uses
  them to get past a challenge.
- ``direct.json``: LLM API hosts that ``run --env-all`` carries direct (never
  to the upstream, from the user's own IP address) and reports as non-target.
  Cloud-storage hosts are deliberately absent: buckets are often scrape
  targets, and carrying them direct would expose the user's IP.

Accuracy limits: the catalogs are curated lists, not detectors. A background
host that is not listed is reported as unattributed; a challenge vendor or page
variant that is not listed is not recognised; vendor signals change without
notice. Every entry cites evidence or vendor documentation, re-checked on its
``last_verified`` date (background) or with each catalog version.

Contract: docs/dev/contracts.md section 8.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

from ..types import Catalogs, host_glob_match, is_catalog_id, validate_host_glob

_FILES = ("background.json", "challenges.json", "direct.json")
_DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_URL_RE = re.compile(r"https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?(?:/[\x21-\x7e]*)?")
_SIGNAL_TYPES = ("header", "cookie", "status", "body")
_STRENGTHS = ("challenge", "vendor")
_HEADER_NAME_RE = re.compile(r"[a-z0-9!#$%&'*+.^_`|~-]{1,64}")
_COOKIE_GLOB_RE = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}")
_LABEL_RE = re.compile(r"[\x21-\x7e]{1,128}")
_VENDOR_NAME_RE = re.compile(r"[\x20-\x7e]{1,64}")


class CatalogError(ValueError):
    """A catalog document is malformed or misses required evidence."""


def _read_package_file(name: str) -> str:
    return resources.files(__name__).joinpath(name).read_text(encoding="utf-8")


def load_documents(
    directory: str | os.PathLike[str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """The raw (background, challenges, direct) JSON documents.

    ``directory`` (tests and catalog development only) reads the three files
    from that directory instead of the installed package.
    """
    docs: list[Any] = []
    for name in _FILES:
        if directory is None:
            text = _read_package_file(name)
        else:
            text = (Path(directory) / name).read_text(encoding="utf-8")
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as exc:
            raise CatalogError(f"{name}: not valid JSON (line {exc.lineno})") from None
        if not isinstance(doc, dict):
            raise CatalogError(f"{name}: expected a JSON object")
        docs.append(doc)
    return docs[0], docs[1], docs[2]


def _urls_ok(value: Any) -> bool:
    return (
        isinstance(value, list)
        and len(value) > 0
        and all(isinstance(u, str) and _URL_RE.fullmatch(u) for u in value)
    )


def _host_evidence_problems(where: str, entry: dict[str, Any]) -> list[str]:
    """Every host glob of a background entry needs its own evidence, listed in ``evidence`` too."""
    problems: list[str] = []
    hosts = entry.get("hosts") if isinstance(entry.get("hosts"), list) else []
    evidence = entry.get("evidence") if isinstance(entry.get("evidence"), list) else []
    by_host = entry.get("host_evidence")
    if not isinstance(by_host, dict):
        return [f"{where}: needs host_evidence naming a source for every host"]
    for host in hosts:
        urls = by_host.get(host)
        if not _urls_ok(urls):
            problems.append(f"{where}: host {host!r} needs at least one https evidence URL in host_evidence")
        elif any(u not in evidence for u in urls):
            problems.append(f"{where}: host_evidence URLs for {host!r} must also be listed in evidence")
    for host in by_host:
        if host not in hosts:
            problems.append(f"{where}: host_evidence names {host!r}, which is not one of the entry's hosts")
    return problems


def check_documents(background: Any, challenges: Any, direct: Any) -> list[str]:
    """Rules beyond ``Catalogs.from_documents``: evidence, dates, signal shapes.

    Returns a list of problems (empty when the documents are acceptable):

    - every background entry has at least one https evidence URL, a
      ``host_evidence`` source for each of its hosts (also listed in
      ``evidence``), a non-empty component and security trade-off, and a
      ``YYYY-MM-DD`` last_verified date;
    - every challenge vendor has at least one https docs URL, a printable name,
      and signals whose fields fit their type (header/cookie need a name,
      status needs statuses, body needs a pattern) with a valid strength, and
      every pattern compiles; every signal lists its own https ``sources``
      (is-antibot's providers.json or a vendor documentation page that
      contains the marker), because provenance is recorded per signal;
    - every direct entry has a reason and at least one https ``docs`` URL;
    - ids are unique within each file, and background and direct ids do not
      collide (``--redact-hosts`` labels hosts ``catalog:<id>`` from either).
    """
    problems: list[str] = []
    bg_ids: set[str] = set()
    for i, entry in enumerate(background.get("entries", []) if isinstance(background, dict) else []):
        where = f"background.json entries[{i}]"
        if not isinstance(entry, dict):
            problems.append(f"{where}: expected an object")
            continue
        eid = entry.get("id")
        if not is_catalog_id(eid):
            problems.append(f"{where}: invalid id")
        else:
            bg_ids.add(eid)
        hosts = entry.get("hosts")
        if not isinstance(hosts, list) or not hosts:
            problems.append(f"{where}: needs at least one host glob")
        else:
            for h in hosts:
                try:
                    validate_host_glob(h)
                except ValueError:
                    problems.append(f"{where}: invalid host glob")
        if not _urls_ok(entry.get("evidence")):
            problems.append(f"{where}: needs at least one https evidence URL")
        problems += _host_evidence_problems(where, entry)
        for key in ("component", "security_tradeoff"):
            if not isinstance(entry.get(key), str) or not entry[key].strip():
                problems.append(f"{where}: {key} must be a non-empty string")
        if not isinstance(entry.get("last_verified"), str) or not _DATE_RE.fullmatch(entry["last_verified"]):
            problems.append(f"{where}: last_verified must be YYYY-MM-DD")

    for i, vendor in enumerate(challenges.get("vendors", []) if isinstance(challenges, dict) else []):
        where = f"challenges.json vendors[{i}]"
        if not isinstance(vendor, dict):
            problems.append(f"{where}: expected an object")
            continue
        if not isinstance(vendor.get("name"), str) or not _VENDOR_NAME_RE.fullmatch(vendor["name"]):
            problems.append(f"{where}: name must be 1-64 printable ASCII characters")
        if not _urls_ok(vendor.get("docs")):
            problems.append(f"{where}: needs at least one https docs URL")
        signals = vendor.get("signals")
        if not isinstance(signals, list) or not signals:
            problems.append(f"{where}: needs at least one signal")
            continue
        if not any(isinstance(s, dict) and s.get("strength", "challenge") == "challenge" for s in signals):
            problems.append(f"{where}: needs at least one challenge-strength signal")
        for j, sig in enumerate(signals):
            sw = f"{where} signals[{j}]"
            if not isinstance(sig, dict):
                problems.append(f"{sw}: expected an object")
                continue
            stype = sig.get("type")
            name = sig.get("name")
            pattern = sig.get("pattern")
            statuses = sig.get("statuses", [])
            if stype not in _SIGNAL_TYPES:
                problems.append(f"{sw}: invalid type")
            if sig.get("strength", "challenge") not in _STRENGTHS:
                problems.append(f"{sw}: invalid strength")
            if not isinstance(statuses, list) or not all(
                isinstance(s, int) and not isinstance(s, bool) and 100 <= s <= 599 for s in statuses
            ):
                problems.append(f"{sw}: statuses must be HTTP status codes")
                statuses = []
            if stype == "header" and (not isinstance(name, str) or not _HEADER_NAME_RE.fullmatch(name)):
                problems.append(f"{sw}: header signals need a lowercase header name")
            if stype == "cookie" and (not isinstance(name, str) or not _COOKIE_GLOB_RE.fullmatch(name)):
                problems.append(f"{sw}: cookie signals need a cookie-name glob")
            if stype == "status" and not statuses:
                problems.append(f"{sw}: status signals need statuses")
            if stype == "body" and not pattern:
                problems.append(f"{sw}: body signals need a pattern")
            if name is not None and (not isinstance(name, str) or not _LABEL_RE.fullmatch(name)):
                problems.append(f"{sw}: name must be printable ASCII without spaces")
            if pattern is not None:
                if not isinstance(pattern, str):
                    problems.append(f"{sw}: pattern must be a string")
                else:
                    try:
                        re.compile(pattern, re.I)
                    except re.error:
                        problems.append(f"{sw}: pattern does not compile")
            if not _urls_ok(sig.get("sources")):
                problems.append(f"{sw}: needs at least one https source URL that contains this signal")
            note = sig.get("note")
            if note is not None and (not isinstance(note, str) or not note.strip()):
                problems.append(f"{sw}: note must be a non-empty string")

    direct_ids: set[str] = set()
    for i, entry in enumerate(direct.get("entries", []) if isinstance(direct, dict) else []):
        where = f"direct.json entries[{i}]"
        if not isinstance(entry, dict):
            problems.append(f"{where}: expected an object")
            continue
        if is_catalog_id(entry.get("id")):
            direct_ids.add(entry["id"])
        if not isinstance(entry.get("reason"), str) or not entry["reason"].strip():
            problems.append(f"{where}: reason must be a non-empty string")
        if not _urls_ok(entry.get("docs")):
            problems.append(f"{where}: needs at least one https docs URL")

    for eid in sorted(bg_ids & direct_ids):
        problems.append(f"id {eid!r} is used in both background.json and direct.json")
    return problems


def _build(docs: tuple[dict[str, Any], dict[str, Any], dict[str, Any]]) -> Catalogs:
    try:
        catalogs = Catalogs.from_documents(*docs)
    except (ValueError, re.error) as exc:
        raise CatalogError(str(exc)) from None
    problems = check_documents(*docs)
    if problems:
        raise CatalogError("; ".join(problems[:10]))
    return catalogs


@lru_cache(maxsize=1)
def _packaged() -> Catalogs:
    return _build(load_documents())


def load_catalogs(directory: str | os.PathLike[str] | None = None) -> Catalogs:
    """Validated catalogs.

    Without ``directory`` the packaged catalogs are loaded once per process and
    cached. ``directory`` (tests only) loads and validates that directory's
    files on every call, without caching. Raises :class:`CatalogError`.
    """
    if directory is None:
        return _packaged()
    return _build(load_documents(directory))


def catalog_versions(catalogs: Catalogs | None = None) -> dict[str, str]:
    """``{"background", "challenges", "direct"}`` versions (packaged catalogs by default)."""
    return (catalogs or load_catalogs()).versions()


def match_host(pattern: str, host: str) -> bool:
    """Host glob matching used by every catalog: ``*`` is the only wildcard.

    ``*`` matches zero or more characters, dots included, so ``*.example.com``
    matches ``a.b.example.com`` but not ``example.com``. Case-insensitive; an
    invalid pattern or host never matches. Same as ``types.host_glob_match``.
    """
    return host_glob_match(pattern, host)


def background_deny_rules(catalogs: Catalogs) -> tuple[Any, ...]:
    """``HostRule`` objects for ``--deny-catalog background``.

    One rule per host glob of every background entry, labelled
    ``catalog:background:<entry id>`` (contracts section 3.1).
    """
    from ..config import HostRule

    return tuple(
        HostRule(pattern=glob, label=f"catalog:background:{entry.id}")
        for entry in catalogs.background
        for glob in entry.hosts
    )


def direct_rules(catalogs: Catalogs) -> tuple[Any, ...]:
    """``HostRule`` objects for ``--env-all`` non-target carriage, labelled with the direct.json id."""
    from ..config import HostRule

    return tuple(HostRule(pattern=glob, label=entry.id) for entry in catalogs.direct for glob in entry.hosts)


def background_hosts_seen(catalogs: Catalogs, hosts: Iterable[str]) -> dict[str, list[str]]:
    """Map background entry id -> sorted concrete hosts from ``hosts`` that match it."""
    seen: dict[str, set[str]] = {}
    for host in hosts:
        entry = catalogs.background_entry_for(host)
        if entry is not None:
            seen.setdefault(entry.id, set()).add(host)
    return {k: sorted(v) for k, v in sorted(seen.items())}


__all__ = [
    "CatalogError",
    "background_deny_rules",
    "background_hosts_seen",
    "catalog_versions",
    "check_documents",
    "direct_rules",
    "load_catalogs",
    "load_documents",
    "match_host",
]
