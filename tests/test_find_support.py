"""Shared helpers for the find tests (no tests here).

- ``TEST_CHALLENGES``: a minimal challenges.json document used so the find
  tests do not depend on the shipped catalog's exact content.
- ``make_test_catalogs()`` / ``shipped_catalogs_or_none()``.
- ``validate_subset(instance, schema, root)``: a tiny validator for the JSON
  Schema subset report/schema.json uses (contracts.md section 11.1), so find
  results can be checked against the ``find`` definition without jsonschema.
"""

from __future__ import annotations

import json
import re
from importlib import resources
from typing import Any

from scrapescope.types import Catalogs

TEST_CHALLENGES: dict[str, Any] = {
    "version": "test-1",
    "attribution": "test catalog for tests/test_find_*.py",
    "vendors": [
        {
            "id": "cloudflare",
            "name": "Cloudflare",
            "source": None,
            "signals": [
                {"type": "header", "name": "cf-mitigated", "pattern": "^challenge$", "statuses": [], "strength": "challenge"},
                {
                    "type": "body",
                    "name": "just-a-moment",
                    "pattern": r"<title>\s*Just a moment\.\.\.\s*</title>",
                    "statuses": [403, 503],
                    "strength": "challenge",
                },
                {"type": "body", "name": None, "pattern": "/cdn-cgi/challenge-platform/", "statuses": [], "strength": "vendor"},
                {"type": "cookie", "name": "__cf_bm", "pattern": None, "statuses": [], "strength": "vendor"},
            ],
            "docs": [
                "https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/"
            ],
        },
        {
            "id": "aws-waf",
            "name": "AWS WAF",
            "source": None,
            "signals": [
                {"type": "header", "name": "x-amzn-waf-action", "pattern": "^challenge$", "statuses": [202], "strength": "challenge"},
                {"type": "header", "name": "x-amzn-waf-action", "pattern": "^captcha$", "statuses": [405], "strength": "challenge"},
            ],
            "docs": ["https://docs.aws.amazon.com/waf/latest/developerguide/waf-captcha-and-challenge-actions.html"],
        },
        {
            "id": "datadome",
            "name": "DataDome",
            "source": "is-antibot (MIT)",
            "signals": [
                {"type": "cookie", "name": "datadome", "pattern": None, "statuses": [403], "strength": "challenge"},
                {"type": "header", "name": "x-datadome", "pattern": None, "statuses": [], "strength": "vendor"},
            ],
            "docs": ["https://github.com/microlinkhq/is-antibot"],
        },
        {
            "id": "teapot",
            "name": "Teapot WAF",
            "source": None,
            "signals": [{"type": "status", "name": None, "pattern": None, "statuses": [418], "strength": "challenge"}],
            "docs": ["https://example.invalid/teapot"],
        },
    ],
}

_EMPTY_BACKGROUND = {"version": "test-1", "entries": []}
_EMPTY_DIRECT = {"version": "test-1", "entries": []}


def make_test_catalogs() -> Catalogs:
    """Catalogs with TEST_CHALLENGES and empty background/direct lists."""
    return Catalogs.from_documents(_EMPTY_BACKGROUND, TEST_CHALLENGES, _EMPTY_DIRECT)


def shipped_catalogs_or_none() -> Catalogs | None:
    """The shipped catalogs when challenges.json has vendors (not the architect stub)."""
    from scrapescope.catalog import load_catalogs

    try:
        catalogs = load_catalogs()
    except Exception:  # noqa: BLE001 - catalog being edited concurrently
        return None
    return catalogs if catalogs.challenges else None


def load_report_schema() -> dict[str, Any]:
    text = resources.files("scrapescope.report").joinpath("schema.json").read_text(encoding="utf-8")
    return json.loads(text)


def _type_ok(instance: Any, name: str) -> bool:
    if name == "null":
        return instance is None
    if name == "boolean":
        return isinstance(instance, bool)
    if name == "integer":
        return isinstance(instance, int) and not isinstance(instance, bool)
    if name == "number":
        return isinstance(instance, (int, float)) and not isinstance(instance, bool)
    if name == "string":
        return isinstance(instance, str)
    if name == "array":
        return isinstance(instance, list)
    if name == "object":
        return isinstance(instance, dict)
    raise AssertionError(f"unsupported type {name}")


def _pattern_ok(pattern: str, value: str) -> bool:
    if pattern.startswith("^") and pattern.endswith("$"):
        return re.fullmatch(pattern[1:-1], value) is not None
    return re.search(pattern, value) is not None


def validate_subset(instance: Any, schema: dict[str, Any], root: dict[str, Any], where: str = "$") -> list[str]:
    """Errors for ``instance`` against ``schema`` (subset of draft 2020-12)."""
    errors: list[str] = []
    if "$ref" in schema:
        ref = schema["$ref"]
        assert ref.startswith("#/$defs/"), ref
        return validate_subset(instance, root["$defs"][ref[len("#/$defs/") :]], root, where)
    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_type_ok(instance, t) for t in types):
            return [f"{where}: {instance!r} is not {types}"]
    if "const" in schema and instance != schema["const"]:
        errors.append(f"{where}: not const {schema['const']!r}")
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{where}: {instance!r} not in enum")
    if isinstance(instance, str):
        if "pattern" in schema and not _pattern_ok(schema["pattern"], instance):
            errors.append(f"{where}: {instance!r} does not match {schema['pattern']}")
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            errors.append(f"{where}: too long")
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append(f"{where}: too short")
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(f"{where}: below minimum")
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append(f"{where}: above maximum")
    if isinstance(instance, list):
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            errors.append(f"{where}: too many items")
        if "items" in schema:
            for i, item in enumerate(instance):
                errors.extend(validate_subset(item, schema["items"], root, f"{where}[{i}]"))
    if isinstance(instance, dict):
        props = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in instance:
                errors.append(f"{where}: missing {key}")
        for key, value in instance.items():
            if "propertyNames" in schema:
                errors.extend(validate_subset(key, schema["propertyNames"], root, f"{where}.<key {key}>"))
            if key in props:
                errors.extend(validate_subset(value, props[key], root, f"{where}.{key}"))
            else:
                extra = schema.get("additionalProperties", True)
                if extra is False:
                    errors.append(f"{where}: unexpected property {key!r}")
                elif isinstance(extra, dict):
                    errors.extend(validate_subset(value, extra, root, f"{where}.{key}"))
    return errors


def find_report_entry(result: Any) -> dict[str, Any]:
    """FindResult.to_dict() plus coverage.line, as the report builder adds it."""
    data = result.to_dict()
    data["coverage"]["line"] = result.coverage.summary(result.status == "found")
    return data


def validate_find_entry(result: Any) -> list[str]:
    schema = load_report_schema()
    return validate_subset(find_report_entry(result), schema["$defs"]["find"], schema)
