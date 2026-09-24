"""A small JSON Schema validator for the subset report/schema.json uses.

Supported keywords (docs/dev/contracts.md section 11.1): ``$schema``, ``$id``,
``$ref`` (JSON pointers into the same document, e.g. ``#/$defs/x``),
``$defs``, ``title``, ``description``, ``type`` (string or list), ``const``,
``enum``, ``properties``, ``required``, ``additionalProperties`` (bool or
schema), ``propertyNames``, ``items``, ``maxItems``, ``minimum``, ``maximum``,
``minLength``, ``maxLength``, ``pattern``. Any other keyword in a schema raises
:class:`SchemaError`, so the schema cannot silently outgrow this validator.

Semantics follow draft 2020-12 for that subset:

- ``integer`` excludes booleans and non-integral floats; ``number`` excludes
  booleans; ``const``/``enum`` compare JSON values (``true`` is not ``1``).
- Keywords apply only to instances of their type (``properties`` on a
  ``["object", "null"]`` schema ignores ``null``).
- A pattern written ``^...$`` must match the whole string, so a trailing
  newline never slips past ``$``; other patterns are searched, as in JSON Schema.
- Lengths count code points.

Error messages give a JSON path and the failed keyword, never the offending
value (a report may be hostile, and values are not needed to fix it).
"""

from __future__ import annotations

import json
import math
import re
from functools import lru_cache
from importlib import resources
from typing import Any

from ..types import safe_text

SUPPORTED_KEYWORDS = frozenset(
    {
        "$schema",
        "$id",
        "$ref",
        "$defs",
        "title",
        "description",
        "type",
        "const",
        "enum",
        "properties",
        "required",
        "additionalProperties",
        "propertyNames",
        "items",
        "maxItems",
        "minimum",
        "maximum",
        "minLength",
        "maxLength",
        "pattern",
    }
)
_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")


class SchemaError(ValueError):
    """The schema itself uses something this validator does not support."""


def _is_type(value: Any, name: str) -> bool:
    if name == "null":
        return value is None
    if name == "boolean":
        return isinstance(value, bool)
    if name == "integer":
        if isinstance(value, bool):
            return False
        if isinstance(value, int):
            return True
        return isinstance(value, float) and math.isfinite(value) and value.is_integer()
    if name == "number":
        if isinstance(value, bool):
            return False
        if isinstance(value, int):
            return True
        return isinstance(value, float) and math.isfinite(value)
    if name == "string":
        return isinstance(value, str)
    if name == "array":
        return isinstance(value, (list, tuple))
    if name == "object":
        return isinstance(value, dict)
    raise SchemaError(f"unsupported type name {name!r}")


def _json_equal(a: Any, b: Any) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_json_equal(a[k], b[k]) for k in a)
    if isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)):
        return len(a) == len(b) and all(_json_equal(x, y) for x, y in zip(a, b))
    if type(a) is not type(b):
        return False
    return a == b


def _child_path(path: str, key: str) -> str:
    if _KEY_RE.fullmatch(key):
        return f"{path}.{key}"
    return f"{path}[{json.dumps(safe_text(key, 64))}]"


class Validator:
    """Validates instances against one schema document (the subset above)."""

    def __init__(self, schema: dict[str, Any]) -> None:
        if not isinstance(schema, dict):
            raise SchemaError("schema must be an object")
        self.root = schema
        self._patterns: dict[str, tuple[re.Pattern[str], bool]] = {}
        self._check_keywords(schema)

    # -- schema checks -------------------------------------------------

    def _check_keywords(self, node: Any) -> None:
        if isinstance(node, dict):
            unknown = set(node) - SUPPORTED_KEYWORDS
            if unknown:
                raise SchemaError(f"unsupported schema keywords: {sorted(unknown)}")
            for key in ("properties", "$defs"):
                for sub in node.get(key, {}).values():
                    self._check_keywords(sub)
            for key in ("items", "propertyNames", "additionalProperties"):
                if isinstance(node.get(key), dict):
                    self._check_keywords(node[key])
            if "pattern" in node:
                self._pattern(node["pattern"])
            if "$ref" in node:
                self._resolve(node["$ref"])
        elif not isinstance(node, bool):
            raise SchemaError("a schema must be an object or a boolean")

    def _pattern(self, pattern: str) -> tuple[re.Pattern[str], bool]:
        cached = self._patterns.get(pattern)
        if cached is None:
            if not isinstance(pattern, str):
                raise SchemaError("pattern must be a string")
            anchored = len(pattern) >= 2 and pattern.startswith("^") and pattern.endswith("$") and not pattern.endswith("\\$")
            body = f"(?:{pattern[1:-1]})" if anchored else pattern
            try:
                cached = (re.compile(body), anchored)
            except re.error as exc:
                raise SchemaError(f"pattern does not compile: {exc}") from None
            self._patterns[pattern] = cached
        return cached

    def _resolve(self, ref: str) -> Any:
        if not isinstance(ref, str) or not ref.startswith("#"):
            raise SchemaError("only local $ref values ('#/...') are supported")
        node: Any = self.root
        pointer = ref[1:]
        if pointer:
            if not pointer.startswith("/"):
                raise SchemaError(f"bad $ref {ref!r}")
            for part in pointer[1:].split("/"):
                part = part.replace("~1", "/").replace("~0", "~")
                if not isinstance(node, dict) or part not in node:
                    raise SchemaError(f"unresolvable $ref {ref!r}")
                node = node[part]
        return node

    # -- instance validation -------------------------------------------

    def errors(self, instance: Any, *, limit: int = 100) -> list[str]:
        """All problems (up to ``limit``) as ``"<path>: <message>"`` strings."""
        out: list[str] = []
        self._validate(instance, self.root, "$", out, limit)
        return out[:limit]

    def _validate(self, value: Any, schema: Any, path: str, out: list[str], limit: int) -> None:
        if len(out) >= limit:
            return
        if schema is True:
            return
        if schema is False:
            out.append(f"{path}: not allowed")
            return
        if "$ref" in schema:
            self._validate(value, self._resolve(schema["$ref"]), path, out, limit)
        if "type" in schema:
            types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
            if not any(_is_type(value, t) for t in types):
                out.append(f"{path}: expected {' or '.join(types)}")
                return
        if "const" in schema and not _json_equal(value, schema["const"]):
            out.append(f"{path}: must equal the schema's constant")
        if "enum" in schema and not any(_json_equal(value, option) for option in schema["enum"]):
            out.append(f"{path}: not one of the allowed values")

        if isinstance(value, dict):
            self._validate_object(value, schema, path, out, limit)
        elif isinstance(value, (list, tuple)):
            if "maxItems" in schema and len(value) > schema["maxItems"]:
                out.append(f"{path}: more than {schema['maxItems']} items")
            if "items" in schema:
                for i, item in enumerate(value):
                    self._validate(item, schema["items"], f"{path}[{i}]", out, limit)
                    if len(out) >= limit:
                        return
        elif isinstance(value, str):
            if "minLength" in schema and len(value) < schema["minLength"]:
                out.append(f"{path}: shorter than {schema['minLength']} characters")
            if "maxLength" in schema and len(value) > schema["maxLength"]:
                out.append(f"{path}: longer than {schema['maxLength']} characters")
            if "pattern" in schema:
                regex, anchored = self._pattern(schema["pattern"])
                ok = regex.fullmatch(value) if anchored else regex.search(value)
                if not ok:
                    out.append(f"{path}: does not match the required pattern")
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            if "minimum" in schema and value < schema["minimum"]:
                out.append(f"{path}: below the minimum {schema['minimum']}")
            if "maximum" in schema and value > schema["maximum"]:
                out.append(f"{path}: above the maximum {schema['maximum']}")

    def _validate_object(self, value: dict[str, Any], schema: dict[str, Any], path: str, out: list[str], limit: int) -> None:
        for name in schema.get("required", []):
            if name not in value:
                out.append(f"{_child_path(path, name)}: required property missing")
        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties", True)
        names = schema.get("propertyNames")
        for key, item in value.items():
            if len(out) >= limit:
                return
            if not isinstance(key, str):
                out.append(f"{path}: property names must be strings")
                continue
            child = _child_path(path, key)
            if names is not None:
                before = len(out)
                self._validate(key, names, child, out, limit)
                if len(out) > before:
                    out[before:] = [f"{child}: property name not allowed"]
                    continue
            if key in properties:
                self._validate(item, properties[key], child, out, limit)
            elif additional is False:
                out.append(f"{child}: unexpected property")
            elif isinstance(additional, dict):
                self._validate(item, additional, child, out, limit)


@lru_cache(maxsize=1)
def _schema_text() -> str:
    return resources.files("scrapescope.report").joinpath("schema.json").read_text(encoding="utf-8")


def load_schema() -> dict[str, Any]:
    """The report.json v1 JSON Schema shipped with the package (a fresh copy)."""
    return json.loads(_schema_text())


@lru_cache(maxsize=1)
def _report_validator() -> Validator:
    return Validator(load_schema())


def validate(report: Any, *, limit: int = 100) -> list[str]:
    """Problems with ``report`` against schema.json; ``[]`` when it is valid."""
    return _report_validator().errors(report, limit=limit)


__all__ = ["SUPPORTED_KEYWORDS", "SchemaError", "Validator", "load_schema", "validate"]
