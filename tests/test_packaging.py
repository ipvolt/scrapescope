"""Packaging and release-readiness checks (docs-1, docs-2, docs-3)."""

from __future__ import annotations

import importlib.metadata
import importlib.util
import os
import re
import tomllib
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _release_check() -> ModuleType:
    spec = importlib.util.spec_from_file_location("release_check", ROOT / "scripts" / "release_check.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _version_tuple(text: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", text)[:3])


def test_h11_floor_excludes_the_chunked_encoding_advisory() -> None:
    """docs-3: h11 < 0.16 accepts malformed chunked bodies (GHSA-vqfr-h8mv-ghfj, CVE-2025-43859)."""
    deps = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["dependencies"]
    (h11,) = [d for d in deps if re.match(r"h11\b", d)]
    floor = re.search(r">=\s*([0-9.]+)", h11)
    assert floor is not None and _version_tuple(floor.group(1)) >= (0, 16), h11
    assert _version_tuple(importlib.metadata.version("h11")) >= (0, 16)


def test_no_project_url_points_at_an_unreserved_namespace() -> None:
    """docs-1 / honest-4: no file the wheel or sdist carries names a URL under an unreserved namespace.

    The file list comes from pyproject.toml's hatch build targets (every file of
    the wheel's package and of the sdist's include list); wheels and sdists
    already built in dist/ are scanned member by member too.
    """
    rc = _release_check()
    shipped = {p.relative_to(ROOT).as_posix() for p in rc.packaged_files()}
    assert {"src/scrapescope/report/schema.json", "src/scrapescope/catalog/challenges.json", "README.md",
            "docs/method.md", "tests/test_packaging.py", "scripts/release_check.py"} <= shipped
    assert rc.namespace_problems() == []


def test_namespace_scan_finds_urls_in_files_and_built_archives(tmp_path: Path) -> None:
    import io
    import tarfile
    import zipfile

    rc = _release_check()
    ns = "github.com/example-unreserved"
    (tmp_path / "pyproject.toml").write_text(
        '[tool.hatch.build.targets.wheel]\npackages = ["src/pkg"]\n'
        '[tool.hatch.build.targets.sdist]\ninclude = ["src/pkg", "docs", "README.md"]\n'
    )
    pkg = tmp_path / "src" / "pkg"
    pkg.mkdir(parents=True)
    (pkg / "schema.json").write_text('{"$id": "https://' + ns + '/pkg/blob/main/schema.json"}\n')
    (pkg / "ok.py").write_text("# the namespace " + ns + " is not reserved yet (prose, not a URL)\n")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "a.md").write_text("see " + ns + "/pkg/issues\n")
    (tmp_path / "README.md").write_text("fine\n")
    (tmp_path / "unshipped.md").write_text("https://" + ns + "\n")
    problems = rc.namespace_problems(tmp_path, (ns,))
    assert len(problems) == 2, problems
    assert problems[0].startswith("docs/a.md:1:") or problems[1].startswith("docs/a.md:1:")
    assert any(p.startswith("src/pkg/schema.json:1:") for p in problems)

    dist = tmp_path / "dist"
    dist.mkdir()
    with zipfile.ZipFile(dist / "pkg-1.0-py3-none-any.whl", "w") as zf:
        zf.writestr("pkg-1.0.dist-info/METADATA", "Project-URL: Homepage, https://" + ns + "\n")
    data = ("User-Agent: pkg/1.0 (+http://www." + ns + ")\n").encode()
    with tarfile.open(dist / "pkg-1.0.tar.gz", "w:gz") as tf:
        info = tarfile.TarInfo("pkg-1.0/PKG-INFO")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    problems = rc.namespace_problems(tmp_path, (ns,))
    assert any("pkg-1.0-py3-none-any.whl!pkg-1.0.dist-info/METADATA:1:" in p for p in problems)
    assert any("pkg-1.0.tar.gz!pkg-1.0/PKG-INFO:1:" in p for p in problems)
    assert rc.namespace_problems(tmp_path, ()) == []


#: The placeholders, assembled so that this file (which the sdist ships) passes the release check.
MAINTAINER_PLACEHOLDER = "<" + "maintainer name>"
CONTACT_PLACEHOLDER = "<" + "security contact email>"


def test_release_check_finds_placeholders_relative_links_and_missing_urls(tmp_path: Path) -> None:
    rc = _release_check()
    (tmp_path / "README.md").write_text(
        f"Maintained by {MAINTAINER_PLACEHOLDER}.\nSee [the notice](NOTICE), [docs](https://example.org/d) and [x](#y).\n"
    )
    (tmp_path / "SECURITY.md").write_text(f"Reports go to {CONTACT_PLACEHOLDER}.\n")
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n')
    src = tmp_path / "src" / "scrapescope"
    src.mkdir(parents=True)
    (src / "config.py").write_text('USER_AGENT = f"scrapescope/{__version__}"\n')
    problems = rc.check(tmp_path)
    text = "\n".join(problems)
    assert f"README.md:1: placeholder '{MAINTAINER_PLACEHOLDER}'" in text
    assert f"SECURITY.md:1: placeholder '{CONTACT_PLACEHOLDER}'" in text
    assert "relative link 'NOTICE'" in text and "example.org" not in text and "'#y'" not in text
    assert "no [project.urls]" in text and "USER_AGENT has no contact URL" in text

    (tmp_path / "README.md").write_text("Maintained by A. Person. [notice](https://example.org/NOTICE)\n")
    (tmp_path / "SECURITY.md").write_text("Reports go to security@example.org.\n")
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n[project.urls]\nSource = "https://example.org/x"\n')
    (src / "config.py").write_text('USER_AGENT = f"scrapescope/{__version__} (+https://example.org/x)"\n')
    assert rc.check(tmp_path) == []


def test_release_check_reads_every_shipped_file_and_not_its_own_documentation() -> None:
    """pkg4-1: the placeholder scan covers everything the sdist ships (docs/dev, scripts, tests), and the
    files that describe the placeholder (CONTRIBUTING, method.md, the checklist, the script itself) do not
    trip it, so filling in the real placeholders is enough to pass."""
    rc = _release_check()
    shipped = {p.relative_to(ROOT).as_posix() for p in rc.shipped_files()}
    assert {"docs/dev/contracts.md", "docs/dev/release-checklist.md", "scripts/release_check.py",
            "scripts/make_example_reports.py", "tests/test_packaging.py", "README.md", "SECURITY.md"} <= shipped
    flagged = {line.split(":", 1)[0] for line in rc.placeholder_problems(rc.shipped_files())}
    assert flagged <= {"README.md", "CONTRIBUTING.md", "SECURITY.md"}, flagged


@pytest.mark.skipif(os.environ.get("SCRAPESCOPE_RELEASE_CHECK") != "1", reason="release gate: set SCRAPESCOPE_RELEASE_CHECK=1")
def test_tree_is_ready_for_a_public_release() -> None:
    """docs-2: fails while the maintainer-name placeholder or other release blockers remain (run before any public build)."""
    assert _release_check().check() == []


@pytest.mark.timeout(180)
def test_the_suite_without_the_browser_extra_needs_no_playwright() -> None:
    """pkg-r3-1: CI's "without a browser" job installs only ``.[dev]``; Playwright is an optional extra.

    Every test module must import without Playwright, and tests not marked ``browser`` must pass
    or skip without it. This runs, in a subprocess with Playwright made unimportable
    (``tests/_no_playwright.py``), a collection of the whole suite and the non-browser tests that
    once needed the package (the find CLI tests fake ``run_find``; the route-wrapper test imports
    Playwright internals).
    """
    import subprocess
    import sys

    env = {**os.environ, "SCRAPESCOPE_SKIP_BROWSER_TESTS": "1"}
    base = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "tests._no_playwright"]
    collect = subprocess.run([*base, "--collect-only", "tests"], cwd=ROOT, env=env, capture_output=True, text=True,
                             timeout=120)
    assert collect.returncode == 0, collect.stdout[-2000:] + collect.stderr[-2000:]
    run = subprocess.run(
        [*base, "-m", "not browser", "tests/test_cli.py", "tests/test_helpers_playwright.py", "-k",
         "find or route_wrappers or helpers_inactive"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=150,
    )
    assert run.returncode == 0, run.stdout[-3000:] + run.stderr[-2000:]
    assert " passed" in run.stdout and "failed" not in run.stdout


def test_shipped_files_name_no_local_home_directory() -> None:
    """pkg-r3-2: no file the wheel or sdist carries holds a developer's absolute home path."""
    rc = _release_check()
    pattern = re.compile(r"(?<![\w.])/(?:Users|home)/[A-Za-z0-9._-]+/")
    hits = []
    for path in rc.packaged_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if pattern.search(line) and "pattern = re.compile" not in line:
                hits.append(f"{path.relative_to(ROOT).as_posix()}:{number}")
    assert hits == []


def test_python_sources_hold_no_invisible_or_bidi_characters() -> None:
    """Contract section 1: write ``\\uXXXX`` escapes, never literal control, bidi or separator characters.

    File-writing tools can turn a typed escape into the literal character (U+202E, U+2028...),
    which then hides in review ("Trojan Source"). Every .py file under src/, tests/ and scripts/.
    """
    import unicodedata

    hits = []
    for folder in ("src", "tests", "scripts"):
        for path in sorted((ROOT / folder).rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            for index, char in enumerate(text):
                if char in "\t\n\r":
                    continue
                if unicodedata.category(char) in ("Cc", "Cf", "Zl", "Zp", "Cs"):
                    line = text.count("\n", 0, index) + 1
                    hits.append(f"{path.relative_to(ROOT).as_posix()}:{line}: U+{ord(char):04X}")
    assert hits == []
