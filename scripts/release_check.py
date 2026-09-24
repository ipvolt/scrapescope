"""Pre-release checks: run before building anything meant for other people.

    python scripts/release_check.py          # exit 0 when ready, 1 with a list of problems
    python scripts/release_check.py --urls   # also print every project URL to open by hand

It never touches the network. It checks every file that ends up in the sdist
or wheel (read from pyproject.toml's build targets; the README is also the
PyPI long description) for:

1. placeholders: the maintainer-name and security-contact placeholders in
   angle brackets (the README's first screen, the maintainer references in
   CONTRIBUTING.md and SECURITY.md), and the unfinished-work markers that
   ``PLACEHOLDER_RE`` lists. Text that describes a placeholder names it in
   words ("the maintainer-name placeholder"), so that the check does not flag
   its own documentation;
2. relative links in README.md, which break in the PyPI long description (the
   package is installed from GitHub for now, where they work; this item stays
   open until the planned PyPI publication);
3. a ``[project.urls]`` table and a User-Agent contact URL: both must exist
   and resolve before a public release. The script lists them with ``--urls``;
   opening each one is a manual step of docs/dev/release-checklist.md;
4. URLs under a namespace nobody has reserved yet (``UNRESERVED_NAMESPACES``),
   in every file the wheel and sdist carry (read from pyproject.toml's build
   targets) and in any wheel or sdist already built in ``dist/``. Anyone could
   register such a namespace and receive the traffic. Remove a namespace from
   the tuple once the project owns it.

The test suite runs the checker on synthetic input always, and on the real
tree only with ``SCRAPESCOPE_RELEASE_CHECK=1`` (tests/test_packaging.py), so a
development checkout stays green while the placeholders are open.
"""

from __future__ import annotations

import re
import sys
import tarfile
import tomllib
import zipfile
from collections.abc import Iterable, Iterator
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: Placeholders that must never ship. The pattern is assembled from pieces so that this file,
#: which the sdist ships, does not match it.
PLACEHOLDER_RE = re.compile("<" r"maintainer[^>\n]*>|<" "name>|<" r"security contact[^>\n]*>|\bT" r"BD\b|\bFIX" r"ME\b")
#: Markdown links whose target is not absolute (http(s), mailto) or an in-page anchor.
RELATIVE_LINK_RE = re.compile(r"\]\((?!https?://|mailto:|#)([^)\s]+)\)")
#: Namespaces the project has not reserved yet (docs/dev/release-checklist.md, item 2). A URL under
#: one of them would send users, and --verify's site operators, to a name anyone could register.
#: The GitHub repository (github.com/ipvolt/scrapescope) exists since 2026-09-24, so its namespace
#: is no longer listed; the PyPI project name stays here until the planned publication reserves it.
UNRESERVED_NAMESPACES: tuple[str, ...] = ("pypi.org/project/scrapescope",)
#: Directories and suffixes hatchling leaves out of the wheel and sdist.
_BUILD_SKIP_PARTS = frozenset({"__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache"})
_BUILD_SKIP_SUFFIXES = (".pyc", ".pyo")


def namespace_url_re(namespaces: Iterable[str] = UNRESERVED_NAMESPACES) -> re.Pattern[str] | None:
    """A pattern for URLs under ``namespaces``: with a scheme, or bare with a path below the namespace.

    Mentions of the bare namespace in prose (``the namespace github.com/x``) do not match.
    """
    names = [re.escape(n.strip("/")) for n in namespaces if n.strip("/")]
    if not names:
        return None
    alt = "|".join(names)
    return re.compile(rf"(?:https?://(?:www\.)?(?:{alt})(?![A-Za-z0-9_.-])|(?<![A-Za-z0-9_.-])(?:www\.)?(?:{alt})/[A-Za-z0-9_.~%-])")


def _build_targets(root: Path) -> tuple[list[str], list[str]]:
    """(wheel package directories, sdist include entries) from pyproject.toml."""
    data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    targets = data.get("tool", {}).get("hatch", {}).get("build", {}).get("targets", {})
    wheel = [str(p) for p in targets.get("wheel", {}).get("packages", [])]
    sdist = [str(p) for p in targets.get("sdist", {}).get("include", [])]
    return wheel, sdist


def _walk(path: Path) -> Iterator[Path]:
    if path.is_file():
        yield path
    elif path.is_dir():
        for child in sorted(path.rglob("*")):
            if child.is_file() and not (set(child.parts) & _BUILD_SKIP_PARTS) and not child.name.endswith(_BUILD_SKIP_SUFFIXES):
                yield child


def packaged_files(root: Path = ROOT) -> list[Path]:
    """Every source file the wheel or the sdist carries, per pyproject.toml's hatch build targets."""
    wheel, sdist = _build_targets(root)
    seen: dict[Path, None] = {}
    for entry in [*wheel, *sdist, "pyproject.toml"]:
        for path in _walk(root / entry):
            seen.setdefault(path, None)
    return list(seen)


def _archive_texts(dist: Path) -> Iterator[tuple[str, str]]:
    """(name, text) of every member of the wheels and sdists in ``dist`` (binary members decoded leniently)."""
    for wheel in sorted(dist.glob("*.whl")):
        with zipfile.ZipFile(wheel) as zf:
            for info in zf.infolist():
                if not info.is_dir():
                    yield f"{wheel.name}!{info.filename}", zf.read(info).decode("utf-8", "replace")
    for sdist in sorted(dist.glob("*.tar.gz")):
        with tarfile.open(sdist, "r:gz") as tf:
            for member in tf.getmembers():
                handle = tf.extractfile(member) if member.isfile() else None
                if handle is not None:
                    yield f"{sdist.name}!{member.name}", handle.read().decode("utf-8", "replace")


def namespace_problems(root: Path = ROOT, namespaces: Iterable[str] = UNRESERVED_NAMESPACES) -> list[str]:
    """URLs under an unreserved namespace in the packaged files and in any built archive in ``dist/``."""
    pattern = namespace_url_re(namespaces)
    if pattern is None:
        return []
    problems = []

    def scan(name: str, text: str) -> None:
        for lineno, line in enumerate(text.splitlines(), start=1):
            match = pattern.search(line)
            if match:
                problems.append(f"{name}:{lineno}: URL under an unreserved namespace {match.group(0)!r}")

    for path in packaged_files(root):
        scan(str(path.relative_to(root)), path.read_bytes().decode("utf-8", "replace"))
    dist = root / "dist"
    if dist.is_dir():
        for name, text in _archive_texts(dist):
            scan(f"dist/{name}", text)
    return problems


def shipped_files(root: Path = ROOT) -> Iterator[Path]:
    """Every file that the sdist or wheel carries (docs/dev, scripts and tests included).

    README.md, SECURITY.md and CONTRIBUTING.md are listed even when pyproject.toml's build
    targets do not name them, since they are the project's public text.
    """
    seen: dict[Path, None] = {}
    for name in ("README.md", "CONTRIBUTING.md", "SECURITY.md"):
        path = root / name
        if path.is_file():
            seen.setdefault(path, None)
    if (root / "pyproject.toml").is_file():
        for path in packaged_files(root):
            seen.setdefault(path, None)
    yield from seen


def placeholder_problems(files: Iterable[Path], root: Path = ROOT) -> list[str]:
    problems = []
    for path in files:
        text = path.read_bytes().decode("utf-8", "replace")
        for lineno, line in enumerate(text.splitlines(), start=1):
            for match in PLACEHOLDER_RE.finditer(line):
                problems.append(f"{path.relative_to(root)}:{lineno}: placeholder {match.group(0)!r}")
    return problems


def relative_link_problems(readme: Path, root: Path = ROOT) -> list[str]:
    if not readme.is_file():
        return [f"{readme.relative_to(root)}: missing"]
    problems = []
    for lineno, line in enumerate(readme.read_text(encoding="utf-8").splitlines(), start=1):
        for match in RELATIVE_LINK_RE.finditer(line):
            problems.append(
                f"{readme.relative_to(root)}:{lineno}: relative link {match.group(1)!r} "
                "(breaks in the PyPI long description; use an absolute URL)"
            )
    return problems


def project_urls(root: Path = ROOT) -> dict[str, str]:
    data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    urls = data.get("project", {}).get("urls", {})
    return {str(k): str(v) for k, v in urls.items()}


def user_agent_contact(root: Path = ROOT) -> str | None:
    text = (root / "src" / "scrapescope" / "config.py").read_text(encoding="utf-8")
    match = re.search(r'^USER_AGENT = f?"([^"]*)"', text, re.M)
    if match is None:
        return None
    url = re.search(r"https?://[^\s)]+", match.group(1))
    return url.group(0) if url else None


def url_problems(root: Path = ROOT) -> list[str]:
    problems = []
    if not project_urls(root):
        problems.append("pyproject.toml: no [project.urls] (add Homepage, Source and Issues once they resolve)")
    if user_agent_contact(root) is None:
        problems.append("src/scrapescope/config.py: USER_AGENT has no contact URL (add one that resolves)")
    return problems


def check(root: Path = ROOT) -> list[str]:
    """Every problem found, one line each; empty when the tree is ready for a release build."""
    return (
        placeholder_problems(shipped_files(root), root)
        + relative_link_problems(root / "README.md", root)
        + url_problems(root)
        + namespace_problems(root)
    )


def main(argv: list[str]) -> int:
    problems = check()
    for line in problems:
        print(line)
    if "--urls" in argv:
        print("URLs to open by hand before a release (each must resolve):")
        for name, url in project_urls().items():
            print(f"  [project.urls] {name}: {url}")
        contact = user_agent_contact()
        print(f"  User-Agent contact: {contact or '(none)'}")
    print(f"{len(problems)} problem(s)" if problems else "release check: no problems found")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
