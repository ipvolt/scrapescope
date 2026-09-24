# Release checklist

Work through this list before building anything meant for other people (a
wheel or sdist shared with testers, a PyPI upload, a public repository). Each
item names who decides it. `python scripts/release_check.py` checks the
mechanical parts and exits 1 while any of them is open;
`SCRAPESCOPE_RELEASE_CHECK=1 python -m pytest tests/test_packaging.py` runs the
same gate as a test.

## Owner decisions

1. **Maintainer name.** Replace every maintainer-name placeholder (the words
   "maintainer name" in angle brackets; `python scripts/release_check.py`
   lists each one): the statements on the README's first screen (plan
   section 6: "reviews it", "every change is reviewed and merged by"),
   CONTRIBUTING.md ("reviews it", "reviews and merges every change") and
   SECURITY.md. The
   README text becomes the PyPI long description, so a build made before this
   step publishes the placeholder. *Done 2026-09-24: the maintainer is named
   as the ipvolt team, no individual.*
2. **Namespace.** Reserve the GitHub organisation and repository (and the PyPI
   project name) before any URL points at them. Until then no shipped file may
   name a URL under the namespace:
   `tests/test_packaging.py::test_no_project_url_points_at_an_unreserved_namespace`
   scans every file the wheel and sdist carry (from pyproject.toml's build
   targets) and every wheel and sdist in `dist/`, for the namespaces in
   `scripts/release_check.py` (`UNRESERVED_NAMESPACES`). Remove a namespace
   from that tuple only once the project owns it. *2026-09-24: the public
   home is https://github.com/ipvolt/scrapescope, so the GitHub namespace
   left the tuple; the PyPI project name is not reserved and stays in it
   (`pypi.org/project/scrapescope`) until the planned publication.*
3. **Security contact (blocker).** SECURITY.md names `hello@ipvolt.com`, a
   shared mailbox that ipvolt staff and ipvolt's AI mail assistants read, and
   says so. Replace it with a dedicated address that only the maintainers
   read (or document exactly who and what processes it). *Still open at the
   first public release (2026-09-24): SECURITY.md keeps the honest mailbox
   note and names GitHub's private vulnerability reporting on the repository
   as the alternative.*
4. **Review record.** A human line-by-line review of the code base has not been
   done yet (2026-09-24). Do that review and record it in the repository's
   history (for example signed-off commits or a merged review) before 1.0.
5. **Prelaunch wording (plan decision 13).** If the release happens before
   ipvolt's proxy access opens, switch every public mention of ipvolt (the
   README's first screen, NOTICE, CONTRIBUTING.md, SECURITY.md and the PyPI
   long description) to prelaunch wording: "a proxy provider launching in
   <month>", not "a proxy provider". Check the wording again on release day.

## After the repository exists

6. Add `[project.urls]` (Homepage, Source, Issues) to `pyproject.toml`.
   *Done 2026-09-24.*
7. Add the contact URL to `config.USER_AGENT`
   (`scrapescope/<version> (+https://...)`), so `--verify` requests identify a
   working contact, as sites such as Wikimedia ask. Update
   `tests/test_config.py::test_user_agent_is_honest`. *Done 2026-09-24.*
8. Replace the README's relative links (`docs/...`, `NOTICE`, `SECURITY.md`,
   `src/scrapescope/catalog/...`) with absolute URLs to the repository, since
   PyPI does not resolve relative links in the long description. *Open: the
   package is installed from GitHub, where relative links work; do this
   before the planned PyPI publication. `release_check.py` keeps reporting
   them until then.*
9. The report schema's `$id` is `urn:scrapescope:report:v1`, which resolves
   nowhere by design. Replace it with the published schema URL only once that
   URL resolves.
10. Open every URL that `python scripts/release_check.py --urls` prints and
   confirm that each resolves.
11. **CI.** Pin every action in `.github/workflows/ci.yml` to a full commit
    SHA (*done 2026-09-24: actions/checkout v4.4.0, astral-sh/setup-uv
    v6.8.0, actions/setup-node v4.4.0; the workflow needs no secrets*), then
    run the workflow. It builds the wheel and sdist, installs the
    wheel into a fresh environment on Linux (ubuntu-22.04 and 24.04) and
    macOS with Python 3.11 to 3.14, runs `--version`, `--help` and `report`,
    installs it as a uv tool, runs the suite without a browser, and runs the
    full suite with Playwright's Chromium and Node on one Linux and one macOS
    job. Once it passes, add the `Operating System :: POSIX :: Linux` and
    Python version classifiers it covers to `pyproject.toml` (they list only
    macOS and 3.12 today) and update claims M7 and O1 in docs/method.md.

## Checks

12. `python scripts/release_check.py` reports no problems.
13. `python -m pytest` passes three times in a row on macOS and on Linux (M7 in
    the claims table is still open for Linux).
14. `python scripts/make_example_reports.py` reports no stale golden reports.
15. `SCRAPESCOPE_CHECK_CATALOG_URLS=1 python -m pytest tests/test_catalog.py -k
    still_name_their_hosts` passes (it fetches every direct.json docs URL and
    background.json host_evidence URL).
16. Re-check the prior-work descriptions and dates in the README against each
    project's pages (claim O5), the Node and aiohttp coverage rows (O6), and
    the README `find` demo values (O2).
17. Dependency floors: check the advisories for `h11`, `httpx`, `httpcore` and
    `playwright` (`h11>=0.16` excludes GHSA-vqfr-h8mv-ghfj).
18. Build the wheel and sdist, then inspect them: `unzip -p dist/*.whl
    '*/METADATA'` has no placeholders and the expected Project-URLs, and NOTICE
    (with the is-antibot licence notice) is in both. Run
    `python scripts/release_check.py` again with the archives in `dist/`: it
    scans every member for URLs under an unreserved namespace.
