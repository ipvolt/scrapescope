"""pytest plugin for tests/test_packaging.py: run tests as if the ``[browser]`` extra were not installed.

``sys.modules[name] = None`` makes ``import playwright...`` raise ModuleNotFoundError and
``importlib.util.find_spec("playwright")`` return None, as for a package that is not installed
(pkg-r3-1). Use it in a subprocess: ``python -m pytest -p tests._no_playwright -m "not browser" ...``.
Subprocesses started by those tests still see the real environment.
"""

from __future__ import annotations

import sys

for _name in [m for m in sys.modules if m == "playwright" or m.startswith("playwright.")]:
    del sys.modules[_name]
for _name in ("playwright", "playwright.sync_api", "playwright.async_api", "playwright._impl",
              "playwright._impl._network"):
    sys.modules[_name] = None  # type: ignore[assignment]
