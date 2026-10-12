"""Every in-app help link resolves on the product documentation site.

Upstream UI code links to documentation paths such as
``user-guide/providers/aws``. Those paths stay in source so upstream merges
are clean; ``cloudsneeker/docs/docs.json`` must therefore serve each of them,
either as a page or through a redirect.
"""

import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCS_DIR = REPO_ROOT / "cloudsneeker" / "docs"
DOCS_JSON = DOCS_DIR / "docs.json"
UI_LINK_FILES = (
    REPO_ROOT / "ui" / "lib" / "external-urls.ts",
    REPO_ROOT / "ui" / "components" / "layout" / "app-sidebar" / "navigation-config.ts",
)
DOCS_URL_CALL = re.compile(r'docsUrl\(\s*(?:`([^`]+)`|"([^"]+)")', re.S)
GENERATED_PREFIXES = ("checks/", "compliance/")


def ui_docs_paths() -> list[str]:
    paths: set[str] = set()
    for file in UI_LINK_FILES:
        for match in DOCS_URL_CALL.finditer(file.read_text(encoding="utf-8")):
            raw = match.group(1) or match.group(2)
            paths.add(raw.split("#", 1)[0].strip("/"))
    return sorted(paths)


def _pages(navigation: dict) -> set[str]:
    found: set[str] = set()

    def walk(node: object) -> None:
        if isinstance(node, str):
            found.add(node)
        elif isinstance(node, dict):
            for key in ("pages", "groups", "tabs"):
                walk(node.get(key, []))
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(navigation)
    return found


def _redirect_matches(source: str, path: str) -> bool:
    """Mintlify redirect sources use ``:name`` and ``:name*`` segments."""
    pattern = "^"
    for segment in source.strip("/").split("/"):
        if segment.endswith("*"):
            pattern += r"(?:/?[^/]+(?:/[^/]+)*)?"
        elif segment.startswith(":"):
            pattern += r"/[^/]+"
        else:
            pattern += "/" + re.escape(segment)
    pattern += "$"
    return re.match(pattern, "/" + path) is not None


@pytest.fixture(scope="module")
def docs_json() -> dict:
    return json.loads(DOCS_JSON.read_text(encoding="utf-8"))


def test_ui_links_something():
    assert len(ui_docs_paths()) > 10


@pytest.mark.parametrize("path", ui_docs_paths())
def test_ui_docs_path_resolves(path: str, docs_json: dict):
    if path.startswith(GENERATED_PREFIXES) and "${" in path:
        pytest.skip("generated per-id page")
    pages = _pages(docs_json["navigation"])
    redirects = docs_json.get("redirects", [])

    served = (
        path in pages
        or f"{path}/index" in pages
        or any(_redirect_matches(r["source"], path) for r in redirects)
    )
    assert served, f"{path!r} is neither a page nor a redirect in docs.json"


def test_redirect_destinations_exist(docs_json: dict):
    pages = _pages(docs_json["navigation"])
    for redirect in docs_json.get("redirects", []):
        destination = redirect["destination"].strip("/")
        assert destination in pages, f"redirect to missing page {destination!r}"
        assert (DOCS_DIR / f"{destination}.mdx").is_file()
