"""Smoke tests: upstream hook points load the shipped brand.

The test session itself runs with upstream-compatible overrides (see
``tests/conftest.py``), so module-level constants in ``prowler`` already carry
upstream names. These tests therefore import the hooked modules in a fresh
interpreter whose environment has no ``CLOUDSNEEKER_*`` variables and assert
what a real installation prints.
"""

import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from cloudsneeker.brand import Brand

REPO_ROOT = Path(__file__).resolve().parents[2]

PROBE = r"""
import json
from prowler.config import config
from prowler.lib.banner import PRODUCT_NAME
from prowler.lib.cli.parser import ProwlerArgumentParser
from prowler.lib.utils.vulnerability_references import PROWLER_HUB_CHECK_URL

parser = ProwlerArgumentParser()
version_action = next(a for a in parser.parser._actions if "--version" in a.option_strings)
push_action = next(
    a
    for a in parser.common_providers_parser._actions
    if "--push-to-cloud" in a.option_strings
)
print(
    json.dumps(
        {
            "product_name": PRODUCT_NAME,
            "prog": parser.parser.prog,
            "version_help": version_action.help,
            "push_to_cloud_help": push_action.help,
            "version_line": config.check_current_version(),
            "html_logo_url": config.html_logo_url,
            "square_logo_img": config.square_logo_img,
            "cloud_api_base_url": config.cloud_api_base_url,
            "hub_check_url": PROWLER_HUB_CHECK_URL,
            "prowler_version": config.prowler_version,
        }
    )
)
"""


@pytest.fixture(scope="module")
def probe() -> dict:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("CLOUDSNEEKER_") and key != "PROWLER_CLOUD_API_BASE_URL"
    }
    env["PYTHONIOENCODING"] = "utf-8"
    completed = subprocess.run(
        [sys.executable, "-c", PROBE],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout.strip().splitlines()[-1])


class TestSdkHooksLoadShippedBrand:
    def test_banner_and_cli_names(self, probe: dict):
        shipped = Brand()
        assert probe["product_name"] == shipped.name
        assert probe["prog"] == shipped.cli_command
        assert probe["version_help"] == f"show {shipped.name} version"
        assert probe["version_line"] == shipped.version_string(probe["prowler_version"])

    def test_urls_point_at_brand(self, probe: dict):
        shipped = Brand()
        assert probe["html_logo_url"] == shipped.website_url
        assert probe["square_logo_img"] == shipped.logo_url
        assert probe["cloud_api_base_url"] == shipped.api_url
        assert probe["hub_check_url"] == shipped.check_docs_url("{check_id}")

    def test_upsell_flag_is_suppressed(self, probe: dict):
        assert probe["push_to_cloud_help"] == "==SUPPRESS=="

    def test_nothing_mentions_upstream(self, probe: dict):
        leaked = {
            key: value
            for key, value in probe.items()
            if key != "prowler_version" and "prowler" in str(value).lower()
        }
        assert leaked == {}


class TestPackaging:
    @pytest.fixture(scope="class")
    def pyproject(self) -> dict:
        with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
            return tomllib.load(handle)

    def test_console_scripts(self, pyproject: dict):
        scripts = pyproject["project"]["scripts"]
        assert scripts["prowler"] == "prowler.__main__:prowler"
        assert scripts[Brand().cli_command] == scripts["prowler"]

    def test_wheel_ships_cloudsneeker_package(self, pyproject: dict):
        build = pyproject["tool"]["hatch"]["build"]["targets"]
        assert "cloudsneeker" in build["wheel"]["packages"]
        assert "cloudsneeker" in build["sdist"]["include"]
