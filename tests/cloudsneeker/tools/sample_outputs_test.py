import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from cloudsneeker.brand import Brand
from cloudsneeker.tools import brand_audit, rebrand, sample_outputs

SCRIPT = sample_outputs.REPO_ROOT / "cloudsneeker" / "tools" / "sample_outputs.py"
EXPECTED_SUFFIXES = [".asff.json", ".csv", ".html", ".ocsf.json", ".sarif.json"]
TRANSFORM_ONLY_ASFF_KEYS = re.compile(
    r"\bProwler(?:ResourceName|AccountOrganizationalUnit\w*)\b"
)


class TestSampleFindings:
    def test_builds_pass_and_fail_findings(self):
        findings = sample_outputs.sample_findings()

        statuses = {finding.status for finding in findings}
        assert {"PASS", "FAIL"} <= statuses
        assert all(finding.uid.startswith("cloudsneeker-") for finding in findings)


class TestWriteSampleOutputs:
    def test_writes_every_format(self, tmp_path: Path):
        written = sample_outputs.write_sample_outputs(tmp_path)

        suffixes = sorted("".join(path.suffixes) for path in written)
        assert suffixes == EXPECTED_SUFFIXES
        for path in written:
            assert path.stat().st_size > 0

    def test_main_writes_to_requested_directory(self, tmp_path: Path, capsys):
        code = sample_outputs.main(["--output-dir", str(tmp_path)])

        assert code == 0
        assert len(list(tmp_path.iterdir())) == 5
        assert "5 files" in capsys.readouterr().out


class TestProductBrandEndToEnd:
    """Run the script as the release pipeline does: default brand, fresh process.

    The test session pins the upstream-compat environment and the writers read
    the brand at import time, so an in-process call cannot exercise the
    shipped defaults.
    """

    @pytest.fixture(scope="class")
    def artifacts(self, tmp_path_factory) -> Path:
        output_dir = tmp_path_factory.mktemp("artifacts")
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("CLOUDSNEEKER_")
        }
        subprocess.run(
            [sys.executable, str(SCRIPT), "--output-dir", str(output_dir)],
            check=True,
            env=env,
            cwd=sample_outputs.REPO_ROOT,
            capture_output=True,
        )
        return output_dir

    def test_files_use_product_prefix(self, artifacts: Path):
        names = sorted(path.name for path in artifacts.iterdir())

        assert names == [f"cloudsneeker-output{s}" for s in EXPECTED_SUFFIXES]

    def test_outputs_pass_brand_audit(self, artifacts: Path):
        # The ASFF ProductFields keys are renamed by the build-time
        # ``asff-product-field-names`` rule, not by a hook, so a source-tree
        # run still emits them. Everything else must already be clean.
        allowlist = brand_audit.load_allowlist(brand_audit.DEFAULT_ALLOW)
        allowlist = brand_audit.Allowlist(
            paths=allowlist.paths,
            patterns=allowlist.patterns + (TRANSFORM_ONLY_ASFF_KEYS,),
        )

        hits = brand_audit.audit_tree(artifacts, allowlist, use_allow_paths=False)

        assert hits == []

    def test_asff_keys_are_covered_by_a_rebrand_rule(self):
        rules = rebrand.load_rules(rebrand.DEFAULT_RULES, Brand())
        rule = next(r for r in rules.rules if r.id == "asff-product-field-names")

        assert rule.pattern.search("ProwlerResourceName")
        assert rule.pattern.search("ProwlerAccountOrganizationalUnitId")
        assert not rule.optional
