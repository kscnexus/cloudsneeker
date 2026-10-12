from pathlib import Path

import pytest

from cloudsneeker.tools import brand_audit

ALLOW = Path(brand_audit.DEFAULT_ALLOW)


def _write(root: Path, relative: str, text: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def allowlist() -> brand_audit.Allowlist:
    return brand_audit.load_allowlist(ALLOW)


class TestScanText:
    @pytest.mark.parametrize(
        "text",
        [
            "Powered by Prowler",
            "see https://docs.prowler.com/x",
            "https://github.com/prowler-cloud/prowler",
            "image: prowlercloud/prowler-api",
            "View on hub.prowler.com",
            "file prowler-output-aws-1.csv",
            '"serviceId": "prowler-ui"',
            "ProwlerPro",
        ],
    )
    def test_flags_forbidden(self, allowlist, text):
        assert brand_audit.scan_text("f", text, allowlist)

    @pytest.mark.parametrize(
        "text",
        [
            "from prowler.lib.outputs import finding",
            "import prowler_mcp_server",
            "PROWLER_AWS_PARTITION=aws",
            "prowler_threatscore_aws",
            "ProwlerAssessmentSession",
            "Cloudsneeker CLI - v5.45.0",
            "git+https://github.com/prowler-cloud/prowler.git@master",
        ],
    )
    def test_ignores_identifiers(self, allowlist, text):
        assert brand_audit.scan_text("f", text, allowlist) == []


class TestAuditTree:
    def test_reports_hits_outside_allowlist(self, tmp_path: Path, allowlist):
        _write(tmp_path, "ui/lib/a.ts", 'const a = "Prowler";\n')
        _write(tmp_path, "NOTICE", "Derived from Prowler\n")
        _write(tmp_path, "ui/lib/a.test.ts", 'expect("Prowler")\n')
        _write(tmp_path, "docs/a.mdx", "Prowler\n")
        (tmp_path / "ui/lib/img.png").write_bytes(b"\x89PNG\x00Prowler")

        hits = brand_audit.audit_tree(tmp_path, allowlist)

        assert [str(hit) for hit in hits] == ['ui/lib/a.ts:1: const a = "Prowler";']

    def test_artifacts_ignore_path_allowlist(self, tmp_path: Path, allowlist):
        _write(tmp_path, "tests/out.csv", "PROWLER_VERSION;x\n")
        _write(tmp_path, "report.md", "Powered by Prowler\n")

        hits = brand_audit.audit_tree(tmp_path, allowlist, use_allow_paths=False)

        assert {hit.path for hit in hits} == {"report.md"}

    def test_clean_tree(self, tmp_path: Path, allowlist):
        _write(tmp_path, "ui/lib/a.ts", 'const a = "Cloudsneeker";\n')

        assert brand_audit.audit_tree(tmp_path, allowlist) == []


class TestAuditSource:
    def test_scans_only_owned_dirs(self, tmp_path: Path, allowlist):
        _write(tmp_path, "cloudsneeker/brand.py", 'name = "Cloudsneeker"\n')
        _write(tmp_path, "cloudsneeker/tools/rules.toml", 'pattern = "Prowler"\n')
        _write(tmp_path, "ui/cloudsneeker/brand.ts", 'export const name = "Prowler";\n')
        _write(tmp_path, "prowler/lib/x.py", 'x = "Prowler"\n')

        hits = brand_audit.audit_source(tmp_path, allowlist)

        assert [hit.path for hit in hits] == ["ui/cloudsneeker/brand.ts"]


class TestMain:
    def test_exit_code(self, tmp_path: Path, capsys):
        _write(tmp_path, "a.html", "<title>Prowler</title>\n")

        assert brand_audit.main(["--artifacts", str(tmp_path)]) == 1
        assert "1 hit" in capsys.readouterr().out

        (tmp_path / "a.html").write_text(
            "<title>Cloudsneeker</title>\n", encoding="utf-8"
        )
        assert brand_audit.main(["--artifacts", str(tmp_path)]) == 0
