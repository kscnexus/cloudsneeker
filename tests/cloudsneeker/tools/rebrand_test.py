from pathlib import Path

import pytest

from cloudsneeker.brand import Brand
from cloudsneeker.tools import rebrand

RULES = Path(rebrand.DEFAULT_RULES)


def _write(root: Path, relative: str, text: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    _write(
        tmp_path,
        "ui/components/x/launch.tsx",
        'export const t = "connected to Prowler";\n'
        'const u = "Available in Prowler Cloud";\n'
        'const h = "View on Prowler Hub";\n'
        'const d = "https://docs.prowler.com/user-guide/x";\n',
    )
    _write(
        tmp_path,
        "ui/components/x/assistant.tsx",
        'export const a = "Lighthouse AI";\nconst b = "Ask Lighthouse";\n',
    )
    _write(
        tmp_path,
        "ui/components/x/launch.test.tsx",
        'expect(screen.getByText("connected to Prowler"))\n',
    )
    _write(
        tmp_path,
        "prowler/providers/aws/services/iam/c/c.metadata.json",
        '{"Remediation": {"Recommendation": {"Url": '
        '"https://hub.prowler.com/check/c"}}, "Description": "Prowler checks"}\n',
    )
    _write(
        tmp_path,
        "prowler/providers/aws/models.py",
        'name = f"prowler-output-{account}-{ts}"\n'
        "ROLE_SESSION_NAME = 'ProwlerAssessmentSession'\n"
        "from prowler.lib import ProwlerFinding\n",
    )
    _write(
        tmp_path,
        "prowler/compliance/aws/x.json",
        '{"Framework": "ProwlerThreatScore", "Name": "Prowler ThreatScore"}',
    )
    _write(
        tmp_path,
        "prowler/lib/outputs/slack/slack.py",
        'text = "I am *Prowler*, ProwlerPro https://prowler.pro"\n',
    )
    _write(
        tmp_path,
        "mcp_server/prowler_mcp_server/app.py",
        'name = "prowler_list_findings"\nimport prowler_mcp_server\n',
    )
    _write(
        tmp_path,
        "mcp_server/prowler_mcp_server/x.py",
        'import "prowler_mcp_server.tools"\n',
    )
    _write(tmp_path, "NOTICE", "Cloudsneeker is derived from Prowler.\n")
    _write(tmp_path, "docs/x.mdx", "Prowler docs\n")
    _write(tmp_path, "api/src/backend/api/migrations/0001.py", 'x = "Prowler"\n')
    return tmp_path


class TestLoadRules:
    def test_parses_shipped_rules(self):
        rules = rebrand.load_rules(RULES, Brand())

        assert [r.id for r in rules.rules][:1] == ["assistant-phrase"]
        assert "NOTICE" in rules.exclude

    def test_unknown_alias_raises(self, tmp_path: Path):
        bad = tmp_path / "rules.toml"
        bad.write_text(
            '[[rule]]\nid="a"\npattern="x"\nreplacement="y"\ninclude="nope"\n',
            encoding="utf-8",
        )

        with pytest.raises(ValueError, match="unknown include alias"):
            rebrand.load_rules(bad, Brand())


class TestRun:
    def test_dry_run_does_not_write(self, tree: Path):
        rules = rebrand.load_rules(RULES, Brand())
        before = (tree / "ui/components/x/launch.tsx").read_text(encoding="utf-8")

        report = rebrand.run(tree, rules, apply=False)

        assert (tree / "ui/components/x/launch.tsx").read_text(
            encoding="utf-8"
        ) == before
        assert "ui/components/x/launch.tsx" in report.changed_files

    def test_apply_rewrites_display_copy(self, tree: Path):
        rules = rebrand.load_rules(RULES, Brand())

        rebrand.run(tree, rules, apply=True)

        text = (tree / "ui/components/x/launch.tsx").read_text(encoding="utf-8")
        assert "connected to Cloudsneeker" in text
        assert 'Available in Cloudsneeker"' in text
        assert "View on Cloudsneeker documentation" in text
        assert "https://docs.cloudsneeker.example" in text
        assert "prowler" not in text.lower()

    def test_apply_rewrites_metadata_hub_url(self, tree: Path):
        rebrand.run(tree, rebrand.load_rules(RULES, Brand()), apply=True)

        text = (
            tree / "prowler/providers/aws/services/iam/c/c.metadata.json"
        ).read_text(encoding="utf-8")
        assert "https://docs.cloudsneeker.example/checks/c" in text
        assert "Cloudsneeker checks" in text

    def test_identifiers_survive(self, tree: Path):
        rebrand.run(tree, rebrand.load_rules(RULES, Brand()), apply=True)

        models = (tree / "prowler/providers/aws/models.py").read_text(encoding="utf-8")
        assert "cloudsneeker-output-" in models
        assert "ProwlerAssessmentSession" in models
        assert "from prowler.lib import ProwlerFinding" in models
        compliance = (tree / "prowler/compliance/aws/x.json").read_text(
            encoding="utf-8"
        )
        assert '"Framework": "ProwlerThreatScore"' in compliance
        assert '"Name": "Cloudsneeker ThreatScore"' in compliance

    def test_slack_and_mcp_rules(self, tree: Path):
        rebrand.run(tree, rebrand.load_rules(RULES, Brand()), apply=True)

        slack = (tree / "prowler/lib/outputs/slack/slack.py").read_text(
            encoding="utf-8"
        )
        assert (
            slack
            == 'text = "I am *Cloudsneeker*, Cloudsneeker https://cloudsneeker.example"\n'
        )
        mcp = (tree / "mcp_server/prowler_mcp_server/app.py").read_text(
            encoding="utf-8"
        )
        assert 'name = "cloudsneeker_list_findings"' in mcp
        assert "import prowler_mcp_server" in mcp
        assert (tree / "mcp_server/prowler_mcp_server/x.py").read_text(
            encoding="utf-8"
        ) == 'import "prowler_mcp_server.tools"\n'

    def test_excluded_paths_untouched(self, tree: Path):
        rebrand.run(tree, rebrand.load_rules(RULES, Brand()), apply=True)

        assert "Prowler" in (tree / "NOTICE").read_text(encoding="utf-8")
        assert "Prowler" in (tree / "docs/x.mdx").read_text(encoding="utf-8")
        assert "Prowler" in (tree / "ui/components/x/launch.test.tsx").read_text(
            encoding="utf-8"
        )
        assert "Prowler" in (tree / "api/src/backend/api/migrations/0001.py").read_text(
            encoding="utf-8"
        )

    def test_stale_rules_reported(self, tmp_path: Path):
        _write(tmp_path, "ui/lib/a.ts", 'const a = "Prowler";\n')

        report = rebrand.run(tmp_path, rebrand.load_rules(RULES, Brand()), apply=False)

        assert "display-name" not in report.stale_rules()
        assert "hub-check-url" in report.stale_rules()


class TestMain:
    def test_apply_refuses_git_tree(self, tmp_path: Path, capsys):
        (tmp_path / ".git").mkdir()

        code = rebrand.main(["--apply", "--root", str(tmp_path)])

        assert code == 2
        assert "refusing" in capsys.readouterr().err

    def test_check_fails_on_stale_rule(self, tmp_path: Path, capsys):
        _write(tmp_path, "ui/lib/a.ts", 'const a = "Prowler";\n')

        code = rebrand.main(["--check", "--root", str(tmp_path)])

        assert code == 1
        assert "stale rules" in capsys.readouterr().out

    def test_check_passes_on_full_tree(self, tree: Path):
        _write(
            tree,
            "prowler/lib/x.py",
            'u = "https://github.com/prowler-cloud/prowler/"\n',
        )
        _write(
            tree,
            "prowler/lib/outputs/asff/asff.py",
            "class ProductFields(BaseModel):\n    ProwlerResourceName: str\n",
        )
        _write(
            tree,
            "ui/lib/external-urls.ts",
            "// CloudFormation template URL for the ProwlerScan role.\n",
        )
        _write(
            tree,
            "permissions/templates/cloudformation/prowler-scan-role.yml",
            "Description: Prowler role\n",
        )
        _write(
            tree,
            "mcp_server/prowler_mcp_server/server.py",
            'root.mount(app_mcp_server, namespace="prowler")\n',
        )

        assert rebrand.main(["--check", "--root", str(tree)]) == 0
