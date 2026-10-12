import json
from pathlib import Path

import pytest

from cloudsneeker.brand import Brand
from cloudsneeker.tools import gen_check_docs

METADATA = {
    "Provider": "aws",
    "CheckID": "s3_bucket_public_access",
    "CheckTitle": "S3 bucket is not publicly accessible",
    "ServiceName": "s3",
    "Severity": "critical",
    "ResourceType": "AwsS3Bucket",
    "Description": "Buckets are evaluated for {public} <access> by Prowler.",
    "Risk": "Data exposure.",
    "RelatedUrl": "https://docs.aws.amazon.com/s3",
    "AdditionalURLs": ["https://example.com/more"],
    "Remediation": {
        "Code": {
            "CLI": "aws s3api put-public-access-block --bucket <name>",
            "NativeIaC": "```yaml\nResources: {}\n```",
            "Other": "",
            "Terraform": "",
        },
        "Recommendation": {
            "Text": "Enable Block Public Access.",
            "Url": "https://hub.prowler.com/check/s3_bucket_public_access",
        },
    },
    "Categories": ["internet-exposed"],
}


def _write_metadata(providers_dir: Path, data: dict) -> Path:
    check_dir = (
        providers_dir
        / data["Provider"]
        / "services"
        / data["ServiceName"]
        / data["CheckID"]
    )
    check_dir.mkdir(parents=True)
    path = check_dir / f"{data['CheckID']}.metadata.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _docs_json(docs_dir: Path) -> Path:
    docs_dir.mkdir(parents=True, exist_ok=True)
    path = docs_dir / "docs.json"
    path.write_text(
        json.dumps(
            {
                "name": "x",
                "navigation": {
                    "tabs": [
                        {"tab": "Guides", "groups": []},
                        {
                            "tab": "Checks",
                            "groups": [{"group": "Checks", "pages": ["checks/index"]}],
                        },
                    ]
                },
            }
        ),
        encoding="utf-8",
    )
    return path


@pytest.fixture
def providers_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "providers"
    _write_metadata(directory, METADATA)
    _write_metadata(
        directory,
        {
            **METADATA,
            "Provider": "azure",
            "CheckID": "storage_public",
            "ServiceName": "storage",
            "Severity": "high",
        },
    )
    return directory


class TestLoadChecks:
    def test_reads_every_metadata_file(self, providers_dir: Path):
        checks = gen_check_docs.load_checks(providers_dir)

        assert [c.check_id for c in checks] == [
            "s3_bucket_public_access",
            "storage_public",
        ]
        assert checks[0].provider == "aws"

    def test_same_id_in_two_providers_groups_into_one_page(self, providers_dir: Path):
        _write_metadata(providers_dir, {**METADATA, "Provider": "gcp"})

        pages = gen_check_docs.group_by_id(gen_check_docs.load_checks(providers_dir))

        assert [c.provider for c in pages["s3_bucket_public_access"]] == ["aws", "gcp"]

    def test_same_id_twice_in_one_provider_fails(self):
        with pytest.raises(ValueError, match="s3_bucket_public_access"):
            gen_check_docs.load_checks_from([METADATA, METADATA])


class TestRenderPage:
    def test_escapes_mdx_and_rewrites_brand(self):
        checks = gen_check_docs.load_checks_from([METADATA])

        page = gen_check_docs.render_page(checks, Brand())

        assert page.startswith("---\ntitle:")
        assert "## Description" in page
        assert (
            "Buckets are evaluated for \\{public\\} \\<access> by Cloudsneeker." in page
        )
        assert "hub.prowler.com" not in page
        assert (
            "```shell\naws s3api put-public-access-block --bucket <name>\n```" in page
        )
        assert "```yaml\nResources: {}\n```" in page
        assert "https://example.com/more" in page

    def test_shared_id_renders_a_section_per_provider(self):
        checks = gen_check_docs.load_checks_from(
            [METADATA, {**METADATA, "Provider": "gcp"}]
        )

        page = gen_check_docs.render_page(checks, Brand())

        assert "## AWS\n" in page
        assert "## Google Cloud\n" in page
        assert page.count("### Description") == 2


class TestWriteDocs:
    def test_writes_pages_index_and_navigation(
        self, providers_dir: Path, tmp_path: Path
    ):
        docs_dir = tmp_path / "docs"
        docs_json = _docs_json(docs_dir)

        written = gen_check_docs.write_docs(providers_dir, docs_dir, Brand())

        assert (docs_dir / "checks" / "s3_bucket_public_access.mdx").exists()
        assert (docs_dir / "checks" / "storage_public.mdx").exists()
        assert (docs_dir / "checks" / "index.mdx").exists()
        assert len(written) == 3
        nav = json.loads(docs_json.read_text(encoding="utf-8"))["navigation"]["tabs"]
        assert nav[0] == {"tab": "Guides", "groups": []}
        checks_tab = nav[1]
        assert [g["group"] for g in checks_tab["groups"]] == [
            "Overview",
            "AWS",
            "Azure",
        ]
        assert checks_tab["groups"][1]["pages"] == [
            {"group": "s3", "pages": ["checks/s3_bucket_public_access"]}
        ]

    def test_shared_id_is_listed_once_in_navigation(
        self, providers_dir: Path, tmp_path: Path
    ):
        _write_metadata(providers_dir, {**METADATA, "Provider": "gcp"})
        docs_dir = tmp_path / "docs"
        docs_json = _docs_json(docs_dir)

        written = gen_check_docs.write_docs(providers_dir, docs_dir, Brand())

        assert len(written) == 3
        nav = json.loads(docs_json.read_text(encoding="utf-8"))["navigation"]["tabs"][1]
        assert [g["group"] for g in nav["groups"]] == ["Overview", "AWS", "Azure"]

    def test_main_returns_zero(
        self,
        providers_dir: Path,
        tmp_path: Path,
        capsys,
        monkeypatch: pytest.MonkeyPatch,
    ):
        # The test session runs with upstream-compatible brand env values.
        monkeypatch.setattr(gen_check_docs, "load_brand", lambda: Brand())
        docs_dir = tmp_path / "docs"
        _docs_json(docs_dir)
        repo = tmp_path / "repo"
        template = repo / gen_check_docs.CLOUDFORMATION_TEMPLATE
        template.parent.mkdir(parents=True)
        template.write_text("Description: Prowler role\n", encoding="utf-8")

        code = gen_check_docs.main(
            [
                "--providers-dir",
                str(providers_dir),
                "--docs-dir",
                str(docs_dir),
                "--repo-root",
                str(repo),
            ]
        )

        assert code == 0
        assert "2 check pages" in capsys.readouterr().out
        assert (docs_dir / "templates" / "cloudsneeker-scan-role.yml").exists()


FRAMEWORK = {
    "Framework": "CIS",
    "Name": "CIS Amazon Web Services Foundations Benchmark v3.0.0",
    "Version": "3.0",
    "Provider": "AWS",
    "Description": "Prescriptive guidance from Prowler's catalog with {braces}.",
    "Requirements": [
        {
            "Id": "1.1",
            "Description": "Maintain current contact details",
            "Checks": ["account_maintain_current_contact_details"],
            "Attributes": [{"Section": "1 Identity and Access Management"}],
        },
        {
            "Id": "2.1.1",
            "Description": "S3 buckets block public access",
            "Checks": [
                "s3_bucket_public_access",
                "s3_account_level_public_access_blocks",
            ],
            "Attributes": [{"Section": "2.1 Simple Storage Service"}],
        },
    ],
}


def _write_framework(
    compliance_dir: Path, provider: str, stem: str, data: dict
) -> Path:
    directory = compliance_dir / provider
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{stem}.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.fixture
def compliance_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "compliance"
    _write_framework(directory, "aws", "cis_3.0_aws", FRAMEWORK)
    _write_framework(
        directory,
        "azure",
        "cis_3.0_azure",
        {
            **FRAMEWORK,
            "Provider": "Azure",
            "Name": "CIS Azure Foundations Benchmark v3.0.0",
        },
    )
    return directory


class TestFrameworks:
    def test_loads_every_framework_file(self, compliance_dir: Path):
        frameworks = gen_check_docs.load_frameworks(compliance_dir)

        assert [f.framework_id for f in frameworks] == ["cis_3.0_aws", "cis_3.0_azure"]
        assert frameworks[0].provider == "aws"
        assert len(frameworks[0].requirements) == 2

    def test_render_framework_page_links_checks(self):
        framework = gen_check_docs.load_frameworks_from(
            [("aws", "cis_3.0_aws", FRAMEWORK)]
        )[0]

        page = gen_check_docs.render_framework_page(framework, Brand())

        assert page.startswith(
            '---\ntitle: "CIS Amazon Web Services Foundations Benchmark v3.0.0"'
        )
        assert "Cloudsneeker's catalog with \\{braces\\}" in page
        assert "[`s3_bucket_public_access`](/checks/s3_bucket_public_access)" in page
        assert "### 2.1 Simple Storage Service" in page
        assert "Prowler" not in page

    def test_universal_schema_merges_checks_across_providers(
        self, compliance_dir: Path
    ):
        (compliance_dir / "cis_controls_8.1.json").write_text(
            json.dumps(
                {
                    "framework": "CIS-Controls",
                    "name": "CIS Controls v8.1",
                    "version": "8.1",
                    "description": "Cross-provider mapping of Prowler checks.",
                    "requirements": [
                        {
                            "id": "1.1",
                            "name": "Asset inventory",
                            "attributes": {"Section": "1. Inventory"},
                            "checks": {
                                "aws": ["config_recorder_all_regions_enabled"],
                                "gcp": ["iam_x"],
                            },
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        frameworks = gen_check_docs.load_frameworks(compliance_dir)
        universal = next(f for f in frameworks if f.framework_id == "cis_controls_8.1")

        assert universal.provider == "universal"
        assert universal.requirements[0].checks == (
            "config_recorder_all_regions_enabled",
            "iam_x",
        )
        assert universal.requirements[0].section == "1. Inventory"
        page = gen_check_docs.render_framework_page(universal, Brand())
        assert "Cross-provider" in page
        assert "Cloudsneeker checks" in page

    def test_write_compliance_docs_updates_navigation(
        self, compliance_dir: Path, tmp_path: Path
    ):
        docs_dir = tmp_path / "docs"
        docs_json = _docs_json(docs_dir)

        written = gen_check_docs.write_compliance_docs(
            compliance_dir, docs_dir, Brand()
        )

        assert (docs_dir / "compliance" / "cis_3.0_aws.mdx").exists()
        assert (docs_dir / "compliance" / "index.mdx").exists()
        assert len(written) == 3
        tabs = json.loads(docs_json.read_text(encoding="utf-8"))["navigation"]["tabs"]
        frameworks_tab = next(
            t for t in tabs if t["tab"] == gen_check_docs.FRAMEWORKS_TAB
        )
        assert [g["group"] for g in frameworks_tab["groups"]] == [
            "Overview",
            "AWS",
            "Azure",
        ]
        assert frameworks_tab["groups"][1]["pages"] == ["compliance/cis_3.0_aws"]


class TestWriteTemplates:
    def test_publishes_rebranded_cloudformation_template(self, tmp_path: Path):
        repo = tmp_path / "repo"
        source = repo / gen_check_docs.CLOUDFORMATION_TEMPLATE
        source.parent.mkdir(parents=True)
        source.write_text(
            "Description: Creates the ProwlerScan role for Prowler.\n"
            "  Url: https://prowler.com\n"
            "  Contact: support@prowler.com\n"
            "  Object: test-prowler-connection.txt\n",
            encoding="utf-8",
        )
        docs_dir = tmp_path / "docs"

        written = gen_check_docs.write_templates(repo, docs_dir, Brand())

        assert written == [docs_dir / "templates" / "cloudsneeker-scan-role.yml"]
        text = written[0].read_text(encoding="utf-8")
        assert "CloudsneekerScan role for Cloudsneeker" in text
        assert "https://cloudsneeker.example" in text
        assert "https://support.cloudsneeker.example" in text
        assert "test-cloudsneeker-connection.txt" in text
        assert "prowler" not in text.lower()

    def test_skips_when_template_missing(self, tmp_path: Path):
        assert (
            gen_check_docs.write_templates(
                tmp_path / "repo", tmp_path / "docs", Brand()
            )
            == []
        )

    def test_template_name_matches_brand_url(self):
        brand = Brand()

        assert brand.cloudformation_template_url.endswith(
            f"/templates/{gen_check_docs.template_file_name(brand)}"
        )
