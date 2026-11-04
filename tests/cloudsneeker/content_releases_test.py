import json

from cloudsneeker import content_releases
from cloudsneeker.tools import content_release_notes as notes

CHECK = "prowler/providers/aws/services/s3/{0}/{0}.metadata.json"


def _files(entries: dict[str, dict]):
    return [(path, json.dumps(document).encode()) for path, document in entries.items()]


def _check(title: str, severity: str = "high") -> dict:
    return {
        "Provider": "aws",
        "ServiceName": "s3",
        "CheckTitle": title,
        "Severity": severity,
        "Description": "d",
        "Risk": "r",
        "Remediation": {},
        "Categories": [],
    }


def _framework(requirements: list[dict]) -> dict:
    return {
        "Name": "CIS",
        "Version": "1.0",
        "Provider": "AWS",
        "Requirements": requirements,
    }


class TestDiffCatalogs:
    def test_reports_added_changed_and_removed_checks(self):
        old = notes.catalog_from_files(
            _files(
                {CHECK.format("s3_a"): _check("A"), CHECK.format("s3_b"): _check("B")}
            )
        )
        new = notes.catalog_from_files(
            _files(
                {
                    CHECK.format("s3_a"): _check("A", severity="critical"),
                    CHECK.format("s3_c"): _check("C"),
                }
            )
        )
        diff = notes.diff_catalogs(old, new)["checks"]
        assert [check["id"] for check in diff["added"]] == ["s3_c"]
        assert [check["id"] for check in diff["removed"]] == ["s3_b"]
        assert diff["changed"] == [
            {
                "id": "s3_a",
                "provider": "aws",
                "service": "s3",
                "title": "A",
                "severity": "critical",
                "fields": ["severity"],
            }
        ]

    def test_reports_framework_requirement_changes(self):
        path = "prowler/compliance/aws/cis_1.0_aws.json"
        old = notes.catalog_from_files(
            _files(
                {
                    path: _framework(
                        [{"Id": "1", "Checks": ["s3_a"]}, {"Id": "2", "Checks": []}]
                    )
                }
            )
        )
        new = notes.catalog_from_files(
            _files(
                {
                    path: _framework(
                        [
                            {"Id": "1", "Checks": ["s3_a", "s3_b"]},
                            {"Id": "3", "Checks": []},
                        ]
                    )
                }
            )
        )
        assert notes.diff_catalogs(old, new)["frameworks"]["changed"] == [
            {
                "id": "aws/cis_1.0_aws",
                "name": "CIS",
                "provider": "aws",
                "version": "1.0",
                "requirements": 2,
                "fields": [],
                "requirements_added": 1,
                "requirements_removed": 1,
                "requirements_remapped": 1,
            }
        ]

    def test_reads_universal_frameworks(self):
        catalog = notes.catalog_from_files(
            _files(
                {
                    "prowler/compliance/cis_controls_8.1.json": {
                        "name": "CIS Controls v8.1",
                        "version": "8.1",
                        "requirements": [
                            {"id": "1.1", "checks": {"aws": ["s3_a"], "gcp": []}}
                        ],
                    }
                }
            )
        )
        framework = catalog["frameworks"]["cis_controls_8.1"]
        assert framework["name"] == "CIS Controls v8.1"
        assert framework["provider"] == "multi-cloud"
        assert framework["requirements"] == {"1.1": ["aws/s3_a"]}

    def test_identical_catalogs_have_no_changes(self):
        catalog = notes.catalog_from_files(_files({CHECK.format("s3_a"): _check("A")}))
        diff = notes.diff_catalogs(catalog, catalog)
        assert all(not values for kind in diff.values() for values in kind.values())


def test_names_use_the_product_brand():
    catalog = notes.catalog_from_files(
        _files(
            {
                "prowler/compliance/aws/prowler_threatscore_aws.json": {
                    "Name": "Prowler ThreatScore Compliance Framework for AWS",
                    "Provider": "AWS",
                    "Requirements": [],
                }
            }
        )
    )
    assert "Prowler" not in catalog["frameworks"]["aws/prowler_threatscore_aws"]["name"]


def test_committed_notes_match_the_tree():
    """After an upstream merge, run python cloudsneeker/tools/content_release_notes.py."""
    committed = json.loads(content_releases.RELEASES_PATH.read_text(encoding="utf-8"))
    assert committed["catalog_digest"] == notes.catalog_digest(
        notes.catalog_from_tree()
    ), (
        "Detection content changed; run python cloudsneeker/tools/content_release_notes.py"
    )
    current = committed["releases"][0]
    assert current["current"] is True
    assert current["version"] == notes.tree_version()
