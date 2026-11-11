"""ASPM engine: capabilities, options, parser, risk, SBOM, failures, policies.

These modules import no Django model, so the tests need no database.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from cloudsneeker_api.appsec import capabilities as caps
from cloudsneeker_api.appsec import policies
from cloudsneeker_api.appsec.failures import (
    FAILURE_AUTH,
    FAILURE_DATABASE,
    FAILURE_ENGINE,
    FAILURE_NOT_FOUND,
    FAILURE_TIMEOUT,
    classify_failure,
    last_error_line,
    retry_delay_seconds,
    stderr_tail,
)
from cloudsneeker_api.appsec.options import (
    OptionError,
    build_scan_args,
    merge_options,
    normalize_scanners,
    validate_options,
    validate_profile_options,
)
from cloudsneeker_api.appsec.parser import (
    REDACTED,
    ReportError,
    bounded_uid,
    cvss_score,
    finding_stats,
    mask_secret,
    normalize_check_id,
    normalize_severity,
    parse_code_rows,
    parse_report,
)
from cloudsneeker_api.appsec.risk import (
    DEFAULT_RISK_CONFIG,
    RiskConfigError,
    RiskInput,
    merge_risk_config,
    merge_sla_days,
    score_finding,
)
from cloudsneeker_api.appsec.sbom import (
    build_cyclonedx,
    detect_document_format,
    diff_components,
    max_severity,
    summarize,
)


def _vuln(**overrides):
    vuln = {
        "VulnerabilityID": "CVE-2024-0001",
        "PkgID": "lodash@4.17.20",
        "PkgName": "lodash",
        "PkgIdentifier": {"PURL": "pkg:npm/lodash@4.17.20", "UID": "abc"},
        "InstalledVersion": "4.17.20",
        "FixedVersion": "4.17.21",
        "Status": "fixed",
        "SeveritySource": "ghsa",
        "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-0001",
        "DataSource": {"ID": "ghsa", "Name": "GitHub Security Advisory npm"},
        "Title": "Prototype pollution",
        "Description": "A long description.",
        "Severity": "HIGH",
        "CweIDs": ["CWE-1321"],
        "VendorSeverity": {"ghsa": 3, "nvd": 4},
        "CVSS": {
            "ghsa": {"V3Vector": "CVSS:3.1/AV:N", "V3Score": 7.4},
            "nvd": {"V2Score": 6.8, "V3Score": 9.8},
        },
        "References": ["https://example.com/a"],
        "PublishedDate": "2024-01-01T00:00:00Z",
        "FutureField": {"kept": True},
    }
    vuln.update(overrides)
    return vuln


def _report(results, **top):
    return {
        "SchemaVersion": 2,
        "Trivy": {"Version": "0.74.0"},
        "ArtifactName": "https://github.com/acme/shop",
        "ArtifactType": "repository",
        "Metadata": {
            "RepoURL": "https://github.com/acme/shop",
            "Branch": "main",
            "Commit": "abc123",
        },
        "Results": results,
        **top,
    }


LOCK_RESULT = {
    "Target": "package-lock.json",
    "Class": "lang-pkgs",
    "Type": "npm",
    "Packages": [
        {
            "ID": "lodash@4.17.20",
            "Name": "lodash",
            "Version": "4.17.20",
            "Identifier": {"PURL": "pkg:npm/lodash@4.17.20"},
            "Licenses": ["MIT"],
            "Relationship": "direct",
            "DependsOn": ["minimist@1.2.0"],
        },
        {
            "ID": "minimist@1.2.0",
            "Name": "minimist",
            "Version": "1.2.0",
            "Identifier": {"PURL": "pkg:npm/minimist@1.2.0"},
            "Relationship": "indirect",
            "Dev": True,
        },
    ],
    "Vulnerabilities": [_vuln()],
}


class TestCapabilities:
    def test_engine_pin_matches_the_image(self):
        from pathlib import Path

        dockerfile = Path(__file__).resolve().parents[4] / "Dockerfile"
        if dockerfile.is_file():
            assert f"ARG TRIVY_VERSION={caps.ENGINE_VERSION}" in dockerfile.read_text()

    def test_scanner_matrix_follows_the_cli_reference(self):
        assert caps.scanners_for("sbom") == ("vuln", "license")
        assert "license" not in caps.scanners_for("k8s")
        assert "rbac" in caps.scanners_for("k8s")
        assert "rbac" not in caps.scanners_for("repo")
        assert caps.scanners_for("vm") == ()

    def test_flags_only_where_the_command_accepts_them(self):
        assert "include_dev_deps" in caps.options_for("repo")
        assert "include_dev_deps" in caps.options_for("fs")
        assert "include_dev_deps" not in caps.options_for("image")
        assert "license_full" not in caps.options_for("sbom")
        assert "skip_dirs" not in caps.options_for("sbom")
        assert "platform" in caps.options_for("image")
        assert "platform" not in caps.options_for("repo")
        assert "branch" not in caps.options_for("fs")

    def test_every_option_and_profile_is_declared(self):
        for target in caps.TARGETS.values():
            for name in target["options"]:
                assert name in caps.OPTION_SPECS
            assert set(target["default_scanners"]) <= set(target["scanners"])
        for profile in caps.BUILTIN_PROFILES.values():
            validate_profile_options(profile["options"], profile["target_types"])

    def test_document_lists_every_status(self):
        document = caps.capability_document()
        assert document["engine_version"] == caps.ENGINE_VERSION
        statuses = {feature["status"] for feature in document["features"]}
        assert statuses <= set(caps.STATUS_LABELS)
        assert {
            "implemented",
            "partial",
            "missing",
            "unsupported",
            "not_applicable",
        } <= statuses
        assert all("flag" not in spec for spec in document["options"].values())
        json.dumps(document)


class TestOptions:
    def test_default_scanners(self):
        assert normalize_scanners("sbom", None) == ["vuln"]
        assert validate_options("repo", {})["scanners"] == ["vuln", "secret"]

    def test_unsupported_scanner_rejected_or_dropped(self):
        with pytest.raises(OptionError, match="does not support: secret"):
            normalize_scanners("sbom", ["vuln", "secret"])
        assert normalize_scanners("sbom", ["vuln", "secret"], strict=False) == ["vuln"]
        with pytest.raises(OptionError, match="None of the selected"):
            normalize_scanners("sbom", ["secret"], strict=False)

    def test_unknown_and_unsupported_options(self):
        with pytest.raises(OptionError, match="Unknown scan option"):
            validate_options("repo", {"made_up": True})
        with pytest.raises(OptionError, match="does not support platform"):
            validate_options("repo", {"platform": "linux/amd64"})
        assert "platform" not in validate_options(
            "repo", {"platform": "linux/amd64"}, strict=False
        )

    @pytest.mark.parametrize(
        "options",
        [
            {"severities": ["SEVERE"]},
            {"timeout_seconds": 5},
            {"timeout_seconds": True},
            {"skip_dirs": ["--config=/etc/passwd"]},
            {"skip_dirs": ["../outside"]},
            {"skip_dirs": ["a,b"]},
            {"branch": "-x"},
            {"branch": "main", "tag": "v1"},
            {"ignore_unfixed": "yes"},
            {"detection_priority": "fast"},
        ],
    )
    def test_malformed_values_rejected(self, options):
        with pytest.raises(OptionError):
            validate_options("repo", options)

    def test_option_of_a_disabled_scanner_is_dropped(self):
        cleaned = validate_options(
            "repo",
            {"scanners": ["secret"], "ignore_unfixed": True, "license_full": True},
        )
        assert cleaned == {"scanners": ["secret"]}

    def test_args_are_a_list_with_valid_flags(self):
        args = build_scan_args(
            "repo",
            {
                "scanners": ["vuln", "license", "misconfig"],
                "severities": ["critical", "HIGH"],
                "ignore_unfixed": True,
                "skip_dirs": ["node_modules", "vendor/**"],
                "timeout_seconds": 600,
                "license_full": True,
                "branch": "release/1.2",
                "misconfig_scanners": ["terraform", "dockerfile"],
            },
        )
        assert args[:2] == ["--format", "json"]
        assert "--list-all-pkgs" in args and "--show-suppressed" in args
        assert args[args.index("--scanners") + 1] == "vuln,misconfig,license"
        assert args[args.index("--severity") + 1] == "HIGH,CRITICAL"
        assert args[args.index("--skip-dirs") + 1] == "node_modules,vendor/**"
        assert args[args.index("--timeout") + 1] == "600s"
        assert args[args.index("--branch") + 1] == "release/1.2"
        assert args[args.index("--misconfig-scanners") + 1] == "dockerfile,terraform"
        assert "--ignore-unfixed" in args and "--license-full" in args
        assert "--exit-code" not in args
        assert all(isinstance(item, str) for item in args)

    def test_target_specific_args(self):
        k8s = build_scan_args("k8s", {"include_namespaces": ["prod"]})
        assert k8s[k8s.index("--report") + 1] == "all"
        assert "--disable-node-collector" in k8s
        assert "--disable-node-collector" not in build_scan_args(
            "k8s", {"disable_node_collector": False}
        )
        image = build_scan_args("image", {"platform": "linux/arm64"})
        assert image[image.index("--image-src") + 1] == "remote"
        assert image[image.index("--platform") + 1] == "linux/arm64"
        assert "--report" not in image

    def test_pkg_relationships_dropped_with_vex(self):
        options = {"pkg_relationships": ["direct"]}
        assert "--pkg-relationships" in build_scan_args("repo", options)
        assert "--pkg-relationships" not in build_scan_args(
            "repo", options, has_vex=True
        )

    def test_profile_validation(self):
        with pytest.raises(OptionError, match="not supported by any"):
            validate_profile_options(
                {"scanners": ["vuln"], "platform": "linux/amd64"}, ["repo"]
            )
        with pytest.raises(OptionError, match="Unknown target type"):
            validate_profile_options({"scanners": ["vuln"]}, ["vm"])
        with pytest.raises(OptionError, match="None of the selected"):
            validate_profile_options({"scanners": ["secret"]}, ["sbom"])

    def test_merge_options(self):
        assert merge_options({"a": 1, "b": 2}, None, {"b": 3, "c": None}) == {
            "a": 1,
            "b": 3,
        }


class TestParserVulnerabilities:
    def test_fields_are_preserved(self):
        parsed = parse_report(_report([LOCK_RESULT]), mode="repo")
        assert parsed.engine_version == "0.74.0"
        assert parsed.metadata["Branch"] == "main"
        (finding,) = parsed.findings
        assert finding.category == "vulnerability"
        assert finding.rule_id == "CVE-2024-0001"
        assert (finding.pkg_name, finding.pkg_version, finding.fixed_version) == (
            "lodash",
            "4.17.20",
            "4.17.21",
        )
        assert finding.ecosystem == "npm"
        assert finding.purl == "pkg:npm/lodash@4.17.20"
        assert finding.severity == "high" and finding.source_severity == "HIGH"
        assert finding.cvss_score == 7.4  # from the severity source, not the max
        assert finding.fix_available is True
        assert finding.direct_dependency is True
        assert finding.details["cwe_ids"] == ["CWE-1321"]
        assert finding.details["data_source"]["ID"] == "ghsa"
        assert finding.details["extra"] == {"FutureField": {"kept": True}}
        assert finding.legacy_uid == "trivy-repo-CVE-2024-0001-lodash-package-lock.json"

    def test_unknown_severity_stays_unknown(self):
        assert normalize_severity("UNKNOWN") == "unknown"
        assert normalize_severity(None) == "unknown"
        assert normalize_severity("weird") == "unknown"
        assert normalize_severity("critical") == "critical"

    def test_cvss_fallbacks(self):
        assert (
            cvss_score({"CVSS": {"nvd": {"V3Score": 9.8}}, "SeveritySource": "redhat"})
            == 9.8
        )
        assert (
            cvss_score({"CVSS": {"a": {"V2Score": 5.0}, "b": {"V40Score": 8.1}}}) == 8.1
        )
        assert cvss_score({"CVSS": {}}) is None
        assert cvss_score({}) is None

    def test_fingerprint_survives_upgrade_and_image_rebuild(self):
        first = parse_report(_report([LOCK_RESULT]), mode="repo").findings[0]
        upgraded = dict(
            LOCK_RESULT, Vulnerabilities=[_vuln(InstalledVersion="4.17.20-patch")]
        )
        assert (
            parse_report(_report([upgraded]), mode="repo").findings[0].fingerprint
            == first.fingerprint
        )

        def image(tag, os_release):
            return _report(
                [
                    {
                        "Target": f"app:{tag} (debian {os_release})",
                        "Class": "os-pkgs",
                        "Type": "debian",
                        "Vulnerabilities": [
                            _vuln(PkgName="openssl", PkgID="openssl@3")
                        ],
                    }
                ]
            )

        one = parse_report(image("1.0", "12.4"), mode="image").findings[0]
        two = parse_report(image("1.1", "12.5"), mode="image").findings[0]
        assert one.fingerprint == two.fingerprint
        other_scope = parse_report(
            image("1.0", "12.4"), mode="image", scope="registry/other"
        )
        assert other_scope.findings[0].fingerprint != one.fingerprint

    def test_same_package_at_two_versions_merges(self):
        result = dict(
            LOCK_RESULT,
            Vulnerabilities=[
                _vuln(),
                _vuln(InstalledVersion="3.10.1", PkgID="lodash@3.10.1"),
            ],
        )
        (finding,) = parse_report(_report([result]), mode="repo").findings
        assert {item["version"] for item in finding.details["instances"]} == {
            "4.17.20",
            "3.10.1",
        }

    def test_unfixed_and_transitive(self):
        result = dict(
            LOCK_RESULT,
            Vulnerabilities=[
                _vuln(
                    PkgID="minimist@1.2.0",
                    PkgName="minimist",
                    FixedVersion="",
                    Status="affected",
                )
            ],
        )
        (finding,) = parse_report(_report([result]), mode="repo").findings
        assert finding.fix_available is False
        assert finding.direct_dependency is False
        assert finding.details["status"] == "affected"


class TestParserOtherCategories:
    MISCONFIG = {
        "Type": "terraform",
        "ID": "AWS-0086",
        "AVDID": "AVD-AWS-0086",
        "Title": "S3 Access block should block public ACL",
        "Description": "PUT calls with a public ACL specified can make objects public.",
        "Message": "No public access block so not blocking public acls",
        "Namespace": "builtin.aws.s3.aws0086",
        "Query": "data.builtin.aws.s3.aws0086.deny",
        "Resolution": "Enable blocking any PUT calls with a public ACL specified",
        "Severity": "HIGH",
        "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0086",
        "References": ["https://example.com"],
        "Status": "FAIL",
        "CauseMetadata": {
            "Resource": "aws_s3_bucket.logs",
            "Provider": "AWS",
            "Service": "s3",
            "StartLine": 10,
            "EndLine": 14,
            "Code": {
                "Lines": [
                    {
                        "Number": 10,
                        "Content": 'resource "aws_s3_bucket" "logs" {',
                        "IsCause": True,
                    },
                    {"Number": 11, "Content": '  bucket = "logs"', "IsCause": True},
                ]
            },
        },
    }

    def _parse(self, misconfigs, target="main.tf"):
        return parse_report(
            _report(
                [
                    {
                        "Target": target,
                        "Class": "config",
                        "Type": "terraform",
                        "MisconfSummary": {"Successes": 4, "Failures": len(misconfigs)},
                        "Misconfigurations": misconfigs,
                    }
                ]
            ),
            mode="iac",
        )

    def test_misconfiguration_fields(self):
        parsed = self._parse([self.MISCONFIG])
        (finding,) = parsed.findings
        assert parsed.passed_checks == 4 and parsed.failed_checks == 1
        assert finding.category == "misconfiguration"
        assert finding.rule_id == "AWS-0086"
        assert finding.finding_type == "terraform"
        assert finding.file_path == "main.tf"
        assert (finding.start_line, finding.end_line) == (10, 14)
        assert finding.resource == "aws_s3_bucket.logs"
        assert finding.details["message"].startswith("No public access block")
        assert finding.details["resolution"].startswith("Enable blocking")
        assert finding.details["legacy_id"] == "AVD-AWS-0086"
        assert finding.details["code"][0]["is_cause"] is True
        assert finding.details["provider"] == "AWS"

    def test_check_id_spellings_share_a_fingerprint(self):
        assert normalize_check_id("AVD-DS-0002") == "DS-0002"
        assert normalize_check_id("DS002") == "DS-0002"
        assert normalize_check_id("ds-0002") == "DS-0002"
        assert normalize_check_id("custom-check") == "CUSTOM-CHECK"
        old = self._parse([dict(self.MISCONFIG, ID="AVD-AWS-0086")]).findings[0]
        new = self._parse([self.MISCONFIG]).findings[0]
        assert old.fingerprint == new.fingerprint

    def test_moved_lines_keep_the_fingerprint_and_resources_differ(self):
        base = self._parse([self.MISCONFIG]).findings[0]
        moved = dict(
            self.MISCONFIG,
            CauseMetadata=dict(
                self.MISCONFIG["CauseMetadata"], StartLine=40, EndLine=44
            ),
        )
        assert self._parse([moved]).findings[0].fingerprint == base.fingerprint
        other = dict(
            self.MISCONFIG,
            CauseMetadata=dict(
                self.MISCONFIG["CauseMetadata"], Resource="aws_s3_bucket.data"
            ),
        )
        both = self._parse([self.MISCONFIG, other]).findings
        assert len({item.fingerprint for item in both}) == 2

    def test_passed_checks_are_not_findings(self):
        parsed = self._parse([dict(self.MISCONFIG, Status="PASS")])
        assert parsed.findings == []

    def test_secret_is_masked_and_numbered(self):
        secret = {
            "RuleID": "aws-access-key-id",
            "Category": "AWS",
            "Severity": "CRITICAL",
            "Title": "AWS Access Key ID",
            "StartLine": 3,
            "EndLine": 3,
            "Match": "AWS_ACCESS_KEY_ID=********************",
            "Code": {
                "Lines": [
                    {"Number": 2, "Content": "# keys", "IsCause": False},
                    {
                        "Number": 3,
                        "Content": "AWS_ACCESS_KEY_ID=********************",
                        "IsCause": True,
                    },
                ]
            },
        }
        result = {
            "Target": "deploy/.env",
            "Class": "secret",
            "Secrets": [secret, dict(secret, StartLine=9, EndLine=9)],
        }
        findings = parse_report(_report([result]), mode="repo").findings
        assert len(findings) == 2
        assert len({item.fingerprint for item in findings}) == 2
        assert all(
            item.category == "secret" and item.severity == "critical"
            for item in findings
        )
        assert findings[0].details["match"].endswith("*" * 20)
        assert findings[0].file_path == "deploy/.env"
        # Same order on a later scan with shifted lines: same fingerprints.
        shifted = {
            "Target": "deploy/.env",
            "Class": "secret",
            "Secrets": [
                dict(secret, StartLine=5, EndLine=5),
                dict(secret, StartLine=20, EndLine=20),
            ],
        }
        again = parse_report(_report([shifted]), mode="repo").findings
        assert {item.fingerprint for item in again} == {
            item.fingerprint for item in findings
        }

    def test_unmasked_secret_is_withheld(self):
        leaked = {
            "RuleID": "generic",
            "Match": "password=hunter2hunter2",
            "Code": {
                "Lines": [
                    {"Number": 1, "Content": "password=hunter2hunter2", "IsCause": True}
                ]
            },
        }
        masked = mask_secret(leaked)
        assert masked["Match"] == REDACTED
        assert masked["Code"]["Lines"][0]["Content"] == REDACTED
        (finding,) = parse_report(
            _report([{"Target": "a.env", "Class": "secret", "Secrets": [leaked]}]),
            mode="fs",
        ).findings
        assert "hunter2" not in json.dumps(finding.details) + json.dumps(finding.raw)

    def test_license_category_and_severity(self):
        result = {
            "Target": "package-lock.json",
            "Class": "license",
            "Type": "npm",
            "Licenses": [
                {
                    "Severity": "HIGH",
                    "Category": "restricted",
                    "PkgName": "readline",
                    "Name": "GPL-3.0",
                    "Confidence": 1,
                    "Link": "https://spdx.org/licenses/GPL-3.0.html",
                    "Text": "x" * 5000,
                },
                {
                    "Severity": "UNKNOWN",
                    "Category": "unknown",
                    "FilePath": "LICENSE.txt",
                    "Name": "Custom",
                },
            ],
        }
        findings = sorted(
            parse_report(_report([result]), mode="repo").findings,
            key=lambda item: item.rule_id,
        )
        custom, gpl = findings
        assert gpl.category == "license" and gpl.finding_type == "restricted"
        assert gpl.severity == "high" and gpl.pkg_name == "readline"
        assert gpl.fix_available is None
        assert len(gpl.details["text"]) == 2000
        assert "Text" not in gpl.raw
        assert custom.severity == "unknown" and custom.file_path == "LICENSE.txt"

    def test_suppressed_findings_are_kept_and_flagged(self):
        result = dict(
            LOCK_RESULT,
            Vulnerabilities=[],
            ExperimentalModifiedFindings=[
                {
                    "Type": "vulnerability",
                    "Status": "not_affected",
                    "Statement": "vulnerable_code_not_in_execute_path",
                    "Source": "OpenVEX",
                    "Finding": _vuln(),
                },
                {"Type": "mystery", "Finding": {}},
            ],
        )
        parsed = parse_report(_report([result]), mode="repo")
        (finding,) = parsed.findings
        assert finding.suppressed is True
        assert finding.suppression["status"] == "not_affected"
        assert finding.suppression["source"] == "OpenVEX"
        assert any("unknown type" in warning for warning in parsed.warnings)
        assert finding_stats(parsed.findings) == {
            "total": 0,
            "suppressed": 1,
            "by_category": {},
        }


class TestParserShapes:
    def test_components(self):
        parsed = parse_report(_report([LOCK_RESULT]), mode="repo")
        lodash, minimist = parsed.components
        assert (lodash.name, lodash.version, lodash.ecosystem) == (
            "lodash",
            "4.17.20",
            "npm",
        )
        assert lodash.relationship == "direct" and lodash.licenses == ["MIT"]
        assert lodash.depends_on == ["minimist@1.2.0"]
        assert minimist.relationship == "indirect" and minimist.dev is True
        assert lodash.location == "package-lock.json"

    def test_deprecated_indirect_flag(self):
        result = {
            "Target": "go.mod",
            "Class": "lang-pkgs",
            "Type": "gomod",
            "Packages": [{"Name": "a", "Version": "1", "Indirect": True}],
        }
        assert (
            parse_report(_report([result]), mode="repo").components[0].relationship
            == "indirect"
        )

    def test_cluster_report(self):
        report = {
            "SchemaVersion": 2,
            "ClusterName": "prod",
            "Resources": [
                {
                    "Namespace": "shop",
                    "Kind": "Deployment",
                    "Name": "api",
                    "Results": [
                        {
                            "Target": "registry/api:1 (alpine 3.19)",
                            "Class": "os-pkgs",
                            "Type": "alpine",
                            "Vulnerabilities": [_vuln(PkgName="musl", PkgID="musl@1")],
                        }
                    ],
                },
                {
                    "Namespace": "shop",
                    "Kind": "Pod",
                    "Name": "broken",
                    "Error": "pull failed",
                },
            ],
        }
        parsed = parse_report(report, mode="k8s")
        assert parsed.artifact_name == "prod" and parsed.artifact_type == "kubernetes"
        (finding,) = parsed.findings
        assert finding.resource == "shop/Deployment/api"
        assert finding.location.startswith("shop/Deployment/api/")
        assert finding.details["kubernetes"]["kind"] == "Deployment"
        assert parsed.resource_errors == [
            {"resource": "shop/Pod/broken", "error": "pull failed"}
        ]
        # The summary report names the array "Findings".
        summary = {"ClusterName": "prod", "Findings": report["Resources"]}
        assert len(parse_report(summary, mode="k8s").findings) == 1

    def test_malformed_input_never_raises(self):
        with pytest.raises(ReportError):
            parse_report([], mode="repo")
        parsed = parse_report(
            {
                "SchemaVersion": 9,
                "Results": [
                    "nope",
                    {
                        "Target": None,
                        "Vulnerabilities": ["x", {}],
                        "Packages": [None, {"Version": "1"}],
                        "Secrets": None,
                        "Licenses": {},
                        "Misconfigurations": [{}],
                    },
                ],
            },
            mode="repo",
        )
        assert any("schema version" in warning for warning in parsed.warnings)
        assert len(parsed.findings) == 2
        assert parsed.components == []
        assert parse_report({}, mode="repo").findings == []

    def test_long_uid_is_bounded_and_unique(self):
        a = bounded_uid("x" * 400 + "a")
        b = bounded_uid("x" * 400 + "b")
        assert len(a) == 300 and a != b

    def test_code_rows(self):
        rows = [
            {
                "uid": "opengrep-sast-python_eval_rule-eval-app.py:3-3",
                "severity": "high",
                "check_id": "python_eval_rule-eval",
                "check_metadata": {
                    "CheckTitle": "Use of eval",
                    "Description": "eval is dangerous",
                    "Categories": ["CWE-95"],
                    "Remediation": {
                        "Recommendation": {"Text": "Avoid eval"},
                        "Code": {"Other": "ast.literal_eval(x)"},
                    },
                },
                "raw_result": {
                    "path": "app.py",
                    "start": {"line": 3},
                    "end": {"line": 3},
                    "extra": {"severity": "ERROR"},
                },
                "resource_uid": "app.py",
            }
        ]
        (finding,) = parse_code_rows(rows)
        assert finding.category == "code" and finding.severity == "high"
        assert finding.file_path == "app.py" and finding.start_line == 3
        assert finding.legacy_uid == rows[0]["uid"]
        assert finding.details["fix"] == "ast.literal_eval(x)"


class TestRisk:
    NOW = datetime(2026, 11, 1, tzinfo=UTC)

    def test_severity_is_the_base_and_factors_explain_the_score(self):
        result = score_finding(
            RiskInput(
                category="vulnerability",
                severity="high",
                cvss_score=8.0,
                fix_available=True,
            )
        )
        keys = [factor["key"] for factor in result.factors]
        assert keys == ["severity", "cvss", "fix_available"]
        assert result.score == round(sum(factor["points"] for factor in result.factors))
        assert result.score == 53 and result.priority == "medium"

    def test_unknown_inputs_add_nothing(self):
        bare = score_finding(RiskInput(category="vulnerability", severity="critical"))
        assert [factor["key"] for factor in bare.factors] == ["severity"]
        assert bare.score == 55

    def test_context_raises_priority_without_touching_severity(self):
        base = RiskInput(category="vulnerability", severity="high", cvss_score=7.5)
        exposed = RiskInput(
            category="vulnerability",
            severity="high",
            cvss_score=7.5,
            known_exploited=True,
            epss_score=0.9,
            internet_exposed=True,
            criticality="critical",
            environment="production",
            direct_dependency=True,
            first_seen_at=self.NOW - timedelta(days=400),
            now=self.NOW,
        )
        low, high = score_finding(base), score_finding(exposed)
        assert high.score > low.score and high.priority == "urgent"
        assert high.score <= 100
        assert {
            "known_exploited",
            "epss",
            "internet_exposed",
            "criticality",
            "environment",
            "age",
        } <= {factor["key"] for factor in high.factors}

    def test_secret_floor(self):
        result = score_finding(RiskInput(category="secret", severity="medium"))
        assert result.score == DEFAULT_RISK_CONFIG["secret_floor"]
        assert result.factors[-1]["key"] == "secret_floor"

    def test_config_overrides(self):
        config = merge_risk_config(
            {"thresholds": {"urgent": 50, "high": 45}, "fix_available_points": 0}
        )
        assert config["thresholds"] == {"urgent": 50, "high": 45, "medium": 35}
        assert config["fix_available_points"] == 0
        assert DEFAULT_RISK_CONFIG["thresholds"]["urgent"] == 80  # defaults untouched
        result = score_finding(
            RiskInput(category="vulnerability", severity="critical"), config
        )
        assert result.priority == "urgent"

    @pytest.mark.parametrize(
        "overrides",
        [
            {"made_up": 1},
            {"severity_points": {"extreme": 5}},
            {"severity_points": 5},
            {"cvss_max_points": "ten"},
            {"cvss_max_points": 500},
            {"thresholds": {"urgent": 10, "high": 60}},
            "nope",
        ],
    )
    def test_bad_config_rejected(self, overrides):
        with pytest.raises(RiskConfigError):
            merge_risk_config(overrides)

    def test_sla_days(self):
        assert merge_sla_days(None)["critical"] == 7
        assert merge_sla_days({"critical": 3})["critical"] == 3
        with pytest.raises(RiskConfigError):
            merge_sla_days({"critical": 0})
        with pytest.raises(RiskConfigError):
            merge_sla_days({"urgent": 3})


class TestSbom:
    BASE = [
        {
            "name": "lodash",
            "version": "4.17.20",
            "ecosystem": "npm",
            "location": "package-lock.json",
            "licenses": ["MIT"],
            "ref": "lodash@4.17.20",
            "depends_on": ["minimist@1.2.0"],
            "purl": "pkg:npm/lodash@4.17.20",
            "relationship": "direct",
        },
        {
            "name": "minimist",
            "version": "1.2.0",
            "ecosystem": "npm",
            "location": "package-lock.json",
            "licenses": [],
            "ref": "minimist@1.2.0",
            "relationship": "indirect",
        },
        {
            "name": "left-pad",
            "version": "1.0.0",
            "ecosystem": "npm",
            "location": "package-lock.json",
            "licenses": ["WTFPL"],
            "ref": "left-pad@1.0.0",
        },
    ]

    def test_diff(self):
        head = [
            dict(self.BASE[0], version="4.17.21"),
            self.BASE[1],
            {
                "name": "axios",
                "version": "1.7.0",
                "ecosystem": "npm",
                "location": "package-lock.json",
                "licenses": ["MIT"],
            },
        ]
        diff = diff_components(self.BASE, head)
        assert [item["name"] for item in diff["added"]] == ["axios"]
        assert [item["name"] for item in diff["removed"]] == ["left-pad"]
        (changed,) = diff["changed"]
        assert changed["from_versions"] == ["4.17.20"] and changed["to_versions"] == [
            "4.17.21"
        ]
        assert diff["unchanged"] == 1
        same = diff_components(self.BASE, self.BASE)
        assert not same["added"] and not same["removed"] and not same["changed"]

    def test_summary(self):
        summary = summarize(self.BASE)
        assert summary["total"] == 3 and summary["ecosystems"] == {"npm": 3}
        assert summary["licenses"] == {"MIT": 1, "WTFPL": 1}
        assert summary["without_license"] == 1
        assert summary["relationships"]["direct"] == 1

    def test_cyclonedx_document(self):
        document = build_cyclonedx(
            self.BASE,
            name="shop",
            created_at=datetime(2026, 11, 1, tzinfo=UTC),
            tool_name="Cloudsneeker",
            tool_version="0.74.0",
        )
        assert document["bomFormat"] == "CycloneDX"
        assert detect_document_format(document) == "cyclonedx"
        assert len(document["components"]) == 3
        assert document["components"][0]["purl"] == "pkg:npm/lodash@4.17.20"
        assert document["dependencies"] == [
            {"ref": "pkg:npm/lodash@4.17.20", "dependsOn": ["minimist@1.2.0"]}
        ]
        refs = [component["bom-ref"] for component in document["components"]]
        assert len(refs) == len(set(refs))

    def test_format_detection(self):
        assert detect_document_format({"spdxVersion": "SPDX-2.3"}) == "spdx"
        assert detect_document_format("SPDXVersion: SPDX-2.3\n") == "spdx"
        assert detect_document_format({"hello": 1}) == ""
        assert detect_document_format("<bom/>") == ""

    def test_max_severity(self):
        assert max_severity(["low", "critical", "medium"]) == "critical"
        assert max_severity([]) == ""


class TestFailures:
    @pytest.mark.parametrize(
        ("stderr", "kind", "retryable"),
        [
            (
                "2026-11-01T00:00:00Z\tFATAL\tFatal error\tinit error: DB error: failed to download vulnerability DB",
                FAILURE_DATABASE,
                True,
            ),
            (
                "FATAL image scan error: context deadline exceeded",
                FAILURE_TIMEOUT,
                False,
            ),
            (
                "FATAL unable to find the specified image: UNAUTHORIZED: authentication required",
                FAILURE_AUTH,
                False,
            ),
            (
                "FATAL repository scan error: repository not found",
                FAILURE_NOT_FOUND,
                False,
            ),
            ("something unexpected", FAILURE_ENGINE, False),
        ],
    )
    def test_classification(self, stderr, kind, retryable):
        failure = classify_failure(1, stderr)
        assert failure.kind == kind and failure.retryable is retryable

    def test_message_and_tail(self):
        stderr = "INFO ok\n2026-11-01T00:00:00Z\tFATAL\tunknown flag: --nope"
        assert last_error_line(stderr) == "unknown flag: --nope"
        assert classify_failure(None, "").message.endswith("error.")
        assert "exit status 2" in classify_failure(2, "").message
        assert len(stderr_tail("a\n" * 5000, 100)) <= 100
        assert stderr_tail(None) == ""

    def test_backoff_is_bounded(self):
        assert [retry_delay_seconds(n) for n in (1, 2, 3, 4, 9)] == [
            15,
            30,
            60,
            120,
            120,
        ]


REGO = """# METADATA
# title: Buckets need an owner tag
# custom:
#   id: ACME-0001
#   severity: HIGH
package user.acme.tags

deny[res] {
  input.kind == "bucket"
  res := result.new("missing owner", input)
}
"""


class TestPolicies:
    def test_rego(self):
        assert policies.validate_policy("rego_check", REGO).valid
        assert policies.rego_namespace(REGO) == "user.acme.tags"
        assert not policies.validate_policy("rego_check", "deny { true }").valid
        assert not policies.validate_policy(
            "rego_check", "package builtin.aws\ndeny { true }"
        ).valid
        assert not policies.validate_policy(
            "rego_check", "package a.b\nallow { true }"
        ).valid

    def test_secret_rules(self):
        good = """
rules:
  - id: acme-token
    category: Acme
    title: Acme token
    severity: HIGH
    regex: acme_[a-z0-9]{32}
disable-rules:
  - slack-web-hook
"""
        result = policies.validate_policy("secret_rules", good)
        assert result.valid and result.info["custom_rules"] == 1
        assert not policies.validate_policy("secret_rules", "rules:\n  - id: x\n").valid
        assert not policies.validate_policy("secret_rules", "nonsense: 1").valid
        assert not policies.validate_policy("secret_rules", ": : :").valid

    def test_license_and_ignore(self):
        assert policies.validate_policy(
            "license_policy", "forbidden: [AGPL-3.0]\nignored: [MIT]"
        ).valid
        assert not policies.validate_policy(
            "license_policy", "forbidden: [GPL-3.0]\nrestricted: [GPL-3.0]"
        ).valid
        assert not policies.validate_policy("license_policy", "banned: [X]").valid
        ignore = "vulnerabilities:\n  - id: CVE-2024-1\n    expired_at: 2027-01-01\n    statement: accepted\n"
        assert policies.validate_policy("ignore_rules", ignore).valid
        assert not policies.validate_policy(
            "ignore_rules", "vulnerabilities:\n  - paths: [a]\n"
        ).valid
        assert not policies.validate_policy(
            "ignore_rules", "secrets:\n  - id: x\n    purls: [pkg:npm/a]\n"
        ).valid
        assert not policies.validate_policy(
            "ignore_rules", "vulnerabilities:\n  - id: x\n    expired_at: soon\n"
        ).valid

    def test_vex(self):
        openvex = json.dumps(
            {"@context": "https://openvex.dev/ns/v0.2.0", "statements": [{}]}
        )
        assert policies.validate_policy("vex", openvex).info["format"] == "openvex"
        assert not policies.validate_policy("vex", "{}").valid
        assert not policies.validate_policy("vex", "not json").valid
        assert not policies.validate_policy("vex", "").valid
        assert not policies.validate_policy("mystery", "x").valid

    def test_files_and_flags(self, tmp_path):
        openvex = json.dumps(
            {"@context": "https://openvex.dev/ns/v0.2.0", "statements": [{}]}
        )
        cdx_vex = json.dumps({"bomFormat": "CycloneDX", "vulnerabilities": [{}]})
        items = [
            {
                "id": "1",
                "kind": "rego_check",
                "name": "tags",
                "version": 2,
                "content": REGO,
            },
            {
                "id": "2",
                "kind": "secret_rules",
                "name": "s",
                "version": 1,
                "content": "disable-rules: [slack-web-hook]",
            },
            {
                "id": "3",
                "kind": "ignore_rules",
                "name": "i",
                "version": 1,
                "content": "vulnerabilities:\n  - id: CVE-1\n",
            },
            {
                "id": "4",
                "kind": "license_policy",
                "name": "l",
                "version": 1,
                "content": "forbidden: [AGPL-3.0]\nignored: [MIT]",
            },
            {"id": "5", "kind": "vex", "name": "v", "version": 1, "content": openvex},
            {"id": "6", "kind": "vex", "name": "cdx", "version": 1, "content": cdx_vex},
        ]
        out = policies.write_policy_files(
            items,
            tmp_path,
            target_type="repo",
            scanners=["vuln", "misconfig", "secret", "license"],
        )
        flags = out.flags
        assert flags[flags.index("--check-namespaces") + 1] == "user.acme.tags"
        for flag in (
            "--config-check",
            "--secret-config",
            "--ignorefile",
            "--config",
            "--vex",
        ):
            assert flag in flags
        assert flags[flags.index("--ignored-licenses") + 1] == "MIT"
        assert out.has_vex is True
        assert [item["id"] for item in out.applied] == ["1", "2", "3", "4", "5"]
        assert out.skipped[0]["id"] == "6"
        assert (tmp_path / "policies" / "checks" / "check_0.rego").read_text() == REGO

        only_vuln = policies.write_policy_files(
            items,
            tmp_path / "b",
            target_type="sbom",
            scanners=["vuln"],
            sbom_format="cyclonedx",
        )
        assert (
            "--config-check" not in only_vuln.flags
            and "--secret-config" not in only_vuln.flags
        )
        assert only_vuln.flags.count("--vex") == 2
        assert {item["id"] for item in only_vuln.skipped} == {"1", "2", "4"}
