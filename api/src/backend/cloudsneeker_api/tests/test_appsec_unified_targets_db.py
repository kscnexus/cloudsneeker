"""One target per repository, with the database: static analysis rows in
the repository run, extra-branch findings, branch runs and target merges."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from api.db_router import MainRouter
from api.models import Finding, Scan
from cloudsneeker_api.appsec import engine, lifecycle
from cloudsneeker_api.appsec.parser import parse_code_rows, parse_report
from cloudsneeker_api.appsec.shared_rows import shared_row
from cloudsneeker_api.models import AppSecFinding, AppSecSbom, TrivyRun, TrivyTarget
from cloudsneeker_api.services import branch_policy
from cloudsneeker_api.services.repo_branches import RepositoryBranches
from cloudsneeker_api.services.target_merge import TargetMergeError, merge_targets
from cloudsneeker_api.services.trivy_import import opengrep_results_to_finding_rows
from django.urls import reverse
from django.utils import timezone

JSONAPI = "application/vnd.api+json"

VULN = {
    "VulnerabilityID": "CVE-2024-0001",
    "PkgID": "lodash@4.17.20",
    "PkgName": "lodash",
    "InstalledVersion": "4.17.20",
    "FixedVersion": "4.17.21",
    "Severity": "HIGH",
    "Title": "CVE-2024-0001 in lodash",
}


def _report(vulns):
    return {
        "SchemaVersion": 2,
        "ArtifactName": "shop",
        "ArtifactType": "repository",
        "Results": [
            {
                "Target": "package-lock.json",
                "Class": "lang-pkgs",
                "Type": "npm",
                "Vulnerabilities": list(vulns),
            }
        ],
    }


def _code_report(rule="python.lang.security.eval"):
    return {
        "results": [
            {
                "check_id": rule,
                "path": "app.py",
                "start": {"line": 3},
                "end": {"line": 3},
                "extra": {"severity": "ERROR", "message": "eval"},
            }
        ],
        "errors": [],
    }


@pytest.fixture
def target(iac_provider):
    return TrivyTarget.objects.create(
        tenant_id=iac_provider.tenant_id,
        provider=iac_provider,
        name="shop repo",
        mode="repo",
        config={"repository_url": iac_provider.uid, "branch": "main"},
    )


def _run(target, branch=""):
    return TrivyRun.objects.create(
        tenant_id=target.tenant_id,
        target=target,
        provider=target.provider,
        status=TrivyRun.Status.RUNNING,
        started_at=timezone.now(),
        branch=branch,
    )


def _persist(target, *, vulns=(VULN,), code=None, branch=""):
    run = _run(target, branch)
    parsed = parse_report(_report(vulns), mode="repo")
    findings = list(parsed.findings)
    coverage = lifecycle.coverage_for({"scanners": ["vuln"]})
    code_rows_for = None
    if code is not None:
        step = engine.CodeStep(
            config={"rulesets": ["auto"], "exclude": []}, report=code
        )
        code_findings, code_rows_for, code_coverage = engine._code_step_results(step)
        findings.extend(code_findings)
        coverage = lifecycle.combine_coverage(coverage, code_coverage)
    stored = engine.persist_results(
        tenant_id=str(target.tenant_id),
        run=run,
        target=target,
        provider=target.provider,
        findings=findings,
        components=parsed.components,
        coverage=coverage,
        artifact_name="shop",
        artifact_type="repository",
        inventory_source="generated",
        document_format="",
        shared_rows_for=lambda uids: [
            shared_row(item, uids[item.fingerprint], mode="repo")
            for item in findings
            if item.category != "code"
        ],
        scan_name="scan",
        using=MainRouter.admin_db,
        code_rows_for=code_rows_for,
        branch=branch,
    )
    return run, stored


@pytest.mark.django_db
class TestRepositoryRunWithStaticAnalysis:
    def test_one_run_writes_two_streams(self, target):
        _run_row, stored = _persist(target, code=_code_report())
        assert stored["scan_id"] and stored["code_scan_id"]
        assert Scan.all_objects.get(id=stored["scan_id"]).scanner_args["mode"] == "repo"
        assert (
            Scan.all_objects.get(id=stored["code_scan_id"]).scanner_args["mode"]
            == "sast"
        )
        assert Finding.all_objects.filter(scan_id=stored["code_scan_id"]).count() == 1
        categories = set(
            AppSecFinding.objects.filter(target=target).values_list(
                "category", flat=True
            )
        )
        assert categories == {"vulnerability", "code"}

    def test_failed_static_analysis_keeps_code_findings_open(self, target):
        _persist(target, code=_code_report())
        step = engine.CodeStep(config={}, error="clone failed")
        code_findings, _rows, code_coverage = engine._code_step_results(step)
        run = _run(target)
        parsed = parse_report(_report([]), mode="repo")
        engine.persist_results(
            tenant_id=str(target.tenant_id),
            run=run,
            target=target,
            provider=target.provider,
            findings=parsed.findings + code_findings,
            components=[],
            coverage=lifecycle.combine_coverage(
                lifecycle.coverage_for({"scanners": ["vuln"]}), code_coverage
            ),
            artifact_name="shop",
            artifact_type="repository",
            inventory_source="generated",
            document_format="",
            shared_rows_for=lambda uids: [],
            scan_name="scan",
            using=MainRouter.admin_db,
        )
        states = dict(
            AppSecFinding.objects.filter(target=target).values_list("category", "state")
        )
        assert states == {"vulnerability": "fixed", "code": "new"}


@pytest.mark.django_db
class TestExtraBranches:
    def test_branch_findings_are_apart_and_write_no_shared_rows(self, target):
        _persist(target)
        _run_row, stored = _persist(target, vulns=[], branch="dev")
        assert stored["scan_id"] is None and stored["sbom_id"] is None
        main = AppSecFinding.objects.get(target=target, branch="")
        assert main.state == "new"  # the empty dev scan does not fix main
        _persist(target, branch="dev")
        dev = AppSecFinding.objects.get(target=target, branch="dev")
        assert dev.uid != main.uid
        assert AppSecSbom.objects.filter(target=target).count() == 1

    def test_findings_api_reads_main_branch_by_default(
        self, authenticated_client, target
    ):
        _persist(target)
        _persist(target, branch="dev")
        url = reverse("appsec-findings-list")
        assert len(authenticated_client.get(url).json()["data"]) == 1
        rows = authenticated_client.get(url, {"filter[branch]": "dev"}).json()["data"]
        assert [row["attributes"]["branch"] for row in rows] == ["dev"]
        assert (
            len(authenticated_client.get(url, {"filter[branch]": "*"}).json()["data"])
            == 2
        )
        summary = authenticated_client.get(
            reverse("appsec-findings-summary"), {"filter[target]": str(target.id)}
        ).json()
        body = summary.get("data", summary)
        branches = body.get("branches") or body.get("attributes", {}).get("branches")
        assert branches == ["dev"]

    def test_queue_branch_runs_skips_unchanged_and_main(self, target):
        target.config = {**target.config, "branches": ["dev", "release/*"]}
        target.save()
        TrivyRun.objects.create(
            tenant_id=target.tenant_id,
            target=target,
            provider=target.provider,
            status=TrivyRun.Status.COMPLETED,
            finished_at=timezone.now(),
            branch="dev",
            summary={"commit": "d1"},
        )
        listing = RepositoryBranches(
            branches=["main", "dev", "release/1", "feature"],
            default_branch="main",
            commits={"main": "m", "dev": "d1", "release/1": "r1", "feature": "f"},
        )
        with (
            patch(
                "cloudsneeker_api.services.repo_branches.list_repository_branches",
                return_value=listing,
            ),
            patch("cloudsneeker_api.tasks.trivy_scan_task.delay"),
        ):
            result = branch_policy.queue_branch_runs(
                tenant_id=str(target.tenant_id),
                target_id=str(target.id),
                trigger="manual",
            )
        assert result["queued"] == ["release/1"]
        assert result["skipped"] == ["dev"]
        run = TrivyRun.objects.get(target=target, branch="release/1")
        assert run.summary == {"commit": "r1"} and run.status == "pending"

    def test_scan_endpoint_runs_one_branch(self, authenticated_client, target):
        with (
            patch("cloudsneeker_api.tasks.trivy_scan_task.delay"),
            patch("cloudsneeker_api.tasks.appsec_branch_runs_task.delay") as fan_out,
        ):
            response = authenticated_client.post(
                reverse("trivy-targets-scan", kwargs={"pk": target.id}),
                data=json.dumps(
                    {"data": {"type": "x", "attributes": {"branch": "dev"}}}
                ),
                content_type=JSONAPI,
            )
        assert response.status_code == 202
        assert TrivyRun.objects.get(target=target).branch == "dev"
        fan_out.assert_not_called()


def _sast_target(provider, name="shop sast", branch="main"):
    return TrivyTarget.objects.create(
        tenant_id=provider.tenant_id,
        provider=provider,
        name=name,
        mode="sast",
        config={
            "repository_url": provider.uid,
            "branch": branch,
            "rulesets": ["python"],
            "exclude": [],
        },
    )


def _code_scan(target, branch=""):
    run = _run(target, branch)
    rows = opengrep_results_to_finding_rows(_code_report())
    findings = parse_code_rows(rows)
    stored = engine.persist_results(
        tenant_id=str(target.tenant_id),
        run=run,
        target=target,
        provider=target.provider,
        findings=findings,
        components=[],
        coverage=lifecycle.coverage_for({"scanners": ["sast"]}),
        artifact_name=target.name,
        artifact_type="sast",
        inventory_source="generated",
        document_format="",
        shared_rows_for=engine.code_shared_rows(rows, findings),
        scan_name="SAST",
        using=MainRouter.admin_db,
    )
    TrivyRun.objects.filter(id=run.id).update(
        scan_id=stored["scan_id"], status=TrivyRun.Status.COMPLETED
    )
    return run


@pytest.mark.django_db
class TestMergeTargets:
    def test_sast_twin_turns_on_static_analysis(self, target, iac_provider):
        _persist(target)
        twin = _sast_target(iac_provider)
        run = _code_scan(twin)
        uid = AppSecFinding.objects.get(target=twin).uid
        result = merge_targets(
            tenant_id=str(target.tenant_id),
            target_id=str(target.id),
            source_ids=[str(twin.id)],
        )
        assert result["sast_enabled"] is True and result["branches"] == []
        target.refresh_from_db()
        assert target.config["sast"] == {"rulesets": ["python"], "exclude": []}
        assert not TrivyTarget.objects.filter(id=twin.id).exists()
        moved = AppSecFinding.objects.get(uid=uid)
        assert moved.target_id == target.id and moved.branch == ""
        run.refresh_from_db()
        assert run.target_id == target.id
        assert run.scan_id is None and run.code_scan_id is not None

    def test_branch_copy_becomes_an_extra_branch(self, target, iac_provider):
        copy = TrivyTarget.objects.create(
            tenant_id=iac_provider.tenant_id,
            provider=iac_provider,
            name="shop repo @ dev",
            mode="repo",
            config={"repository_url": iac_provider.uid, "branch": "dev"},
        )
        _persist(copy)
        merge_targets(
            tenant_id=str(target.tenant_id),
            target_id=str(target.id),
            source_ids=[str(copy.id)],
        )
        target.refresh_from_db()
        assert target.config["branches"] == ["dev"]
        assert AppSecFinding.objects.get(target=target).branch == "dev"
        assert not AppSecSbom.objects.filter(target=target).exists()

    def test_other_repository_or_conflicts_are_refused(
        self, target, iac_provider, github_provider
    ):
        other = TrivyTarget.objects.create(
            tenant_id=iac_provider.tenant_id,
            provider=github_provider,
            name="other",
            mode="sbom",
            config={"sbom": "{}"},
        )
        with pytest.raises(TargetMergeError):
            merge_targets(
                tenant_id=str(target.tenant_id),
                target_id=str(target.id),
                source_ids=[str(other.id)],
            )
        twin = TrivyTarget.objects.create(
            tenant_id=iac_provider.tenant_id,
            provider=iac_provider,
            name="shop repo copy",
            mode="repo",
            config={"repository_url": iac_provider.uid, "branch": "main"},
        )
        _persist(target)
        _persist(twin)
        with pytest.raises(TargetMergeError, match="same branch"):
            merge_targets(
                tenant_id=str(target.tenant_id),
                target_id=str(target.id),
                source_ids=[str(twin.id)],
            )
        assert TrivyTarget.objects.filter(id=twin.id).exists()

    def test_merge_endpoint(self, authenticated_client, target, iac_provider):
        twin = _sast_target(iac_provider)
        response = authenticated_client.post(
            reverse("trivy-targets-merge", kwargs={"pk": target.id}),
            data=json.dumps(
                {
                    "data": {
                        "type": "x",
                        "attributes": {"source_target_ids": [str(twin.id)]},
                    }
                }
            ),
            content_type=JSONAPI,
        )
        assert response.status_code == 200
        assert response.json()["data"]["attributes"]["config"]["sast"]["rulesets"] == [
            "python"
        ]
        response = authenticated_client.post(
            reverse("trivy-targets-merge", kwargs={"pk": target.id}),
            data=json.dumps(
                {
                    "data": {
                        "type": "x",
                        "attributes": {"source_target_ids": [str(target.id)]},
                    }
                }
            ),
            content_type=JSONAPI,
        )
        assert response.status_code == 409
