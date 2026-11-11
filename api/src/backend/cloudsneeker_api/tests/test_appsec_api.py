"""ASPM with the database: finding lifecycle across scans, inventory, the
API, permissions and tenant isolation."""

from __future__ import annotations

import json
from datetime import timedelta
from unittest.mock import patch

import pytest
from api.db_router import MainRouter
from api.models import Finding
from cloudsneeker_api.appsec import engine, inventory, lifecycle
from cloudsneeker_api.appsec.parser import parse_report
from cloudsneeker_api.appsec.risk import DEFAULT_RISK_CONFIG, DEFAULT_SLA_DAYS
from cloudsneeker_api.appsec.shared_rows import shared_row
from cloudsneeker_api.models import (
    AppSecApplication,
    AppSecFinding,
    AppSecFindingEvent,
    AppSecPolicy,
    AppSecSbom,
    AppSecScanProfile,
    FindingTriage,
    TrivyRun,
    TrivyTarget,
)
from django.urls import reverse
from django.utils import timezone

JSONAPI = "application/vnd.api+json"


def _vuln(cve="CVE-2024-0001", pkg="lodash", severity="HIGH", fixed="4.17.21"):
    return {
        "VulnerabilityID": cve,
        "PkgID": f"{pkg}@4.17.20",
        "PkgName": pkg,
        "InstalledVersion": "4.17.20",
        "FixedVersion": fixed,
        "Severity": severity,
        "Title": f"{cve} in {pkg}",
        "CVSS": {"nvd": {"V3Score": 8.1}},
    }


def _report(vulns, secrets=()):
    results = [
        {
            "Target": "package-lock.json",
            "Class": "lang-pkgs",
            "Type": "npm",
            "Packages": [
                {
                    "ID": "lodash@4.17.20",
                    "Name": "lodash",
                    "Version": "4.17.20",
                    "Licenses": ["MIT"],
                    "Relationship": "direct",
                },
                {
                    "ID": "minimist@1.2.0",
                    "Name": "minimist",
                    "Version": "1.2.0",
                    "Relationship": "indirect",
                },
            ],
            "Vulnerabilities": list(vulns),
        }
    ]
    if secrets:
        results.append({"Target": ".env", "Class": "secret", "Secrets": list(secrets)})
    return {
        "SchemaVersion": 2,
        "ArtifactName": "shop",
        "ArtifactType": "repository",
        "Results": results,
    }


SECRET = {
    "RuleID": "aws-access-key-id",
    "Category": "AWS",
    "Severity": "CRITICAL",
    "Title": "AWS Access Key ID",
    "StartLine": 1,
    "EndLine": 1,
    "Match": "KEY=********************",
}


@pytest.fixture
def target(iac_provider):
    return TrivyTarget.objects.create(
        tenant_id=iac_provider.tenant_id,
        provider=iac_provider,
        name="shop repo",
        mode="repo",
        config={"repository_url": iac_provider.uid},
    )


def _run(target, at=None) -> TrivyRun:
    return TrivyRun.objects.create(
        tenant_id=target.tenant_id,
        target=target,
        provider=target.provider,
        status=TrivyRun.Status.RUNNING,
        started_at=at or timezone.now(),
    )


def _scan(target, report, *, options=None, complete=True, at=None):
    """Persist one scan the way the engine does."""
    run = _run(target, at)
    parsed = parse_report(report, mode=target.mode)
    options = options or {"scanners": ["vuln", "secret"]}
    stored = engine.persist_results(
        tenant_id=str(target.tenant_id),
        run=run,
        target=target,
        provider=target.provider,
        findings=parsed.findings,
        components=parsed.components,
        coverage=lifecycle.coverage_for(options, complete=complete),
        artifact_name=parsed.artifact_name,
        artifact_type=parsed.artifact_type,
        inventory_source="generated",
        document_format="",
        shared_rows_for=lambda uids: [
            shared_row(finding, uids[finding.fingerprint], mode=target.mode)
            for finding in parsed.findings
            if not finding.suppressed
        ],
        scan_name="scan",
        using=MainRouter.admin_db,
    )
    return run, stored


def _state(target) -> dict[str, str]:
    return {
        row.rule_id: row.state for row in AppSecFinding.objects.filter(target=target)
    }


@pytest.mark.django_db
class TestLifecycle:
    def test_new_open_fixed_reopened(self, target):
        _, first = _scan(target, _report([_vuln(), _vuln("CVE-2024-0002")], [SECRET]))
        assert first["lifecycle"] == {
            "new": 3,
            "reopened": 0,
            "open": 0,
            "fixed": 0,
            "suppressed": 0,
        }
        assert set(_state(target).values()) == {"new"}

        _, second = _scan(target, _report([_vuln()], [SECRET]))
        assert second["lifecycle"]["open"] == 2 and second["lifecycle"]["fixed"] == 1
        assert _state(target) == {
            "CVE-2024-0001": "open",
            "CVE-2024-0002": "fixed",
            "aws-access-key-id": "open",
        }
        fixed = AppSecFinding.objects.get(target=target, rule_id="CVE-2024-0002")
        assert fixed.fixed_at is not None

        _, third = _scan(target, _report([_vuln(), _vuln("CVE-2024-0002")], [SECRET]))
        assert third["lifecycle"]["reopened"] == 1
        reopened = AppSecFinding.objects.get(target=target, rule_id="CVE-2024-0002")
        assert reopened.state == "reopened" and reopened.reopen_count == 1
        assert reopened.fixed_at is None
        kinds = list(
            AppSecFindingEvent.objects.filter(finding=reopened)
            .order_by("inserted_at")
            .values_list("kind", flat=True)
        )
        assert kinds == ["detected", "fixed", "reopened"]
        # One row per finding however many scans report it.
        assert AppSecFinding.objects.filter(target=target).count() == 3

    def test_absence_without_coverage_is_not_a_fix(self, target):
        _scan(target, _report([_vuln(severity="MEDIUM")], [SECRET]))
        # A secrets-only scan says nothing about vulnerabilities, so the
        # finding keeps its state instead of being marked fixed.
        _scan(target, _report([], [SECRET]), options={"scanners": ["secret"]})
        assert _state(target)["CVE-2024-0001"] == "new"
        # A severity filter above the finding's severity.
        _scan(
            target,
            _report([]),
            options={"scanners": ["vuln"], "severities": ["CRITICAL"]},
        )
        assert _state(target)["CVE-2024-0001"] == "new"
        # A partial scan.
        _scan(target, _report([]), complete=False)
        assert _state(target)["CVE-2024-0001"] == "new"
        # A full scan that no longer reports it.
        _scan(target, _report([]))
        assert _state(target)["CVE-2024-0001"] == "fixed"

    def test_priority_deadline_and_uid(self, target):
        _scan(target, _report([_vuln(severity="CRITICAL")], [SECRET]))
        vuln = AppSecFinding.objects.get(target=target, rule_id="CVE-2024-0001")
        assert vuln.uid == "trivy-repo-CVE-2024-0001-lodash-package-lock.json"
        assert vuln.severity == "critical" and vuln.cvss_score == 8.1
        assert vuln.priority_score > DEFAULT_RISK_CONFIG["severity_points"]["critical"]
        assert [factor["key"] for factor in vuln.priority_factors][0] == "severity"
        assert vuln.due_at - vuln.first_seen_at == timedelta(
            days=DEFAULT_SLA_DAYS["critical"]
        )
        secret = AppSecFinding.objects.get(target=target, category="secret")
        assert secret.priority_score >= DEFAULT_RISK_CONFIG["secret_floor"]

    def test_shared_rows_and_triage_use_the_same_uid(self, target):
        run, stored = _scan(target, _report([_vuln()]))
        finding = AppSecFinding.objects.get(target=target)
        shared = Finding.all_objects.filter(scan_id=stored["scan_id"])
        assert [row.uid for row in shared] == [finding.uid]
        assert finding.last_run_id == run.id

    def test_same_legacy_uid_on_two_targets_stays_unique(self, target, iac_provider):
        other = TrivyTarget.objects.create(
            tenant_id=target.tenant_id,
            provider=iac_provider,
            name="other repo",
            mode="repo",
            config={"repository_url": iac_provider.uid},
        )
        _scan(target, _report([_vuln()]))
        _scan(other, _report([_vuln()]))
        uids = list(AppSecFinding.objects.values_list("uid", flat=True))
        assert len(uids) == 2 and len(set(uids)) == 2

    def test_inventory_versions_and_retention(self, target):
        _scan(target, _report([_vuln()]))
        _scan(target, _report([]))
        sboms = list(AppSecSbom.objects.filter(target=target).order_by("version"))
        assert [row.version for row in sboms] == [1, 2]
        assert sboms[0].component_count == 2
        assert (
            sboms[0].vulnerable_component_count == 1
            and sboms[1].vulnerability_count == 0
        )
        assert sboms[0].summary["licenses"] == {"MIT": 1}
        run = _run(target)
        parsed = parse_report(_report([]), mode="repo")
        inventory.store_inventory(
            tenant_id=str(target.tenant_id),
            target=target,
            run=run,
            components=parsed.components,
            findings=[],
            artifact_name="shop",
            artifact_type="repository",
            source="generated",
            keep_versions=2,
        )
        assert sorted(
            AppSecSbom.objects.filter(target=target).values_list("version", flat=True)
        ) == [2, 3]


def _get(client, name, query=None, **kwargs):
    return client.get(reverse(name, kwargs=kwargs or None), query or {})


def _write(client, method, name, attributes, **kwargs):
    return getattr(client, method)(
        reverse(name, kwargs=kwargs or None),
        data=json.dumps({"data": {"type": "x", "attributes": attributes}}),
        content_type=JSONAPI,
    )


@pytest.mark.django_db
class TestFindingsApi:
    def test_list_filters_and_detail(self, authenticated_client, target):
        _scan(
            target,
            _report(
                [
                    _vuln(severity="CRITICAL"),
                    _vuln("CVE-2024-0002", "axios", "LOW", ""),
                ],
                [SECRET],
            ),
        )
        response = _get(authenticated_client, "appsec-findings-list")
        assert response.status_code == 200
        body = response.json()
        assert body["meta"]["pagination"]["count"] == 3
        first = body["data"][0]["attributes"]
        assert first["target_name"] == "shop repo" and first["triage_status"] == "open"

        vulns = _get(
            authenticated_client,
            "appsec-findings-list",
            {"filter[category]": "vulnerability", "filter[fix_available]": "false"},
        ).json()
        assert [row["attributes"]["rule_id"] for row in vulns["data"]] == [
            "CVE-2024-0002"
        ]

        searched = _get(
            authenticated_client, "appsec-findings-list", {"filter[search]": "lodash"}
        ).json()
        assert searched["meta"]["pagination"]["count"] == 1

        bad = _get(
            authenticated_client,
            "appsec-findings-list",
            {"filter[severity__in]": "severe"},
        )
        assert bad.status_code == 400

        finding_id = vulns["data"][0]["id"]
        detail = _get(
            authenticated_client, "appsec-findings-detail", pk=finding_id
        ).json()
        attributes = detail["data"]["attributes"]
        assert attributes["events"][0]["kind"] == "detected"
        assert attributes["priority_factors"]
        assert "related" in attributes and "recent_scans" in attributes

    def test_summary_keeps_metrics_apart(self, authenticated_client, target):
        _scan(
            target,
            _report(
                [
                    _vuln(),
                    _vuln("CVE-2024-0002"),
                    _vuln("CVE-2024-0003", "axios", fixed=""),
                ]
            ),
        )
        summary = _get(authenticated_client, "appsec-findings-summary").json()["data"][
            "attributes"
        ]
        assert summary["vulnerabilities"] == {
            "instances": 3,
            "unique_ids": 3,
            "affected_packages": 2,
            "fixable": 2,
            "unfixed": 1,
        }
        assert summary["by_category"] == {"vulnerability": 3}

    def test_triage_status_follows_the_existing_triage_routes(
        self, authenticated_client, target
    ):
        _scan(target, _report([_vuln()]))
        finding = AppSecFinding.objects.get(target=target)
        response = authenticated_client.patch(
            reverse("finding-uid-triage", kwargs={"finding_uid": finding.uid}),
            data=json.dumps(
                {
                    "data": {
                        "type": "x",
                        "attributes": {
                            "status": "risk_accepted",
                            "note": "compensating control",
                        },
                    }
                }
            ),
            content_type=JSONAPI,
        )
        assert response.status_code in (200, 201), response.content
        triage = FindingTriage.objects.get(finding_uid=finding.uid)
        assert triage.area == "application_security"
        accepted = _get(
            authenticated_client,
            "appsec-findings-list",
            {"filter[triage_status__in]": "risk_accepted"},
        ).json()
        assert accepted["meta"]["pagination"]["count"] == 1

    def test_export_csv(self, authenticated_client, target):
        _scan(target, _report([_vuln()]))
        response = _get(
            authenticated_client, "appsec-findings-export", {"format": "csv"}
        )
        assert response.status_code == 200
        assert response["Content-Type"].startswith("text/csv")
        lines = response.content.decode().splitlines()
        assert lines[0].startswith("uid,category,severity") and len(lines) == 2

    def test_other_tenant_sees_nothing(
        self, authenticated_client, target, tenants_fixture
    ):
        _scan(target, _report([_vuln()]))
        finding = AppSecFinding.objects.filter(target=target).first()
        assert finding is not None
        # Move the scan's rows to a tenant the signed-in user is not in.
        other = tenants_fixture[2]
        AppSecFinding.objects.filter(target=target).update(tenant_id=other.id)
        AppSecSbom.objects.filter(target=target).update(tenant_id=other.id)

        listed = authenticated_client.get(reverse("appsec-findings-list"))
        assert listed.status_code == 200
        assert listed.json()["data"] == []
        detail = authenticated_client.get(
            reverse("appsec-findings-detail", kwargs={"pk": finding.id})
        )
        assert detail.status_code == 404


@pytest.mark.django_db
class TestInventoryApi:
    def test_sboms_components_and_compare(self, authenticated_client, target):
        _scan(target, _report([_vuln()]))
        report = _report([])
        report["Results"][0]["Packages"][0]["Version"] = "4.17.21"
        report["Results"][0]["Packages"].append(
            {"ID": "axios@1", "Name": "axios", "Version": "1"}
        )
        _scan(target, report)
        sboms = _get(authenticated_client, "appsec-sboms-list").json()
        assert sboms["meta"]["pagination"]["count"] == 2
        head, base = sboms["data"][0], sboms["data"][1]
        assert head["attributes"]["version"] == 2

        components = _get(
            authenticated_client, "appsec-sboms-components", pk=base["id"]
        ).json()
        names = {
            row["attributes"]["name"]: row["attributes"] for row in components["data"]
        }
        assert names["lodash"]["vulnerability_count"] == 1
        assert names["lodash"]["fixed_version"] == "4.17.21"

        diff = _get(
            authenticated_client,
            "appsec-sboms-compare",
            {"base": base["id"]},
            pk=head["id"],
        ).json()["data"]["attributes"]
        assert diff["counts"] == {
            "added": 1,
            "removed": 0,
            "changed": 1,
            "unchanged": 1,
        }

        current = _get(authenticated_client, "appsec-components-list").json()
        assert current["meta"]["pagination"]["count"] == 3
        download = _get(
            authenticated_client,
            "appsec-sboms-download",
            {"format": "cyclonedx"},
            pk=head["id"],
        )
        assert download.status_code == 200
        assert json.loads(download.content)["bomFormat"] == "CycloneDX"

    def test_overview_counts_stored_data_only(self, authenticated_client, target):
        empty = _get(authenticated_client, "appsec-overview").json()["data"][
            "attributes"
        ]
        assert empty["findings"]["active"] == 0 and empty["components"]["total"] == 0
        _scan(target, _report([_vuln(severity="CRITICAL")], [SECRET]))
        data = _get(authenticated_client, "appsec-overview").json()["data"][
            "attributes"
        ]
        assert data["inventory"]["targets"] == 1
        assert data["findings"]["by_severity"] == {"critical": 2}
        assert (
            data["components"]["total"] == 2 and data["components"]["vulnerable"] == 1
        )
        assert data["trend"][-1]["detected"] == 2
        assert data["top_targets"][0]["name"] == "shop repo"


@pytest.mark.django_db
class TestConfigurationApi:
    def test_application_crud_and_assets(self, authenticated_client, target):
        created = _write(
            authenticated_client,
            "post",
            "appsec-applications-list",
            {
                "name": "Shop",
                "criticality": "critical",
                "environment": "production",
                "internet_exposed": True,
                "target_ids": [str(target.id)],
            },
        )
        assert created.status_code == 201, created.content
        application_id = created.json()["data"]["id"]
        target.refresh_from_db()
        assert str(target.application_id) == application_id
        duplicate = _write(
            authenticated_client, "post", "appsec-applications-list", {"name": "Shop"}
        )
        assert duplicate.status_code == 400
        invalid = _write(
            authenticated_client,
            "post",
            "appsec-applications-list",
            {"name": "X2", "criticality": "extreme"},
        )
        assert invalid.status_code == 400
        detail = _get(
            authenticated_client, "appsec-applications-detail", pk=application_id
        ).json()
        assert detail["data"]["attributes"]["assets"][0]["name"] == "shop repo"
        listing = _get(authenticated_client, "appsec-applications-list").json()
        assert listing["data"][0]["attributes"]["targets"] == 1
        deleted = authenticated_client.delete(
            reverse("appsec-applications-detail", kwargs={"pk": application_id})
        )
        assert deleted.status_code == 204
        target.refresh_from_db()
        assert target.application_id is None and AppSecApplication.objects.count() == 0

    def test_profiles(self, authenticated_client):
        listing = _get(authenticated_client, "appsec-scan-profiles-list").json()
        assert listing["data"][0]["attributes"]["builtin"] is True
        created = _write(
            authenticated_client,
            "post",
            "appsec-scan-profiles-list",
            {
                "name": "Nightly",
                "target_types": ["repo"],
                "options": {"scanners": ["vuln", "license"], "ignore_unfixed": True},
            },
        )
        assert created.status_code == 201, created.content
        rejected = _write(
            authenticated_client,
            "post",
            "appsec-scan-profiles-list",
            {
                "name": "Broken",
                "target_types": ["sbom"],
                "options": {"scanners": ["secret"]},
            },
        )
        assert rejected.status_code == 400
        unknown = _write(
            authenticated_client,
            "post",
            "appsec-scan-profiles-list",
            {"name": "Flag", "options": {"scanners": ["vuln"], "exit_code": 1}},
        )
        assert unknown.status_code == 400
        assert AppSecScanProfile.objects.count() == 1

    def test_policies_are_validated_and_versioned(self, authenticated_client):
        bad = _write(
            authenticated_client,
            "post",
            "appsec-policies-list",
            {
                "kind": "ignore_rules",
                "name": "exceptions",
                "content": "vulnerabilities:\n  - paths: [a]\n",
            },
        )
        assert bad.status_code == 400
        created = _write(
            authenticated_client,
            "post",
            "appsec-policies-list",
            {
                "kind": "ignore_rules",
                "name": "exceptions",
                "content": "vulnerabilities:\n  - id: CVE-1\n    statement: accepted\n",
            },
        )
        assert created.status_code == 201, created.content
        policy_id = created.json()["data"]["id"]
        updated = _write(
            authenticated_client,
            "patch",
            "appsec-policies-detail",
            {"content": "vulnerabilities:\n  - id: CVE-2\n    statement: accepted\n"},
            pk=policy_id,
        )
        assert updated.json()["data"]["attributes"]["version"] == 2
        policy = AppSecPolicy.objects.get(id=policy_id)
        assert (
            policy.versions.count() == 1 and "CVE-1" in policy.versions.first().content
        )
        check = _write(
            authenticated_client,
            "post",
            "appsec-policies-validate",
            {"kind": "vex", "content": "{}"},
        )
        assert check.json()["data"]["attributes"]["valid"] is False

    def test_settings_validate_and_merge(self, authenticated_client):
        defaults = _get(authenticated_client, "appsec-settings").json()["data"][
            "attributes"
        ]
        assert (
            defaults["sla_days"]["critical"] == 7 and defaults["risk_overrides"] == {}
        )
        bad = _write(
            authenticated_client, "patch", "appsec-settings", {"risk": {"made_up": 1}}
        )
        assert bad.status_code == 400
        saved = _write(
            authenticated_client,
            "patch",
            "appsec-settings",
            {"sla_days": {"critical": 3}, "retention": {"sbom_versions": 5}},
        )
        attributes = saved.json()["data"]["attributes"]
        assert attributes["sla_days"]["critical"] == 3
        assert attributes["retention"]["sbom_versions"] == 5

    def test_capabilities_document(self, authenticated_client):
        document = _get(authenticated_client, "appsec-capabilities").json()["data"][
            "attributes"
        ]
        assert {target["id"] for target in document["targets"]} >= {
            "repo",
            "image",
            "sbom",
            "k8s",
        }
        assert "trivy" not in json.dumps(document).lower()

    def test_writes_need_manage_scans(self, authenticated_client_no_permissions_rbac):
        client = authenticated_client_no_permissions_rbac
        assert _get(client, "appsec-scan-profiles-list").status_code == 200
        denied = _write(client, "post", "appsec-applications-list", {"name": "Shop"})
        assert denied.status_code == 403
        denied = _write(
            client, "patch", "appsec-settings", {"sla_days": {"critical": 3}}
        )
        assert denied.status_code == 403

    def test_unauthenticated(self, client):
        assert client.get(reverse("appsec-findings-list")).status_code == 401


@pytest.mark.django_db
class TestRunActions:
    def test_cancel_pending_and_finished(self, authenticated_client, target):
        run = TrivyRun.objects.create(
            tenant_id=target.tenant_id,
            target=target,
            provider=target.provider,
            status=TrivyRun.Status.PENDING,
        )
        response = authenticated_client.post(
            reverse("trivy-runs-cancel", kwargs={"pk": run.id}), content_type=JSONAPI
        )
        assert response.status_code == 202, response.content
        run.refresh_from_db()
        assert run.status == "cancelled" and run.cancel_requested_at is not None
        again = authenticated_client.post(
            reverse("trivy-runs-cancel", kwargs={"pk": run.id}), content_type=JSONAPI
        )
        assert again.status_code == 409

    def test_cancelled_run_is_not_executed(self, target):
        run = TrivyRun.objects.create(
            tenant_id=target.tenant_id,
            target=target,
            provider=target.provider,
            status=TrivyRun.Status.PENDING,
            cancel_requested_at=timezone.now(),
        )
        result = engine.execute_run(tenant_id=str(target.tenant_id), run_id=str(run.id))
        assert result["status"] == "cancelled"

    def test_export_needs_a_stored_report(self, authenticated_client, target):
        run = TrivyRun.objects.create(
            tenant_id=target.tenant_id,
            target=target,
            provider=target.provider,
            status=TrivyRun.Status.COMPLETED,
        )
        url = reverse("trivy-runs-export", kwargs={"pk": run.id})
        assert authenticated_client.get(url, {"format": "json"}).status_code == 404
        assert authenticated_client.get(url, {"format": "pdf"}).status_code == 400


@pytest.mark.django_db
class TestTenantScanLimit:
    """The organization limit caps scans running at once, not scans queued."""

    def _second_target(self, target):
        return TrivyTarget.objects.create(
            tenant_id=target.tenant_id,
            provider=target.provider,
            name="shop repo two",
            mode="repo",
            config={"repository_url": target.provider.uid},
        )

    def test_scans_queue_past_the_running_limit(self, target, monkeypatch):
        from cloudsneeker_api.services.trivy import enqueue_trivy_run

        monkeypatch.setenv("APPSEC_MAX_ACTIVE_RUNS_PER_TENANT", "1")
        other = self._second_target(target)
        with patch("cloudsneeker_api.tasks.trivy_scan_task"):
            first = enqueue_trivy_run(
                tenant_id=str(target.tenant_id), target_id=str(target.id)
            )
            second = enqueue_trivy_run(
                tenant_id=str(target.tenant_id), target_id=str(other.id)
            )
        assert first.status == second.status == TrivyRun.Status.PENDING

    def test_the_queue_has_a_ceiling(self, target, monkeypatch):
        from cloudsneeker_api.services.trivy import TrivyHubError, enqueue_trivy_run

        monkeypatch.setenv("APPSEC_MAX_QUEUED_RUNS_PER_TENANT", "1")
        other = self._second_target(target)
        with patch("cloudsneeker_api.tasks.trivy_scan_task"):
            enqueue_trivy_run(tenant_id=str(target.tenant_id), target_id=str(target.id))
            with pytest.raises(TrivyHubError, match="queued or running"):
                enqueue_trivy_run(
                    tenant_id=str(target.tenant_id), target_id=str(other.id)
                )

    def test_a_run_waits_while_the_organization_is_at_its_limit(
        self, target, monkeypatch
    ):
        monkeypatch.setenv("APPSEC_MAX_ACTIVE_RUNS_PER_TENANT", "1")
        _run(self._second_target(target))
        pending = TrivyRun.objects.create(
            tenant_id=target.tenant_id,
            target=target,
            provider=target.provider,
            status=TrivyRun.Status.PENDING,
        )
        with patch("cloudsneeker_api.tasks.trivy_scan_task") as task:
            result = engine.execute_run(
                tenant_id=str(target.tenant_id), run_id=str(pending.id)
            )
        assert result["status"] == "deferred"
        pending.refresh_from_db()
        assert pending.status == TrivyRun.Status.PENDING
        task.apply_async.assert_called_once()
        assert task.apply_async.call_args.kwargs["countdown"] > 0

    def test_a_stale_running_row_does_not_hold_the_slot(self, target, monkeypatch):
        monkeypatch.setenv("APPSEC_MAX_ACTIVE_RUNS_PER_TENANT", "1")
        other = self._second_target(target)
        _run(other, at=timezone.now() - timedelta(days=1))
        assert engine.running_slots_full(str(target.tenant_id)) is False
        _run(other)
        assert engine.running_slots_full(str(target.tenant_id)) is True
