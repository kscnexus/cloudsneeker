"""Shared mutelist across Cloud Security, Application Security and Governance."""

from __future__ import annotations

import pytest
from api.models import Finding, MuteRule, Scan, StateChoices
from cloudsneeker_api.models import (
    CustodianPolicy,
    CustodianRun,
    TrivyRun,
    TrivyTarget,
)
from cloudsneeker_api.services.area_mute import (
    AreaMuteError,
    muted_uid_map,
    reconcile_scan,
)
from cloudsneeker_api.services.governance_findings import findings_for_run
from django.urls import reverse
from django.utils import timezone

JSONAPI = "application/vnd.api+json"


def _scan(provider, source=None):
    now = timezone.now()
    return Scan.objects.create(
        tenant_id=provider.tenant_id,
        provider=provider,
        name="scan",
        trigger=Scan.TriggerChoices.MANUAL,
        state=StateChoices.COMPLETED,
        started_at=now,
        completed_at=now,
        scanner_args={"source": source, "mode": "repo"} if source else {},
    )


def _finding(scan, uid):
    return Finding.objects.create(
        tenant_id=scan.tenant_id,
        uid=uid,
        scan=scan,
        status="FAIL",
        status_extended="detail",
        severity="high",
        impact="high",
        raw_result={},
        check_id="check",
        check_metadata={},
        first_seen_at=timezone.now(),
    )


def _app_scan(provider):
    scan = _scan(provider, source="trivy_hub")
    target = TrivyTarget.objects.create(
        tenant_id=provider.tenant_id, name="repo", mode="repo", provider=provider
    )
    TrivyRun.objects.create(
        tenant_id=provider.tenant_id,
        target=target,
        provider=provider,
        status=TrivyRun.Status.COMPLETED,
        finished_at=timezone.now(),
        scan_id=scan.id,
    )
    return scan, target


def _governance(provider):
    policy = CustodianPolicy.objects.create(
        tenant_id=provider.tenant_id,
        name="gov",
        provider=provider,
        policy_yaml="policies:\n  - name: unused-ebs\n    resource: aws.ebs\n",
    )
    run = CustodianRun.objects.create(
        tenant_id=provider.tenant_id,
        policy=policy,
        provider=provider,
        status=CustodianRun.Status.COMPLETED,
        mode=CustodianRun.Mode.DRYRUN,
        finished_at=timezone.now(),
        output={"resources": [{"VolumeId": "vol-1"}, {"VolumeId": "vol-2"}]},
    )
    return [finding.uid for finding in findings_for_run(run, policy)]


def _mute(client, uids, name="mute rule", reason="accepted by owner"):
    return client.post(
        reverse("area-findings-mute"),
        data={"finding_uids": uids, "name": name, "reason": reason},
        content_type="application/json",
    )


@pytest.mark.django_db
class TestAreaMute:
    def test_mutes_app_security_rows_and_keeps_them(
        self, authenticated_client, aws_provider
    ):
        scan, _ = _app_scan(aws_provider)
        _finding(scan, "trivy-repo-1")
        _finding(scan, "trivy-repo-2")

        response = _mute(authenticated_client, ["trivy-repo-1"])
        assert response.status_code == 201, response.content
        rule = MuteRule.objects.get(id=response.json()["data"]["id"])
        assert rule.finding_uids == ["trivy-repo-1"]

        rows = {f.uid: f for f in Finding.objects.filter(scan=scan)}
        assert rows["trivy-repo-1"].muted is True
        assert rows["trivy-repo-1"].muted_reason == "accepted by owner"
        assert rows["trivy-repo-2"].muted is False

        listed = authenticated_client.get(
            reverse("area-findings-list"),
            {"filter[area]": "application_security"},
        )
        assert [row["id"] for row in listed.json()["data"]] == ["trivy-repo-2"]
        with_muted = authenticated_client.get(
            reverse("area-findings-list"),
            {"filter[area]": "application_security", "filter[muted]": "include"},
        )
        assert len(with_muted.json()["data"]) == 2

    def test_governance_findings_can_be_muted(
        self, authenticated_client, aws_provider
    ):
        uids = _governance(aws_provider)
        response = _mute(authenticated_client, [uids[0]])
        assert response.status_code == 201, response.content

        listed = authenticated_client.get(
            reverse("area-findings-list"), {"filter[area]": "governance"}
        )
        assert [row["id"] for row in listed.json()["data"]] == [uids[1]]
        everything = authenticated_client.get(
            reverse("area-findings-list"),
            {"filter[area]": "governance", "filter[muted]": "include"},
        )
        muted = {
            row["id"]: row["attributes"] for row in everything.json()["data"]
        }
        assert muted[uids[0]]["muted"] is True
        assert muted[uids[0]]["muted_reason"] == "accepted by owner"

    def test_unknown_and_duplicate_uids_are_skipped(
        self, authenticated_client, aws_provider
    ):
        scan = _scan(aws_provider)
        _finding(scan, "cloud-1")
        first = _mute(authenticated_client, ["cloud-1", "ghost"])
        assert first.status_code == 201
        assert first.json()["meta"]["skipped_uids"] == ["ghost"]
        again = _mute(authenticated_client, ["cloud-1"])
        assert again.status_code == 400

    def test_validation(self, authenticated_client):
        assert _mute(authenticated_client, []).status_code == 400
        assert _mute(authenticated_client, ["x"], name="a").status_code == 400

    def test_rescan_applies_enabled_rules(self, aws_provider):
        tenant_id = str(aws_provider.tenant_id)
        MuteRule.objects.create(
            tenant_id=tenant_id,
            name="rule",
            reason="known issue",
            finding_uids=["trivy-repo-1"],
        )
        scan, target = _app_scan(aws_provider)
        _finding(scan, "trivy-repo-1")
        result = reconcile_scan(tenant_id, str(scan.id), str(target.id))
        assert result["shared_muted"] == 1
        assert Finding.objects.get(scan=scan, uid="trivy-repo-1").muted is True

    def test_disabled_rules_are_ignored(self, aws_provider):
        tenant_id = str(aws_provider.tenant_id)
        MuteRule.objects.create(
            tenant_id=tenant_id,
            name="rule",
            reason="known issue",
            finding_uids=["a"],
            enabled=False,
        )
        assert muted_uid_map(tenant_id) == {}


def test_error_type_is_value_error():
    assert issubclass(AreaMuteError, ValueError)
