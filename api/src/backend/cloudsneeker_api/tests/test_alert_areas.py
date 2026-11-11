"""Alert rules across Cloud Security, Application Security and Governance."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone as dt_timezone
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

import pytest
from api.models import Finding, Scan, StateChoices
from cloudsneeker_api.models import (
    AlertRule,
    CustodianPolicy,
    CustodianRun,
    TrivyRun,
    TrivyTarget,
)
from cloudsneeker_api.services.alert_dispatch import evaluate_rules
from cloudsneeker_api.services.alert_evaluation import (
    AREA_APPLICATION_SECURITY,
    AREA_CLOUD,
    AREA_GOVERNANCE,
    AreaMatch,
    RuleMatch,
    condition_areas,
    evaluate_governance_condition,
    notification_body,
    seed_condition,
)
from django.test import override_settings
from django.utils import timezone

NOW = datetime(2026, 11, 1, tzinfo=dt_timezone.utc)


def _gov(uid, severity="high", *, first=NOW, last=NOW, policy="p1", run="r1"):
    return SimpleNamespace(
        uid=uid,
        severity=severity,
        policy_id=policy,
        policy_name="unused volumes",
        rule_name="unused-ebs",
        provider_id="prov-1",
        run_id=run,
        resource_id=uid,
        resource_type="aws.ebs",
        region="us-east-1",
        first_seen_at=first,
        last_seen_at=last,
    )


class TestConditionAreas:
    def test_defaults_to_finding_backed_areas(self):
        assert condition_areas({"op": "any", "filter": {"severity": ["high"]}}) == {
            AREA_CLOUD,
            AREA_APPLICATION_SECURITY,
        }

    def test_collects_areas_from_nested_leaves(self):
        condition = {
            "op": "or",
            "children": [
                {"op": "any", "filter": {"area": ["governance"]}},
                {"op": "not", "child": {"op": "any", "filter": {"area": "cloud"}}},
            ],
        }
        assert condition_areas(condition) == {AREA_GOVERNANCE, AREA_CLOUD}

    def test_ignores_unknown_areas(self):
        assert condition_areas({"op": "any", "filter": {"area": ["nope"]}}) == {
            AREA_CLOUD,
            AREA_APPLICATION_SECURITY,
        }


class TestGovernanceEvaluation:
    def test_severity_and_area_filter(self):
        findings = [_gov("a", "high"), _gov("b", "low")]
        matched, items = evaluate_governance_condition(
            findings,
            {
                "op": "count_gte",
                "value": 1,
                "filter": {"area": ["governance"], "severity": ["high"]},
            },
            {},
        )
        assert matched is True
        assert [item.uid for item in items] == ["a"]

    def test_other_area_leaf_matches_nothing(self):
        matched, items = evaluate_governance_condition(
            [_gov("a")], {"op": "any", "filter": {"area": ["cloud"]}}, {}
        )
        assert matched is False
        assert items == []

    def test_provider_type_and_delta(self):
        old = _gov("old", first=datetime(2026, 1, 1, tzinfo=dt_timezone.utc))
        new = _gov("new")
        matched, items = evaluate_governance_condition(
            [old, new],
            {"op": "any", "filter": {"provider_type": ["aws"], "delta": "new"}},
            {"prov-1": "aws"},
        )
        assert matched is True
        assert [item.uid for item in items] == ["new"]

    def test_not_and_or(self):
        findings = [_gov("a", "high"), _gov("b", "low"), _gov("c", "critical")]
        matched, items = evaluate_governance_condition(
            findings,
            {"op": "not", "child": {"op": "any", "filter": {"severity": ["low"]}}},
            {},
        )
        assert matched is True
        assert {item.uid for item in items} == {"a", "c"}
        matched, items = evaluate_governance_condition(
            findings,
            {
                "op": "or",
                "children": [
                    {"op": "any", "filter": {"severity": ["critical"]}},
                    {"op": "any", "filter": {"severity": ["low"]}},
                ],
            },
            {},
        )
        assert {item.uid for item in items} == {"b", "c"}


class TestSeedAndMessage:
    def test_seed_keeps_findings_filters_and_area(self):
        condition = seed_condition(
            {
                "filter[severity__in]": "critical,high",
                "filter[provider_type__in]": "aws",
                "filter[region__in]": ["us-east-1", "eu-west-1"],
                "filter[delta]": "new",
                "area": "application_security",
            }
        )
        leaf = condition["filter"]
        assert leaf["severity"] == ["critical", "high"]
        assert leaf["provider_type"] == ["aws"]
        assert leaf["resource_regions"] == ["eu-west-1", "us-east-1"]
        assert leaf["delta"] == "new"
        assert leaf["area"] == ["application_security"]

    def test_seed_defaults_to_critical_and_high(self):
        assert seed_condition({})["filter"] == {"severity": ["critical", "high"]}

    @override_settings(UI_BASE_URL="https://app.example")
    def test_body_names_each_area_with_its_links(self):
        match = RuleMatch(
            matched=True,
            areas=[
                AreaMatch(
                    area=AREA_APPLICATION_SECURITY,
                    count=2,
                    severity_counts={"high": 2},
                    links=["https://app.example/application-security/t/runs/r"],
                ),
                AreaMatch(
                    area=AREA_GOVERNANCE,
                    count=1,
                    severity_counts={"medium": 1},
                    links=["https://app.example/governance/p/runs/r"],
                ),
            ],
        )
        body = notification_body("rule", "why", match)
        assert "matched 3 finding(s)" in body
        assert "Application Security: 2 finding(s) (high 2)" in body
        assert "/application-security/t/runs/r" in body
        assert "Cloud Governance: 1 finding(s)" in body
        assert "/findings?" not in body


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


def _finding(scan, uid, *, severity="high", status="FAIL", muted=False):
    return Finding.objects.create(
        tenant_id=scan.tenant_id,
        uid=uid,
        scan=scan,
        status=status,
        status_extended="detail",
        severity=severity,
        impact=severity,
        raw_result={},
        check_id="check",
        check_metadata={},
        muted=muted,
        first_seen_at=timezone.now(),
    )


def _rule(tenant_id, condition, trigger=AlertRule.Trigger.AFTER_SCAN):
    return AlertRule.objects.create(
        tenant_id=tenant_id,
        name=f"rule-{uuid4().hex[:8]}",
        condition=condition,
        trigger=trigger,
    )


@pytest.mark.django_db
class TestEvaluateRules:
    def test_app_security_scan_links_to_its_run(self, aws_provider):
        tenant_id = str(aws_provider.tenant_id)
        scan = _scan(aws_provider, source="trivy_hub")
        target = TrivyTarget.objects.create(
            tenant_id=tenant_id, name="repo", mode="repo", provider=aws_provider
        )
        run = TrivyRun.objects.create(
            tenant_id=tenant_id,
            target=target,
            provider=aws_provider,
            status=TrivyRun.Status.COMPLETED,
            finished_at=timezone.now(),
            scan_id=scan.id,
        )
        _finding(scan, "trivy-repo-1")
        _finding(scan, "trivy-repo-muted", muted=True)
        _finding(scan, "trivy-repo-pass", status="PASS")
        _rule(tenant_id, {"op": "any", "filter": {"severity": ["high"]}})

        matches = evaluate_rules(tenant_id, scan_id=str(scan.id))
        assert len(matches) == 1
        (area,) = matches[0][1].areas
        assert area.area == AREA_APPLICATION_SECURITY
        assert area.count == 1
        assert area.links[0].endswith(
            f"/application-security/{target.id}/runs/{run.id}"
        )

    def test_area_leaf_keeps_cloud_rule_off_app_scans(self, aws_provider):
        tenant_id = str(aws_provider.tenant_id)
        app_scan = _scan(aws_provider, source="trivy_hub")
        _finding(app_scan, "trivy-repo-1")
        cloud_scan = _scan(aws_provider)
        _finding(cloud_scan, "cloud-1")
        _rule(tenant_id, {"op": "any", "filter": {"area": ["cloud"]}})

        assert evaluate_rules(tenant_id, scan_id=str(app_scan.id)) == []
        matches = evaluate_rules(tenant_id, scan_id=str(cloud_scan.id))
        (area,) = matches[0][1].areas
        assert area.area == AREA_CLOUD
        assert f"filter[scan__in]={cloud_scan.id}" in area.links[0]

    def test_governance_run_only_matches_governance_rules(self, aws_provider):
        tenant_id = str(aws_provider.tenant_id)
        policy = CustodianPolicy.objects.create(
            tenant_id=tenant_id,
            name="gov",
            provider=aws_provider,
            policy_yaml=(
                "policies:\n  - name: unused-ebs\n    resource: aws.ebs\n"
                "    metadata:\n      severity: high\n"
            ),
        )
        run = CustodianRun.objects.create(
            tenant_id=tenant_id,
            policy=policy,
            provider=aws_provider,
            status=CustodianRun.Status.COMPLETED,
            mode=CustodianRun.Mode.DRYRUN,
            finished_at=timezone.now(),
            output={"resources": [{"VolumeId": "vol-1", "c7n:policy": "unused-ebs"}]},
        )
        _rule(tenant_id, {"op": "any", "filter": {"severity": ["high"]}})
        governance_rule = _rule(
            tenant_id, {"op": "any", "filter": {"area": ["governance"]}}
        )

        matches = evaluate_rules(tenant_id, custodian_run_id=str(run.id))
        assert [rule.id for rule, _ in matches] == [governance_rule.id]
        (area,) = matches[0][1].areas
        assert area.area == AREA_GOVERNANCE
        assert area.links[0].endswith(f"/governance/{policy.id}/runs/{run.id}")

    def test_daily_uses_latest_scan_per_provider(self, aws_provider):
        tenant_id = str(aws_provider.tenant_id)
        old = _scan(aws_provider)
        _finding(old, "cloud-old", severity="critical")
        Scan.objects.filter(id=old.id).update(
            completed_at=timezone.now() - timedelta(days=2)
        )
        latest = _scan(aws_provider)
        _finding(latest, "cloud-new", severity="low")
        _rule(
            tenant_id,
            {"op": "any", "filter": {"severity": ["critical"]}},
            trigger=AlertRule.Trigger.DAILY,
        )
        assert evaluate_rules(tenant_id, trigger="daily") == []
        assert evaluate_rules(tenant_id, scan_id=str(latest.id)) == []

    def test_notify_sends_area_text(self, aws_provider):
        from cloudsneeker_api.services.alert_dispatch import evaluate_and_notify

        tenant_id = str(aws_provider.tenant_id)
        scan = _scan(aws_provider)
        _finding(scan, "cloud-1")
        rule = _rule(tenant_id, {"op": "any", "filter": {"severity": ["high"]}})
        rule.slack_channel_ids = ["C1"]
        rule.save()
        with patch(
            "cloudsneeker_api.services.slack.post_alert_to_channels"
        ) as post:
            result = evaluate_and_notify(tenant_id, scan_id=str(scan.id))
        assert result == {
            "rules_matched": 1,
            "rules_notified": 1,
            "already_recorded": 0,
        }
        assert "Cloud Security: 1 finding(s)" in post.call_args.kwargs["text"]
