"""Alert history: events written per firing, deduplicated, and triaged."""

from __future__ import annotations

from unittest.mock import patch
from uuid import uuid4

import pytest
from api.models import Finding, Scan, StateChoices
from cloudsneeker_api.models import AlertEvent, AlertRule
from cloudsneeker_api.services.alert_evaluation import AreaMatch, RuleMatch
from cloudsneeker_api.services.alert_events import (
    event_dedup_key,
    event_fields,
    record_event,
    set_status,
)
from django.urls import reverse
from django.utils import timezone

MATCH = RuleMatch(
    matched=True,
    areas=[
        AreaMatch(
            area="cloud",
            count=2,
            severity_counts={"critical": 1, "high": 1, "low": 0},
            links=["/findings?a"],
        ),
        AreaMatch(
            area="application_security",
            count=3,
            severity_counts={"high": 3},
            links=["/application-security/t/runs/r", "/findings?a"],
        ),
        AreaMatch(area="governance", count=0),
    ],
)


class TestEventShape:
    def test_dedup_key_per_scan_run_and_day(self):
        assert event_dedup_key("r", trigger="after_scan", scan_id="s") == "r:scan:s"
        assert (
            event_dedup_key("r", trigger="after_scan", custodian_run_id="c")
            == "r:run:c"
        )
        assert (
            event_dedup_key("r", trigger="daily", scan_id="s", day="2026-11-12")
            == "r:daily:2026-11-12"
        )

    def test_fields_merge_areas_and_drop_empty_counts(self):
        fields = event_fields(MATCH)
        assert fields["areas"] == ["cloud", "application_security"]
        assert fields["area_counts"] == {"cloud": 2, "application_security": 3}
        assert fields["severity_counts"] == {"critical": 1, "high": 4}
        assert fields["total"] == 5
        assert fields["links"] == ["/findings?a", "/application-security/t/runs/r"]


def _rule(tenant_id, name="rule-a", **extra):
    return AlertRule.objects.create(
        tenant_id=tenant_id,
        name=name,
        condition={"op": "any", "filter": {"severity": ["high"]}},
        **extra,
    )


def _event(tenant_id, rule=None, status=AlertEvent.Status.OPEN, **extra):
    return AlertEvent.objects.create(
        tenant_id=tenant_id,
        rule=rule,
        rule_name=rule.name if rule else "deleted rule",
        trigger="after_scan",
        dedup_key=f"k-{uuid4()}",
        status=status,
        **{**event_fields(MATCH), **extra},
    )


def _scan_with_finding(provider):
    now = timezone.now()
    scan = Scan.objects.create(
        tenant_id=provider.tenant_id,
        provider=provider,
        name="scan",
        trigger=Scan.TriggerChoices.MANUAL,
        state=StateChoices.COMPLETED,
        started_at=now,
        completed_at=now,
        scanner_args={},
    )
    Finding.objects.create(
        tenant_id=provider.tenant_id,
        uid="cloud-1",
        scan=scan,
        delta=None,
        status="FAIL",
        status_extended="detail",
        severity="high",
        impact="high",
        raw_result={},
        check_id="check",
        check_metadata={},
        muted=False,
        first_seen_at=now,
    )
    return scan


@pytest.mark.django_db
class TestRecordEvent:
    def test_second_record_of_a_firing_is_not_created(self, tenants_fixture):
        tenant_id = str(tenants_fixture[0].id)
        rule = _rule(tenant_id)
        first, created = record_event(
            tenant_id, rule, MATCH, trigger="after_scan", scan_id=str(uuid4())
        )
        again, created_again = record_event(
            tenant_id,
            rule,
            MATCH,
            trigger="after_scan",
            scan_id=str(first.scan_id),
        )
        assert created is True
        assert created_again is False
        assert again.id == first.id
        assert first.total == 5
        assert first.status == AlertEvent.Status.OPEN

    def test_status_change_records_who_and_when(
        self, tenants_fixture, create_test_user
    ):
        tenant_id = str(tenants_fixture[0].id)
        event = _event(tenant_id, _rule(tenant_id))
        set_status(
            event,
            status=AlertEvent.Status.ACKNOWLEDGED,
            user=create_test_user,
            note="looking",
        )
        event.refresh_from_db()
        assert event.status == AlertEvent.Status.ACKNOWLEDGED
        assert event.status_changed_by_id == create_test_user.id
        assert event.status_changed_at is not None
        assert event.note == "looking"

    def test_rule_delete_keeps_history(self, tenants_fixture):
        tenant_id = str(tenants_fixture[0].id)
        rule = _rule(tenant_id)
        event = _event(tenant_id, rule)
        rule.delete()
        event.refresh_from_db()
        assert event.rule_id is None
        assert event.rule_name == "rule-a"


@pytest.mark.django_db
class TestDispatchWritesHistory:
    def test_retry_does_not_notify_twice(self, aws_provider):
        from cloudsneeker_api.services.alert_dispatch import evaluate_and_notify

        tenant_id = str(aws_provider.tenant_id)
        scan = _scan_with_finding(aws_provider)
        _rule(tenant_id, slack_channel_ids=["C1"])
        with patch("cloudsneeker_api.services.slack.post_alert_to_channels") as post:
            first = evaluate_and_notify(tenant_id, scan_id=str(scan.id))
            second = evaluate_and_notify(tenant_id, scan_id=str(scan.id))

        assert first["rules_notified"] == 1
        assert second == {
            "rules_matched": 1,
            "rules_notified": 0,
            "already_recorded": 1,
        }
        assert post.call_count == 1
        event = AlertEvent.objects.get(tenant_id=tenant_id)
        assert event.delivered is True
        assert event.areas == ["cloud"]
        assert str(event.scan_id) == str(scan.id)

    def test_history_failure_still_delivers(self, aws_provider):
        from cloudsneeker_api.services.alert_dispatch import evaluate_and_notify

        tenant_id = str(aws_provider.tenant_id)
        scan = _scan_with_finding(aws_provider)
        _rule(tenant_id, slack_channel_ids=["C1"])
        with (
            patch("cloudsneeker_api.services.slack.post_alert_to_channels") as post,
            patch(
                "cloudsneeker_api.models.AlertEvent.objects.get_or_create",
                side_effect=RuntimeError("table missing"),
            ),
        ):
            result = evaluate_and_notify(tenant_id, scan_id=str(scan.id))
        assert result["rules_notified"] == 1
        assert post.call_count == 1


@pytest.mark.django_db
class TestAlertEventApi:
    def test_list_filters_by_status_and_area(
        self, authenticated_client, tenants_fixture
    ):
        tenant_id = str(tenants_fixture[0].id)
        rule = _rule(tenant_id)
        open_event = _event(tenant_id, rule)
        _event(tenant_id, rule, status=AlertEvent.Status.RESOLVED)
        _event(tenant_id, rule, areas=["governance"])

        response = authenticated_client.get(
            reverse("alert-events-list"),
            {"filter[status]": "open", "filter[area]": "application_security"},
        )
        assert response.status_code == 200
        ids = [row["id"] for row in response.json()["data"]]
        assert ids == [str(open_event.id)]
        attributes = response.json()["data"][0]["attributes"]
        assert attributes["area_counts"] == {"cloud": 2, "application_security": 3}
        assert attributes["rule_id"] == str(rule.id)

    def test_filter_by_severity(self, authenticated_client, tenants_fixture):
        tenant_id = str(tenants_fixture[0].id)
        critical = _event(tenant_id)
        _event(tenant_id, severity_counts={"low": 1})
        response = authenticated_client.get(
            reverse("alert-events-list"), {"filter[severity]": "critical"}
        )
        assert [row["id"] for row in response.json()["data"]] == [str(critical.id)]

    def test_acknowledge(self, authenticated_client, tenants_fixture):
        tenant_id = str(tenants_fixture[0].id)
        event = _event(tenant_id)
        response = authenticated_client.patch(
            reverse("alert-events-detail", kwargs={"pk": event.id}),
            data={
                "data": {
                    "type": "alert-events",
                    "id": str(event.id),
                    "attributes": {"status": "acknowledged", "note": "on it"},
                }
            },
            content_type="application/vnd.api+json",
        )
        assert response.status_code == 200, response.content
        attributes = response.json()["data"]["attributes"]
        assert attributes["status"] == "acknowledged"
        assert attributes["note"] == "on it"
        assert attributes["status_changed_by"] is not None

    def test_other_fields_are_not_writable(self, authenticated_client, tenants_fixture):
        tenant_id = str(tenants_fixture[0].id)
        event = _event(tenant_id)
        response = authenticated_client.patch(
            reverse("alert-events-detail", kwargs={"pk": event.id}),
            data={
                "data": {
                    "type": "alert-events",
                    "id": str(event.id),
                    "attributes": {"total": 0},
                }
            },
            content_type="application/vnd.api+json",
        )
        assert response.status_code == 400

    def test_unknown_status_is_rejected(self, authenticated_client, tenants_fixture):
        tenant_id = str(tenants_fixture[0].id)
        event = _event(tenant_id)
        response = authenticated_client.patch(
            reverse("alert-events-detail", kwargs={"pk": event.id}),
            data={
                "data": {
                    "type": "alert-events",
                    "id": str(event.id),
                    "attributes": {"status": "closed"},
                }
            },
            content_type="application/vnd.api+json",
        )
        assert response.status_code == 400

    def test_read_only_role_lists_but_cannot_change(
        self, authenticated_client_no_permissions_rbac, tenants_fixture
    ):
        tenant_id = str(tenants_fixture[0].id)
        event = _event(tenant_id)
        client = authenticated_client_no_permissions_rbac
        assert client.get(reverse("alert-events-list")).status_code == 200
        response = client.patch(
            reverse("alert-events-detail", kwargs={"pk": event.id}),
            data={
                "data": {
                    "type": "alert-events",
                    "id": str(event.id),
                    "attributes": {"status": "resolved"},
                }
            },
            content_type="application/vnd.api+json",
        )
        assert response.status_code == 403

    def test_other_tenant_events_are_hidden(
        self, authenticated_client, tenants_fixture
    ):
        other_tenant_id = str(tenants_fixture[1].id)
        _event(other_tenant_id)
        response = authenticated_client.get(reverse("alert-events-list"))
        assert response.status_code == 200
        assert response.json()["data"] == []

    def test_no_create_or_delete(self, authenticated_client, tenants_fixture):
        event = _event(str(tenants_fixture[0].id))
        assert (
            authenticated_client.delete(
                reverse("alert-events-detail", kwargs={"pk": event.id})
            ).status_code
            == 405
        )
        assert (
            authenticated_client.post(
                reverse("alert-events-list"),
                data={"data": {"type": "alert-events", "attributes": {}}},
                content_type="application/vnd.api+json",
            ).status_code
            == 405
        )
