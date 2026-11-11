"""Risk acceptance with expiry and approver (EB-019)."""

from __future__ import annotations

from datetime import date, timedelta
from unittest.mock import patch

import pytest
from api.db_utils import rls_transaction
from cloudsneeker_api.models import FindingTriage, FindingTriageNote
from cloudsneeker_api.services import risk_acceptance
from cloudsneeker_api.services.finding_triage import (
    RISK_DEFAULT_DAYS,
    RISK_MAX_DAYS,
    TriageError,
    clean_risk_acceptance,
)
from cloudsneeker_api.tasks import expire_risk_acceptances_task
from cloudsneeker_api.tests.test_finding_triage import (
    _body,
    _finding,
    _patch_uid,
    _scan,
)
from django.urls import reverse
from django.utils import timezone

JSONAPI = "application/vnd.api+json"


def _today() -> date:
    return timezone.now().date()


class TestCleanRiskAcceptance:
    def test_accepts_reason_and_iso_date(self):
        today = date(2026, 11, 10)
        acceptance = clean_risk_acceptance(
            "  Compensating WAF rule ", "2026-12-01", today=today
        )
        assert acceptance.reason == "Compensating WAF rule"
        assert acceptance.expires_on == date(2026, 12, 1)
        assert acceptance.sent
        assert not clean_risk_acceptance(today=today).sent

    @pytest.mark.parametrize(
        "expires_on",
        [
            "2026-11-10",
            "2026-11-01",
            "not-a-date",
            date(2026, 11, 10) + timedelta(days=RISK_MAX_DAYS + 1),
        ],
    )
    def test_rejects_bad_expiry(self, expires_on):
        with pytest.raises(TriageError):
            clean_risk_acceptance(None, expires_on, today=date(2026, 11, 10))

    def test_rejects_long_reason(self):
        with pytest.raises(TriageError):
            clean_risk_acceptance("x" * 1001)


@pytest.mark.django_db
class TestAcceptRisk:
    def test_accept_with_reason_and_expiry(
        self, authenticated_client, aws_provider, create_test_user
    ):
        _finding(_scan(aws_provider), "uid-risk")
        expires = (_today() + timedelta(days=30)).isoformat()
        response = _patch_uid(
            authenticated_client,
            "uid-risk",
            {
                "status": "risk_accepted",
                "risk_reason": "Behind VPN",
                "risk_expires_on": expires,
            },
        )
        assert response.status_code == 201, response.content
        attributes = response.json()["data"]["attributes"]
        assert attributes["status"] == "risk_accepted"
        assert attributes["risk_reason"] == "Behind VPN"
        assert attributes["risk_expires_on"] == expires
        assert attributes["risk_approved_by_id"] == str(create_test_user.id)
        assert attributes["risk_approved_by_name"]
        assert attributes["risk_approved_at"]
        assert attributes["risk_expired_at"] is None

    def test_inherited_ui_gets_defaults(self, authenticated_client, aws_provider):
        """The inherited cloud UI sends only a status and a note."""
        _finding(_scan(aws_provider), "uid-risk-default")
        response = _patch_uid(
            authenticated_client,
            "uid-risk-default",
            {"status": "risk_accepted", "note": "Accepted by the CISO"},
        )
        assert response.status_code == 201, response.content
        attributes = response.json()["data"]["attributes"]
        assert attributes["risk_reason"] == "Accepted by the CISO"
        assert (
            attributes["risk_expires_on"]
            == (_today() + timedelta(days=RISK_DEFAULT_DAYS)).isoformat()
        )

    def test_renewal_keeps_reason_and_moves_expiry(
        self, authenticated_client, aws_provider
    ):
        _finding(_scan(aws_provider), "uid-renew")
        _patch_uid(
            authenticated_client,
            "uid-renew",
            {
                "status": "risk_accepted",
                "risk_reason": "Legacy app",
                "risk_expires_on": (_today() + timedelta(days=10)).isoformat(),
            },
        )
        later = (_today() + timedelta(days=60)).isoformat()
        response = _patch_uid(
            authenticated_client, "uid-renew", {"risk_expires_on": later}
        )
        assert response.status_code == 200, response.content
        attributes = response.json()["data"]["attributes"]
        assert attributes["risk_reason"] == "Legacy app"
        assert attributes["risk_expires_on"] == later

    @pytest.mark.parametrize(
        "attributes",
        [
            {"status": "remediating", "risk_reason": "nope"},
            {"status": "risk_accepted", "risk_expires_on": "2000-01-01"},
            {"risk_reason": "no status on an open finding"},
        ],
    )
    def test_validation(self, authenticated_client, aws_provider, attributes):
        _finding(_scan(aws_provider), "uid-risk-bad")
        response = _patch_uid(authenticated_client, "uid-risk-bad", attributes)
        assert response.status_code == 400, response.content
        assert not FindingTriage.objects.filter(
            finding_uid="uid-risk-bad", status="risk_accepted"
        ).exists()

    def test_bulk_accept(self, authenticated_client, aws_provider):
        scan = _scan(aws_provider)
        for uid in ("uid-rb1", "uid-rb2"):
            _finding(scan, uid)
        expires = (_today() + timedelta(days=14)).isoformat()
        response = authenticated_client.post(
            reverse("finding-triages-bulk"),
            data=_body(
                "finding-triages",
                {
                    "finding_uids": ["uid-rb1", "uid-rb2"],
                    "status": "risk_accepted",
                    "risk_reason": "Pen test window",
                    "risk_expires_on": expires,
                },
            ),
            content_type=JSONAPI,
        )
        assert response.status_code == 200, response.content
        rows = FindingTriage.objects.filter(finding_uid__in=["uid-rb1", "uid-rb2"])
        assert {row.risk_reason for row in rows} == {"Pen test window"}
        assert {row.risk_expires_on.isoformat() for row in rows} == {expires}

        bad = authenticated_client.post(
            reverse("finding-triages-bulk"),
            data=_body(
                "finding-triages",
                {"finding_uids": ["uid-rb1"], "status": "open", "risk_reason": "x"},
            ),
            content_type=JSONAPI,
        )
        assert bad.status_code == 400


def _accepted(tenant_id, uid: str, *, expires_on: date, approver=None, assignee=None):
    return FindingTriage.objects.create(
        tenant_id=tenant_id,
        finding_uid=uid,
        check_id="s3_bucket_public",
        status=FindingTriage.Status.RISK_ACCEPTED,
        risk_reason="Temporary exception",
        risk_expires_on=expires_on,
        risk_approved_by=approver,
        risk_approved_at=timezone.now(),
        assignee=assignee,
    )


@pytest.mark.django_db
class TestExpiry:
    def test_reopens_expired_and_keeps_current(self, tenants_fixture, create_test_user):
        tenant = tenants_fixture[0]
        today = _today()
        expired = _accepted(
            tenant.id,
            "uid-old",
            expires_on=today - timedelta(days=1),
            approver=create_test_user,
        )
        current = _accepted(tenant.id, "uid-today", expires_on=today)

        with patch(
            "cloudsneeker_api.services.email_delivery.send_with_tenant_smtp",
            return_value=1,
        ) as send:
            result = expire_risk_acceptances_task()

        assert result == {"reopened": 1, "emails_sent": 1}
        expired.refresh_from_db()
        current.refresh_from_db()
        assert expired.status == "reopened"
        assert expired.source == "automation"
        assert expired.risk_expired_at is not None
        assert expired.risk_reason == "Temporary exception"
        assert current.status == "risk_accepted"
        note = FindingTriageNote.objects.get(triage=expired)
        assert note.status == "reopened"
        assert note.author_id is None
        assert "expired on" in note.body
        kwargs = send.call_args.kwargs
        assert kwargs["recipient_list"] == [create_test_user.email]
        assert "s3_bucket_public" in kwargs["message"]

        # A second run finds nothing to do.
        assert expire_risk_acceptances_task() == {"reopened": 0, "emails_sent": 0}

    def test_no_smtp_still_reopens(self, tenants_fixture, create_test_user):
        tenant = tenants_fixture[0]
        triage = _accepted(
            tenant.id,
            "uid-nosmtp",
            expires_on=_today() - timedelta(days=3),
            assignee=create_test_user,
        )
        result = expire_risk_acceptances_task()
        assert result["reopened"] == 1
        assert result["emails_sent"] == 0
        triage.refresh_from_db()
        assert triage.status == "reopened"

    def test_note_mentions_mute(self):
        assert "Mutelist" in risk_acceptance.expiry_note(date(2026, 1, 1), muted=True)
        assert "Mutelist" not in risk_acceptance.expiry_note(
            date(2026, 1, 1), muted=False
        )


@pytest.mark.django_db
class TestReportsAndLists:
    def test_executive_report_lists_accepted_risks(
        self, tenants_fixture, aws_provider, create_test_user
    ):
        from cloudsneeker_api.reports.data import assemble_report
        from cloudsneeker_api.reports.schema import ReportFilters

        tenant = tenants_fixture[0]
        scan = _scan(aws_provider)
        _finding(scan, "uid-rep")
        _finding(scan, "uid-rep-open")
        _accepted(
            tenant.id,
            "uid-rep",
            expires_on=_today() + timedelta(days=5),
            approver=create_test_user,
        )
        _accepted(
            tenant.id, "uid-not-in-scope", expires_on=_today() + timedelta(days=5)
        )

        with rls_transaction(str(tenant.id)):
            data = assemble_report(str(tenant.id), "executive", ReportFilters())
        table = next(t for t in data.tables if t.key == "accepted_risks")
        assert [row["finding_uid"] for row in table.rows] == ["uid-rep"]
        assert table.rows[0]["approved_by"] == create_test_user.email
        assert table.rows[0]["reason"] == "Temporary exception"
        assert data.kpis["triage_risk_accepted"] == 1

    def test_area_findings_show_acceptance(self, authenticated_client, aws_provider):
        _finding(_scan(aws_provider), "uid-area-risk")
        expires = (_today() + timedelta(days=20)).isoformat()
        _patch_uid(
            authenticated_client,
            "uid-area-risk",
            {
                "status": "risk_accepted",
                "risk_reason": "Isolated",
                "risk_expires_on": expires,
            },
        )
        response = authenticated_client.get(
            reverse("area-findings-list"),
            {"filter[area]": "cloud", "filter[triage_status__in]": "risk_accepted"},
        )
        assert response.status_code == 200, response.content
        row = response.json()["data"][0]["attributes"]
        assert row["risk_reason"] == "Isolated"
        assert row["risk_expires_on"] == expires
