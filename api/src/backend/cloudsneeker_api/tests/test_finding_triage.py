"""Finding triage (EB-010): upsert, rescans, visibility, bulk, notes, filters."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from urllib.parse import quote
from uuid import uuid4

import pytest
from api.db_utils import rls_transaction
from api.models import (
    Finding,
    ProviderGroup,
    ProviderGroupMembership,
    Role,
    RoleProviderGroupRelationship,
    Scan,
    StateChoices,
)
from cloudsneeker_api.models import (
    FINDING_TRIAGE_NOTE_MAX_LENGTH,
    JSON_API_TYPE_PREFIX,
    FindingTriage,
    FindingTriageNote,
)
from cloudsneeker_api.services.finding_triage import (
    BULK_MAX_FINDINGS,
    FindingSnapshot,
    TriageError,
    check_note_author,
    clean_note_body,
    effective_status,
)
from django.urls import reverse
from django.utils import timezone

JSONAPI = "application/vnd.api+json"
TRIAGE_TYPE = f"{JSON_API_TYPE_PREFIX}finding-triages"


def _body(resource: str, attributes: dict) -> str:
    # The inherited UI sends unprefixed types; the lenient parser accepts them.
    return json.dumps({"data": {"type": resource, "attributes": attributes}})


def _scan(provider, *, at: datetime | None = None) -> Scan:
    at = at or timezone.now()
    return Scan.objects.create(
        tenant_id=provider.tenant_id,
        provider=provider,
        name="triage scan",
        trigger=Scan.TriggerChoices.MANUAL,
        state=StateChoices.COMPLETED,
        started_at=at,
        completed_at=at,
    )


def _finding(scan: Scan, uid: str, *, status="FAIL", check_id="s3_bucket_public") -> Finding:
    return Finding.objects.create(
        tenant_id=scan.tenant_id,
        uid=uid,
        scan=scan,
        status=status,
        status_extended="detail",
        severity="high",
        impact="high",
        raw_result={},
        check_id=check_id,
        check_metadata={"CheckTitle": check_id},
        first_seen_at=timezone.now(),
    )


def _patch_uid(client, uid: str, attributes: dict):
    return client.patch(
        reverse("finding-uid-triage", kwargs={"finding_uid": uid}),
        data=_body("finding-triages", attributes),
        content_type=JSONAPI,
    )


def _grant_provider(tenant, provider):
    with rls_transaction(str(tenant.id)):
        role = Role.objects.get(tenant_id=tenant.id, name="limited")
        group = ProviderGroup.objects.create(tenant_id=tenant.id, name="triage-group")
        ProviderGroupMembership.objects.create(
            tenant_id=tenant.id, provider_group=group, provider=provider
        )
        RoleProviderGroupRelationship.objects.create(
            tenant_id=tenant.id, role=role, provider_group=group
        )


@pytest.mark.django_db
class TestUpsert:
    def test_first_patch_creates_then_updates(self, authenticated_client, aws_provider):
        finding = _finding(_scan(aws_provider), "uid-upsert")

        created = _patch_uid(
            authenticated_client, "uid-upsert", {"status": "under_review", "note": "Looking"}
        )
        assert created.status_code == 201, created.content
        document = created.json()["data"]
        assert document["type"] == TRIAGE_TYPE
        attributes = document["attributes"]
        assert attributes["status"] == "under_review"
        assert attributes["finding_uid"] == "uid-upsert"
        assert attributes["finding_id"] == str(finding.id)
        assert attributes["check_id"] == "s3_bucket_public"
        assert attributes["provider_id"] == str(aws_provider.id)
        assert attributes["triage_notes_count"] == 1
        assert attributes["current_note"] == "Looking"
        first_change = attributes["status_changed_at"]

        updated = _patch_uid(authenticated_client, "uid-upsert", {"status": "remediating"})
        assert updated.status_code == 200
        assert updated.json()["data"]["attributes"]["status"] == "remediating"
        assert updated.json()["data"]["attributes"]["status_changed_at"] >= first_change
        assert FindingTriage.objects.filter(finding_uid="uid-upsert").count() == 1

        by_id = authenticated_client.patch(
            reverse("finding-triages-detail", kwargs={"pk": document["id"]}),
            data=_body("finding-triages", {"status": "false_positive"}),
            content_type=JSONAPI,
        )
        assert by_id.status_code == 200
        assert by_id.json()["data"]["attributes"]["status"] == "false_positive"

    def test_get_untriaged_finding_reads_open(self, authenticated_client, aws_provider):
        _finding(_scan(aws_provider), "uid-fresh")
        response = authenticated_client.get(
            reverse("finding-uid-triage", kwargs={"finding_uid": "uid-fresh"})
        )
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["id"] is None
        assert data["attributes"]["status"] == "open"
        assert data["attributes"]["raw_finding_status"] == "FAIL"
        assert not FindingTriage.objects.filter(finding_uid="uid-fresh").exists()

    def test_uid_with_slash(self, authenticated_client, aws_provider):
        uid = "aws-iam-123-us-east-1-role/path.name"
        _finding(_scan(aws_provider), uid)
        url = f"/api/v1/findings/{quote(uid, safe='')}/triage"
        response = authenticated_client.patch(
            url, data=_body("finding-triages", {"status": "open"}), content_type=JSONAPI
        )
        assert response.status_code == 201, response.content
        assert response.json()["data"]["attributes"]["finding_uid"] == uid

    @pytest.mark.parametrize(
        "attributes",
        [{"status": "done"}, {}, {"unknown": 1}, {"note": "x" * (FINDING_TRIAGE_NOTE_MAX_LENGTH + 1)}],
    )
    def test_validation(self, authenticated_client, aws_provider, attributes):
        _finding(_scan(aws_provider), "uid-invalid")
        response = _patch_uid(authenticated_client, "uid-invalid", attributes)
        assert response.status_code == 400

    def test_unknown_uid_is_404(self, authenticated_client):
        assert _patch_uid(authenticated_client, "missing", {"status": "open"}).status_code == 404

    def test_post_collection_not_allowed(self, authenticated_client):
        response = authenticated_client.post(
            reverse("finding-triages-list"),
            data=_body("finding-triages", {"status": "open"}),
            content_type=JSONAPI,
        )
        assert response.status_code == 405


@pytest.mark.django_db
class TestRescans:
    def test_status_survives_rescan_and_reopens_on_new_failure(
        self, authenticated_client, aws_provider
    ):
        past = timezone.now() - timedelta(days=2)
        _finding(_scan(aws_provider, at=past), "uid-rescan")
        assert _patch_uid(authenticated_client, "uid-rescan", {"status": "resolved"}).status_code == 201

        rescan_pass = _finding(_scan(aws_provider), "uid-rescan", status="PASS")
        lookup = authenticated_client.get(
            reverse("finding-triages-lookup")
            + f"?filter[finding_id__in]={rescan_pass.id}"
        )
        assert lookup.status_code == 200
        [entry] = lookup.json()["data"]
        assert entry["id"] == str(rescan_pass.id)
        assert entry["attributes"]["triage_status"] == "resolved"

        rescan_fail = _finding(_scan(aws_provider), "uid-rescan", status="FAIL")
        detail = authenticated_client.get(
            reverse("finding-uid-triage", kwargs={"finding_uid": "uid-rescan"})
        ).json()["data"]["attributes"]
        assert detail["status"] == "reopened"
        assert detail["stored_status"] == "resolved"
        assert detail["finding_id"] == str(rescan_fail.id)

    def test_effective_status_rules(self):
        changed = datetime(2026, 10, 1, tzinfo=UTC)
        triage = FindingTriage(status="resolved", status_changed_at=changed)

        def snap(status, at, muted=False):
            return FindingSnapshot("id", "uid", "check", None, status, muted, at)

        assert effective_status(triage, None) == "resolved"
        assert effective_status(triage, snap("FAIL", changed - timedelta(hours=1))) == "resolved"
        assert effective_status(triage, snap("FAIL", changed + timedelta(hours=1))) == "reopened"
        assert effective_status(triage, snap("FAIL", changed + timedelta(hours=1), True)) == "resolved"
        assert effective_status(triage, snap("PASS", changed + timedelta(hours=1))) == "resolved"
        triage.status = "under_review"
        assert effective_status(triage, snap("FAIL", changed + timedelta(hours=1))) == "under_review"


@pytest.mark.django_db
class TestIsolationAndPermissions:
    def test_other_tenant_rows_are_invisible(
        self, authenticated_client, tenants_fixture, aws_provider
    ):
        _finding(_scan(aws_provider), "uid-mine")
        assert _patch_uid(authenticated_client, "uid-mine", {"status": "open"}).status_code == 201
        other = tenants_fixture[1]
        with rls_transaction(str(other.id)):
            FindingTriage.objects.create(
                tenant_id=other.id, finding_uid="uid-other", status="resolved"
            )

        uids = [
            item["attributes"]["finding_uid"]
            for item in authenticated_client.get(reverse("finding-triages-list")).json()["data"]
        ]
        assert uids == ["uid-mine"]
        assert (
            authenticated_client.get(
                reverse("finding-uid-triage", kwargs={"finding_uid": "uid-other"})
            ).status_code
            == 404
        )

    def test_limited_role_reads_visible_providers_only_and_cannot_write(
        self,
        authenticated_client_no_permissions_rbac,
        tenants_fixture,
        aws_provider_pair,
    ):
        # One Django ``client`` backs every authenticated fixture, so the rows
        # are created directly instead of through an admin client.
        tenant = tenants_fixture[0]
        allowed, denied = aws_provider_pair
        for provider, uid in ((allowed, "uid-allowed"), (denied, "uid-denied")):
            _finding(_scan(provider), uid)
            FindingTriage.objects.create(
                tenant_id=tenant.id,
                finding_uid=uid,
                status="under_review",
                provider=provider,
                check_id="s3_bucket_public",
            )

        limited = authenticated_client_no_permissions_rbac
        assert limited.get(reverse("finding-triages-list")).json()["data"] == []

        _grant_provider(tenants_fixture[0], allowed)
        uids = [
            item["attributes"]["finding_uid"]
            for item in limited.get(reverse("finding-triages-list")).json()["data"]
        ]
        assert uids == ["uid-allowed"]
        assert (
            limited.get(
                reverse("finding-uid-triage", kwargs={"finding_uid": "uid-denied"})
            ).status_code
            == 404
        )
        assert _patch_uid(limited, "uid-allowed", {"status": "resolved"}).status_code == 403
        bulk = limited.post(
            reverse("finding-triages-bulk"),
            data=_body("finding-triages", {"finding_uids": ["uid-allowed"], "status": "open"}),
            content_type=JSONAPI,
        )
        assert bulk.status_code == 403

    def test_requires_authentication(self, client):
        assert client.get(reverse("finding-triages-list")).status_code == 401


@pytest.mark.django_db
class TestBulk:
    def test_bulk_creates_updates_and_skips(self, authenticated_client, aws_provider):
        scan = _scan(aws_provider)
        for uid in ("uid-b1", "uid-b2"):
            _finding(scan, uid)
        assert _patch_uid(authenticated_client, "uid-b1", {"status": "under_review"}).status_code == 201

        response = authenticated_client.post(
            reverse("finding-triages-bulk"),
            data=_body(
                "finding-triages",
                {
                    "finding_uids": ["uid-b1", "uid-b2", "uid-missing", "uid-b2"],
                    "status": "false_positive",
                    "note": "Test data",
                },
            ),
            content_type=JSONAPI,
        )
        assert response.status_code == 200, response.content
        attributes = response.json()["data"]["attributes"]
        assert attributes == {
            "status": "false_positive",
            "created": 1,
            "updated": 1,
            "unchanged": 0,
            "skipped_uids": ["uid-missing"],
        }
        assert set(
            FindingTriage.objects.filter(status="false_positive").values_list(
                "finding_uid", flat=True
            )
        ) == {"uid-b1", "uid-b2"}
        assert FindingTriageNote.objects.filter(body="Test data").count() == 2
        assert FindingTriage.objects.get(finding_uid="uid-b2").source == "bulk"

    def test_bulk_cap(self, authenticated_client):
        uids = [f"uid-{index}" for index in range(BULK_MAX_FINDINGS + 1)]
        response = authenticated_client.post(
            reverse("finding-triages-bulk"),
            data=_body("finding-triages", {"finding_uids": uids, "status": "open"}),
            content_type=JSONAPI,
        )
        assert response.status_code == 400

    def test_bulk_rejects_empty_and_bad_status(self, authenticated_client):
        for attributes in (
            {"finding_uids": [], "status": "open"},
            {"finding_uids": ["a"], "status": "nope"},
        ):
            response = authenticated_client.post(
                reverse("finding-triages-bulk"),
                data=_body("finding-triages", attributes),
                content_type=JSONAPI,
            )
            assert response.status_code == 400


@pytest.mark.django_db
class TestNotes:
    def test_thread_crud(self, authenticated_client, aws_provider):
        _finding(_scan(aws_provider), "uid-notes")
        triage_id = _patch_uid(
            authenticated_client, "uid-notes", {"status": "under_review"}
        ).json()["data"]["id"]
        notes_url = reverse("finding-triages-notes", kwargs={"pk": triage_id})

        for body in ("first", "second"):
            created = authenticated_client.post(
                notes_url,
                data=_body("finding-triage-notes", {"body": body}),
                content_type=JSONAPI,
            )
            assert created.status_code == 201, created.content
            assert created.json()["data"]["type"] == f"{JSON_API_TYPE_PREFIX}finding-triage-notes"

        listed = authenticated_client.get(notes_url).json()["data"]
        assert [item["attributes"]["body"] for item in listed] == ["second", "first"]
        latest_id = listed[0]["id"]

        by_uid = authenticated_client.get(
            reverse("finding-uid-triage-notes", kwargs={"finding_uid": "uid-notes"})
        ).json()["data"]
        assert by_uid[0]["id"] == latest_id

        detail_url = reverse(
            "finding-triages-note-detail", kwargs={"pk": triage_id, "note_id": latest_id}
        )
        edited = authenticated_client.patch(
            detail_url,
            data=_body("finding-triage-notes", {"body": "edited"}),
            content_type=JSONAPI,
        )
        assert edited.status_code == 200
        assert edited.json()["data"]["attributes"]["body"] == "edited"

        deleted = authenticated_client.delete(
            reverse(
                "finding-uid-triage-note-detail",
                kwargs={"finding_uid": "uid-notes", "note_id": latest_id},
            )
        )
        assert deleted.status_code == 204
        assert FindingTriageNote.objects.filter(triage_id=triage_id).count() == 1

    def test_first_note_by_uid_creates_triage(self, authenticated_client, aws_provider):
        _finding(_scan(aws_provider), "uid-note-first")
        url = reverse("finding-uid-triage-notes", kwargs={"finding_uid": "uid-note-first"})
        assert authenticated_client.get(url).json()["data"] == []
        response = authenticated_client.post(
            url, data=_body("finding-triage-notes", {"body": "hello"}), content_type=JSONAPI
        )
        assert response.status_code == 201
        assert FindingTriage.objects.get(finding_uid="uid-note-first").status == "open"

    def test_note_validation(self, authenticated_client, aws_provider):
        _finding(_scan(aws_provider), "uid-note-bad")
        url = reverse("finding-uid-triage-notes", kwargs={"finding_uid": "uid-note-bad"})
        for body in ("   ", "x" * (FINDING_TRIAGE_NOTE_MAX_LENGTH + 1)):
            response = authenticated_client.post(
                url, data=_body("finding-triage-notes", {"body": body}), content_type=JSONAPI
            )
            assert response.status_code == 400

    def test_clean_note_body_and_author_rule(self):
        assert clean_note_body("  a\x00b\nc\t ") == "ab\nc"
        with pytest.raises(TriageError):
            clean_note_body(5)
        note = FindingTriageNote(author_id=uuid4())
        with pytest.raises(PermissionError):
            check_note_author(note, uuid4())
        check_note_author(note, note.author_id)


@pytest.mark.django_db
class TestFilters:
    def test_list_filters(self, authenticated_client, aws_provider_pair):
        first, second = aws_provider_pair
        _finding(_scan(first), "uid-f1", check_id="check_a")
        _finding(_scan(second), "uid-f2", check_id="check_b")
        _finding(_scan(second), "uid-f3", check_id="check_b")
        _patch_uid(authenticated_client, "uid-f1", {"status": "resolved"})
        _patch_uid(authenticated_client, "uid-f2", {"status": "false_positive"})
        _patch_uid(authenticated_client, "uid-f3", {"status": "under_review"})

        def uids(query: str) -> set[str]:
            response = authenticated_client.get(reverse("finding-triages-list") + query)
            assert response.status_code == 200, response.content
            return {item["attributes"]["finding_uid"] for item in response.json()["data"]}

        assert uids("?filter[status]=resolved") == {"uid-f1"}
        assert uids("?filter[status__in]=resolved,under_review") == {"uid-f1", "uid-f3"}
        assert uids("?filter[check_id]=check_b") == {"uid-f2", "uid-f3"}
        assert uids(f"?filter[provider]={first.id}") == {"uid-f1"}
        assert uids("?filter[finding_uid__in]=uid-f2,uid-f3") == {"uid-f2", "uid-f3"}
        page = authenticated_client.get(reverse("finding-triages-list") + "?page[size]=2").json()
        assert len(page["data"]) == 2
        assert page["meta"]["pagination"]["count"] == 3

    def test_lookup_cap(self, authenticated_client):
        ids = ",".join(str(uuid4()) for _ in range(201))
        response = authenticated_client.get(
            reverse("finding-triages-lookup") + f"?filter[finding_id__in]={ids}"
        )
        assert response.status_code == 400


@pytest.mark.django_db
class TestExecutiveReport:
    def test_triage_counts_in_scope(self, tenants_fixture, aws_provider):
        from cloudsneeker_api.reports.data import assemble_report
        from cloudsneeker_api.reports.data.executive import finding_triage_summary
        from cloudsneeker_api.reports.schema import ReportFilters

        tenant = tenants_fixture[0]
        scan = _scan(aws_provider)
        for uid in ("uid-e1", "uid-e2", "uid-e3", "uid-e4"):
            _finding(scan, uid)
        for uid, status in (
            ("uid-e1", "resolved"),
            ("uid-e2", "false_positive"),
            ("uid-e3", "remediating"),
            ("uid-out-of-scope", "resolved"),
        ):
            FindingTriage.objects.create(tenant_id=tenant.id, finding_uid=uid, status=status)

        with rls_transaction(str(tenant.id)):
            summary = finding_triage_summary(str(tenant.id), [scan.id], ReportFilters())
            empty = finding_triage_summary(str(tenant.id), [], ReportFilters())
        assert summary["resolved"] == 1
        assert summary["false_positive"] == 1
        assert summary["in_progress"] == 1
        assert summary["triaged"] == 3
        assert empty["triaged"] == 0

        with rls_transaction(str(tenant.id)):
            data = assemble_report(str(tenant.id), "executive", ReportFilters())
        assert data.kpis["triage_resolved"] == 1
        assert data.kpis["triage_false_positive"] == 1
        assert data.kpis["triage_in_progress"] == 1
        assert data.extra["triage"]["by_status"]["remediating"] == 1
