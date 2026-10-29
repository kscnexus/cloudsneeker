"""Report run generation, artifact storage, share links, and delivery."""

from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from email import message_from_string
from unittest.mock import MagicMock, patch

import pytest
from api.db_utils import rls_transaction
from cloudsneeker_api.models import ReportRun, ReportShareLink
from cloudsneeker_api.reports import delivery, runs, share
from cloudsneeker_api.reports.catalog import ReportParamsError
from cloudsneeker_api.reports.runs import (
    ReportRunError,
    artifact_path,
    enqueue_report_run,
    process_report_run,
    read_report_json,
)
from cloudsneeker_api.reports.share import (
    ShareLinkError,
    create_share_link,
    hash_token,
    link_state,
    resolve_share_token,
    revoke_share_link,
)
from cloudsneeker_api.services.email_delivery import send_with_tenant_smtp
from django.test import override_settings
from django.utils import timezone


@pytest.fixture
def report_dir(tmp_path):
    with override_settings(DJANGO_TMP_OUTPUT_DIRECTORY=str(tmp_path)):
        yield tmp_path


def _completed_run(tenant, formats=("pdf", "csv", "json")):
    with patch("cloudsneeker_api.reports.runs.transaction.on_commit"):
        run = enqueue_report_run(
            tenant_id=str(tenant.id),
            report_type="cloud_posture",
            params={},
            formats=list(formats),
        )
    result = process_report_run(tenant_id=str(tenant.id), run_id=str(run.id))
    assert result["status"] == ReportRun.Status.COMPLETED
    with rls_transaction(str(tenant.id)):
        return ReportRun.objects.get(id=run.id)


@pytest.mark.django_db
class TestEnqueueAndProcess:
    def test_enqueue_creates_pending_run_and_dispatches_on_commit(self, tenants_fixture):
        tenant = tenants_fixture[0]
        with (
            patch("cloudsneeker_api.reports.runs.transaction.on_commit") as on_commit,
            patch("cloudsneeker_api.tasks.generate_report_task") as task,
        ):
            run = enqueue_report_run(
                tenant_id=str(tenant.id),
                report_type="executive",
                params={"severity_floor": "high"},
                formats=["pdf"],
            )
            on_commit.assert_called_once()
            on_commit.call_args[0][0]()
        task.delay.assert_called_once_with(tenant_id=str(tenant.id), run_id=str(run.id))
        assert run.status == ReportRun.Status.PENDING
        assert run.formats == ["pdf", "json"]
        assert run.params["severity_floor"] == "high"

    def test_enqueue_without_dispatch(self, tenants_fixture):
        with patch("cloudsneeker_api.reports.runs.transaction.on_commit") as on_commit:
            enqueue_report_run(
                tenant_id=str(tenants_fixture[0].id),
                report_type="sast",
                params=None,
                formats=None,
                dispatch=False,
            )
        on_commit.assert_not_called()

    def test_enqueue_rejects_invalid_params(self, tenants_fixture):
        with pytest.raises(ReportParamsError):
            enqueue_report_run(
                tenant_id=str(tenants_fixture[0].id),
                report_type="compliance",
                params={},
                formats=None,
            )

    def test_process_writes_every_format(self, tenants_fixture, report_dir):
        tenant = tenants_fixture[0]
        run = _completed_run(tenant, formats=("pdf", "xlsx", "csv", "json"))
        assert set(run.artifacts) == {"pdf", "xlsx", "csv", "json"}
        assert run.size_bytes == sum(run.artifact_sizes.values()) > 0
        assert run.summary["empty"] is True
        assert artifact_path(run, "pdf").read_bytes().startswith(b"%PDF")
        assert artifact_path(run, "xlsx").read_bytes().startswith(b"PK")
        assert artifact_path(run, "pdf").name.startswith("cloudsneeker-cloud-posture-")
        assert read_report_json(run)["report_type"] == "cloud_posture"
        assert str(report_dir) in str(artifact_path(run, "csv"))

    def test_process_is_idempotent_for_completed_runs(self, tenants_fixture, report_dir):
        tenant = tenants_fixture[0]
        run = _completed_run(tenant)
        with patch("cloudsneeker_api.reports.runs.assemble_report") as assemble:
            result = process_report_run(tenant_id=str(tenant.id), run_id=str(run.id))
        assemble.assert_not_called()
        assert result["status"] == ReportRun.Status.COMPLETED

    def test_process_records_failure(self, tenants_fixture, report_dir):
        tenant = tenants_fixture[0]
        with patch("cloudsneeker_api.reports.runs.transaction.on_commit"):
            run = enqueue_report_run(
                tenant_id=str(tenant.id), report_type="iac", params={}, formats=None
            )
        with patch(
            "cloudsneeker_api.reports.runs.assemble_report",
            side_effect=RuntimeError("boom"),
        ):
            result = process_report_run(tenant_id=str(tenant.id), run_id=str(run.id))
        assert result["status"] == ReportRun.Status.FAILED
        with rls_transaction(str(tenant.id)):
            run.refresh_from_db()
        assert run.status == ReportRun.Status.FAILED
        assert run.error == "boom"
        assert run.finished_at is not None

    def test_process_unknown_run_raises(self, tenants_fixture):
        with pytest.raises(ReportRunError, match="was not found"):
            process_report_run(
                tenant_id=str(tenants_fixture[0].id),
                run_id="00000000-0000-4000-8000-000000000000",
            )

    def test_generate_task_delegates(self):
        from cloudsneeker_api.tasks import generate_report_task

        with patch(
            "cloudsneeker_api.reports.runs.process_report_run",
            return_value={"status": "completed"},
        ) as process:
            result = generate_report_task.run.__wrapped__(tenant_id="t", run_id="r")
        process.assert_called_once_with(tenant_id="t", run_id="r")
        assert result == {"status": "completed"}


@pytest.mark.django_db
class TestArtifactPath:
    def test_not_ready(self, tenants_fixture):
        run = ReportRun(tenant_id=tenants_fixture[0].id, status=ReportRun.Status.PENDING)
        with pytest.raises(ReportRunError, match="not ready"):
            artifact_path(run, "pdf")

    def test_format_not_generated(self, tenants_fixture, report_dir):
        run = _completed_run(tenants_fixture[0], formats=("json",))
        with pytest.raises(ReportRunError, match="not generated as pdf"):
            artifact_path(run, "pdf")

    def test_rejects_path_traversal(self, tenants_fixture, report_dir):
        run = _completed_run(tenants_fixture[0], formats=("json",))
        run.artifacts = {"json": "../../etc/passwd"}
        with pytest.raises(ReportRunError, match="Invalid artifact path"):
            artifact_path(run, "json")

    def test_missing_file(self, tenants_fixture, report_dir):
        run = _completed_run(tenants_fixture[0], formats=("json",))
        artifact_path(run, "json").unlink()
        with pytest.raises(ReportRunError, match="no longer available"):
            artifact_path(run, "json")

    def test_delete_artifacts(self, tenants_fixture, report_dir):
        tenant = tenants_fixture[0]
        run = _completed_run(tenant)
        runs.delete_run_artifacts(str(tenant.id), str(run.id))
        assert not runs.run_directory(str(tenant.id), str(run.id)).exists()
        # Second call is a no-op.
        runs.delete_run_artifacts(str(tenant.id), str(run.id))


@pytest.mark.django_db
class TestShareLinks:
    def test_stores_only_the_hash(self, tenants_fixture, report_dir):
        tenant = tenants_fixture[0]
        run = _completed_run(tenant)
        link, token = create_share_link(tenant_id=str(tenant.id), run=run)
        assert len(token) >= 40
        assert link.token_hash == hashlib.sha256(token.encode()).hexdigest()
        assert token not in link.token_hash
        assert link.expires_at > timezone.now() + timedelta(hours=71)
        assert link_state(link) == "active"

    def test_resolve_returns_payload_and_counts_access(self, tenants_fixture, report_dir):
        tenant = tenants_fixture[0]
        run = _completed_run(tenant)
        link, token = create_share_link(tenant_id=str(tenant.id), run=run)
        resolved, payload = resolve_share_token(token)
        assert resolved.id == link.id
        assert payload["report_type"] == "cloud_posture"
        assert "tenant_id" not in json.dumps(payload)
        with rls_transaction(str(tenant.id)):
            link.refresh_from_db()
        assert link.access_count == 1
        assert link.last_accessed_at is not None

    @pytest.mark.parametrize("token", ["", "x" * 200, "unknown-token"])
    def test_unknown_tokens(self, tenants_fixture, token):
        with pytest.raises(ShareLinkError) as exc:
            resolve_share_token(token)
        assert exc.value.code == "not_found"

    def test_expired_and_revoked(self, tenants_fixture, report_dir):
        tenant = tenants_fixture[0]
        run = _completed_run(tenant)
        link, token = create_share_link(tenant_id=str(tenant.id), run=run)
        with rls_transaction(str(tenant.id)):
            ReportShareLink.objects.filter(id=link.id).update(
                expires_at=timezone.now() - timedelta(minutes=1)
            )
        with pytest.raises(ShareLinkError) as exc:
            resolve_share_token(token)
        assert exc.value.code == "expired"

        link2, token2 = create_share_link(tenant_id=str(tenant.id), run=run)
        with rls_transaction(str(tenant.id)):
            revoke_share_link(link2)
            first_revoked_at = link2.revoked_at
            revoke_share_link(link2)
        assert link2.revoked_at == first_revoked_at
        with pytest.raises(ShareLinkError) as exc:
            resolve_share_token(token2)
        assert exc.value.code == "revoked"
        assert link_state(link2) == "revoked"

    def test_missing_artifact_is_not_ready(self, tenants_fixture, report_dir):
        tenant = tenants_fixture[0]
        run = _completed_run(tenant)
        _, token = create_share_link(tenant_id=str(tenant.id), run=run)
        artifact_path(run, "json").unlink()
        with pytest.raises(ShareLinkError) as exc:
            resolve_share_token(token)
        assert exc.value.code == "not_ready"

    def test_only_completed_runs(self, tenants_fixture):
        run = ReportRun(tenant_id=tenants_fixture[0].id, status=ReportRun.Status.RUNNING)
        with pytest.raises(ShareLinkError) as exc:
            create_share_link(tenant_id=str(tenants_fixture[0].id), run=run)
        assert exc.value.code == "not_ready"

    @pytest.mark.parametrize("hours", [0, share.MAX_TTL_HOURS + 1, "abc"])
    def test_rejects_bad_lifetime(self, tenants_fixture, report_dir, hours):
        run = _completed_run(tenants_fixture[0], formats=("json",))
        with pytest.raises(ShareLinkError):
            create_share_link(
                tenant_id=str(tenants_fixture[0].id), run=run, expires_in_hours=hours
            )

    def test_hash_token_is_sha256(self):
        assert hash_token("abc") == hashlib.sha256(b"abc").hexdigest()
        assert share.generate_token() != share.generate_token()


class TestEmailAttachments:
    def _config(self):
        config = MagicMock()
        config.host = "smtp.example.com"
        config.port = 465
        config.use_ssl = True
        config.use_tls = False
        config.username = ""
        config.from_email = "reports@example.com"
        return config

    def test_sends_multipart_with_attachment(self):
        smtp = MagicMock()
        smtp.__enter__ = MagicMock(return_value=smtp)
        smtp.__exit__ = MagicMock(return_value=False)
        smtp.sendmail.return_value = {}
        with patch(
            "cloudsneeker_api.services.email_delivery.SMTP_SSL", return_value=smtp
        ):
            sent = send_with_tenant_smtp(
                tenant_id="t",
                subject="Report",
                message="Body",
                recipient_list=["a@example.com"],
                config=self._config(),
                attachments=[("report.pdf", b"%PDF-1.4", "application/pdf")],
            )
        assert sent == 1
        smtp.login.assert_not_called()
        raw = smtp.sendmail.call_args[0][2]
        message = message_from_string(raw)
        assert message.is_multipart()
        parts = message.get_payload()
        assert parts[1].get_filename() == "report.pdf"
        assert parts[1].get_content_type() == "application/pdf"


@pytest.mark.django_db
class TestDelivery:
    def test_no_recipients(self, tenants_fixture):
        run = ReportRun(tenant_id=tenants_fixture[0].id)
        assert delivery.deliver_report_email(
            tenant_id=str(tenants_fixture[0].id), run=run, recipients=["", None]
        ) == {"delivery": "no_recipients", "sent": 0}

    def test_attaches_small_pdf(self, tenants_fixture, report_dir):
        tenant = tenants_fixture[0]
        run = _completed_run(tenant)
        with patch(
            "cloudsneeker_api.reports.delivery.send_with_tenant_smtp", return_value=2
        ) as send:
            result = delivery.deliver_report_email(
                tenant_id=str(tenant.id), run=run, recipients=["a@x.io", "b@x.io"]
            )
        assert result == {"delivery": "attachment", "sent": 2}
        kwargs = send.call_args.kwargs
        assert kwargs["attachments"][0][0].endswith(".pdf")
        assert kwargs["subject"].startswith("[Cloudsneeker] ")
        assert "attached" in kwargs["message"]

    def test_large_pdf_sends_share_link(self, tenants_fixture, report_dir, monkeypatch):
        tenant = tenants_fixture[0]
        run = _completed_run(tenant)
        monkeypatch.setenv("REPORT_EMAIL_MAX_ATTACHMENT_MB", "0")
        with (
            override_settings(UI_BASE_URL="https://app.example.com"),
            patch(
                "cloudsneeker_api.reports.delivery.send_with_tenant_smtp", return_value=1
            ) as send,
        ):
            result = delivery.deliver_report_email(
                tenant_id=str(tenant.id), run=run, recipients=["a@x.io"]
            )
        assert result == {"delivery": "link", "sent": 1}
        kwargs = send.call_args.kwargs
        assert kwargs["attachments"] == []
        assert "https://app.example.com/shared-reports/" in kwargs["message"]
        with rls_transaction(str(tenant.id)):
            assert ReportShareLink.objects.filter(report_run=run).count() == 1

    def test_missing_pdf_falls_back_to_link(self, tenants_fixture, report_dir):
        tenant = tenants_fixture[0]
        run = _completed_run(tenant, formats=("json",))
        with patch(
            "cloudsneeker_api.reports.delivery.send_with_tenant_smtp", return_value=1
        ):
            result = delivery.deliver_report_email(
                tenant_id=str(tenant.id), run=run, recipients=["a@x.io"]
            )
        assert result["delivery"] == "link"

    def test_smtp_failure_is_reported(self, tenants_fixture, report_dir):
        tenant = tenants_fixture[0]
        run = _completed_run(tenant)
        with patch(
            "cloudsneeker_api.reports.delivery.send_with_tenant_smtp",
            side_effect=ValueError("Email delivery is not configured for this tenant."),
        ):
            result = delivery.deliver_report_email(
                tenant_id=str(tenant.id), run=run, recipients=["a@x.io"]
            )
        assert result == {"delivery": "failed", "sent": 0}

    def test_bad_attachment_cap_uses_default(self, monkeypatch):
        monkeypatch.setenv("REPORT_EMAIL_MAX_ATTACHMENT_MB", "lots")
        assert delivery.max_attachment_bytes() == 10 * 1024 * 1024
