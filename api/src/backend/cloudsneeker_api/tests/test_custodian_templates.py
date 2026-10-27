"""Tests for Custodian templates, validation helpers, and error classification."""

from datetime import timedelta
from unittest.mock import MagicMock, patch

import pytest
from api.db_utils import rls_transaction
from cloudsneeker_api.models import CustodianPolicy, CustodianRun
from cloudsneeker_api.services.custodian import (
    CustodianDryRunError,
    cancel_custodian_dry_run,
    trim_old_custodian_run_output,
)
from cloudsneeker_api.services.custodian_templates import (
    get_pack,
    list_packs,
    list_templates,
    prowler_check_ids_for_policy_yaml,
)
from cloudsneeker_api.services.custodian_validate import (
    ERROR_CANCELLED,
    ERROR_CREDENTIALS,
    ERROR_INVALID_POLICY,
    ERROR_TIMEOUT,
    build_resources_preview,
    classify_custodian_error,
    compute_resource_delta,
    validate_custodian_policy_schema,
)
from django.utils import timezone


class TestTemplates:
    def test_lists_aws_templates(self):
        templates = list_templates(provider_type="aws")
        ids = {item["id"] for item in templates}
        assert "aws-public-s3" in ids
        assert "aws-unused-ebs" in ids
        assert "azure-stopped-vm" not in ids

    def test_hygiene_pack_includes_public_s3(self):
        pack = get_pack("aws-hygiene")
        assert pack is not None
        assert "aws-public-s3" in pack["template_ids"]
        assert list_packs(provider_type="aws")

    def test_maps_s3_policy_to_prowler_checks(self):
        yaml_text = list_templates(provider_type="aws")[0]["policy_yaml"]
        # Find public s3 template yaml explicitly.
        public = next(
            item for item in list_templates() if item["id"] == "aws-public-s3"
        )
        checks = prowler_check_ids_for_policy_yaml(public["policy_yaml"])
        assert "s3_bucket_public_access" in checks
        assert yaml_text  # keep import used for lint silence in some runners


class TestValidate:
    def test_rejects_actions(self):
        with pytest.raises(CustodianDryRunError, match="actions"):
            validate_custodian_policy_schema(
                """policies:
  - name: mutate
    resource: aws.s3
    actions:
      - delete
"""
            )

    def test_validate_calls_c7n_when_available(self):
        with patch(
            "cloudsneeker_api.services.custodian_validate._resolve_custodian_bin",
            return_value="custodian",
        ), patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            validate_custodian_policy_schema(
                """policies:
  - name: unused-ebs
    resource: aws.ebs
    filters:
      - Attachments: []
"""
            )
        mock_run.assert_called_once()
        assert mock_run.call_args.args[0][1] == "validate"

    def test_validate_surfaces_schema_errors(self):
        with patch(
            "cloudsneeker_api.services.custodian_validate._resolve_custodian_bin",
            return_value="custodian",
        ), patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="Failed to validate policy unknown Error on policy:x",
            )
            with pytest.raises(CustodianDryRunError, match="Failed to validate"):
                validate_custodian_policy_schema(
                    """policies:
  - name: bad
    resource: aws.s3
    filters:
      - type: global-grants
"""
                )


class TestClassifyAndPreview:
    def test_classifies_invalid_policy(self):
        assert (
            classify_custodian_error("Failed to validate policy schema")
            == ERROR_INVALID_POLICY
        )

    def test_classifies_credentials(self):
        assert classify_custodian_error("Unable to locate credentials") == ERROR_CREDENTIALS

    def test_classifies_timeout(self):
        assert classify_custodian_error("dry-run timed out after 900s") == ERROR_TIMEOUT

    def test_resources_preview_and_delta(self):
        current = [{"VolumeId": "vol-1", "c7n:region": "us-east-1"}]
        previous = [{"VolumeId": "vol-2"}]
        preview = build_resources_preview(current)
        assert preview[0]["uid"] == "vol-1"
        delta = compute_resource_delta(current, previous)
        assert delta["new"] == ["vol-1"]
        assert delta["gone"] == ["vol-2"]
        assert delta["still_matched"] == []


@pytest.mark.django_db
class TestCancelAndTrim:
    def test_cancel_pending_run(self, tenants_fixture, aws_provider):
        tenant = tenants_fixture[0]
        with rls_transaction(str(tenant.id)):
            policy = CustodianPolicy.objects.create(
                tenant_id=tenant.id,
                name="cancel-me",
                description="",
                policy_yaml=list_templates(provider_type="aws")[0]["policy_yaml"],
                provider=aws_provider,
            )
            run = CustodianRun.objects.create(
                tenant_id=tenant.id,
                policy=policy,
                provider=aws_provider,
                status=CustodianRun.Status.PENDING,
                mode=CustodianRun.Mode.DRYRUN,
            )
            run_id = str(run.id)

        cancelled = cancel_custodian_dry_run(
            tenant_id=str(tenant.id), run_id=run_id
        )
        assert cancelled.status == CustodianRun.Status.FAILED
        assert cancelled.error_class == ERROR_CANCELLED

    def test_trim_clears_old_resources(self, tenants_fixture, aws_provider):
        tenant = tenants_fixture[0]
        with rls_transaction(str(tenant.id)):
            policy = CustodianPolicy.objects.create(
                tenant_id=tenant.id,
                name="trim-me",
                description="",
                policy_yaml=list_templates(provider_type="aws")[0]["policy_yaml"],
                provider=aws_provider,
            )
            run = CustodianRun.objects.create(
                tenant_id=tenant.id,
                policy=policy,
                provider=aws_provider,
                status=CustodianRun.Status.COMPLETED,
                mode=CustodianRun.Mode.DRYRUN,
                finished_at=timezone.now() - timedelta(days=45),
                summary={"resource_count": 1},
                output={"resources": [{"VolumeId": "vol-old"}]},
            )
            run_id = str(run.id)

        trimmed = trim_old_custodian_run_output(
            tenant_id=str(tenant.id), older_than_days=30
        )
        assert trimmed == 1
        with rls_transaction(str(tenant.id)):
            run = CustodianRun.objects.get(id=run_id)
            assert run.output.get("resources") == []
            assert run.output.get("resources_trimmed") is True
            assert run.summary["resource_count"] == 1
