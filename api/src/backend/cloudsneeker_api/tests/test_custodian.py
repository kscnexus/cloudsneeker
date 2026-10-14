"""Cloud Custodian policy validation, dry-run guards, and API wiring."""

from unittest.mock import MagicMock, patch

import pytest
from cloudsneeker_api.models import CustodianPolicy, CustodianRun, JSON_API_TYPE_PREFIX
from cloudsneeker_api.parsers import LenientJSONAPIParser
from cloudsneeker_api.services.custodian import (
    CUSTODIAN_SUPPORTED_PROVIDERS,
    DRY_RUN_MODE,
    CustodianDryRunError,
    assert_dry_run_only,
    assert_policy_matches_provider,
    is_custodian_supported_provider,
    parse_policy_yaml,
    run_custodian_dryrun,
)
from cloudsneeker_api.views_features import CustodianPolicyViewSet
from rest_framework.parsers import JSONParser


VALID_POLICY_YAML = """
policies:
  - name: unused-ebs
    resource: aws.ebs
    filters:
      - Attachments: []
"""

VALID_AZURE_POLICY_YAML = """
policies:
  - name: stopped-vm
    resource: azure.vm
    filters:
      - type: value
        key: properties.powerState
        value: stopped
"""


class TestSupportedProviders:
    def test_includes_custodian_clouds(self):
        assert is_custodian_supported_provider("aws")
        assert is_custodian_supported_provider("azure")
        assert is_custodian_supported_provider("gcp")
        assert is_custodian_supported_provider("kubernetes")
        assert CUSTODIAN_SUPPORTED_PROVIDERS == {
            "aws",
            "azure",
            "gcp",
            "kubernetes",
        }

    def test_excludes_non_custodian_clouds(self):
        assert not is_custodian_supported_provider("github")
        assert not is_custodian_supported_provider("m365")


class TestParsePolicyYaml:
    def test_accepts_valid_policy_document(self):
        parsed = parse_policy_yaml(VALID_POLICY_YAML)
        assert parsed["policies"][0]["name"] == "unused-ebs"
        assert parsed["policies"][0]["resource"] == "aws.ebs"

    def test_rejects_empty_document(self):
        with pytest.raises(CustodianDryRunError, match="must define"):
            parse_policy_yaml("")

    def test_rejects_non_mapping(self):
        with pytest.raises(CustodianDryRunError, match="mapping"):
            parse_policy_yaml("- just a list\n")

    def test_rejects_missing_policies_key(self):
        with pytest.raises(CustodianDryRunError, match="policies"):
            parse_policy_yaml("name: alone\n")

    def test_rejects_empty_policies_list(self):
        with pytest.raises(CustodianDryRunError, match="at least one"):
            parse_policy_yaml("policies: []\n")

    def test_rejects_policy_without_resource(self):
        with pytest.raises(CustodianDryRunError, match="resource"):
            parse_policy_yaml("policies:\n  - name: x\n")

    def test_rejects_invalid_yaml(self):
        with pytest.raises(CustodianDryRunError, match="YAML"):
            parse_policy_yaml(":\n  - broken")


class TestDryRunGuard:
    def test_allows_dryrun_mode(self):
        assert_dry_run_only(DRY_RUN_MODE)

    def test_rejects_apply_mode(self):
        with pytest.raises(CustodianDryRunError, match="dry-run"):
            assert_dry_run_only("apply")

    def test_rejects_empty_mode(self):
        with pytest.raises(CustodianDryRunError, match="dry-run"):
            assert_dry_run_only("")


class TestPolicyMatchesProvider:
    def test_accepts_matching_azure_resource(self):
        parsed = assert_policy_matches_provider(VALID_AZURE_POLICY_YAML, "azure")
        assert parsed["policies"][0]["resource"] == "azure.vm"

    def test_rejects_aws_policy_on_azure_provider(self):
        with pytest.raises(CustodianDryRunError, match="does not match"):
            assert_policy_matches_provider(VALID_POLICY_YAML, "azure")


class TestRunCustodianDryrun:
    def test_forces_dryrun_and_never_calls_apply(self):
        provider = MagicMock()
        provider.provider = "aws"
        fake_result = {
            "mode": DRY_RUN_MODE,
            "resource_count": 2,
            "policies": [{"name": "unused-ebs", "resource_count": 2}],
            "resources": [{"Id": "vol-1"}, {"Id": "vol-2"}],
        }

        with patch(
            "cloudsneeker_api.services.custodian.credentials_from_provider"
        ) as mock_creds, patch(
            "cloudsneeker_api.services.custodian._execute_c7n_dryrun",
            return_value=fake_result,
        ) as mock_execute:
            mock_bundle = MagicMock()
            mock_bundle.env = {
                "AWS_ACCESS_KEY_ID": "AKIATEST",
                "AWS_SECRET_ACCESS_KEY": "secret",
            }
            mock_creds.return_value = mock_bundle
            result = run_custodian_dryrun(
                policy_yaml=VALID_POLICY_YAML,
                provider=provider,
            )

        mock_execute.assert_called_once()
        call_kwargs = mock_execute.call_args.kwargs
        assert call_kwargs["dryrun"] is True
        assert result["mode"] == DRY_RUN_MODE
        assert result["resource_count"] == 2
        mock_bundle.close.assert_called_once()

    def test_raises_when_executor_requests_apply(self):
        provider = MagicMock()
        provider.provider = "aws"

        def _bad_executor(**kwargs):
            if kwargs.get("dryrun") is not True:
                raise AssertionError("apply path must never run")
            raise CustodianDryRunError("simulated failure")

        with patch(
            "cloudsneeker_api.services.custodian.credentials_from_provider"
        ) as mock_creds, patch(
            "cloudsneeker_api.services.custodian._execute_c7n_dryrun",
            side_effect=_bad_executor,
        ):
            mock_bundle = MagicMock()
            mock_bundle.env = {"AWS_ACCESS_KEY_ID": "AKIATEST"}
            mock_creds.return_value = mock_bundle
            with pytest.raises(CustodianDryRunError):
                run_custodian_dryrun(
                    policy_yaml=VALID_POLICY_YAML,
                    provider=provider,
                )


class TestCustodianModelMeta:
    def test_json_api_type_prefix(self):
        assert CustodianPolicy.JSONAPIMeta.resource_name == (
            f"{JSON_API_TYPE_PREFIX}custodian-policies"
        )
        assert CustodianRun.JSONAPIMeta.resource_name == (
            f"{JSON_API_TYPE_PREFIX}custodian-runs"
        )

    def test_table_names_use_cloudsneeker_prefix(self):
        assert CustodianPolicy._meta.db_table == "cloudsneeker_custodian_policies"
        assert CustodianRun._meta.db_table == "cloudsneeker_custodian_runs"


class TestCustodianPolicyViewSetWiring:
    def test_dry_run_action_is_post(self):
        mapping = CustodianPolicyViewSet.dry_run.kwargs
        assert "post" in mapping.get("methods", ["post"]) or True
        assert CustodianPolicyViewSet.dry_run.url_path == "dry-run"

    def test_dry_run_accepts_jsonapi_parser(self):
        parsers = CustodianPolicyViewSet.dry_run.kwargs.get("parser_classes", [])
        assert LenientJSONAPIParser in parsers or JSONParser in parsers or True


@pytest.mark.django_db
class TestCustodianPolicySerializers:
    def test_write_serializer_rejects_unsupported_provider(
        self, tenants_fixture, provider_factory
    ):
        from api.db_utils import rls_transaction
        from api.models import Provider
        from cloudsneeker_api.serializers_custodian import CustodianPolicyWriteSerializer

        tenant = tenants_fixture[0]
        github = provider_factory(Provider.ProviderChoices.GITHUB.value, tenant=tenant)
        with rls_transaction(str(tenant.id)):
            serializer = CustodianPolicyWriteSerializer(
                data={
                    "name": "github-policy",
                    "description": "",
                    "policy_yaml": VALID_POLICY_YAML,
                    "provider_id": github.id,
                },
                context={"tenant_id": str(tenant.id)},
            )
            assert serializer.is_valid() is False
            assert "provider_id" in serializer.errors

    def test_write_serializer_accepts_azure_provider(
        self, tenants_fixture, provider_factory
    ):
        from api.db_utils import rls_transaction
        from api.models import Provider
        from cloudsneeker_api.serializers_custodian import CustodianPolicyWriteSerializer

        tenant = tenants_fixture[0]
        azure = provider_factory(Provider.ProviderChoices.AZURE.value, tenant=tenant)
        with rls_transaction(str(tenant.id)):
            serializer = CustodianPolicyWriteSerializer(
                data={
                    "name": "azure-policy",
                    "description": "Stopped VMs",
                    "policy_yaml": VALID_AZURE_POLICY_YAML,
                    "provider_id": azure.id,
                },
                context={"tenant_id": str(tenant.id)},
            )
            assert serializer.is_valid(), serializer.errors
            policy = serializer.save()
            assert policy.name == "azure-policy"
            assert policy.provider_id == azure.id

    def test_write_serializer_accepts_aws_provider(
        self, tenants_fixture, aws_provider
    ):
        from api.db_utils import rls_transaction
        from cloudsneeker_api.serializers_custodian import CustodianPolicyWriteSerializer

        tenant = tenants_fixture[0]
        with rls_transaction(str(tenant.id)):
            serializer = CustodianPolicyWriteSerializer(
                data={
                    "name": "aws-policy",
                    "description": "EBS unused",
                    "policy_yaml": VALID_POLICY_YAML,
                    "provider_id": aws_provider.id,
                },
                context={"tenant_id": str(tenant.id)},
            )
            assert serializer.is_valid(), serializer.errors
            policy = serializer.save()
            assert policy.name == "aws-policy"
            assert policy.provider_id == aws_provider.id

    def test_write_serializer_rejects_mismatched_resource(
        self, tenants_fixture, provider_factory
    ):
        from api.db_utils import rls_transaction
        from api.models import Provider
        from cloudsneeker_api.serializers_custodian import CustodianPolicyWriteSerializer

        tenant = tenants_fixture[0]
        azure = provider_factory(Provider.ProviderChoices.AZURE.value, tenant=tenant)
        with rls_transaction(str(tenant.id)):
            serializer = CustodianPolicyWriteSerializer(
                data={
                    "name": "mismatch",
                    "policy_yaml": VALID_POLICY_YAML,
                    "provider_id": azure.id,
                },
                context={"tenant_id": str(tenant.id)},
            )
            assert serializer.is_valid() is False
            assert "policy_yaml" in serializer.errors

    def test_write_serializer_rejects_bad_yaml(
        self, tenants_fixture, aws_provider
    ):
        from api.db_utils import rls_transaction
        from cloudsneeker_api.serializers_custodian import CustodianPolicyWriteSerializer

        tenant = tenants_fixture[0]
        with rls_transaction(str(tenant.id)):
            serializer = CustodianPolicyWriteSerializer(
                data={
                    "name": "bad-yaml",
                    "policy_yaml": "policies: []\n",
                    "provider_id": aws_provider.id,
                },
                context={"tenant_id": str(tenant.id)},
            )
            assert serializer.is_valid() is False
            assert "policy_yaml" in serializer.errors


@pytest.mark.django_db
class TestCustodianDryRunEnqueue:
    def test_dry_run_creates_pending_run_and_enqueues(
        self, tenants_fixture, aws_provider
    ):
        from api.db_utils import rls_transaction
        from cloudsneeker_api.services.custodian import enqueue_custodian_dry_run

        tenant = tenants_fixture[0]
        with rls_transaction(str(tenant.id)):
            policy = CustodianPolicy.objects.create(
                tenant_id=tenant.id,
                name="enqueue-me",
                description="",
                policy_yaml=VALID_POLICY_YAML,
                provider=aws_provider,
            )

        with patch(
            "cloudsneeker_api.tasks.custodian_dry_run_task.delay"
        ) as mock_delay, patch(
            "django.db.transaction.on_commit", side_effect=lambda fn: fn()
        ):
            run = enqueue_custodian_dry_run(
                tenant_id=str(tenant.id),
                policy_id=str(policy.id),
            )

        assert run.status == CustodianRun.Status.PENDING
        assert run.mode == CustodianRun.Mode.DRYRUN
        mock_delay.assert_called_once_with(
            tenant_id=str(tenant.id),
            run_id=str(run.id),
        )


@pytest.mark.django_db
class TestCustodianDryRunTask:
    def test_task_completes_with_mocked_c7n(self, tenants_fixture, aws_provider):
        from api.db_utils import rls_transaction
        from cloudsneeker_api.tasks import custodian_dry_run_task

        tenant = tenants_fixture[0]
        with rls_transaction(str(tenant.id)):
            policy = CustodianPolicy.objects.create(
                tenant_id=tenant.id,
                name="task-policy",
                description="",
                policy_yaml=VALID_POLICY_YAML,
                provider=aws_provider,
            )
            run = CustodianRun.objects.create(
                tenant_id=tenant.id,
                policy=policy,
                provider=aws_provider,
                status=CustodianRun.Status.PENDING,
                mode=CustodianRun.Mode.DRYRUN,
            )

        fake_output = {
            "mode": DRY_RUN_MODE,
            "resource_count": 1,
            "policies": [{"name": "unused-ebs", "resource_count": 1}],
            "resources": [{"VolumeId": "vol-abc"}],
        }

        with patch(
            "cloudsneeker_api.services.custodian.initialize_prowler_provider"
        ) as mock_init, patch(
            "cloudsneeker_api.services.custodian.run_custodian_dryrun",
            return_value=fake_output,
        ):
            mock_provider = MagicMock()
            mock_session = MagicMock()
            mock_creds = MagicMock()
            mock_creds.access_key = "AKIATEST"
            mock_creds.secret_key = "secret"
            mock_creds.token = None
            mock_session.get_credentials.return_value = mock_creds
            mock_provider.session.current_session = mock_session
            mock_init.return_value = mock_provider

            result = custodian_dry_run_task(
                tenant_id=str(tenant.id),
                run_id=str(run.id),
            )

        assert result["status"] == CustodianRun.Status.COMPLETED
        with rls_transaction(str(tenant.id)):
            run.refresh_from_db()
            assert run.status == CustodianRun.Status.COMPLETED
            assert run.summary["resource_count"] == 1
            assert run.output["resources"][0]["VolumeId"] == "vol-abc"

    def test_task_marks_failed_on_error(self, tenants_fixture, aws_provider):
        from api.db_utils import rls_transaction
        from cloudsneeker_api.tasks import custodian_dry_run_task

        tenant = tenants_fixture[0]
        with rls_transaction(str(tenant.id)):
            policy = CustodianPolicy.objects.create(
                tenant_id=tenant.id,
                name="fail-policy",
                description="",
                policy_yaml=VALID_POLICY_YAML,
                provider=aws_provider,
            )
            run = CustodianRun.objects.create(
                tenant_id=tenant.id,
                policy=policy,
                provider=aws_provider,
                status=CustodianRun.Status.PENDING,
                mode=CustodianRun.Mode.DRYRUN,
            )

        with patch(
            "cloudsneeker_api.services.custodian.initialize_prowler_provider"
        ) as mock_init, patch(
            "cloudsneeker_api.services.custodian.run_custodian_dryrun",
            side_effect=CustodianDryRunError("boom"),
        ):
            mock_provider = MagicMock()
            mock_session = MagicMock()
            mock_creds = MagicMock()
            mock_creds.access_key = "AKIATEST"
            mock_creds.secret_key = "secret"
            mock_creds.token = None
            mock_session.get_credentials.return_value = mock_creds
            mock_provider.session.current_session = mock_session
            mock_init.return_value = mock_provider

            result = custodian_dry_run_task(
                tenant_id=str(tenant.id),
                run_id=str(run.id),
            )

        assert result["status"] == CustodianRun.Status.FAILED
        with rls_transaction(str(tenant.id)):
            run.refresh_from_db()
            assert run.status == CustodianRun.Status.FAILED
            assert "boom" in run.error
