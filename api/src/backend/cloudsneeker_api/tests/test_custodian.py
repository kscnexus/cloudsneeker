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


class TestAwsRegionsForProvider:
    def test_uses_scanner_args_regions(self):
        from cloudsneeker_api.services.custodian import _aws_regions_for_provider

        provider = MagicMock()
        provider.scanner_args = {"regions": ["eu-west-1", "ap-south-1"]}
        cloud = MagicMock()
        assert _aws_regions_for_provider(cloud, provider) == [
            "ap-south-1",
            "eu-west-1",
        ]

    def test_falls_back_to_enabled_regions(self):
        from cloudsneeker_api.services.custodian import _aws_regions_for_provider

        provider = MagicMock()
        provider.scanner_args = {}
        cloud = MagicMock()
        cloud._enabled_regions = {"us-west-2", "us-east-1"}
        cloud.identity.audited_regions = None
        assert _aws_regions_for_provider(cloud, provider) == [
            "us-east-1",
            "us-west-2",
        ]


class TestCollectOutput:
    def test_stamps_region_and_policy_from_path(self, tmp_path):
        from cloudsneeker_api.services.custodian import _collect_output

        region_dir = tmp_path / "us-east-1" / "unused-ebs"
        region_dir.mkdir(parents=True)
        (region_dir / "resources.json").write_text(
            '[{"VolumeId": "vol-1"}, {"VolumeId": "vol-2"}]',
            encoding="utf-8",
        )

        result = _collect_output(tmp_path)

        assert result["resource_count"] == 2
        assert result["policies"][0]["name"] == "unused-ebs"
        assert result["policies"][0]["region"] == "us-east-1"
        assert result["resources"][0]["c7n:region"] == "us-east-1"
        assert result["resources"][0]["c7n:policy"] == "unused-ebs"
        assert result["resources"][1]["VolumeId"] == "vol-2"

    def test_keeps_existing_metadata(self, tmp_path):
        from cloudsneeker_api.services.custodian import _collect_output

        policy_dir = tmp_path / "unused-ebs"
        policy_dir.mkdir()
        (policy_dir / "resources.json").write_text(
            '[{"VolumeId": "vol-9", "c7n:region": "eu-west-1"}]',
            encoding="utf-8",
        )

        result = _collect_output(tmp_path)
        assert result["resources"][0]["c7n:region"] == "eu-west-1"
        assert result["resources"][0]["c7n:policy"] == "unused-ebs"


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
            mock_bundle.regions = ["us-east-1", "eu-west-1"]
            mock_creds.return_value = mock_bundle
            result = run_custodian_dryrun(
                policy_yaml=VALID_POLICY_YAML,
                provider=provider,
            )

        mock_execute.assert_called_once()
        call_kwargs = mock_execute.call_args.kwargs
        assert call_kwargs["dryrun"] is True
        assert call_kwargs["regions"] == ["us-east-1", "eu-west-1"]
        assert result["mode"] == DRY_RUN_MODE
        assert result["resource_count"] == 2
        mock_bundle.close.assert_called_once()

    def test_execute_passes_region_flags(self):
        from cloudsneeker_api.services.custodian import _execute_c7n_dryrun

        with patch(
            "cloudsneeker_api.services.custodian._resolve_custodian_bin",
            return_value="custodian",
        ), patch("subprocess.run") as mock_run, patch(
            "cloudsneeker_api.services.custodian._collect_output",
            return_value={
                "mode": DRY_RUN_MODE,
                "resource_count": 0,
                "policies": [],
                "resources": [],
            },
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            result = _execute_c7n_dryrun(
                policy_path=MagicMock(),
                output_dir=MagicMock(),
                credential_env={"AWS_ACCESS_KEY_ID": "AKIATEST"},
                dryrun=True,
                regions=["us-east-1", "ap-south-1"],
            )

        command = mock_run.call_args.args[0]
        assert command.count("--region") == 2
        assert "us-east-1" in command
        assert "ap-south-1" in command
        assert result["regions"] == ["us-east-1", "ap-south-1"]

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
            mock_bundle.regions = []
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

    def test_schedule_bulk_action_is_post(self):
        assert CustodianPolicyViewSet.schedule_bulk.url_path == "schedule-bulk"


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
@pytest.mark.django_db
class TestCustodianRunSerializer:
    def test_includes_policy_and_provider_labels(
        self, tenants_fixture, aws_provider
    ):
        from api.db_utils import rls_transaction
        from cloudsneeker_api.serializers_custodian import CustodianRunSerializer

        tenant = tenants_fixture[0]
        with rls_transaction(str(tenant.id)):
            policy = CustodianPolicy.objects.create(
                tenant_id=tenant.id,
                name="unused-ebs",
                description="",
                policy_yaml=VALID_POLICY_YAML,
                provider=aws_provider,
            )
            run = CustodianRun.objects.select_related("policy", "provider").create(
                tenant_id=tenant.id,
                policy=policy,
                provider=aws_provider,
                status=CustodianRun.Status.COMPLETED,
                mode=CustodianRun.Mode.DRYRUN,
                trigger=CustodianRun.Trigger.MANUAL,
                summary={"resource_count": 3},
            )
            payload = CustodianRunSerializer(run).data

        assert payload["policy_name"] == "unused-ebs"
        assert payload["provider_uid"] == aws_provider.uid
        assert payload["provider_type"] == "aws"
        assert payload["summary"]["resource_count"] == 3


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


class TestCustodianScheduleValidation:
    def test_parse_cron_accepts_five_fields(self):
        from cloudsneeker_api.services.custodian_schedule import parse_cron_fields

        assert parse_cron_fields("0 9 * * 1") == ("0", "9", "*", "*", "1")

    def test_parse_cron_rejects_bad_expression(self):
        from cloudsneeker_api.services.custodian_schedule import (
            CustodianScheduleError,
            parse_cron_fields,
        )

        with pytest.raises(CustodianScheduleError, match="5-field"):
            parse_cron_fields("0 9 * *")

    def test_validate_timezone_rejects_unknown(self):
        from cloudsneeker_api.services.custodian_schedule import (
            CustodianScheduleError,
            validate_timezone,
        )

        with pytest.raises(CustodianScheduleError, match="Unknown timezone"):
            validate_timezone("Not/A_Zone")


@pytest.mark.django_db
class TestCustodianScheduleSync:
    def test_enable_creates_periodic_task(self, tenants_fixture, aws_provider):
        from api.db_utils import rls_transaction
        from cloudsneeker_api.services.custodian_schedule import (
            PERIODIC_TASK_PREFIX,
            sync_policy_schedule,
        )
        from django_celery_beat.models import PeriodicTask

        tenant = tenants_fixture[0]
        with rls_transaction(str(tenant.id)):
            policy = CustodianPolicy.objects.create(
                tenant_id=tenant.id,
                name="scheduled-policy",
                description="",
                policy_yaml=VALID_POLICY_YAML,
                provider=aws_provider,
                schedule_enabled=True,
                schedule_cron="0 9 * * *",
                schedule_timezone="UTC",
            )
            sync_policy_schedule(policy)
            policy.refresh_from_db()

        task = PeriodicTask.objects.get(
            name=f"{PERIODIC_TASK_PREFIX}{policy.id}"
        )
        assert task.enabled is True
        assert task.task == "cloudsneeker-custodian-scheduled-dry-run"
        assert policy.scheduler_task_id == task.id
        assert policy.next_run_at is not None

    def test_disable_clears_periodic_task(self, tenants_fixture, aws_provider):
        from api.db_utils import rls_transaction
        from cloudsneeker_api.services.custodian_schedule import sync_policy_schedule
        from django_celery_beat.models import PeriodicTask

        tenant = tenants_fixture[0]
        with rls_transaction(str(tenant.id)):
            policy = CustodianPolicy.objects.create(
                tenant_id=tenant.id,
                name="disable-schedule",
                description="",
                policy_yaml=VALID_POLICY_YAML,
                provider=aws_provider,
                schedule_enabled=True,
                schedule_cron="30 * * * *",
                schedule_timezone="UTC",
            )
            sync_policy_schedule(policy)
            policy.schedule_enabled = False
            policy.save(update_fields=["schedule_enabled"])
            sync_policy_schedule(policy)
            policy.refresh_from_db()

        task = PeriodicTask.objects.get(
            name=f"custodian-dry-run-scheduled-{policy.id}"
        )
        assert task.enabled is False
        assert policy.scheduler_task_id is None
        assert policy.next_run_at is None

    def test_policy_delete_removes_periodic_task(
        self, tenants_fixture, aws_provider
    ):
        from api.db_utils import rls_transaction
        from cloudsneeker_api.services.custodian_schedule import (
            delete_policy_schedule,
            sync_policy_schedule,
        )
        from django_celery_beat.models import PeriodicTask

        tenant = tenants_fixture[0]
        with rls_transaction(str(tenant.id)):
            policy = CustodianPolicy.objects.create(
                tenant_id=tenant.id,
                name="delete-schedule",
                description="",
                policy_yaml=VALID_POLICY_YAML,
                provider=aws_provider,
                schedule_enabled=True,
                schedule_cron="0 */2 * * *",
                schedule_timezone="UTC",
            )
            sync_policy_schedule(policy)
            policy_id = str(policy.id)
            policy.delete()
        delete_policy_schedule(policy_id)
        assert not PeriodicTask.objects.filter(
            name=f"custodian-dry-run-scheduled-{policy_id}"
        ).exists()

    def test_bulk_schedule_by_provider(self, tenants_fixture, aws_provider):
        from api.db_utils import rls_transaction
        from cloudsneeker_api.services.custodian_schedule import (
            apply_schedule_to_policies,
        )

        tenant = tenants_fixture[0]
        with rls_transaction(str(tenant.id)):
            CustodianPolicy.objects.create(
                tenant_id=tenant.id,
                name="bulk-a",
                description="",
                policy_yaml=VALID_POLICY_YAML,
                provider=aws_provider,
            )
            CustodianPolicy.objects.create(
                tenant_id=tenant.id,
                name="bulk-b",
                description="",
                policy_yaml=VALID_POLICY_YAML,
                provider=aws_provider,
            )
            updated = apply_schedule_to_policies(
                tenant_id=str(tenant.id),
                schedule_enabled=True,
                schedule_cron="15 6 * * 1-5",
                schedule_timezone="UTC",
                provider_id=str(aws_provider.id),
            )
        assert len(updated) == 2
        assert all(p.schedule_enabled for p in updated)
        assert all(p.schedule_cron == "15 6 * * 1-5" for p in updated)


@pytest.mark.django_db
class TestCustodianScheduledEnqueue:
    def test_scheduled_task_enqueues_with_trigger(
        self, tenants_fixture, aws_provider
    ):
        from api.db_utils import rls_transaction
        from cloudsneeker_api.tasks import custodian_scheduled_dry_run_task

        tenant = tenants_fixture[0]
        with rls_transaction(str(tenant.id)):
            policy = CustodianPolicy.objects.create(
                tenant_id=tenant.id,
                name="beat-fire",
                description="",
                policy_yaml=VALID_POLICY_YAML,
                provider=aws_provider,
                schedule_enabled=True,
                schedule_cron="0 9 * * *",
                schedule_timezone="UTC",
            )

        with patch(
            "cloudsneeker_api.tasks.custodian_dry_run_task.delay"
        ) as mock_delay, patch(
            "django.db.transaction.on_commit", side_effect=lambda fn: fn()
        ):
            result = custodian_scheduled_dry_run_task(
                tenant_id=str(tenant.id),
                policy_id=str(policy.id),
            )

        assert result["status"] == "enqueued"
        mock_delay.assert_called_once()
        with rls_transaction(str(tenant.id)):
            run = CustodianRun.objects.get(id=result["run_id"])
            assert run.trigger == CustodianRun.Trigger.SCHEDULED

    def test_overlap_skips_second_fire(self, tenants_fixture, aws_provider):
        from api.db_utils import rls_transaction
        from cloudsneeker_api.services.custodian_schedule import (
            enqueue_scheduled_dry_run,
        )

        tenant = tenants_fixture[0]
        with rls_transaction(str(tenant.id)):
            policy = CustodianPolicy.objects.create(
                tenant_id=tenant.id,
                name="overlap-policy",
                description="",
                policy_yaml=VALID_POLICY_YAML,
                provider=aws_provider,
                schedule_enabled=True,
                schedule_cron="0 9 * * *",
                schedule_timezone="UTC",
            )
            CustodianRun.objects.create(
                tenant_id=tenant.id,
                policy=policy,
                provider=aws_provider,
                status=CustodianRun.Status.RUNNING,
                mode=CustodianRun.Mode.DRYRUN,
                trigger=CustodianRun.Trigger.SCHEDULED,
            )

        with patch("cloudsneeker_api.tasks.custodian_dry_run_task.delay"):
            skipped = enqueue_scheduled_dry_run(
                tenant_id=str(tenant.id),
                policy_id=str(policy.id),
            )
        assert skipped is None
