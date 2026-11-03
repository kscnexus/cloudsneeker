"""Governance policy library and Seeker AI policy drafting."""

from __future__ import annotations

import json
from collections import Counter
from unittest.mock import patch

import pytest
import yaml
from api.db_utils import rls_transaction
from api.models import (
    LighthouseProviderConfiguration,
    LighthouseProviderModels,
    LighthouseTenantConfiguration,
    Provider,
)
from cloudsneeker_api.models import CustodianPolicy
from cloudsneeker_api.services.custodian import assert_policy_matches_provider
from cloudsneeker_api.services.custodian_ai import (
    LLMSettings,
    PolicyGenerationError,
    build_messages,
    extract_policy_yaml,
    generate_policy_draft,
    is_valid_resource_type,
    normalize_policy_yaml,
    resolve_llm_settings,
)
from cloudsneeker_api.services.custodian_library import (
    LIBRARY_CATEGORIES,
    LIBRARY_PROVIDERS,
    get_library_policy,
    library_coverage,
    library_policy_ids_in_yaml,
    list_library_policies,
)
from cloudsneeker_api.services.custodian_validate import (
    validate_custodian_policy_schema,
)
from django.urls import reverse

JSONAPI = "application/vnd.api+json"

VALID_DRAFT = """Here you go:
```yaml
policies:
  - name: Unencrypted Volumes!
    resource: aws.ebs
    description: Volumes that are not encrypted.
    filters:
      - Encrypted: false
    actions:
      - delete
```
"""


@pytest.fixture(autouse=True)
def _skip_engine_validate(monkeypatch):
    monkeypatch.setenv("C7N_SKIP_VALIDATE", "1")


def _body(attributes: dict) -> str:
    return json.dumps(
        {"data": {"type": "cloudsneeker-custodian-library-policies", "attributes": attributes}}
    )


class TestLibraryCatalogue:
    @pytest.mark.parametrize("provider_type", LIBRARY_PROVIDERS)
    def test_each_cloud_has_50_to_100_policies(self, provider_type):
        count = len(list_library_policies(provider_type=provider_type))
        assert 50 <= count <= 100

    @pytest.mark.parametrize("provider_type", LIBRARY_PROVIDERS)
    def test_each_cloud_covers_every_category(self, provider_type):
        categories = {
            item["category"] for item in list_library_policies(provider_type=provider_type)
        }
        assert categories == set(LIBRARY_CATEGORIES)

    @pytest.mark.parametrize("provider_type", LIBRARY_PROVIDERS)
    def test_each_cloud_has_a_starter_pack(self, provider_type):
        starters = list_library_policies(provider_type=provider_type, starter_only=True)
        assert 10 <= len(starters) <= 30
        assert all(item["starter"] for item in starters)

    def test_ids_are_unique_and_prefixed_by_cloud(self):
        entries = list_library_policies()
        counts = Counter(item["id"] for item in entries)
        assert [key for key, value in counts.items() if value > 1] == []
        for item in entries:
            assert item["id"].startswith(f"{item['provider_type']}-")

    def test_every_policy_is_a_valid_dry_run_document(self):
        for item in list_library_policies():
            parsed = assert_policy_matches_provider(
                item["policy_yaml"], item["provider_type"]
            )
            validate_custodian_policy_schema(item["policy_yaml"])
            policy = parsed["policies"][0]
            assert len(parsed["policies"]) == 1
            assert policy["name"] == item["id"]
            assert policy["resource"] == item["resource"]
            assert "actions" not in policy
            assert item["severity"] in ("critical", "high", "medium", "low")
            assert item["category_name"] == LIBRARY_CATEGORIES[item["category"]]["name"]

    def test_filters_by_category_and_search(self):
        network = list_library_policies(provider_type="aws", category="network")
        assert network
        assert {item["category"] for item in network} == {"network"}

        ssh = list_library_policies(search="ssh open")
        assert {item["provider_type"] for item in ssh} == {"aws", "azure", "gcp"}

        tagged = list_library_policies(provider_type="gcp", search="finops")
        assert tagged
        assert all("FinOps" in item["frameworks"] for item in tagged)

    def test_get_library_policy_returns_copy(self):
        item = get_library_policy("aws-s3-public")
        assert item is not None
        item["frameworks"].append("changed")
        assert "changed" not in get_library_policy("aws-s3-public")["frameworks"]
        assert get_library_policy("does-not-exist") is None


class TestCoverage:
    def test_ids_found_in_workspace_yaml(self):
        entry = get_library_policy("aws-ebs-unencrypted")
        assert library_policy_ids_in_yaml(entry["policy_yaml"]) == {"aws-ebs-unencrypted"}
        assert library_policy_ids_in_yaml("policies: [") == set()
        assert library_policy_ids_in_yaml("just text") == set()

    def test_counts_active_policies_per_category(self):
        entry = get_library_policy("aws-ebs-unencrypted")
        coverage = library_coverage([("aws", entry["policy_yaml"])], provider_type="aws")

        assert coverage["installed_ids"] == ["aws-ebs-unencrypted"]
        rows = {row["category"]: row for row in coverage["categories"]}
        assert rows["encryption"]["active"] == 1
        assert rows["encryption"]["total"] == len(
            list_library_policies(provider_type="aws", category="encryption")
        )
        assert rows["network"]["active"] == 0
        assert {row["provider_type"] for row in coverage["categories"]} == {"aws"}

    def test_empty_workspace_has_no_active_categories(self):
        coverage = library_coverage([])
        assert coverage["installed_ids"] == []
        assert all(row["active"] == 0 for row in coverage["categories"])
        assert {row["provider_type"] for row in coverage["categories"]} == set(
            LIBRARY_PROVIDERS
        )


class TestDraftParsing:
    def test_extracts_fenced_yaml(self):
        assert extract_policy_yaml(VALID_DRAFT).startswith("policies:")
        assert extract_policy_yaml("policies: []") == "policies: []\n"

    def test_normalize_strips_actions_and_slugs_name(self):
        policy_yaml, policy = normalize_policy_yaml(extract_policy_yaml(VALID_DRAFT))
        assert "actions" not in policy
        assert policy["name"] == "unencrypted-volumes"
        assert yaml.safe_load(policy_yaml)["policies"][0]["resource"] == "aws.ebs"

    def test_normalize_keeps_only_first_policy(self):
        text = "policies:\n  - name: one\n    resource: aws.ebs\n  - name: two\n    resource: aws.ec2\n"
        policy_yaml, _ = normalize_policy_yaml(text)
        assert len(yaml.safe_load(policy_yaml)["policies"]) == 1

    @pytest.mark.parametrize("text", ["- just a list", "policies: []", "policies: ["])
    def test_normalize_rejects_non_policies(self, text):
        from cloudsneeker_api.services.custodian import CustodianDryRunError

        with pytest.raises(CustodianDryRunError):
            normalize_policy_yaml(text)

    def test_messages_ask_for_provider_and_include_examples(self):
        messages = build_messages(
            provider_type="azure", prompt="storage that allows http", resource_type="azure.storage"
        )
        assert messages[0]["role"] == "system"
        assert "azure." in messages[0]["content"]
        assert "resource: azure.storage" in messages[0]["content"]
        assert "azure.storage" in messages[1]["content"]
        assert "actions" in messages[0]["content"]

    def test_resource_type_must_match_cloud(self):
        assert is_valid_resource_type("", "aws")
        assert is_valid_resource_type("aws.s3", "aws")
        assert not is_valid_resource_type("azure.vm", "aws")
        assert not is_valid_resource_type("aws.s3; rm", "aws")


class TestGeneratePolicyDraft:
    def _settings(self):
        return LLMSettings(provider_type="openai", model_id="test-model", config=None)

    def test_valid_draft_on_first_attempt(self):
        with patch(
            "cloudsneeker_api.services.custodian_ai.resolve_llm_settings",
            return_value=self._settings(),
        ), patch(
            "cloudsneeker_api.services.custodian_ai.complete_chat",
            return_value=VALID_DRAFT,
        ) as chat:
            draft = generate_policy_draft(
                tenant_id="t", provider_type="aws", prompt="unencrypted ebs volumes"
            )
        assert draft["valid"] is True
        assert draft["validation_error"] == ""
        assert draft["attempts"] == 1
        assert draft["resource"] == "aws.ebs"
        assert "actions" not in draft["policy_yaml"]
        chat.assert_called_once()

    def test_repairs_invalid_draft_once(self):
        wrong_cloud = "```yaml\npolicies:\n  - name: vm\n    resource: azure.vm\n```"
        with patch(
            "cloudsneeker_api.services.custodian_ai.resolve_llm_settings",
            return_value=self._settings(),
        ), patch(
            "cloudsneeker_api.services.custodian_ai.complete_chat",
            side_effect=[wrong_cloud, VALID_DRAFT],
        ) as chat:
            draft = generate_policy_draft(
                tenant_id="t", provider_type="aws", prompt="unencrypted ebs volumes"
            )
        assert draft["valid"] is True
        assert draft["attempts"] == 2
        repair_messages = chat.call_args_list[1].args[1]
        assert "failed validation" in repair_messages[-1]["content"]

    def test_returns_invalid_draft_after_retries(self):
        with patch(
            "cloudsneeker_api.services.custodian_ai.resolve_llm_settings",
            return_value=self._settings(),
        ), patch(
            "cloudsneeker_api.services.custodian_ai.complete_chat",
            return_value="not yaml: [",
        ):
            draft = generate_policy_draft(
                tenant_id="t", provider_type="aws", prompt="unencrypted ebs volumes"
            )
        assert draft["valid"] is False
        assert draft["validation_error"]
        assert draft["attempts"] == 2


@pytest.mark.django_db
class TestResolveLLMSettings:
    def test_requires_a_configured_provider(self, tenants_fixture):
        with pytest.raises(PolicyGenerationError) as exc:
            resolve_llm_settings(str(tenants_fixture[0].id))
        assert exc.value.code == "llm_not_configured"

    def test_uses_tenant_default_model(self, tenants_fixture):
        tenant = tenants_fixture[0]
        with rls_transaction(str(tenant.id)):
            config = LighthouseProviderConfiguration(
                tenant_id=tenant.id,
                provider_type="openai",
                is_active=True,
            )
            config.credentials_decoded = {"api_key": "sk-test"}
            config.save()
            LighthouseProviderModels.objects.create(
                tenant_id=tenant.id,
                provider_configuration=config,
                model_id="alpha-model",
                model_name="Alpha",
            )
            LighthouseTenantConfiguration.objects.create(
                tenant_id=tenant.id,
                default_provider="openai",
                default_models={"openai": "chosen-model"},
            )
        settings = resolve_llm_settings(str(tenant.id))
        assert settings.provider_type == "openai"
        assert settings.model_id == "chosen-model"

    def test_falls_back_to_first_model(self, tenants_fixture):
        tenant = tenants_fixture[0]
        with rls_transaction(str(tenant.id)):
            config = LighthouseProviderConfiguration(
                tenant_id=tenant.id, provider_type="openai", is_active=True
            )
            config.credentials_decoded = {"api_key": "sk-test"}
            config.save()
            LighthouseProviderModels.objects.create(
                tenant_id=tenant.id,
                provider_configuration=config,
                model_id="alpha-model",
                model_name="Alpha",
            )
        assert resolve_llm_settings(str(tenant.id)).model_id == "alpha-model"


@pytest.mark.django_db
class TestLibraryAPI:
    def test_lists_library_with_coverage(self, authenticated_client, aws_provider):
        entry = get_library_policy("aws-ebs-unencrypted")
        with rls_transaction(str(aws_provider.tenant_id)):
            CustodianPolicy.objects.create(
                tenant_id=aws_provider.tenant_id,
                name="Mine",
                policy_yaml=entry["policy_yaml"],
                provider=aws_provider,
            )

        response = authenticated_client.get(
            reverse("custodian-library-list"),
            {"provider_type": "aws", "category": "encryption"},
        )

        assert response.status_code == 200
        body = response.json()
        assert body["meta"]["count"] == len(body["data"])
        assert {item["attributes"]["category"] for item in body["data"]} == {"encryption"}
        installed = {
            item["id"] for item in body["data"] if item["attributes"]["installed"]
        }
        assert installed == {"aws-ebs-unencrypted"}
        assert len(body["meta"]["categories"]) == len(LIBRARY_CATEGORIES)
        encryption = next(
            row for row in body["meta"]["coverage"] if row["category"] == "encryption"
        )
        assert encryption["active"] == 1

    def test_install_creates_policies_and_skips_existing(
        self, authenticated_client, aws_provider
    ):
        url = reverse("custodian-library-install")
        payload = _body(
            {
                "provider_id": str(aws_provider.id),
                "policy_ids": ["aws-s3-public", "aws-ebs-unattached"],
            }
        )
        first = authenticated_client.post(url, data=payload, content_type=JSONAPI)
        assert first.status_code == 201
        assert first.json()["meta"] == {"created": 2, "skipped": []}

        second = authenticated_client.post(url, data=payload, content_type=JSONAPI)
        assert second.status_code == 201
        assert second.json()["meta"]["created"] == 0
        assert set(second.json()["meta"]["skipped"]) == {
            "aws-s3-public",
            "aws-ebs-unattached",
        }
        with rls_transaction(str(aws_provider.tenant_id)):
            assert (
                CustodianPolicy.objects.filter(
                    tenant_id=aws_provider.tenant_id, provider=aws_provider
                ).count()
                == 2
            )

    def test_install_suffixes_name_for_second_provider(
        self, authenticated_client, provider_factory
    ):
        first = provider_factory(Provider.ProviderChoices.AWS.value)
        second = provider_factory(Provider.ProviderChoices.AWS.value)
        url = reverse("custodian-library-install")
        for provider in (first, second):
            response = authenticated_client.post(
                url,
                data=_body({"provider_id": str(provider.id), "policy_ids": ["aws-s3-public"]}),
                content_type=JSONAPI,
            )
            assert response.json()["meta"]["created"] == 1
        with rls_transaction(str(first.tenant_id)):
            names = set(
                CustodianPolicy.objects.filter(tenant_id=first.tenant_id).values_list(
                    "name", flat=True
                )
            )
        assert names == {"Public S3 buckets", f"Public S3 buckets ({second.alias})"}

    def test_install_rejects_other_cloud(self, authenticated_client, aws_provider):
        response = authenticated_client.post(
            reverse("custodian-library-install"),
            data=_body(
                {"provider_id": str(aws_provider.id), "policy_ids": ["azure-nsg-ssh-open"]}
            ),
            content_type=JSONAPI,
        )
        assert response.status_code == 400

    def test_install_rejects_unknown_id(self, authenticated_client, aws_provider):
        response = authenticated_client.post(
            reverse("custodian-library-install"),
            data=_body({"provider_id": str(aws_provider.id), "policy_ids": ["nope"]}),
            content_type=JSONAPI,
        )
        assert response.status_code == 400

    def test_generate_without_seeker_ai_is_a_clear_error(self, authenticated_client):
        response = authenticated_client.post(
            reverse("custodian-library-generate"),
            data=_body({"provider_type": "aws", "prompt": "public buckets please"}),
            content_type=JSONAPI,
        )
        assert response.status_code == 400
        assert response.json()["errors"][0]["code"] == "llm_not_configured"

    def test_generate_returns_validated_draft(self, authenticated_client):
        draft = {
            "policy_yaml": "policies: []\n",
            "name": "x",
            "description": "",
            "resource": "aws.ebs",
            "provider_type": "aws",
            "valid": True,
            "validation_error": "",
            "attempts": 1,
        }
        with patch(
            "cloudsneeker_api.views_custodian_library.generate_policy_draft",
            return_value=draft,
        ) as generate:
            response = authenticated_client.post(
                reverse("custodian-library-generate"),
                data=_body(
                    {
                        "provider_type": "aws",
                        "prompt": "volumes that are not encrypted",
                        "resource_type": "AWS.EBS",
                    }
                ),
                content_type=JSONAPI,
            )
        assert response.status_code == 200
        assert response.json()["data"]["attributes"]["valid"] is True
        assert generate.call_args.kwargs["resource_type"] == "aws.ebs"

    def test_generate_validates_input(self, authenticated_client):
        response = authenticated_client.post(
            reverse("custodian-library-generate"),
            data=_body({"provider_type": "kubernetes", "prompt": "short"}),
            content_type=JSONAPI,
        )
        assert response.status_code == 400

    def test_generate_maps_llm_failure_to_failed_dependency(self, authenticated_client):
        with patch(
            "cloudsneeker_api.views_custodian_library.generate_policy_draft",
            side_effect=PolicyGenerationError("quota exceeded", code="llm_error"),
        ):
            response = authenticated_client.post(
                reverse("custodian-library-generate"),
                data=_body({"provider_type": "gcp", "prompt": "public buckets please"}),
                content_type=JSONAPI,
            )
        assert response.status_code == 424
        assert response.json()["errors"][0]["code"] == "llm_error"

    def test_validate_reports_errors(self, authenticated_client):
        url = reverse("custodian-library-validate")
        good = authenticated_client.post(
            url,
            data=_body(
                {
                    "provider_type": "aws",
                    "policy_yaml": get_library_policy("aws-ebs-unattached")["policy_yaml"],
                }
            ),
            content_type=JSONAPI,
        )
        assert good.json()["data"]["attributes"] == {"valid": True, "error": ""}

        bad = authenticated_client.post(
            url,
            data=_body(
                {
                    "provider_type": "aws",
                    "policy_yaml": "policies:\n  - name: x\n    resource: gcp.instance\n",
                }
            ),
            content_type=JSONAPI,
        )
        attributes = bad.json()["data"]["attributes"]
        assert attributes["valid"] is False
        assert "does not match" in attributes["error"]

    def test_requires_authentication(self, client):
        response = client.get(reverse("custodian-library-list"))
        assert response.status_code == 401
