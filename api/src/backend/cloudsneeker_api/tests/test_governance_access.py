"""Governance policies and runs follow provider visibility; writes need manage_scans."""

from __future__ import annotations

import pytest
from cloudsneeker_api.models import CustodianPolicy, CustodianRun
from django.urls import reverse
from django.utils import timezone

POLICY_YAML = "policies:\n  - name: unused-ebs\n    resource: aws.ebs\n"


def _policy(provider, name="gov-policy"):
    policy = CustodianPolicy.objects.create(
        tenant_id=provider.tenant_id,
        name=name,
        policy_yaml=POLICY_YAML,
        provider=provider,
    )
    CustodianRun.objects.create(
        tenant_id=provider.tenant_id,
        policy=policy,
        provider=provider,
        status=CustodianRun.Status.COMPLETED,
        mode=CustodianRun.Mode.DRYRUN,
        finished_at=timezone.now(),
        output={"resources": []},
    )
    return policy


@pytest.mark.django_db
class TestGovernanceAccess:
    def test_admin_lists_and_filters(self, authenticated_client, aws_provider):
        _policy(aws_provider, "alpha-policy")
        _policy(aws_provider, "beta-policy")
        response = authenticated_client.get(
            reverse("custodian-policies-list"), {"filter[search]": "beta"}
        )
        assert response.status_code == 200
        names = [row["attributes"]["name"] for row in response.json()["data"]]
        assert names == ["beta-policy"]

        runs = authenticated_client.get(
            reverse("custodian-runs-list"), {"filter[status__in]": "completed"}
        )
        assert runs.status_code == 200
        assert len(runs.json()["data"]) == 2

    def test_limited_role_reads_only_visible_providers(
        self, authenticated_client_no_permissions_rbac, aws_provider
    ):
        _policy(aws_provider)
        limited = authenticated_client_no_permissions_rbac
        policies = limited.get(reverse("custodian-policies-list"))
        runs = limited.get(reverse("custodian-runs-list"))
        assert policies.status_code == 200
        assert policies.json()["data"] == []
        assert runs.status_code == 200
        assert runs.json()["data"] == []

    def test_limited_role_cannot_write(
        self, authenticated_client_no_permissions_rbac, aws_provider
    ):
        response = authenticated_client_no_permissions_rbac.post(
            reverse("custodian-policies-list"),
            data={
                "data": {
                    "type": "custodian-policies",
                    "attributes": {"name": "x-policy", "policy_yaml": POLICY_YAML},
                }
            },
            content_type="application/vnd.api+json",
        )
        assert response.status_code == 403
