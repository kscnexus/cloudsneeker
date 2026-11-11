"""Global search: groups per product area, visibility and query rules."""

from __future__ import annotations

import pytest
from api.models import Finding, Scan, StateChoices
from cloudsneeker_api.models import AlertRule, CustodianPolicy, CustodianRun
from cloudsneeker_api.services.global_search import (
    GlobalSearchError,
    clean_query,
)
from django.urls import reverse
from django.utils import timezone

POLICY_YAML = """
policies:
  - name: public-bucket
    resource: aws.s3
    metadata:
      severity: high
"""


class TestCleanQuery:
    def test_collapses_whitespace_and_bounds_length(self):
        assert clean_query("  prod   bucket ") == "prod bucket"
        assert len(clean_query("x" * 500)) == 200

    @pytest.mark.parametrize("raw", [None, "", " ", "a"])
    def test_rejects_short_queries(self, raw):
        with pytest.raises(GlobalSearchError):
            clean_query(raw)


def _cloud_finding(provider, uid, check_id):
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
    return Finding.objects.create(
        tenant_id=provider.tenant_id,
        uid=uid,
        scan=scan,
        delta=None,
        status="FAIL",
        status_extended="detail",
        severity="high",
        impact="high",
        raw_result={},
        check_id=check_id,
        check_metadata={"CheckTitle": "Bucket is public"},
        muted=False,
        first_seen_at=now,
    )


def _policy(provider, name):
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
        output={
            "resources": [{"Name": "payroll-bucket", "c7n:policy": "public-bucket"}]
        },
    )
    return policy


def _groups(response) -> dict[str, dict]:
    assert response.status_code == 200, response.content
    return {item["id"]: item["attributes"] for item in response.json()["data"]}


@pytest.mark.django_db
class TestGlobalSearchApi:
    def test_groups_across_areas(self, authenticated_client, aws_provider):
        _cloud_finding(aws_provider, "cloud-1", "s3_bucket_public_access")
        _policy(aws_provider, "Public payroll bucket")
        AlertRule.objects.create(
            tenant_id=aws_provider.tenant_id,
            name="Public bucket alert",
            condition={"op": "any", "filter": {"severity": ["high"]}},
        )

        groups = _groups(
            authenticated_client.get(
                reverse("global-search-list"), {"filter[search]": "bucket"}
            )
        )

        assert groups["cloud_findings"]["count"] == 1
        hit = groups["cloud_findings"]["hits"][0]
        assert hit["id"] == "cloud-1"
        assert hit["area"] == "cloud"
        assert hit["check_id"] == "s3_bucket_public_access"
        assert groups["governance_findings"]["hits"][0]["subtitle"].startswith(
            "payroll-bucket"
        )
        assert groups["governance_findings"]["count"] == 1
        assert groups["governance_policies"]["hits"][0]["title"] == (
            "Public payroll bucket"
        )
        assert groups["alert_rules"]["hits"][0]["subtitle"] == "Enabled"
        assert "application_security_findings" in groups

    def test_accounts_match_alias_or_uid(self, authenticated_client, aws_provider):
        aws_provider.alias = "Production"
        aws_provider.save()
        groups = _groups(
            authenticated_client.get(
                reverse("global-search-list"), {"filter[search]": "producti"}
            )
        )
        assert [hit["id"] for hit in groups["cloud_accounts"]["hits"]] == [
            str(aws_provider.id)
        ]

    def test_limited_role_sees_no_hidden_provider_data(
        self, authenticated_client_no_permissions_rbac, aws_provider
    ):
        _cloud_finding(aws_provider, "cloud-1", "s3_bucket_public_access")
        _policy(aws_provider, "Public payroll bucket")
        groups = _groups(
            authenticated_client_no_permissions_rbac.get(
                reverse("global-search-list"), {"filter[search]": "bucket"}
            )
        )
        for kind in (
            "cloud_findings",
            "governance_findings",
            "cloud_accounts",
            "governance_policies",
        ):
            assert groups[kind]["count"] == 0, kind
            assert groups[kind]["hits"] == [], kind

    def test_other_tenant_rows_are_hidden(self, authenticated_client, tenants_fixture):
        AlertRule.objects.create(
            tenant_id=tenants_fixture[1].id,
            name="Other tenant bucket",
            condition={},
        )
        groups = _groups(
            authenticated_client.get(
                reverse("global-search-list"), {"filter[search]": "bucket"}
            )
        )
        assert groups["alert_rules"]["count"] == 0

    def test_short_query_is_400(self, authenticated_client):
        response = authenticated_client.get(
            reverse("global-search-list"), {"filter[search]": "a"}
        )
        assert response.status_code == 400

    def test_requires_authentication(self, client):
        response = client.get(reverse("global-search-list"), {"filter[search]": "ab"})
        assert response.status_code == 401
