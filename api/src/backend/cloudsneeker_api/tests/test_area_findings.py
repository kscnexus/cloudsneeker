"""Area findings: per-area lists, governance findings and triage by area."""

from __future__ import annotations

import json
from datetime import timedelta
from unittest.mock import patch

import pytest
from api.models import Finding, Scan, StateChoices
from cloudsneeker_api.models import (
    JSON_API_TYPE_PREFIX,
    CustodianPolicy,
    CustodianRun,
    FindingTriage,
    TrivyRun,
    TrivyTarget,
)
from cloudsneeker_api.services.area_findings import (
    AreaFindingsError,
    app_security_location,
    parse_query,
)
from cloudsneeker_api.services.custodian_library import get_library_policy
from cloudsneeker_api.services.governance_findings import (
    findings_for_run,
    governance_uid,
    policy_rules,
    resource_id,
)
from django.urls import reverse
from django.utils import timezone

JSONAPI = "application/vnd.api+json"
AREA_TYPE = f"{JSON_API_TYPE_PREFIX}area-findings"

POLICY_YAML = """
policies:
  - name: unused-ebs
    resource: aws.ebs
    description: Unattached volumes
    metadata:
      severity: high
    filters:
      - Attachments: []
  - name: no-severity
    resource: aws.ec2
"""


def _scan(provider, *, source: str | None = None, at=None) -> Scan:
    at = at or timezone.now()
    return Scan.objects.create(
        tenant_id=provider.tenant_id,
        provider=provider,
        name="area scan",
        trigger=Scan.TriggerChoices.MANUAL,
        state=StateChoices.COMPLETED,
        started_at=at,
        completed_at=at,
        scanner_args={"source": source, "mode": "repo"} if source else {},
    )


def _finding(
    scan: Scan, uid: str, *, severity="high", raw=None, check_id="check"
) -> Finding:
    return Finding.objects.create(
        tenant_id=scan.tenant_id,
        uid=uid,
        scan=scan,
        status="FAIL",
        status_extended="detail",
        severity=severity,
        impact=severity,
        raw_result=raw or {},
        check_id=check_id,
        check_metadata={"CheckTitle": f"Title {check_id}", "Description": "desc"},
        first_seen_at=timezone.now(),
    )


def _app_security_scan(provider, name="web-repo") -> Scan:
    scan = _scan(provider, source="trivy_hub")
    target = TrivyTarget.objects.create(
        tenant_id=provider.tenant_id, name=name, mode="repo", provider=provider
    )
    TrivyRun.objects.create(
        tenant_id=provider.tenant_id,
        target=target,
        provider=provider,
        status=TrivyRun.Status.COMPLETED,
        finished_at=timezone.now(),
        scan_id=scan.id,
    )
    return scan


def _policy_run(provider, resources, *, yaml_text=POLICY_YAML, finished=None):
    policy = CustodianPolicy.objects.create(
        tenant_id=provider.tenant_id,
        name="gov-policy",
        policy_yaml=yaml_text,
        provider=provider,
    )
    run = CustodianRun.objects.create(
        tenant_id=provider.tenant_id,
        policy=policy,
        provider=provider,
        status=CustodianRun.Status.COMPLETED,
        mode=CustodianRun.Mode.DRYRUN,
        finished_at=finished or timezone.now(),
        output={"resources": resources},
    )
    return policy, run


def _list(client, area: str, **params):
    query = {"filter[area]": area, **params}
    return client.get(reverse("area-findings-list"), query)


def _uids(response) -> list[str]:
    assert response.status_code == 200, response.content
    return [item["attributes"]["uid"] for item in response.json()["data"]]


class TestParseQuery:
    def test_defaults_and_bounds(self):
        query = parse_query({"filter[area]": "governance", "page[size]": "1000"})
        assert query.area == "governance"
        assert query.sort == "severity"
        assert query.page_size == 100
        assert not query.include_muted

    @pytest.mark.parametrize(
        "params",
        [
            {},
            {"filter[area]": "nope"},
            {"filter[area]": "cloud", "filter[severity__in]": "urgent"},
            {"filter[area]": "cloud", "filter[triage_status__in]": "done"},
            {"filter[area]": "cloud", "sort": "uid"},
            {"filter[area]": "cloud", "filter[region__in]": "us-east-1"},
            {"filter[area]": "application_security", "filter[resource_type__in]": "x"},
        ],
    )
    def test_rejects_unknown_values(self, params):
        with pytest.raises(AreaFindingsError):
            parse_query(params)

    def test_location(self):
        assert app_security_location(
            {"PkgName": "lodash", "InstalledVersion": "4.0"}
        ) == ("lodash 4.0")
        assert (
            app_security_location({"path": "app.py", "start": {"line": 12}})
            == "app.py:12"
        )
        assert app_security_location({"CauseMetadata": {"StartLine": 3}}) == "line 3"
        assert (
            app_security_location({"CauseMetadata": {"StartLine": 3}}, "main.tf")
            == "main.tf:3"
        )
        assert app_security_location({"StartLine": 7}, ".env") == ".env:7"
        assert app_security_location({}, "main.tf") == "main.tf"
        assert app_security_location({}) == ""


class TestGovernanceFindings:
    def test_policy_rules_read_severity_with_default(self):
        rules = policy_rules(POLICY_YAML)
        assert rules["unused-ebs"].severity == "high"
        assert rules["unused-ebs"].resource_type == "aws.ebs"
        assert rules["no-severity"].severity == "medium"
        assert policy_rules("not: [valid") == {}

    def test_library_rules_without_metadata_use_the_library_severity(self):
        # Policies added from the library before the severity was written
        # into the YAML: the rule name is the library id.
        rules = policy_rules(
            """
policies:
  - name: aws-sg-ssh-open
    resource: aws.security-group
  - name: aws-ec2-no-owner-tag
    resource: aws.ec2
    metadata:
      severity: critical
  - name: my-own-rule
    resource: aws.ec2
"""
        )
        library = get_library_policy("aws-sg-ssh-open")
        assert rules["aws-sg-ssh-open"].severity == library["severity"]
        assert rules["aws-sg-ssh-open"].severity != "medium"
        assert rules["aws-ec2-no-owner-tag"].severity == "critical"
        assert rules["my-own-rule"].severity == "medium"

    def test_resource_id_covers_network_and_account_resources(self):
        # Security groups, VPCs, Elastic IPs and similar resources were
        # dropped because none of their id fields was known.
        group = {"GroupId": "sg-1", "GroupName": "web", "VpcId": "vpc-9"}
        assert resource_id(group) == "sg-1"
        assert resource_id({"VpcId": "vpc-9", "CidrBlock": "10.0.0.0/16"}) == "vpc-9"
        assert resource_id({"AllocationId": "eipalloc-1", "PublicIp": "1.2.3.4"}) == (
            "eipalloc-1"
        )
        assert resource_id({"SnapshotId": "snap-1", "VolumeId": "vol-1"}) == "vol-1"
        assert resource_id({"ImageId": "ami-1"}) == "ami-1"
        assert resource_id({"account_id": "123456789012"}) == "123456789012"
        # Keys already in use keep their priority, so existing ids are stable.
        assert resource_id({"InstanceId": "i-1", "VpcId": "vpc-9"}) == "i-1"
        assert resource_id({"Arn": "arn:x", "GroupId": "sg-1"}) == "arn:x"

    def test_resource_id_lookup_order(self):
        assert resource_id({"VolumeId": "vol-1", "Arn": "arn:x"}) == "vol-1"
        assert resource_id({"metadata": {"namespace": "ns", "name": "pod"}}) == "ns/pod"
        assert resource_id({}) == ""

    def test_findings_for_run_dedupes_and_maps_rules(self):
        policy = CustodianPolicy(
            id="00000000-0000-0000-0000-000000000001", name="p", policy_yaml=POLICY_YAML
        )
        run = CustodianRun(
            id="00000000-0000-0000-0000-000000000002",
            provider_id="00000000-0000-0000-0000-000000000003",
            output={
                "resources": [
                    {
                        "VolumeId": "vol-1",
                        "c7n:policy": "unused-ebs",
                        "c7n:region": "us-east-1",
                    },
                    {"VolumeId": "vol-1", "c7n:policy": "unused-ebs"},
                    {"InstanceId": "i-1", "c7n:policy": "no-severity"},
                    {"nothing": True},
                ]
            },
        )
        findings = findings_for_run(run, policy)
        assert [finding.resource_id for finding in findings] == ["vol-1", "i-1"]
        assert findings[0].severity == "high"
        assert findings[0].region == "us-east-1"
        assert findings[0].uid == governance_uid(str(policy.id), "vol-1")
        assert findings[1].severity == "medium"
        assert findings[1].resource_type == "aws.ec2"


@pytest.mark.django_db
class TestAreaFindingsApi:
    def test_areas_stay_separate(self, authenticated_client, aws_provider):
        cloud = _scan(aws_provider)
        _finding(cloud, "cloud-1")
        app_scan = _app_security_scan(aws_provider)
        _finding(
            app_scan,
            "trivy-repo-CVE-1",
            raw={"PkgName": "lodash", "InstalledVersion": "1"},
        )
        _policy_run(aws_provider, [{"VolumeId": "vol-1", "c7n:policy": "unused-ebs"}])

        assert _uids(_list(authenticated_client, "cloud")) == ["cloud-1"]

        app = _list(authenticated_client, "application_security")
        assert _uids(app) == ["trivy-repo-CVE-1"]
        attributes = app.json()["data"][0]["attributes"]
        assert app.json()["data"][0]["type"] == AREA_TYPE
        assert attributes["location"] == "lodash 1"
        assert attributes["source_kind"] == "target"
        assert attributes["source_name"] == "web-repo"
        assert attributes["triage_status"] == "open"

        gov = _list(authenticated_client, "governance")
        assert len(_uids(gov)) == 1
        attributes = gov.json()["data"][0]["attributes"]
        assert attributes["severity"] == "high"
        assert attributes["source_kind"] == "policy"
        assert gov.json()["meta"]["sources"][0]["name"] == "gov-policy"

    def test_only_latest_scan_per_source(self, authenticated_client, aws_provider):
        old = _scan(aws_provider, at=timezone.now() - timedelta(days=2))
        _finding(old, "old-uid")
        _finding(_scan(aws_provider), "new-uid")
        assert _uids(_list(authenticated_client, "cloud")) == ["new-uid"]

    def test_filters_sort_and_pagination(self, authenticated_client, aws_provider):
        scan = _scan(aws_provider)
        _finding(scan, "low-1", severity="low", check_id="a_check")
        _finding(scan, "crit-1", severity="critical", check_id="b_check")
        _finding(scan, "med-1", severity="medium", check_id="c_check")

        assert _uids(_list(authenticated_client, "cloud")) == [
            "crit-1",
            "med-1",
            "low-1",
        ]
        assert (
            _uids(_list(authenticated_client, "cloud", sort="-severity"))[0] == "low-1"
        )
        assert _uids(
            _list(
                authenticated_client, "cloud", **{"filter[severity__in]": "low,medium"}
            )
        ) == ["med-1", "low-1"]
        assert _uids(
            _list(authenticated_client, "cloud", **{"filter[search]": "b_ch"})
        ) == ["crit-1"]
        page = _list(
            authenticated_client, "cloud", **{"page[size]": "2", "page[number]": "2"}
        )
        assert _uids(page) == ["low-1"]
        assert page.json()["meta"]["pagination"] == {"page": 2, "pages": 2, "count": 3}

    def test_triage_filter_counts_untriaged_as_open(
        self, authenticated_client, tenants_fixture, aws_provider
    ):
        scan = _scan(aws_provider)
        for uid in ("t-open", "t-review", "t-none"):
            _finding(scan, uid)
        for uid, status in (("t-open", "open"), ("t-review", "under_review")):
            FindingTriage.objects.create(
                tenant_id=tenants_fixture[0].id,
                finding_uid=uid,
                status=status,
                provider=aws_provider,
            )

        open_uids = _uids(
            _list(
                authenticated_client, "cloud", **{"filter[triage_status__in]": "open"}
            )
        )
        assert sorted(open_uids) == ["t-none", "t-open"]
        review = _list(
            authenticated_client,
            "cloud",
            **{"filter[triage_status__in]": "under_review"},
        )
        assert _uids(review) == ["t-review"]
        assert review.json()["data"][0]["attributes"]["triage_status"] == "under_review"

    def test_governance_triage_round_trip(self, authenticated_client, aws_provider):
        policy, _ = _policy_run(
            aws_provider, [{"VolumeId": "vol-9", "c7n:policy": "unused-ebs"}]
        )
        uid = governance_uid(str(policy.id), "vol-9")

        patched = authenticated_client.patch(
            reverse("finding-uid-triage", kwargs={"finding_uid": uid}),
            data=json.dumps(
                {
                    "data": {
                        "type": "finding-triages",
                        "attributes": {"status": "risk_accepted"},
                    }
                }
            ),
            content_type=JSONAPI,
        )
        assert patched.status_code == 201, patched.content
        assert patched.json()["data"]["attributes"]["area"] == "governance"
        assert FindingTriage.objects.get(finding_uid=uid).provider_id == aws_provider.id

        listed = _list(
            authenticated_client,
            "governance",
            **{"filter[triage_status__in]": "risk_accepted"},
        )
        assert _uids(listed) == [uid]
        by_area = authenticated_client.get(
            reverse("finding-triages-list"), {"filter[area]": "governance"}
        )
        assert [
            item["attributes"]["finding_uid"] for item in by_area.json()["data"]
        ] == [uid]
        cloud = authenticated_client.get(
            reverse("finding-triages-list"), {"filter[area]": "cloud"}
        )
        assert cloud.json()["data"] == []

    def test_governance_uid_lookup_returns_one_finding_with_resource(
        self, authenticated_client, aws_provider
    ):
        from api.models import MuteRule

        policy, _ = _policy_run(
            aws_provider,
            [
                {"VolumeId": "vol-1", "Size": 8, "c7n:policy": "unused-ebs"},
                {"VolumeId": "vol-2", "c7n:policy": "unused-ebs"},
            ],
        )
        uid = governance_uid(str(policy.id), "vol-1")
        MuteRule.objects.create(
            tenant_id=aws_provider.tenant_id,
            name="muted volume",
            reason="scratch disk",
            finding_uids=[uid],
        )

        listed = _list(authenticated_client, "governance")
        assert uid not in _uids(listed)
        assert all(
            "resource_details" not in item["attributes"]
            for item in listed.json()["data"]
        )

        one = _list(authenticated_client, "governance", **{"filter[uid]": uid})
        assert _uids(one) == [uid]
        attributes = one.json()["data"][0]["attributes"]
        assert attributes["muted"] is True
        assert attributes["muted_reason"] == "scratch disk"
        assert attributes["resource_details"]["VolumeId"] == "vol-1"
        assert attributes["resource_details"]["Size"] == 8

    def test_governance_uid_lookup_follows_visibility(
        self, authenticated_client_no_permissions_rbac, aws_provider
    ):
        policy, _ = _policy_run(
            aws_provider, [{"VolumeId": "vol-1", "c7n:policy": "unused-ebs"}]
        )
        uid = governance_uid(str(policy.id), "vol-1")
        response = _list(
            authenticated_client_no_permissions_rbac,
            "governance",
            **{"filter[uid]": uid},
        )
        assert _uids(response) == []

    def test_governance_filters_by_account_region_and_type_with_facets(
        self, authenticated_client, aws_provider
    ):
        _policy_run(
            aws_provider,
            [
                {"VolumeId": "vol-1", "c7n:policy": "unused-ebs", "c7n:region": "us-east-1"},
                {"VolumeId": "vol-2", "c7n:policy": "unused-ebs", "c7n:region": "eu-west-1"},
            ],
        )

        everything = _list(authenticated_client, "governance")
        facets = everything.json()["meta"]["facets"]
        assert facets["regions"] == ["eu-west-1", "us-east-1"]
        assert facets["resource_types"] == ["aws.ebs"]
        assert [item["id"] for item in facets["accounts"]] == [str(aws_provider.id)]

        by_region = _list(
            authenticated_client, "governance", **{"filter[region__in]": "eu-west-1"}
        )
        assert [row["attributes"]["resource_id"] for row in by_region.json()["data"]] == [
            "vol-2"
        ]
        by_type = _list(
            authenticated_client,
            "governance",
            **{"filter[resource_type__in]": "aws.ec2"},
        )
        assert by_type.json()["data"] == []
        by_account = _list(
            authenticated_client,
            "governance",
            **{"filter[provider__in]": str(aws_provider.id)},
        )
        assert len(by_account.json()["data"]) == 2
        other = _list(
            authenticated_client,
            "governance",
            **{"filter[provider__in]": "00000000-0000-0000-0000-000000000000"},
        )
        assert other.json()["data"] == []

    def test_app_security_triage_records_area(self, authenticated_client, aws_provider):
        _finding(_app_security_scan(aws_provider), "trivy-repo-CVE-2")
        response = authenticated_client.patch(
            reverse("finding-uid-triage", kwargs={"finding_uid": "trivy-repo-CVE-2"}),
            data=json.dumps(
                {
                    "data": {
                        "type": "finding-triages",
                        "attributes": {"status": "remediating"},
                    }
                }
            ),
            content_type=JSONAPI,
        )
        assert response.status_code == 201, response.content
        assert response.json()["data"]["attributes"]["area"] == "application_security"

    def test_unknown_governance_uid_is_404(self, authenticated_client):
        response = authenticated_client.get(
            reverse(
                "finding-uid-triage", kwargs={"finding_uid": "custodian-missing-vol"}
            )
        )
        assert response.status_code == 404

    def test_limited_role_sees_nothing_without_providers(
        self, authenticated_client_no_permissions_rbac, aws_provider
    ):
        _finding(_scan(aws_provider), "hidden")
        _policy_run(aws_provider, [{"VolumeId": "vol-1"}])
        limited = authenticated_client_no_permissions_rbac
        assert _uids(_list(limited, "cloud")) == []
        assert _uids(_list(limited, "governance")) == []

    def test_area_needs_plan_feature(self, authenticated_client):
        entitlements = type("E", (), {"has_feature": lambda self, feature: False})()
        with patch(
            "cloudsneeker_api.views_area_findings.entitlements.for_tenant",
            return_value=entitlements,
        ):
            assert _list(authenticated_client, "governance").status_code == 403

    def test_bad_area_is_400(self, authenticated_client):
        assert _list(authenticated_client, "elsewhere").status_code == 400

    def test_requires_authentication(self, client):
        assert _list(client, "cloud").status_code == 401
