"""Operator console API (``/api/v1/operator/*``): access, subscriptions, plans."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest
from api.db_utils import rls_transaction
from cloudsneeker_api.models import (
    JSON_API_TYPE_PREFIX,
    AuditEvent,
    OperatorAuditEvent,
    Plan,
    PlatformOperator,
    Subscription,
    SubscriptionEvent,
    UsageSnapshot,
)
from cloudsneeker_api.services import entitlements as service
from cloudsneeker_api.services import plan_catalog as catalog
from cloudsneeker_api.views_operator import OPERATOR_ENABLED_ENV
from django.core.cache import cache
from django.urls import reverse
from django.utils import timezone

JSONAPI = "application/vnd.api+json"
SUBSCRIPTION_TYPE = f"{JSON_API_TYPE_PREFIX}subscriptions"
PLAN_TYPE = f"{JSON_API_TYPE_PREFIX}plans"
ROLES = ("owner", "billing", "support", "read_only")


@pytest.fixture(autouse=True)
def _clear_entitlement_cache():
    cache.clear()
    yield
    cache.clear()


@pytest.fixture(autouse=True)
def _plans(request):
    """The default catalogue (a transactional test elsewhere may flush it)."""
    if request.node.get_closest_marker("django_db"):
        request.getfixturevalue("db")
        catalog.seed_plans(Plan, using="default")


@pytest.fixture
def make_operator(create_test_user):
    def _make(role: str = "owner", active: bool = True):
        operator, _ = PlatformOperator.objects.update_or_create(
            user=create_test_user, defaults={"role": role, "active": active}
        )
        return operator

    return _make


def _body(resource_type: str, attributes: dict) -> str:
    return json.dumps({"data": {"type": resource_type, "attributes": attributes}})


def _patch_subscription(client, tenant, attributes: dict):
    return client.patch(
        reverse("operator-subscription-detail", kwargs={"tenant_id": tenant.id}),
        data=_body(SUBSCRIPTION_TYPE, attributes),
        content_type=JSONAPI,
    )


def _create_plan(client, **attributes):
    payload = {
        "code": "team",
        "name": "Team",
        "features": ["cloud_posture", "reports"],
        "limits": {"providers": 5, "users": None},
    }
    payload.update(attributes)
    return client.post(
        reverse("operator-plan-list"),
        data=_body(PLAN_TYPE, payload),
        content_type=JSONAPI,
    )


# --- Access ----------------------------------------------------------------------


@pytest.mark.django_db
class TestOperatorAccess:
    def test_tenant_admin_is_not_an_operator(self, authenticated_client):
        # ``authenticated_client`` is a tenant administrator; that never counts.
        for name in ("operator-me", "operator-tenant-list", "operator-plan-list"):
            response = authenticated_client.get(reverse(name))
            assert response.status_code == 404, name
            assert "errors" in response.json()

    def test_me_returns_role(self, authenticated_client, make_operator):
        make_operator("billing")
        response = authenticated_client.get(reverse("operator-me"))
        assert response.status_code == 200
        attributes = response.json()["data"]["attributes"]
        assert attributes["role"] == "billing"
        assert "manage_plans" in attributes["capabilities"]
        assert "suspend_tenants" not in attributes["capabilities"]

    def test_inactive_operator_is_refused(self, authenticated_client, make_operator):
        make_operator("owner", active=False)
        assert authenticated_client.get(reverse("operator-me")).status_code == 404

    def test_switch_turns_the_api_off(
        self, authenticated_client, make_operator, monkeypatch
    ):
        make_operator("owner")
        monkeypatch.setenv(OPERATOR_ENABLED_ENV, "false")
        assert authenticated_client.get(reverse("operator-me")).status_code == 404
        monkeypatch.setenv(OPERATOR_ENABLED_ENV, "true")
        assert authenticated_client.get(reverse("operator-me")).status_code == 200

    def test_requires_authentication(self, client):
        assert client.get(reverse("operator-tenant-list")).status_code == 401

    @pytest.mark.parametrize("role", ROLES)
    def test_every_role_can_read(self, authenticated_client, make_operator, role):
        make_operator(role)
        for name in (
            "operator-tenant-list",
            "operator-plan-list",
            "operator-audit-list",
        ):
            assert authenticated_client.get(reverse(name)).status_code == 200, name

    @pytest.mark.parametrize(
        ("role", "allowed"),
        [("owner", True), ("billing", True), ("support", False), ("read_only", False)],
    )
    def test_subscription_changes(
        self, authenticated_client, make_operator, tenants_fixture, role, allowed
    ):
        make_operator(role)
        response = _patch_subscription(
            authenticated_client, tenants_fixture[2], {"plan": "starter"}
        )
        assert response.status_code == (200 if allowed else 403), response.content

    @pytest.mark.parametrize(
        ("role", "allowed"),
        [("owner", True), ("billing", True), ("support", False), ("read_only", False)],
    )
    def test_plan_changes(self, authenticated_client, make_operator, role, allowed):
        make_operator(role)
        response = _create_plan(authenticated_client)
        assert response.status_code == (201 if allowed else 403), response.content

    @pytest.mark.parametrize(
        ("role", "allowed"),
        [("owner", True), ("billing", False), ("support", False), ("read_only", False)],
    )
    def test_operator_list_is_owner_only(
        self, authenticated_client, make_operator, role, allowed
    ):
        make_operator(role)
        response = authenticated_client.get(reverse("operator-operator-list"))
        assert response.status_code == (200 if allowed else 403)

    @pytest.mark.parametrize(
        ("role", "status_value", "allowed"),
        [
            ("billing", "suspended", False),
            ("billing", "cancelled", False),
            ("billing", "past_due", True),
            ("owner", "suspended", True),
            ("owner", "cancelled", True),
        ],
    )
    def test_only_owner_suspends(
        self,
        authenticated_client,
        make_operator,
        tenants_fixture,
        role,
        status_value,
        allowed,
    ):
        make_operator(role)
        response = _patch_subscription(
            authenticated_client, tenants_fixture[2], {"status": status_value}
        )
        assert response.status_code == (200 if allowed else 403), response.content


# --- Subscriptions -----------------------------------------------------------------


@pytest.mark.django_db
class TestSubscriptionPatch:
    def test_patch_writes_history_and_both_audit_logs(
        self, authenticated_client, make_operator, tenants_fixture
    ):
        make_operator("owner")
        tenant = tenants_fixture[1]
        response = _patch_subscription(
            authenticated_client,
            tenant,
            {
                "plan": "professional",
                "status": "trial",
                "trial_ends_at": "2031-03-01",
                "seats": 12,
                "feature_overrides": {"sso": True},
                "limit_overrides": {"providers": 40},
                "notes": "Renewal call booked",
            },
        )
        assert response.status_code == 200, response.content
        attributes = response.json()["data"]["attributes"]
        assert attributes["plan"] == "professional"
        assert attributes["status"] == "trial"
        assert attributes["seats"] == 12
        assert "sso" in attributes["features"]
        assert attributes["limits"]["providers"] == 40
        assert attributes["limits"]["users"] == 12
        changed = response.json()["meta"]["changed"]
        assert {"plan", "status", "seats", "feature_overrides"} <= set(changed)

        event = SubscriptionEvent.objects.get(tenant_id=tenant.id, action="updated")
        assert event.source == "operator"
        assert event.actor_email
        assert event.changes["plan"]["to"] == "professional"

        operator_event = OperatorAuditEvent.objects.get(action="subscription.update")
        assert operator_event.tenant_id == tenant.id
        assert operator_event.actor_role == "owner"
        assert operator_event.changed_fields == sorted(changed)
        assert "Renewal" not in json.dumps(operator_event.metadata)

        with rls_transaction(str(tenant.id)):
            customer_event = AuditEvent.objects.get(
                tenant_id=tenant.id, action="operator.subscription_update"
            )
        assert customer_event.metadata["operator"] is True

    def test_patch_invalidates_entitlements(
        self, authenticated_client, make_operator, tenants_fixture
    ):
        make_operator("owner")
        tenant = tenants_fixture[0]
        assert service.for_tenant(str(tenant.id)).plan_code == "legacy"
        _patch_subscription(authenticated_client, tenant, {"plan": "starter"})
        assert service.for_tenant(str(tenant.id)).plan_code == "starter"

    def test_unchanged_patch_writes_no_events(
        self, authenticated_client, make_operator, tenants_fixture
    ):
        make_operator("owner")
        response = _patch_subscription(
            authenticated_client, tenants_fixture[1], {"plan": "legacy"}
        )
        assert response.status_code == 200
        assert response.json()["meta"]["changed"] == []
        assert not OperatorAuditEvent.objects.exists()

    def test_invalid_values_return_400(
        self, authenticated_client, make_operator, tenants_fixture
    ):
        make_operator("owner")
        response = _patch_subscription(
            authenticated_client, tenants_fixture[1], {"status": "frozen"}
        )
        assert response.status_code == 400
        assert response.json()["errors"][0]["detail"]

    def test_unknown_tenant_is_404(self, authenticated_client, make_operator):
        make_operator("owner")
        response = authenticated_client.get(
            reverse(
                "operator-subscription-detail",
                kwargs={"tenant_id": "00000000-0000-4000-8000-000000000000"},
            )
        )
        assert response.status_code == 404


# --- Tenants -----------------------------------------------------------------------


@pytest.mark.django_db
class TestTenants:
    def test_list_has_plan_usage_and_summary(
        self, authenticated_client, make_operator, tenants_fixture, aws_provider
    ):
        make_operator("read_only")
        response = authenticated_client.get(reverse("operator-tenant-list"))
        assert response.status_code == 200
        body = response.json()
        rows = {row["id"]: row["attributes"] for row in body["data"]}
        first = rows[str(tenants_fixture[0].id)]
        assert first["plan"] == "legacy"
        assert first["effective_status"] == "active"
        assert first["usage"]["providers"] == 1
        assert first["member_count"] == 1
        assert body["meta"]["summary"]["total"] >= 3
        assert body["meta"]["pagination"]["count"] >= 3

    def test_filters(self, authenticated_client, make_operator, tenants_fixture):
        make_operator("owner")
        service.update_subscription(
            str(tenants_fixture[1].id), {"status": "suspended"}, source="system"
        )
        service.update_subscription(
            str(tenants_fixture[2].id),
            {"ends_at": (timezone.now() + timedelta(days=10)).isoformat()},
            source="system",
        )
        suspended = authenticated_client.get(
            reverse("operator-tenant-list"), {"filter[status]": "suspended"}
        ).json()["data"]
        assert [row["id"] for row in suspended] == [str(tenants_fixture[1].id)]

        expiring = authenticated_client.get(
            reverse("operator-tenant-list"), {"filter[expiring_within_days]": "30"}
        ).json()["data"]
        assert [row["id"] for row in expiring] == [str(tenants_fixture[2].id)]

        found = authenticated_client.get(
            reverse("operator-tenant-list"), {"filter[search]": "three"}
        ).json()["data"]
        assert [row["id"] for row in found] == [str(tenants_fixture[2].id)]

    def test_over_limit_filter(
        self, authenticated_client, make_operator, tenants_fixture, aws_provider
    ):
        make_operator("owner")
        service.update_subscription(
            str(tenants_fixture[0].id),
            {"plan": "starter", "limit_overrides": {"providers": 0}},
            source="system",
        )
        rows = authenticated_client.get(
            reverse("operator-tenant-list"), {"filter[over_limit]": "true"}
        ).json()["data"]
        assert [row["id"] for row in rows] == [str(tenants_fixture[0].id)]
        assert rows[0]["attributes"]["over_limit"] == ["providers"]

    def test_bad_sort_is_400(self, authenticated_client, make_operator):
        make_operator("owner")
        response = authenticated_client.get(
            reverse("operator-tenant-list"), {"sort": "secret"}
        )
        assert response.status_code == 400

    def test_detail(self, authenticated_client, make_operator, tenants_fixture):
        make_operator("support")
        tenant = tenants_fixture[0]
        service.update_subscription(str(tenant.id), {"plan": "starter"})
        response = authenticated_client.get(
            reverse("operator-tenant-detail", kwargs={"tenant_id": tenant.id})
        )
        assert response.status_code == 200
        attributes = response.json()["data"]["attributes"]
        assert attributes["name"] == tenant.name
        assert attributes["subscription"]["plan"] == "starter"
        assert attributes["members"][0]["email"]
        actions = [event["attributes"]["action"] for event in attributes["history"]]
        assert "updated" in actions
        assert isinstance(attributes["recent_scans"], list)

    def test_usage_snapshots(
        self, authenticated_client, make_operator, tenants_fixture
    ):
        make_operator("owner")
        tenant = tenants_fixture[0]
        UsageSnapshot.objects.create(
            tenant_id=tenant.id, date=timezone.now().date(), counts={"providers": 2}
        )
        UsageSnapshot.objects.create(
            tenant_id=tenant.id,
            date=timezone.now().date() - timedelta(days=90),
            counts={"providers": 1},
        )
        response = authenticated_client.get(
            reverse("operator-tenant-usage", kwargs={"tenant_id": tenant.id})
        )
        assert response.status_code == 200
        rows = response.json()["data"]
        assert len(rows) == 1
        assert rows[0]["attributes"]["counts"] == {"providers": 2}


# --- Plans -------------------------------------------------------------------------


@pytest.mark.django_db
class TestPlans:
    def test_create_patch_delete(self, authenticated_client, make_operator):
        make_operator("billing")
        created = _create_plan(authenticated_client)
        assert created.status_code == 201, created.content
        attributes = created.json()["data"]["attributes"]
        assert attributes["features"] == ["cloud_posture", "reports"]
        assert attributes["limits"]["providers"] == 5
        assert attributes["limits"]["users"] is None

        assert _create_plan(authenticated_client).status_code == 409

        patched = authenticated_client.patch(
            reverse("operator-plan-detail", kwargs={"code": "team"}),
            data=_body(PLAN_TYPE, {"name": "Team plus", "features": ["sso"]}),
            content_type=JSONAPI,
        )
        assert patched.status_code == 200, patched.content
        assert patched.json()["meta"]["changed"] == ["features", "name"]

        deleted = authenticated_client.delete(
            reverse("operator-plan-detail", kwargs={"code": "team"})
        )
        assert deleted.status_code == 204
        assert not Plan.objects.filter(code="team").exists()

        actions = set(OperatorAuditEvent.objects.values_list("action", flat=True))
        assert {"plan.create", "plan.update", "plan.delete"} <= actions

    def test_plan_in_use_and_legacy_cannot_be_deleted(
        self, authenticated_client, make_operator, tenants_fixture
    ):
        make_operator("owner")
        service.update_subscription(str(tenants_fixture[0].id), {"plan": "starter"})
        for code in ("starter", "legacy"):
            response = authenticated_client.delete(
                reverse("operator-plan-detail", kwargs={"code": code})
            )
            assert response.status_code == 409, code

    def test_invalid_plan_is_400(self, authenticated_client, make_operator):
        make_operator("owner")
        assert (
            _create_plan(authenticated_client, limits={"galaxies": 1}).status_code
            == 400
        )
        assert (
            _create_plan(authenticated_client, features=["teleport"]).status_code == 400
        )
        assert _create_plan(authenticated_client, code="", name="").status_code == 400

    def test_code_cannot_change(self, authenticated_client, make_operator):
        make_operator("owner")
        response = authenticated_client.patch(
            reverse("operator-plan-detail", kwargs={"code": "starter"}),
            data=_body(PLAN_TYPE, {"code": "renamed"}),
            content_type=JSONAPI,
        )
        assert response.status_code == 400

    def test_plan_edit_reaches_tenants(
        self, authenticated_client, make_operator, tenants_fixture
    ):
        make_operator("owner")
        tenant = tenants_fixture[0]
        service.update_subscription(str(tenant.id), {"plan": "starter"})
        assert "sso" not in service.for_tenant(str(tenant.id)).features
        authenticated_client.patch(
            reverse("operator-plan-detail", kwargs={"code": "starter"}),
            data=_body(PLAN_TYPE, {"features": ["cloud_posture", "sso"]}),
            content_type=JSONAPI,
        )
        assert "sso" in service.for_tenant(str(tenant.id)).features

    def test_list_includes_catalogue_keys(self, authenticated_client, make_operator):
        make_operator("read_only")
        body = authenticated_client.get(reverse("operator-plan-list")).json()
        assert "legacy" in [row["id"] for row in body["data"]]
        assert "seeker_ai" in body["meta"]["feature_keys"]
        assert "providers" in body["meta"]["limit_keys"]


# --- Operators and audit -----------------------------------------------------------


@pytest.mark.django_db
class TestOperatorsAndAudit:
    def test_operator_list(self, authenticated_client, make_operator):
        make_operator("owner")
        rows = authenticated_client.get(reverse("operator-operator-list")).json()[
            "data"
        ]
        assert rows[0]["attributes"]["role"] == "owner"

    def test_audit_filters(self, authenticated_client, make_operator, tenants_fixture):
        make_operator("owner")
        OperatorAuditEvent.objects.create(
            action="plan.update", target_type="plan", actor_email="a@example.com"
        )
        OperatorAuditEvent.objects.create(
            action="subscription.update",
            tenant_id=tenants_fixture[0].id,
            actor_email="b@example.com",
        )
        rows = authenticated_client.get(
            reverse("operator-audit-list"), {"filter[action]": "plan."}
        ).json()["data"]
        assert [row["attributes"]["action"] for row in rows] == ["plan.update"]
        rows = authenticated_client.get(
            reverse("operator-audit-list"),
            {"filter[tenant]": str(tenants_fixture[0].id)},
        ).json()["data"]
        assert [row["attributes"]["action"] for row in rows] == ["subscription.update"]
        bad = authenticated_client.get(
            reverse("operator-audit-list"), {"filter[tenant]": "nope"}
        )
        assert bad.status_code == 400

    def test_operator_requests_stay_out_of_the_tenant_audit_log(
        self, authenticated_client, make_operator, tenants_fixture
    ):
        make_operator("owner")
        _create_plan(authenticated_client)
        with rls_transaction(str(tenants_fixture[0].id)):
            assert not AuditEvent.objects.filter(
                tenant_id=tenants_fixture[0].id, path__startswith="/api/v1/operator"
            ).exists()


def test_openapi_schema_lists_the_operator_api():
    from drf_spectacular.generators import SchemaGenerator

    schema = SchemaGenerator().get_schema(request=None, public=True)
    for path in (
        "/api/v1/entitlements",
        "/api/v1/operator/me",
        "/api/v1/operator/tenants",
        "/api/v1/operator/tenants/{tenant_id}",
        "/api/v1/operator/subscriptions/{tenant_id}",
        "/api/v1/operator/plans",
        "/api/v1/operator/plans/{code}",
        "/api/v1/operator/audit-events",
    ):
        assert path in schema["paths"], path
    assert "patch" in schema["paths"]["/api/v1/operator/subscriptions/{tenant_id}"]


def test_subscription_table_is_not_row_level_security_protected():
    from api.rls import RowLevelSecurityProtectedModel

    for model in (PlatformOperator, Plan, Subscription, OperatorAuditEvent):
        assert not issubclass(model, RowLevelSecurityProtectedModel)
