"""Operator console, Phase 1: plans, entitlements, enforcement, usage, expiry."""

from __future__ import annotations

import importlib
import json
from datetime import timedelta
from io import StringIO
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from api.models import Tenant
from cloudsneeker_api import subscriptions as enforcement
from cloudsneeker_api.models import (
    JSON_API_TYPE_PREFIX,
    OperatorAuditEvent,
    Plan,
    PlatformOperator,
    Subscription,
    SubscriptionEvent,
    UsageSnapshot,
)
from cloudsneeker_api.services import entitlements as service
from cloudsneeker_api.services import plan_catalog as catalog
from cloudsneeker_api.tasks import operator_daily_task
from conftest import TEST_USER
from django.apps import apps as django_apps
from django.core.cache import cache
from django.core.management import CommandError, call_command
from django.http import HttpResponse
from django.test import RequestFactory
from django.urls import reverse
from django.utils import timezone
from django_celery_beat.models import PeriodicTask

JSONAPI = "application/vnd.api+json"
ENTITLEMENTS_TYPE = f"{JSON_API_TYPE_PREFIX}entitlements"


@pytest.fixture(autouse=True)
def _clear_entitlement_cache():
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def plans(db):
    """The default catalogue (a transactional test elsewhere may flush it)."""
    catalog.seed_plans(Plan, using="default")


def _migration():
    return importlib.import_module("cloudsneeker_api.migrations.0014_operator_console")


def _schema_editor():
    return SimpleNamespace(connection=SimpleNamespace(alias="default"))


def _set_plan(tenant, plan_code: str = "starter", **fields):
    """Put ``tenant`` on ``plan_code`` with extra subscription fields."""
    service.update_subscription(
        str(tenant.id), {"plan": plan_code, **fields}, source="system"
    )
    return Subscription.objects.get(tenant_id=tenant.id)


def _role_payload(name: str = "Plan Role") -> str:
    return json.dumps(
        {
            "data": {
                "type": "roles",
                "attributes": {"name": name, "manage_scans": "true"},
                "relationships": {"provider_groups": {"data": []}},
            }
        }
    )


def _error_code(response) -> str:
    return response.json()["errors"][0]["code"]


# --- Pure computation ------------------------------------------------------------


class TestComputation:
    def test_feature_overrides_add_and_remove(self):
        features = service.effective_features(
            ["cloud_posture", "reports"],
            {"reports": False, "audit_log": True, "not_a_feature": True},
        )
        assert features == ["cloud_posture", "audit_log"]

    def test_unknown_plan_features_are_dropped(self):
        assert service.effective_features(["bogus", "sso"], None) == ["sso"]

    def test_limits_seats_then_overrides(self):
        limits = service.effective_limits(
            {"providers": 3, "users": 5}, {"providers": None, "scans_per_month": 7}, 9
        )
        assert limits["providers"] is None
        assert limits["users"] == 9
        assert limits["scans_per_month"] == 7
        assert limits["report_schedules"] is None

    def test_limit_override_beats_seats(self):
        limits = service.effective_limits({"users": 5}, {"users": 2}, 9)
        assert limits["users"] == 2

    def test_effective_status_expires_on_end_date(self):
        now = timezone.now()
        past = now - timedelta(minutes=1)
        future = now + timedelta(days=1)
        assert service.effective_status("active", past, None, now) == "expired"
        assert service.effective_status("trial", None, past, now) == "expired"
        assert service.effective_status("active", future, None, now) == "active"
        assert service.effective_status("suspended", future, None, now) == "suspended"
        assert service.effective_status("past_due", None, past, now) == "past_due"

    def test_read_only_statuses(self):
        for value in ("suspended", "expired", "cancelled"):
            assert service.is_read_only(value)
        for value in ("trial", "active", "past_due"):
            assert not service.is_read_only(value)

    def test_clean_limits_rejects_negative_and_text(self):
        with pytest.raises(ValueError):
            catalog.clean_limits({"providers": -1})
        with pytest.raises(ValueError):
            catalog.clean_limits({"providers": "many"})
        assert catalog.clean_limits({"providers": "4", "users": None, "x": 1}) == {
            "providers": 4,
            "users": None,
        }

    def test_over_limit_keys(self):
        usage = {"providers": 4, "users": 2, "scans_this_month": 10}
        limits = {"providers": 3, "users": 2, "scans_per_month": None}
        assert service.over_limit_keys(usage, limits) == ["providers"]

    def test_default_plan_env(self, monkeypatch):
        monkeypatch.delenv(catalog.DEFAULT_PLAN_ENV, raising=False)
        assert catalog.default_plan_code() == "legacy"
        monkeypatch.setenv(catalog.DEFAULT_PLAN_ENV, " Starter ")
        assert catalog.default_plan_code() == "starter"


class TestPathMapping:
    @pytest.mark.parametrize(
        ("path", "feature"),
        [
            ("trivy-targets", "application_security"),
            ("trivy-runs/abc", "application_security"),
            ("report-runs", "reports"),
            ("report-schedules", "report_schedules"),
            ("custodian-policies", "governance"),
            ("attack-paths-scans", "attack_paths"),
            ("lighthouse/configuration", "seeker_ai"),
            ("lighthouse-configurations", "seeker_ai"),
            ("finding-triages", "finding_triage"),
            ("findings/aws/x/y/triage", "finding_triage"),
            ("findings/aws/x/y/triage/notes", "finding_triage"),
            ("audit-events/export", "audit_log"),
            ("integrations", "integrations"),
            ("saml-config", "sso"),
            ("api-keys", "api_access"),
            ("compliance-overviews", "compliance"),
            ("providers", None),
            ("findings", None),
            ("scans", None),
        ],
    )
    def test_feature_for_path(self, path, feature):
        assert enforcement.feature_for_path(path) == feature

    @pytest.mark.parametrize(
        ("path", "method", "allowed"),
        [
            ("tokens", "POST", True),
            ("tokens/refresh", "POST", True),
            ("tokens/switch", "POST", True),
            ("entitlements", "POST", True),
            ("invitations/accept", "POST", True),
            ("users/me", "PATCH", True),
            ("users/u-1", "PATCH", True),
            ("users/u-2", "PATCH", False),
            ("users/u-1", "DELETE", False),
            ("roles", "POST", False),
            ("providers", "POST", False),
        ],
    )
    def test_allowed_while_inactive(self, path, method, allowed):
        assert enforcement.allowed_while_inactive(path, method, "u-1") is allowed

    def test_operator_paths_are_exempt(self):
        assert enforcement.is_exempt("operator/tenants")
        assert enforcement.is_exempt("operator")
        assert not enforcement.is_exempt("operators-x")

    def test_api_key_needs_api_access(self):
        entitlements = service.Entitlements(
            tenant_id="t",
            plan_code="starter",
            plan_name="Starter",
            status="active",
            effective_status="active",
            read_only=False,
            features=["cloud_posture"],
            limits={},
        )
        request = RequestFactory().get("/api/v1/providers")
        identity = enforcement.RequestIdentity(tenant_id="t", api_key=True)
        response = enforcement.decide(request, "providers", identity, entitlements)
        assert response.status_code == 403
        assert json.loads(response.content)["errors"][0]["code"] == (
            enforcement.CODE_FEATURE_NOT_IN_PLAN
        )

    def test_middleware_never_reads_the_body(self):
        seen = {}

        def get_response(request):
            seen["body_read"] = hasattr(request, "_body")
            return HttpResponse(status=201)

        request = RequestFactory().post(
            "/api/v1/roles",
            data=_role_payload(),
            content_type=JSONAPI,
            HTTP_AUTHORIZATION="Bearer not-a-token",
        )
        response = enforcement.SubscriptionEnforcementMiddleware(get_response)(request)
        assert response.status_code == 201
        assert seen["body_read"] is False


# --- Seeding ---------------------------------------------------------------------


@pytest.mark.django_db
class TestSeeding:
    def test_migration_seeds_the_catalogue(self, tenants_fixture):
        _migration().seed_catalogue(django_apps, _schema_editor())
        _migration().seed_catalogue(django_apps, _schema_editor())
        for tenant in tenants_fixture:
            subscription = Subscription.objects.get(tenant_id=tenant.id)
            assert subscription.plan.code == "legacy"
            assert subscription.status == "active"
            assert SubscriptionEvent.objects.filter(tenant_id=tenant.id).count() == 1
        codes = set(Plan.objects.values_list("code", flat=True))
        assert {"legacy", "starter", "professional", "enterprise", "managed"} <= codes
        legacy = Plan.objects.get(code="legacy")
        assert legacy.features == list(catalog.FEATURE_KEYS)
        assert all(value is None for value in legacy.limits.values())
        assert legacy.is_public is False
        for code in ("enterprise", "managed"):
            plan = Plan.objects.get(code=code)
            assert all(value is None for value in plan.limits.values())

    def test_migration_registers_the_daily_task(self):
        _migration().create_daily_task(django_apps, _schema_editor())
        _migration().create_daily_task(django_apps, _schema_editor())
        task = PeriodicTask.objects.get(name="cloudsneeker-operator-daily")
        assert task.task == "cloudsneeker-operator-daily"
        assert task.enabled

    def test_seed_plans_is_idempotent_and_keeps_edits(self, plans):
        Plan.objects.filter(code="starter").update(name="Edited")
        assert catalog.seed_plans(Plan, using="default") == 0
        assert Plan.objects.get(code="starter").name == "Edited"
        Plan.objects.filter(code="managed").delete()
        assert catalog.seed_plans(Plan, using="default") == 1

    def test_seed_subscriptions_is_idempotent(self, plans, tenants_fixture):
        created = catalog.seed_subscriptions(
            Tenant, Subscription, Plan, SubscriptionEvent, using="default"
        )
        assert created >= len(tenants_fixture)
        for tenant in tenants_fixture:
            subscription = Subscription.objects.get(tenant_id=tenant.id)
            assert subscription.plan.code == "legacy"
            assert subscription.status == "active"
        assert (
            catalog.seed_subscriptions(
                Tenant, Subscription, Plan, SubscriptionEvent, using="default"
            )
            == 0
        )


# --- Service -----------------------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.usefixtures("plans")
class TestEntitlementService:
    def test_missing_subscription_is_created_on_legacy(
        self, tenants_fixture, monkeypatch
    ):
        monkeypatch.delenv(catalog.DEFAULT_PLAN_ENV, raising=False)
        tenant = tenants_fixture[0]
        entitlements = service.for_tenant(str(tenant.id))
        assert entitlements.plan_code == "legacy"
        assert entitlements.status == "active"
        assert entitlements.read_only is False
        assert entitlements.features == list(catalog.FEATURE_KEYS)
        assert all(value is None for value in entitlements.limits.values())
        (event,) = SubscriptionEvent.objects.filter(tenant_id=tenant.id)
        assert event.action == "created"
        assert event.source == "system"

    def test_default_plan_env_applies_to_new_tenants(
        self, tenants_fixture, monkeypatch
    ):
        monkeypatch.setenv(catalog.DEFAULT_PLAN_ENV, "starter")
        entitlements = service.for_tenant(str(tenants_fixture[1].id))
        assert entitlements.plan_code == "starter"
        assert "attack_paths" not in entitlements.features

    def test_unknown_default_plan_falls_back_to_legacy(
        self, tenants_fixture, monkeypatch
    ):
        monkeypatch.setenv(catalog.DEFAULT_PLAN_ENV, "no-such-plan")
        assert service.for_tenant(str(tenants_fixture[2].id)).plan_code == "legacy"

    def test_missing_legacy_plan_is_recreated(self, tenants_fixture, monkeypatch):
        monkeypatch.delenv(catalog.DEFAULT_PLAN_ENV, raising=False)
        Subscription.objects.all().delete()
        Plan.objects.filter(code="legacy").delete()
        assert service.for_tenant(str(tenants_fixture[0].id)).plan_code == "legacy"
        assert Plan.objects.filter(code="legacy").exists()

    def test_overrides_and_cache_invalidation(self, tenants_fixture):
        tenant = tenants_fixture[0]
        assert service.for_tenant(str(tenant.id)).plan_code == "legacy"
        _set_plan(
            tenant,
            "starter",
            feature_overrides={"audit_log": True, "reports": False},
            limit_overrides={"providers": 10},
            seats=8,
        )
        entitlements = service.for_tenant(str(tenant.id))
        assert entitlements.plan_code == "starter"
        assert "audit_log" in entitlements.features
        assert "reports" not in entitlements.features
        assert entitlements.limits["providers"] == 10
        assert entitlements.limits["users"] == 8

    def test_plan_change_invalidates_every_tenant(self, tenants_fixture):
        tenant = tenants_fixture[0]
        _set_plan(tenant, "starter")
        assert "sso" not in service.for_tenant(str(tenant.id)).features
        Plan.objects.filter(code="starter").update(features=list(catalog.FEATURE_KEYS))
        service.invalidate()
        assert "sso" in service.for_tenant(str(tenant.id)).features

    def test_update_writes_history(self, tenants_fixture):
        tenant = tenants_fixture[0]
        service.ensure_subscription(str(tenant.id))
        subscription, changed = service.update_subscription(
            str(tenant.id),
            {
                "plan": "professional",
                "status": "trial",
                "trial_ends_at": "2030-01-31",
                "notes": "Secret deal terms",
            },
            actor_email="ops@example.com",
        )
        assert changed == ["notes", "plan", "status", "trial_ends_at"]
        event = SubscriptionEvent.objects.filter(
            tenant_id=tenant.id, action="updated"
        ).get()
        assert event.changes["plan"] == {"from": "legacy", "to": "professional"}
        assert event.changes["status"] == {"from": "active", "to": "trial"}
        assert event.changes["trial_ends_at"]["to"].startswith("2030-01-31")
        # Free text is recorded by name only.
        assert event.changes["notes"] == {"changed": True}
        assert "Secret" not in json.dumps(event.changes)
        assert event.actor_email == "ops@example.com"
        assert subscription.trial_ends_at.year == 2030

    def test_unchanged_update_writes_nothing(self, tenants_fixture):
        tenant = tenants_fixture[0]
        service.ensure_subscription(str(tenant.id))
        _, changed = service.update_subscription(str(tenant.id), {"plan": "legacy"})
        assert changed == []
        assert not SubscriptionEvent.objects.filter(
            tenant_id=tenant.id, action="updated"
        ).exists()

    @pytest.mark.parametrize(
        "data",
        [
            {"plan": "nope"},
            {"status": "frozen"},
            {"ends_at": "tomorrow"},
            {"seats": -1},
            {"feature_overrides": {"teleport": True}},
            {"limit_overrides": {"providers": -2}},
            {"limit_overrides": {"galaxies": 1}},
            {"billing_source": "barter"},
        ],
    )
    def test_invalid_changes_are_refused(self, tenants_fixture, data):
        with pytest.raises(service.SubscriptionError):
            service.update_subscription(str(tenants_fixture[0].id), data)

    def test_usage_counts(self, tenants_fixture, aws_provider):
        usage = service.usage_for_tenant(str(tenants_fixture[0].id))
        assert usage["providers"] == 1
        assert usage["members"] == 1
        assert usage["users"] == 1
        assert usage["application_security_targets"] == 0
        assert usage["seeker_ai_requests_this_month"] is None
        assert service.usage_for_tenant(str(tenants_fixture[2].id))["members"] == 0


# --- Tasks -------------------------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.usefixtures("plans")
class TestDailyTask:
    def test_expiry_moves_ended_subscriptions(self, tenants_fixture):
        now = timezone.now()
        ended, trial, suspended = tenants_fixture
        _set_plan(ended, "starter", ends_at=(now - timedelta(days=1)).isoformat())
        _set_plan(
            trial,
            "starter",
            status="trial",
            trial_ends_at=(now - timedelta(hours=1)).isoformat(),
        )
        _set_plan(
            suspended,
            "starter",
            status="suspended",
            ends_at=(now - timedelta(days=1)).isoformat(),
        )

        assert service.expire_subscriptions() == 2
        assert Subscription.objects.get(tenant_id=ended.id).status == "expired"
        assert Subscription.objects.get(tenant_id=trial.id).status == "expired"
        assert Subscription.objects.get(tenant_id=suspended.id).status == "suspended"
        events = SubscriptionEvent.objects.filter(action="expired")
        assert {event.tenant_id for event in events} == {ended.id, trial.id}
        assert all(event.source == "system" for event in events)
        assert service.expire_subscriptions() == 0

    def test_future_end_dates_stay_active(self, tenants_fixture):
        tenant = tenants_fixture[0]
        _set_plan(tenant, ends_at=(timezone.now() + timedelta(days=3)).isoformat())
        assert service.expire_subscriptions() == 0
        assert Subscription.objects.get(tenant_id=tenant.id).status == "active"

    def test_usage_snapshot_is_one_row_per_tenant_and_day(
        self, tenants_fixture, aws_provider
    ):
        written = service.snapshot_usage()
        assert written >= len(tenants_fixture)
        snapshot = UsageSnapshot.objects.get(
            tenant_id=tenants_fixture[0].id, date=timezone.now().date()
        )
        assert snapshot.counts["providers"] == 1
        assert "findings_this_month" in snapshot.counts
        service.snapshot_usage()
        assert (
            UsageSnapshot.objects.filter(tenant_id=tenants_fixture[0].id).count() == 1
        )

    def test_daily_task_runs_both(self, tenants_fixture):
        _set_plan(
            tenants_fixture[0],
            ends_at=(timezone.now() - timedelta(days=1)).isoformat(),
        )
        result = operator_daily_task()
        assert result["expired"] == 1
        assert result["snapshots"] >= len(tenants_fixture)


# --- Entitlements endpoint ----------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.usefixtures("plans")
class TestEntitlementsEndpoint:
    def test_returns_plan_features_limits_and_usage(
        self, authenticated_client, tenants_fixture, aws_provider
    ):
        response = authenticated_client.get(reverse("entitlements"))
        assert response.status_code == 200, response.content
        data = response.json()["data"]
        assert data["type"] == ENTITLEMENTS_TYPE
        assert data["id"] == str(tenants_fixture[0].id)
        attributes = data["attributes"]
        assert attributes["plan"] == {"code": "legacy", "name": "Legacy (unlimited)"}
        assert attributes["read_only"] is False
        assert attributes["features"] == list(catalog.FEATURE_KEYS)
        assert attributes["usage"]["providers"] == 1
        assert attributes["over_limit"] == []

    def test_reflects_operator_changes(self, authenticated_client, tenants_fixture):
        authenticated_client.get(reverse("entitlements"))
        _set_plan(tenants_fixture[0], "starter", status="suspended")
        attributes = authenticated_client.get(reverse("entitlements")).json()["data"][
            "attributes"
        ]
        assert attributes["plan"]["code"] == "starter"
        assert attributes["effective_status"] == "suspended"
        assert attributes["read_only"] is True

    def test_requires_authentication(self, client):
        assert client.get(reverse("entitlements")).status_code == 401

    def test_lookup_failure_falls_back_to_unlimited(
        self, authenticated_client, tenants_fixture
    ):
        with patch.object(service, "for_tenant", side_effect=RuntimeError("db down")):
            response = authenticated_client.get(reverse("entitlements"))
        assert response.status_code == 200
        assert response.json()["data"]["attributes"]["read_only"] is False


# --- Enforcement -------------------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.usefixtures("plans")
class TestEnforcement:
    def test_legacy_tenant_is_untouched(self, authenticated_client, tenants_fixture):
        response = authenticated_client.post(
            reverse("role-list"), data=_role_payload(), content_type=JSONAPI
        )
        assert response.status_code == 201, response.content

    def test_suspended_tenant_is_read_only(self, authenticated_client, tenants_fixture):
        _set_plan(tenants_fixture[0], "legacy", status="suspended")
        response = authenticated_client.post(
            reverse("role-list"), data=_role_payload(), content_type=JSONAPI
        )
        assert response.status_code == 403
        assert _error_code(response) == "subscription_inactive"
        assert response["Content-Type"].startswith(JSONAPI)
        # Reads still work.
        assert authenticated_client.get(reverse("role-list")).status_code == 200
        # The tenant can still read its entitlements.
        assert authenticated_client.get(reverse("entitlements")).status_code == 200

    def test_ended_subscription_is_read_only_before_the_task_runs(
        self, authenticated_client, tenants_fixture
    ):
        _set_plan(
            tenants_fixture[0],
            "legacy",
            ends_at=(timezone.now() - timedelta(minutes=5)).isoformat(),
        )
        response = authenticated_client.delete(
            reverse(
                "role-detail", kwargs={"pk": "00000000-0000-4000-8000-000000000000"}
            )
        )
        assert response.status_code == 403
        assert _error_code(response) == "subscription_inactive"

    def test_own_profile_stays_editable_while_suspended(
        self, authenticated_client, tenants_fixture, create_test_user
    ):
        _set_plan(tenants_fixture[0], "legacy", status="expired")
        response = authenticated_client.patch(
            reverse("user-detail", kwargs={"pk": create_test_user.id}),
            data=json.dumps(
                {
                    "data": {
                        "type": "users",
                        "id": str(create_test_user.id),
                        "attributes": {"name": "Renamed user"},
                    }
                }
            ),
            content_type=JSONAPI,
        )
        assert b"subscription_inactive" not in response.content

    def test_feature_outside_plan_is_refused(
        self, authenticated_client, tenants_fixture
    ):
        _set_plan(tenants_fixture[0], "starter")
        response = authenticated_client.get(reverse("audit-events-list"))
        assert response.status_code == 403
        assert _error_code(response) == "feature_not_in_plan"
        assert response.json()["errors"][0]["meta"]["feature"] == "audit_log"

        attack = authenticated_client.get(reverse("attack-paths-scans-list"))
        assert attack.status_code == 403
        assert _error_code(attack) == "feature_not_in_plan"

    def test_feature_override_opens_the_path(
        self, authenticated_client, tenants_fixture
    ):
        _set_plan(tenants_fixture[0], "starter", feature_overrides={"audit_log": True})
        assert authenticated_client.get(reverse("audit-events-list")).status_code == 200

    def test_core_paths_are_never_feature_gated(
        self, authenticated_client, tenants_fixture
    ):
        _set_plan(tenants_fixture[0], "starter")
        assert authenticated_client.get(reverse("provider-list")).status_code == 200
        assert authenticated_client.get(reverse("finding-list")).status_code != 403

    def test_provider_limit(self, authenticated_client, tenants_fixture, aws_provider):
        _set_plan(tenants_fixture[0], "starter", limit_overrides={"providers": 1})
        response = authenticated_client.post(
            reverse("provider-list"),
            data=json.dumps(
                {
                    "data": {
                        "type": "providers",
                        "attributes": {
                            "alias": "over the limit",
                            "provider": "aws",
                            "uid": "123456789099",
                        },
                    }
                }
            ),
            content_type=JSONAPI,
        )
        assert response.status_code == 403
        assert _error_code(response) == "plan_limit_reached"
        meta = response.json()["errors"][0]["meta"]
        assert meta == {"limit": "providers", "max": 1, "usage": 1}

    def test_invitation_limit_counts_members(
        self, authenticated_client, tenants_fixture
    ):
        _set_plan(tenants_fixture[0], "starter", seats=1)
        response = authenticated_client.post(
            reverse("invitation-list"),
            data=json.dumps(
                {
                    "data": {
                        "type": "invitations",
                        "attributes": {"email": "new.member@example.com"},
                    }
                }
            ),
            content_type=JSONAPI,
        )
        assert response.status_code == 403
        assert _error_code(response) == "plan_limit_reached"

    def test_under_the_limit_is_allowed(self, authenticated_client, tenants_fixture):
        _set_plan(tenants_fixture[0], "starter", limit_overrides={"providers": 5})
        response = authenticated_client.post(
            reverse("provider-list"),
            data=json.dumps(
                {
                    "data": {
                        "type": "providers",
                        "attributes": {
                            "alias": "within limit",
                            "provider": "aws",
                            "uid": "123456789098",
                        },
                    }
                }
            ),
            content_type=JSONAPI,
        )
        assert b"plan_limit_reached" not in response.content

    def test_internal_errors_fail_open(self, authenticated_client, tenants_fixture):
        with patch.object(service, "for_tenant", side_effect=RuntimeError("boom")):
            response = authenticated_client.post(
                reverse("role-list"), data=_role_payload(), content_type=JSONAPI
            )
        assert response.status_code == 201, response.content

    def test_unauthenticated_requests_are_left_to_the_view(self, client):
        response = client.post(
            reverse("role-list"), data=_role_payload(), content_type=JSONAPI
        )
        assert response.status_code == 401

    def test_operator_api_ignores_the_operator_tenant_status(
        self, authenticated_client, tenants_fixture, create_test_user
    ):
        PlatformOperator.objects.create(user=create_test_user, role="owner")
        _set_plan(tenants_fixture[0], "starter", status="suspended")
        response = authenticated_client.patch(
            reverse(
                "operator-subscription-detail",
                kwargs={"tenant_id": tenants_fixture[0].id},
            ),
            data=json.dumps(
                {
                    "data": {
                        "type": "cloudsneeker-subscriptions",
                        "attributes": {"status": "active"},
                    }
                }
            ),
            content_type=JSONAPI,
        )
        assert response.status_code == 200, response.content
        assert Subscription.objects.get(tenant_id=tenants_fixture[0].id).status == (
            "active"
        )


# --- Management command --------------------------------------------------------------


@pytest.mark.django_db
class TestOperatorCommand:
    def test_grant_change_and_revoke(self, create_test_user):
        out = StringIO()
        call_command(
            "cloudsneeker_operator", "grant", TEST_USER, "--role", "owner", stdout=out
        )
        operator = PlatformOperator.objects.get(user=create_test_user)
        assert operator.role == "owner"
        assert operator.active
        assert "owner" in out.getvalue()

        call_command(
            "cloudsneeker_operator",
            "grant",
            TEST_USER.upper(),
            "--role",
            "support",
            stdout=StringIO(),
        )
        operator.refresh_from_db()
        assert operator.role == "support"

        call_command("cloudsneeker_operator", "revoke", TEST_USER, stdout=StringIO())
        operator.refresh_from_db()
        assert operator.active is False

        actions = list(
            OperatorAuditEvent.objects.order_by("inserted_at").values_list(
                "action", flat=True
            )
        )
        assert actions == ["operator.grant", "operator.grant", "operator.revoke"]
        assert all(
            event.actor_email == "cli" for event in OperatorAuditEvent.objects.all()
        )

    def test_regrant_reactivates(self, create_test_user):
        PlatformOperator.objects.create(
            user=create_test_user, role="billing", active=False
        )
        call_command(
            "cloudsneeker_operator",
            "grant",
            TEST_USER,
            "--role",
            "billing",
            stdout=StringIO(),
        )
        assert PlatformOperator.objects.get(user=create_test_user).active

    def test_unknown_user(self):
        with pytest.raises(CommandError):
            call_command("cloudsneeker_operator", "grant", "nobody@example.com")

    def test_list(self, create_test_user):
        call_command("cloudsneeker_operator", "grant", TEST_USER, stdout=StringIO())
        out = StringIO()
        call_command("cloudsneeker_operator", "list", stdout=out)
        assert TEST_USER in out.getvalue()
        assert "read_only" in out.getvalue()

    def test_no_operator_exists_by_default(self):
        assert not PlatformOperator.objects.exists()


def test_identity_ignores_garbage_headers():
    request = SimpleNamespace(META={"HTTP_AUTHORIZATION": "Basic abc"})
    assert enforcement.request_identity(request) is None
    request = SimpleNamespace(META={"HTTP_AUTHORIZATION": "Api-Key no-separator"})
    assert enforcement.request_identity(request) is None
