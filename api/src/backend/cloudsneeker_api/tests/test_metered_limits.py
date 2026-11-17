"""Monthly plan limits (EB-080): scans and assistant requests are enforced."""

from __future__ import annotations

import json
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from api.db_utils import rls_transaction
from api.models import Scan, StateChoices
from cloudsneeker_api import audit
from cloudsneeker_api import subscriptions as enforcement
from cloudsneeker_api.models import AuditEvent, Plan, Subscription
from cloudsneeker_api.services import entitlements as service
from cloudsneeker_api.services import plan_catalog as catalog
from django.core.cache import cache
from django.test import RequestFactory
from django.urls import reverse

JSONAPI = "application/vnd.api+json"
SCANS = catalog.LIMIT_SCANS_PER_MONTH
ASSISTANT = catalog.LIMIT_SEEKER_AI_REQUESTS_PER_MONTH
SCAN_USAGE = "scans_this_month"
ASSISTANT_USAGE = "seeker_ai_requests_this_month"
METERED_CASES = [
    ("scans", SCANS, SCAN_USAGE),
    ("trivy-targets/6f1c/scan", SCANS, SCAN_USAGE),
    ("seeker-ai/requests", ASSISTANT, ASSISTANT_USAGE),
]


def _entitlements(limits: dict, fallback: bool = False) -> service.Entitlements:
    return service.Entitlements(
        tenant_id="t",
        plan_code="professional",
        plan_name="Professional",
        status="active",
        effective_status="active",
        read_only=False,
        features=list(catalog.FEATURE_KEYS),
        limits=limits,
        fallback=fallback,
    )


def _decide(path: str, limits: dict, usage: dict, method: str = "POST"):
    request = getattr(RequestFactory(), method.lower())(f"/api/v1/{path}")
    identity = enforcement.RequestIdentity(tenant_id="t", user_id="u")
    with patch.object(service, "usage_for_tenant", return_value=usage) as lookup:
        response = enforcement.decide(request, path, identity, _entitlements(limits))
    return response, lookup


def _error(response) -> dict:
    return json.loads(response.content)["errors"][0]


# --- Decision (no database) ---------------------------------------------------------


class TestMeteredDecision:
    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("scans", (SCANS, SCAN_USAGE)),
            ("trivy-targets/6f1c/scan", (SCANS, SCAN_USAGE)),
            ("seeker-ai/requests", (ASSISTANT, ASSISTANT_USAGE)),
            ("scans/6f1c", None),
            ("trivy-targets", None),
            ("trivy-targets/6f1c/scan/extra", None),
            ("lighthouse/configuration", None),
            ("providers", None),
        ],
    )
    def test_metered_limit_for_path(self, path, expected):
        assert enforcement.metered_limit_for_path(path) == expected

    def test_assistant_requests_need_the_assistant_feature(self):
        assert enforcement.feature_for_path("seeker-ai/requests") == (
            catalog.FEATURE_SEEKER_AI
        )

    @pytest.mark.parametrize(("path", "limit_key", "usage_key"), METERED_CASES)
    def test_under_the_limit_is_allowed(self, path, limit_key, usage_key):
        response, _ = _decide(path, {limit_key: 10}, {usage_key: 9})
        assert response is None

    @pytest.mark.parametrize(("path", "limit_key", "usage_key"), METERED_CASES)
    @pytest.mark.parametrize("used", [10, 11])
    def test_at_and_over_the_limit_is_refused(self, path, limit_key, usage_key, used):
        response, _ = _decide(path, {limit_key: 10}, {usage_key: used})
        assert response.status_code == 403
        assert response["Content-Type"] == JSONAPI
        error = _error(response)
        assert error["code"] == enforcement.CODE_PLAN_LIMIT_REACHED
        assert error["title"] == "Plan limit reached"
        assert error["meta"] == {"limit": limit_key, "max": 10, "usage": used}
        assert enforcement.LIMIT_LABELS[limit_key] in error["detail"]
        assert "per month" in error["detail"]

    @pytest.mark.parametrize(("path", "limit_key", "usage_key"), METERED_CASES)
    def test_unlimited_is_never_refused(self, path, limit_key, usage_key):
        for limits in ({limit_key: None}, {}):
            response, lookup = _decide(path, limits, {usage_key: 10**6})
            assert response is None
            lookup.assert_not_called()

    @pytest.mark.parametrize(("path", "limit_key", "usage_key"), METERED_CASES)
    def test_zero_allowance_refuses_the_first_request(self, path, limit_key, usage_key):
        response, _ = _decide(path, {limit_key: 0}, {usage_key: 0})
        assert _error(response)["meta"] == {"limit": limit_key, "max": 0, "usage": 0}

    def test_untracked_usage_counts_as_zero(self):
        response, _ = _decide("scans", {SCANS: 1}, {SCAN_USAGE: None})
        assert response is None

    @pytest.mark.parametrize("method", ["GET", "PATCH", "DELETE"])
    def test_only_posts_use_the_allowance(self, method):
        response, lookup = _decide("scans", {SCANS: 1}, {SCAN_USAGE: 5}, method)
        assert response is None
        lookup.assert_not_called()

    def test_one_limit_does_not_block_the_other(self):
        limits = {SCANS: 1, ASSISTANT: 5}
        usage = {SCAN_USAGE: 1, ASSISTANT_USAGE: 0}
        assert _decide("seeker-ai/requests", limits, usage)[0] is None
        assert _decide("scans", limits, usage)[0].status_code == 403

    def test_fallback_entitlements_are_unlimited(self):
        fallback = service.fallback_entitlements("t")
        assert fallback.fallback is True
        assert fallback.limit(SCANS) is None
        assert fallback.limit(ASSISTANT) is None

    def test_over_limit_keys_include_assistant_requests(self):
        usage = {SCAN_USAGE: 3, ASSISTANT_USAGE: 9}
        assert service.over_limit_keys(usage, {SCANS: 3, ASSISTANT: 8}) == [ASSISTANT]

    def test_assistant_request_route_maps_to_the_counted_action(self):
        func = SimpleNamespace(
            initkwargs={"basename": "seeker-ai-requests"}, actions={"post": "create"}
        )
        match = SimpleNamespace(url_name="seeker-ai-requests-list", func=func)
        route = audit.resolve_action(match, "POST")
        assert route.action == service.SEEKER_AI_REQUEST_ACTION
        assert route.target_type == "seeker_ai"


# --- Endpoints (database) -----------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_entitlement_cache():
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def plans(db):
    catalog.seed_plans(Plan, using="default")


def _set_limits(tenant, **limits):
    """Put ``tenant`` on Professional (has the assistant) with limit overrides."""
    service.update_subscription(
        str(tenant.id),
        {"plan": "professional", "limit_overrides": limits},
        source="system",
    )


def _scan(tenant, provider, days_ago: int = 0) -> Scan:
    scan = Scan.objects.create(
        name="Metered",
        provider=provider,
        trigger=Scan.TriggerChoices.MANUAL,
        state=StateChoices.COMPLETED,
        tenant_id=tenant.id,
    )
    if days_ago:
        Scan.all_objects.filter(id=scan.id).update(
            inserted_at=service.month_start() - timedelta(days=days_ago)
        )
    return scan


def _assistant_event(tenant, days_ago: int = 0, **fields) -> AuditEvent:
    defaults = {"action": service.SEEKER_AI_REQUEST_ACTION}
    defaults.update(fields)
    with rls_transaction(str(tenant.id)):
        event = AuditEvent.objects.create(tenant_id=tenant.id, **defaults)
        if days_ago:
            AuditEvent.objects.filter(id=event.id).update(
                inserted_at=service.month_start() - timedelta(days=days_ago)
            )
    return event


def _scan_payload(provider) -> str:
    return json.dumps(
        {
            "data": {
                "type": "scans",
                "attributes": {"name": "Metered scan"},
                "relationships": {
                    "provider": {"data": {"type": "providers", "id": str(provider.id)}}
                },
            }
        }
    )


def _post_scan(client, provider):
    with patch("api.v1.views.enqueue_scan_execution_on_commit"):
        return client.post(
            reverse("scan-list"), data=_scan_payload(provider), content_type=JSONAPI
        )


def _post_assistant_request(client):
    return client.post(reverse("seeker-ai-requests-list"), content_type=JSONAPI)


def _assistant_usage(tenant) -> int:
    return service.usage_for_tenant(str(tenant.id))[ASSISTANT_USAGE]


@pytest.mark.django_db
@pytest.mark.usefixtures("plans")
class TestMonthlyUsage:
    def test_scans_count_the_current_month_only(self, tenants_fixture, aws_provider):
        tenant = tenants_fixture[0]
        _scan(tenant, aws_provider)
        _scan(tenant, aws_provider, days_ago=1)
        assert service.usage_for_tenant(str(tenant.id))[SCAN_USAGE] == 1

    def test_assistant_requests_count_successful_events_of_the_month(
        self, tenants_fixture
    ):
        tenant, other, *_ = tenants_fixture
        _assistant_event(tenant)
        _assistant_event(tenant)
        _assistant_event(tenant, days_ago=1)
        _assistant_event(tenant, outcome=AuditEvent.Outcome.FAILURE)
        _assistant_event(tenant, action="role.create")
        _assistant_event(other)
        assert _assistant_usage(tenant) == 2
        assert _assistant_usage(other) == 1


@pytest.mark.django_db
@pytest.mark.usefixtures("plans")
class TestScanLimit:
    def test_under_the_limit_is_allowed(
        self, authenticated_client, tenants_fixture, aws_provider
    ):
        _set_limits(tenants_fixture[0], **{SCANS: 2})
        _scan(tenants_fixture[0], aws_provider)
        response = _post_scan(authenticated_client, aws_provider)
        assert response.status_code != 403, response.content
        assert b"plan_limit_reached" not in response.content

    @pytest.mark.parametrize("existing", [2, 3])
    def test_at_and_over_the_limit_is_refused(
        self, authenticated_client, tenants_fixture, aws_provider, existing
    ):
        tenant = tenants_fixture[0]
        _set_limits(tenant, **{SCANS: 2})
        for _ in range(existing):
            _scan(tenant, aws_provider)
        response = _post_scan(authenticated_client, aws_provider)
        assert response.status_code == 403
        error = response.json()["errors"][0]
        assert error["code"] == "plan_limit_reached"
        assert error["meta"] == {"limit": SCANS, "max": 2, "usage": existing}
        assert Scan.all_objects.filter(tenant_id=tenant.id).count() == existing

    def test_last_month_scans_do_not_count(
        self, authenticated_client, tenants_fixture, aws_provider
    ):
        tenant = tenants_fixture[0]
        _set_limits(tenant, **{SCANS: 1})
        _scan(tenant, aws_provider, days_ago=1)
        response = _post_scan(authenticated_client, aws_provider)
        assert b"plan_limit_reached" not in response.content

    def test_unlimited_is_never_refused(
        self, authenticated_client, tenants_fixture, aws_provider
    ):
        tenant = tenants_fixture[0]
        _set_limits(tenant, **{SCANS: None})
        for _ in range(3):
            _scan(tenant, aws_provider)
        response = _post_scan(authenticated_client, aws_provider)
        assert b"plan_limit_reached" not in response.content

    def test_tenant_without_a_subscription_row_is_never_refused(
        self, authenticated_client, tenants_fixture, aws_provider
    ):
        tenant = tenants_fixture[0]
        assert not Subscription.objects.filter(tenant_id=tenant.id).exists()
        for _ in range(3):
            _scan(tenant, aws_provider)
        response = _post_scan(authenticated_client, aws_provider)
        assert response.status_code != 403, response.content

    def test_lookup_failure_fails_open(
        self, authenticated_client, tenants_fixture, aws_provider
    ):
        tenant = tenants_fixture[0]
        _set_limits(tenant, **{SCANS: 1})
        _scan(tenant, aws_provider)
        with patch.object(service, "usage_for_tenant", side_effect=RuntimeError("x")):
            response = _post_scan(authenticated_client, aws_provider)
        assert response.status_code != 403, response.content


@pytest.mark.django_db
@pytest.mark.usefixtures("plans")
class TestAssistantRequestLimit:
    def test_under_the_limit_is_recorded(self, authenticated_client, tenants_fixture):
        tenant = tenants_fixture[0]
        _set_limits(tenant, **{ASSISTANT: 2})
        _assistant_event(tenant)
        response = _post_assistant_request(authenticated_client)
        assert response.status_code == 201, response.content
        assert response.json()["data"]["attributes"] == {"limit": 2}
        assert _assistant_usage(tenant) == 2

    @pytest.mark.parametrize("existing", [2, 3])
    def test_at_and_over_the_limit_is_refused(
        self, authenticated_client, tenants_fixture, existing
    ):
        tenant = tenants_fixture[0]
        _set_limits(tenant, **{ASSISTANT: 2})
        for _ in range(existing):
            _assistant_event(tenant)
        response = _post_assistant_request(authenticated_client)
        assert response.status_code == 403
        error = response.json()["errors"][0]
        assert error["code"] == "plan_limit_reached"
        assert error["meta"] == {"limit": ASSISTANT, "max": 2, "usage": existing}
        # A refused request is not counted.
        assert _assistant_usage(tenant) == existing

    def test_requests_run_up_to_the_limit_then_stop(
        self, authenticated_client, tenants_fixture
    ):
        _set_limits(tenants_fixture[0], **{ASSISTANT: 2})
        codes = []
        for _ in range(3):
            codes.append(_post_assistant_request(authenticated_client).status_code)
        assert codes == [201, 201, 403]

    def test_unlimited_is_never_refused(self, authenticated_client, tenants_fixture):
        tenant = tenants_fixture[0]
        _set_limits(tenant, **{ASSISTANT: None})
        for _ in range(3):
            _assistant_event(tenant)
        response = _post_assistant_request(authenticated_client)
        assert response.status_code == 201, response.content
        assert response.json()["data"]["attributes"] == {"limit": None}

    def test_tenant_without_a_subscription_row_is_never_refused(
        self, authenticated_client, tenants_fixture
    ):
        tenant = tenants_fixture[0]
        assert not Subscription.objects.filter(tenant_id=tenant.id).exists()
        for _ in range(3):
            _assistant_event(tenant)
        assert _post_assistant_request(authenticated_client).status_code == 201

    def test_lookup_failure_fails_open(self, authenticated_client, tenants_fixture):
        with patch.object(service, "for_tenant", side_effect=RuntimeError("boom")):
            response = _post_assistant_request(authenticated_client)
        assert response.status_code == 201, response.content

    def test_plan_without_the_assistant_is_refused_as_a_feature(
        self, authenticated_client, tenants_fixture
    ):
        service.update_subscription(
            str(tenants_fixture[0].id), {"plan": "starter"}, source="system"
        )
        response = _post_assistant_request(authenticated_client)
        assert response.status_code == 403
        assert response.json()["errors"][0]["code"] == "feature_not_in_plan"

    def test_requires_authentication(self, client):
        assert _post_assistant_request(client).status_code == 401

    def test_get_is_not_allowed(self, authenticated_client, tenants_fixture):
        response = authenticated_client.get(reverse("seeker-ai-requests-list"))
        assert response.status_code == 405
