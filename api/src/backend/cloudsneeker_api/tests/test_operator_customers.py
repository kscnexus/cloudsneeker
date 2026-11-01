"""Operator console: create a customer organization and invite its admin."""

from __future__ import annotations

import json

import pytest
from api.models import (
    Invitation,
    InvitationRoleRelationship,
    Membership,
    Role,
    Tenant,
    User,
)
from api.utils import accept_invitation_for_user
from cloudsneeker_api import signup
from cloudsneeker_api.models import (
    JSON_API_TYPE_PREFIX,
    OperatorAuditEvent,
    Plan,
    PlatformOperator,
    Subscription,
    SubscriptionEvent,
)
from cloudsneeker_api.services import plan_catalog as catalog
from django.core.cache import cache
from django.urls import reverse
from rest_framework import status

JSONAPI = "application/vnd.api+json"
TENANT_TYPE = f"{JSON_API_TYPE_PREFIX}operator-tenants"
PASSWORD = "NewPassword123!"
ADMIN_EMAIL = "admin@acme.example"


@pytest.fixture(autouse=True)
def _clear_entitlement_cache():
    cache.clear()
    yield
    cache.clear()


@pytest.fixture(autouse=True)
def _plans(request):
    if request.node.get_closest_marker("django_db"):
        request.getfixturevalue("db")
        catalog.seed_plans(Plan, using="default")


@pytest.fixture
def make_operator(create_test_user):
    def _make(role: str = "owner"):
        operator, _ = PlatformOperator.objects.update_or_create(
            user=create_test_user, defaults={"role": role, "active": True}
        )
        return operator

    return _make


def _create_customer(client, **attributes):
    payload = {"name": "Acme Corp", "admin_email": ADMIN_EMAIL}
    payload.update(attributes)
    return client.post(
        reverse("operator-tenant-list"),
        data=json.dumps({"data": {"type": TENANT_TYPE, "attributes": payload}}),
        content_type=JSONAPI,
    )


def _resend(client, tenant_id):
    return client.post(
        reverse("operator-tenant-invitation", kwargs={"tenant_id": tenant_id}),
        data=json.dumps({"data": {"type": TENANT_TYPE, "attributes": {}}}),
        content_type=JSONAPI,
    )


@pytest.mark.django_db
class TestCreateCustomer:
    def test_creates_tenant_admin_role_invitation_and_subscription(
        self, authenticated_client, make_operator, create_test_user
    ):
        make_operator("billing")
        response = _create_customer(
            authenticated_client,
            plan="starter",
            status="trial",
            trial_ends_at="2027-01-31",
            external_customer_id="CRM-42",
        )
        assert response.status_code == status.HTTP_201_CREATED, response.json()
        body = response.json()
        tenant = Tenant.objects.get(id=body["data"]["id"])
        assert tenant.name == "Acme Corp"
        assert body["data"]["attributes"]["plan"] == "starter"
        assert body["data"]["attributes"]["status"] == "trial"

        role = Role.objects.get(tenant_id=tenant.id, name="admin")
        assert all(getattr(role, field) for field in Role.PERMISSION_FIELDS)
        assert role.unlimited_visibility

        invitation = Invitation.objects.get(tenant_id=tenant.id)
        assert invitation.email == ADMIN_EMAIL
        assert invitation.state == Invitation.State.PENDING
        assert invitation.inviter_id == create_test_user.id
        assert InvitationRoleRelationship.objects.filter(
            invitation=invitation, role=role
        ).exists()
        meta = body["meta"]["invitation"]
        assert meta["token"] == invitation.token
        assert meta["email"] == ADMIN_EMAIL
        assert meta["expires_at"]

        subscription = Subscription.objects.select_related("plan").get(
            tenant_id=tenant.id
        )
        assert subscription.plan.code == "starter"
        assert subscription.status == "trial"
        assert subscription.trial_ends_at.date().isoformat() == "2027-01-31"
        assert subscription.external_customer_id == "CRM-42"
        assert SubscriptionEvent.objects.filter(tenant_id=tenant.id).exists()

        # The operator never becomes a member of the customer's organization.
        assert not Membership.objects.filter(tenant_id=tenant.id).exists()

        event = OperatorAuditEvent.objects.get(action="tenant.create")
        assert event.tenant_id == tenant.id
        assert event.actor_email == create_test_user.email
        assert ADMIN_EMAIL not in json.dumps(event.metadata)

    def test_defaults_to_default_plan_and_active(
        self, authenticated_client, make_operator
    ):
        make_operator("owner")
        response = _create_customer(authenticated_client)
        assert response.status_code == status.HTTP_201_CREATED
        subscription = Subscription.objects.select_related("plan").get(
            tenant_id=response.json()["data"]["id"]
        )
        assert subscription.plan.code == catalog.default_plan_code()
        assert subscription.status == catalog.STATUS_ACTIVE

    @pytest.mark.parametrize("role", ["support", "read_only"])
    def test_viewing_roles_cannot_create(
        self, authenticated_client, make_operator, role
    ):
        make_operator(role)
        before = Tenant.objects.count()
        assert _create_customer(authenticated_client).status_code == 403
        assert Tenant.objects.count() == before

    def test_tenant_admin_without_operator_role_gets_404(self, authenticated_client):
        assert _create_customer(authenticated_client).status_code == 404

    @pytest.mark.parametrize(
        "attributes",
        [
            {"name": ""},
            {"name": "x" * 101},
            {"admin_email": ""},
            {"admin_email": "not-an-email"},
            {"plan": "no-such-plan"},
            {"status": "suspended"},
            {"ends_at": "tomorrow"},
        ],
    )
    def test_invalid_request_creates_nothing(
        self, authenticated_client, make_operator, attributes
    ):
        make_operator("owner")
        tenants = Tenant.objects.count()
        invitations = Invitation.objects.count()
        response = _create_customer(authenticated_client, **attributes)
        assert response.status_code == 400, response.json()
        assert "errors" in response.json()
        assert Tenant.objects.count() == tenants
        assert Invitation.objects.count() == invitations

    def test_new_customer_appears_in_the_list(
        self, authenticated_client, make_operator
    ):
        make_operator("owner")
        tenant_id = _create_customer(authenticated_client).json()["data"]["id"]
        listed = authenticated_client.get(
            reverse("operator-tenant-list"), {"filter[search]": "acme"}
        ).json()["data"]
        assert [row["id"] for row in listed] == [tenant_id]
        assert listed[0]["attributes"]["member_count"] == 0


@pytest.mark.django_db
class TestFirstAdminBecomesOwner:
    def test_sign_up_with_invitation_makes_the_admin_owner(
        self, authenticated_client, make_operator, client, monkeypatch
    ):
        monkeypatch.setenv(signup.ENV_VAR, "false")
        make_operator("owner")
        body = _create_customer(authenticated_client).json()
        token = body["meta"]["invitation"]["token"]

        response = client.post(
            f"{reverse('user-list')}?invitation_token={token}",
            data={"name": "Acme Admin", "password": PASSWORD, "email": ADMIN_EMAIL},
            format="json",
        )
        assert response.status_code == status.HTTP_201_CREATED, response.json()

        user = User.objects.get(email=ADMIN_EMAIL)
        membership = Membership.objects.get(user=user, tenant_id=body["data"]["id"])
        assert membership.role == Membership.RoleChoices.OWNER
        role = Role.objects.get(tenant_id=body["data"]["id"], name="admin")
        assert role.users.filter(id=user.id).exists()

    def test_existing_user_accepting_becomes_owner(
        self, authenticated_client, make_operator
    ):
        make_operator("owner")
        body = _create_customer(authenticated_client).json()
        user = User.objects.create_user(
            name="Acme Admin", email=ADMIN_EMAIL, password=PASSWORD
        )
        accept_invitation_for_user(
            user=user, invitation_token=body["meta"]["invitation"]["token"]
        )
        membership = Membership.objects.get(user=user, tenant_id=body["data"]["id"])
        assert membership.role == Membership.RoleChoices.OWNER

    def test_non_operator_invitation_to_an_empty_organization_stays_member(
        self, create_test_user
    ):
        # Upstream flows (e.g. social sign-in) can accept into a tenant with no
        # members; only invitations sent by a platform operator promote.
        tenant = Tenant.objects.create(name="Empty")
        invitation = Invitation.objects.create(
            tenant_id=tenant.id, email="frank@example.com", inviter=create_test_user
        )
        user = User.objects.create_user(
            name="Frank", email="frank@example.com", password=PASSWORD
        )
        accept_invitation_for_user(user=user, invitation_token=invitation.token)
        membership = Membership.objects.get(user=user, tenant=tenant)
        assert membership.role == Membership.RoleChoices.MEMBER

    def test_invitation_to_an_existing_organization_stays_member(
        self, tenants_fixture, create_test_user
    ):
        # ``tenants_fixture[0]`` already has a member (the test user).
        tenant = tenants_fixture[0]
        invitation = Invitation.objects.create(
            tenant_id=tenant.id, email="teammate@example.com"
        )
        user = User.objects.create_user(
            name="Teammate", email="teammate@example.com", password=PASSWORD
        )
        accept_invitation_for_user(user=user, invitation_token=invitation.token)
        membership = Membership.objects.get(user=user, tenant=tenant)
        assert membership.role == Membership.RoleChoices.MEMBER


@pytest.mark.django_db
class TestResendAdminInvitation:
    def test_resend_revokes_the_pending_invitation(
        self, authenticated_client, make_operator
    ):
        make_operator("billing")
        body = _create_customer(authenticated_client).json()
        tenant_id = body["data"]["id"]
        first = Invitation.objects.get(tenant_id=tenant_id)

        response = _resend(authenticated_client, tenant_id)
        assert response.status_code == status.HTTP_201_CREATED, response.json()
        first.refresh_from_db()
        assert first.state == Invitation.State.REVOKED
        pending = Invitation.objects.get(
            tenant_id=tenant_id, state=Invitation.State.PENDING
        )
        assert pending.email == ADMIN_EMAIL
        assert response.json()["meta"]["invitation"]["token"] == pending.token
        assert pending.roles.filter(name="admin").exists()
        assert OperatorAuditEvent.objects.filter(
            action="tenant.invitation_resend", tenant_id=tenant_id
        ).exists()

    def test_resend_to_another_email(self, authenticated_client, make_operator):
        make_operator("owner")
        tenant_id = _create_customer(authenticated_client).json()["data"]["id"]
        response = authenticated_client.post(
            reverse("operator-tenant-invitation", kwargs={"tenant_id": tenant_id}),
            data=json.dumps(
                {
                    "data": {
                        "type": TENANT_TYPE,
                        "attributes": {"admin_email": "other@acme.example"},
                    }
                }
            ),
            content_type=JSONAPI,
        )
        assert response.status_code == status.HTTP_201_CREATED
        assert response.json()["meta"]["invitation"]["email"] == "other@acme.example"

    def test_resend_refused_once_the_organization_has_members(
        self, authenticated_client, make_operator, tenants_fixture
    ):
        make_operator("owner")
        response = _resend(authenticated_client, tenants_fixture[0].id)
        assert response.status_code == status.HTTP_409_CONFLICT

    def test_support_cannot_resend(self, authenticated_client, make_operator):
        make_operator("owner")
        tenant_id = _create_customer(authenticated_client).json()["data"]["id"]
        make_operator("support")
        assert _resend(authenticated_client, tenant_id).status_code == 403

    def test_detail_shows_the_pending_admin_invitation(
        self, authenticated_client, make_operator
    ):
        make_operator("owner")
        tenant_id = _create_customer(authenticated_client).json()["data"]["id"]
        attributes = authenticated_client.get(
            reverse("operator-tenant-detail", kwargs={"tenant_id": tenant_id})
        ).json()["data"]["attributes"]
        pending = attributes["pending_invitations"]
        assert len(pending) == 1
        assert pending[0]["email"] == ADMIN_EMAIL
        assert pending[0]["token"]


def test_openapi_schema_lists_customer_creation():
    from drf_spectacular.generators import SchemaGenerator

    paths = SchemaGenerator().get_schema(request=None, public=True)["paths"]
    assert "post" in paths["/api/v1/operator/tenants"]
    assert "post" in paths["/api/v1/operator/tenants/{tenant_id}/invitations"]


def test_signal_receiver_is_connected():
    from django.db.models.signals import post_save

    assert any(
        "invitation_promote_sole_member" in str(receiver[0])
        for receiver in post_save.receivers
    )
