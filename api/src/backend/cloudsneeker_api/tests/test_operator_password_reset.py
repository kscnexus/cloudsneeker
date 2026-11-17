"""Operator console: reset a user's password with a one-time temporary password."""

from __future__ import annotations

import json
import logging
from unittest.mock import patch
from uuid import uuid4

import pytest
from api.models import Membership, User
from cloudsneeker_api import login_guard
from cloudsneeker_api.models import OperatorAuditEvent, PlatformOperator
from cloudsneeker_api.services import password_reset
from django.contrib.auth.password_validation import validate_password
from django.core.cache import cache, caches
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework_simplejwt.token_blacklist.models import (
    BlacklistedToken,
    OutstandingToken,
)
from rest_framework_simplejwt.tokens import RefreshToken

OLD_PASSWORD = "OldPassword123!"
TARGET_EMAIL = "member@acme.example"


@pytest.fixture(autouse=True)
def _clear_caches():
    cache.clear()
    caches[login_guard.CACHE_ALIAS].clear()
    yield
    cache.clear()
    caches[login_guard.CACHE_ALIAS].clear()


@pytest.fixture
def make_operator(create_test_user):
    def _make(role: str = "owner", user=None):
        operator, _ = PlatformOperator.objects.update_or_create(
            user=user or create_test_user, defaults={"role": role, "active": True}
        )
        return operator

    return _make


@pytest.fixture
def target_user(tenants_fixture):
    user = User.objects.create_user(
        name="Member", email=TARGET_EMAIL, password=OLD_PASSWORD
    )
    Membership.objects.create(user=user, tenant=tenants_fixture[2])
    return user


def _reset(client, tenant_id, user_id):
    return client.post(
        reverse(
            "operator-user-password-reset",
            kwargs={"tenant_id": tenant_id, "user_id": user_id},
        )
    )


def _sign_in(email, password):
    return APIClient().post(
        reverse("token-obtain"),
        data={
            "data": {
                "type": "tokens",
                "attributes": {"email": email, "password": password},
            }
        },
        format="vnd.api+json",
    )


@pytest.mark.django_db
class TestOperatorPasswordReset:
    @pytest.mark.parametrize("role", ["owner", "support"])
    def test_operator_resets_password(
        self, authenticated_client, make_operator, target_user, tenants_fixture, role
    ):
        make_operator(role)
        response = _reset(authenticated_client, tenants_fixture[2].id, target_user.id)

        assert response.status_code == status.HTTP_200_OK, response.json()
        assert response["Cache-Control"] == "no-store"
        body = response.json()
        temporary = body["meta"]["temporary_password"]
        assert body["data"]["attributes"]["email"] == TARGET_EMAIL
        assert len(temporary) == password_reset.TEMPORARY_PASSWORD_LENGTH

        target_user.refresh_from_db()
        assert target_user.check_password(temporary)
        assert not target_user.check_password(OLD_PASSWORD)
        # Only the hash is stored.
        assert temporary not in target_user.password

    def test_new_password_signs_in_and_old_does_not(
        self, authenticated_client, make_operator, target_user, tenants_fixture
    ):
        make_operator("owner")
        temporary = _reset(
            authenticated_client, tenants_fixture[2].id, target_user.id
        ).json()["meta"]["temporary_password"]

        assert _sign_in(TARGET_EMAIL, temporary).status_code == status.HTTP_200_OK
        assert _sign_in(TARGET_EMAIL, OLD_PASSWORD).status_code == 400

    def test_writes_operator_audit_without_secret(
        self,
        authenticated_client,
        make_operator,
        target_user,
        tenants_fixture,
        create_test_user,
    ):
        make_operator("support")
        temporary = _reset(
            authenticated_client, tenants_fixture[2].id, target_user.id
        ).json()["meta"]["temporary_password"]

        event = OperatorAuditEvent.objects.get(action="user.password_reset")
        assert event.tenant_id == tenants_fixture[2].id
        assert event.target_type == "user"
        assert event.target_id == str(target_user.id)
        assert event.actor_email == create_test_user.email
        assert event.actor_role == "support"
        assert event.changed_fields == ["password"]
        assert event.metadata["method"] == "temporary_password"
        stored = json.dumps(
            [event.metadata, event.changed_fields, event.target_id, event.user_agent]
        )
        assert temporary not in stored

    def test_temporary_password_is_never_logged(
        self, authenticated_client, make_operator, target_user, tenants_fixture, caplog
    ):
        make_operator("owner")
        with caplog.at_level(logging.DEBUG):
            temporary = _reset(
                authenticated_client, tenants_fixture[2].id, target_user.id
            ).json()["meta"]["temporary_password"]
        assert temporary not in caplog.text

    def test_clears_sign_in_lockout(
        self, authenticated_client, make_operator, target_user, tenants_fixture
    ):
        make_operator("owner")
        for _ in range(5):
            login_guard.record_failure(TARGET_EMAIL)
        assert login_guard.failures(TARGET_EMAIL) == 5

        response = _reset(authenticated_client, tenants_fixture[2].id, target_user.id)

        assert response.json()["data"]["attributes"]["lockout_cleared"] is True
        assert login_guard.failures(TARGET_EMAIL) == 0

    def test_revokes_refresh_tokens(
        self, authenticated_client, make_operator, target_user, tenants_fixture
    ):
        make_operator("owner")
        refresh_tokens = [RefreshToken.for_user(target_user) for _ in range(2)]
        assert OutstandingToken.objects.filter(user=target_user).count() == 2

        response = _reset(authenticated_client, tenants_fixture[2].id, target_user.id)

        assert response.json()["data"]["attributes"]["revoked_sessions"] == 2
        assert BlacklistedToken.objects.filter(token__user=target_user).count() == 2
        refresh = APIClient().post(
            reverse("token-refresh"),
            data={
                "data": {
                    "type": "tokens-refresh",
                    "attributes": {"refresh": str(refresh_tokens[0])},
                }
            },
            format="vnd.api+json",
        )
        assert refresh.status_code != status.HTTP_200_OK

    @pytest.mark.parametrize("role", ["billing", "read_only"])
    def test_other_operator_roles_get_403(
        self, authenticated_client, make_operator, target_user, tenants_fixture, role
    ):
        make_operator(role)
        response = _reset(authenticated_client, tenants_fixture[2].id, target_user.id)

        assert response.status_code == status.HTTP_403_FORBIDDEN
        target_user.refresh_from_db()
        assert target_user.check_password(OLD_PASSWORD)
        assert not OperatorAuditEvent.objects.filter(
            action="user.password_reset"
        ).exists()

    def test_tenant_admin_without_operator_role_is_refused(
        self, authenticated_client, target_user, tenants_fixture
    ):
        # The signed-in user is an admin of the tenant, but not an operator:
        # the operator API answers 404, like every other operator route.
        response = _reset(authenticated_client, tenants_fixture[0].id, target_user.id)
        assert response.status_code == status.HTTP_404_NOT_FOUND
        response = _reset(authenticated_client, tenants_fixture[2].id, target_user.id)
        assert response.status_code == status.HTTP_404_NOT_FOUND
        target_user.refresh_from_db()
        assert target_user.check_password(OLD_PASSWORD)

    def test_anonymous_is_refused(self, target_user, tenants_fixture):
        response = _reset(APIClient(), tenants_fixture[2].id, target_user.id)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_user_outside_tenant_is_404(
        self, authenticated_client, make_operator, target_user, tenants_fixture
    ):
        make_operator("owner")
        response = _reset(authenticated_client, tenants_fixture[1].id, target_user.id)
        assert response.status_code == status.HTTP_404_NOT_FOUND
        response = _reset(authenticated_client, tenants_fixture[2].id, uuid4())
        assert response.status_code == status.HTTP_404_NOT_FOUND
        target_user.refresh_from_db()
        assert target_user.check_password(OLD_PASSWORD)

    def test_cannot_reset_own_password(
        self, authenticated_client, make_operator, create_test_user, tenants_fixture
    ):
        make_operator("owner")
        response = _reset(
            authenticated_client, tenants_fixture[0].id, create_test_user.id
        )
        assert response.status_code == status.HTTP_409_CONFLICT

    def test_cannot_reset_another_operator(
        self, authenticated_client, make_operator, target_user, tenants_fixture
    ):
        make_operator("support")
        make_operator("owner", user=target_user)
        response = _reset(authenticated_client, tenants_fixture[2].id, target_user.id)
        assert response.status_code == status.HTTP_409_CONFLICT
        target_user.refresh_from_db()
        assert target_user.check_password(OLD_PASSWORD)

    def test_cache_outage_still_resets(
        self, authenticated_client, make_operator, target_user, tenants_fixture
    ):
        make_operator("owner")
        with patch.object(
            login_guard, "clear_failures", side_effect=ConnectionError("down")
        ):
            response = _reset(
                authenticated_client, tenants_fixture[2].id, target_user.id
            )
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["lockout_cleared"] is False

    def test_me_lists_reset_capability(self, authenticated_client, make_operator):
        make_operator("support")
        response = authenticated_client.get(reverse("operator-me"))
        assert (
            "reset_passwords" in response.json()["data"]["attributes"]["capabilities"]
        )


@pytest.mark.django_db
class TestTemporaryPassword:
    def test_passes_validators_and_is_random(self, target_user):
        passwords = {
            password_reset.generate_temporary_password(target_user) for _ in range(20)
        }
        assert len(passwords) == 20
        for password in passwords:
            validate_password(password, target_user)
