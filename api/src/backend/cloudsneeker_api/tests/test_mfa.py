"""Multi-factor authentication (EB-008): TOTP, enrolment, sign-in, policy."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from api.db_utils import rls_transaction
from api.models import Membership, Role, Tenant, User, UserRoleRelationship
from cloudsneeker_api import mfa as middleware
from cloudsneeker_api.models import TenantMfaPolicy, UserMfa
from cloudsneeker_api.services import mfa as service
from cloudsneeker_api.services import totp
from conftest import TEST_PASSWORD, TEST_USER
from django.core.cache import cache
from django.test import Client
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

JSONAPI = "application/vnd.api+json"
# RFC 6238 appendix B: ASCII "12345678901234567890" as base32.
RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


@pytest.fixture(autouse=True)
def _clear_cache():
    cache.clear()
    yield
    cache.clear()


def _body(resource_type: str, attributes: dict) -> dict:
    return {"data": {"type": resource_type, "attributes": attributes}}


def _post(client, name: str, attributes: dict | None = None):
    return client.post(
        reverse(name),
        data=_body("mfa", attributes or {}),
        content_type=JSONAPI,
    )


def _sign_in(otp_code=None, email=TEST_USER, password=TEST_PASSWORD):
    attributes = {"email": email, "password": password}
    if otp_code is not None:
        attributes["otp_code"] = otp_code
    return APIClient().post(
        reverse("token-obtain"),
        data=_body("tokens", attributes),
        format="vnd.api+json",
    )


def _current_code(secret: str, offset_steps: int = 0) -> str:
    return totp.code_at(secret, totp.current_step() + offset_steps)


def _enrol(client) -> tuple[str, list[str]]:
    response = _post(client, "mfa-enrolment")
    assert response.status_code == status.HTTP_201_CREATED, response.content
    secret = response.json()["data"]["attributes"]["secret"]
    response = _post(client, "mfa-enrolment-confirm", {"code": _current_code(secret)})
    assert response.status_code == status.HTTP_200_OK, response.content
    return secret, response.json()["data"]["attributes"]["codes"]


def _force_next_step(user):
    """Let the test use the next code: the enrolment code spent this step."""
    UserMfa.objects.filter(user=user).update(last_used_step=totp.current_step() - 2)


class TestTotp:
    @pytest.mark.parametrize(
        "now,expected",
        [(59, "287082"), (1111111109, "081804"), (1234567890, "005924")],
    )
    def test_rfc_6238_vectors(self, now, expected):
        assert totp.code_at(RFC_SECRET, totp.current_step(now)) == expected

    def test_accepts_one_step_of_drift(self):
        code = totp.code_at(RFC_SECRET, totp.current_step(1000) - 1)
        assert totp.matching_step(RFC_SECRET, code, now=1000) is not None

    def test_refuses_two_steps_of_drift(self):
        code = totp.code_at(RFC_SECRET, totp.current_step(1000) - 2)
        assert totp.matching_step(RFC_SECRET, code, now=1000) is None

    def test_refuses_a_replayed_step(self):
        step = totp.current_step(1000)
        code = totp.code_at(RFC_SECRET, step)
        assert totp.matching_step(RFC_SECRET, code, after_step=step, now=1000) is None

    @pytest.mark.parametrize("code", ["", None, "12345", "abcdef", "1234567"])
    def test_refuses_malformed_codes(self, code):
        assert totp.matching_step(RFC_SECRET, code) is None

    def test_accepts_spaced_codes(self):
        code = totp.code_at(RFC_SECRET, totp.current_step(1000))
        assert totp.matching_step(RFC_SECRET, f"{code[:3]} {code[3:]}", now=1000)

    def test_provisioning_uri(self):
        uri = totp.provisioning_uri(RFC_SECRET, "a@example.com", "Cloudsneeker")
        assert uri.startswith("otpauth://totp/Cloudsneeker%3Aa%40example.com?")
        assert f"secret={RFC_SECRET}" in uri
        assert "issuer=Cloudsneeker" in uri


@pytest.mark.django_db
class TestEnrolment:
    def test_status_starts_off(self, authenticated_client):
        response = authenticated_client.get(reverse("mfa-status"))
        assert response.status_code == status.HTTP_200_OK
        attributes = response.json()["data"]["attributes"]
        assert attributes["enabled"] is False
        assert attributes["applies"] is True
        assert attributes["enrolment_required"] is False

    def test_enrol_and_confirm(self, authenticated_client, create_test_user):
        secret, codes = _enrol(authenticated_client)
        assert len(codes) == service.RECOVERY_CODE_COUNT
        assert len(set(codes)) == service.RECOVERY_CODE_COUNT
        mfa = UserMfa.objects.get(user=create_test_user)
        assert mfa.enabled
        assert mfa.secret == secret
        # Neither the secret nor the codes are stored in clear text.
        assert secret not in mfa.secret_encrypted
        assert not set(codes) & set(mfa.recovery_code_hashes)
        status_response = authenticated_client.get(reverse("mfa-status"))
        attributes = status_response.json()["data"]["attributes"]
        assert attributes["enabled"] is True
        assert attributes["recovery_codes_remaining"] == service.RECOVERY_CODE_COUNT

    def test_confirm_with_a_wrong_code(self, authenticated_client):
        _post(authenticated_client, "mfa-enrolment")
        response = _post(
            authenticated_client, "mfa-enrolment-confirm", {"code": "000000"}
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.json()["errors"][0]["code"] == "mfa_invalid"

    def test_confirm_without_enrolment(self, authenticated_client):
        response = _post(
            authenticated_client, "mfa-enrolment-confirm", {"code": "123456"}
        )
        assert response.status_code == status.HTTP_409_CONFLICT
        assert response.json()["errors"][0]["code"] == "mfa_not_pending"

    def test_cannot_restart_once_enabled(self, authenticated_client):
        _enrol(authenticated_client)
        response = _post(authenticated_client, "mfa-enrolment")
        assert response.status_code == status.HTTP_409_CONFLICT

    def test_unconfirmed_enrolment_does_not_gate_sign_in(self, authenticated_client):
        _post(authenticated_client, "mfa-enrolment")
        assert _sign_in().status_code == status.HTTP_200_OK

    def test_regenerate_recovery_codes(self, authenticated_client, create_test_user):
        secret, old_codes = _enrol(authenticated_client)
        _force_next_step(create_test_user)
        response = _post(
            authenticated_client, "mfa-recovery-codes", {"code": _current_code(secret)}
        )
        assert response.status_code == status.HTTP_200_OK
        new_codes = response.json()["data"]["attributes"]["codes"]
        assert not set(new_codes) & set(old_codes)
        assert _sign_in(old_codes[0]).status_code == status.HTTP_401_UNAUTHORIZED

    def test_disable(self, authenticated_client, create_test_user):
        secret, _ = _enrol(authenticated_client)
        _force_next_step(create_test_user)
        response = _post(
            authenticated_client, "mfa-disable", {"code": _current_code(secret)}
        )
        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not UserMfa.objects.filter(user=create_test_user).exists()
        assert _sign_in().status_code == status.HTTP_200_OK

    def test_disable_needs_a_valid_code(self, authenticated_client):
        _enrol(authenticated_client)
        response = _post(authenticated_client, "mfa-disable", {"code": "000000"})
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_sso_users_are_not_asked(self, authenticated_client, create_test_user):
        with patch.object(service, "is_password_user", return_value=False):
            response = _post(authenticated_client, "mfa-enrolment")
        assert response.status_code == status.HTTP_409_CONFLICT
        assert response.json()["errors"][0]["code"] == "mfa_not_applicable"


@pytest.mark.django_db
class TestSignIn:
    def test_without_mfa_nothing_changes(self, authenticated_client):
        response = _sign_in()
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["access"]

    def test_requires_a_code(self, authenticated_client):
        _enrol(authenticated_client)
        response = _sign_in()
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        body = response.json()
        assert body["errors"][0]["code"] == middleware.CODE_MFA_REQUIRED
        assert "access" not in str(body)

    def test_refuses_a_wrong_code(self, authenticated_client):
        _enrol(authenticated_client)
        response = _sign_in("000000")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response.json()["errors"][0]["code"] == middleware.CODE_MFA_INVALID

    def test_wrong_password_stays_a_plain_failure(self, authenticated_client):
        secret, _ = _enrol(authenticated_client)
        response = _sign_in(_current_code(secret, 1), password="wrong-password-1")
        assert response.status_code >= status.HTTP_400_BAD_REQUEST
        assert "mfa" not in str(response.json())

    def test_accepts_a_fresh_code_once(self, authenticated_client, create_test_user):
        secret, _ = _enrol(authenticated_client)
        _force_next_step(create_test_user)
        code = _current_code(secret)
        response = _sign_in(code)
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["access"]
        assert _sign_in(code).status_code == status.HTTP_401_UNAUTHORIZED

    def test_recovery_code_works_once(self, authenticated_client):
        _, codes = _enrol(authenticated_client)
        assert _sign_in(codes[0].lower()).status_code == status.HTTP_200_OK
        assert _sign_in(codes[0]).status_code == status.HTTP_401_UNAUTHORIZED
        assert _sign_in(codes[1]).status_code == status.HTTP_200_OK

    def test_sso_users_are_not_asked(self, authenticated_client):
        _enrol(authenticated_client)
        with patch.object(service, "is_password_user", return_value=False):
            assert _sign_in().status_code == status.HTTP_200_OK

    def test_fails_closed_when_the_check_errors(self, authenticated_client):
        _enrol(authenticated_client)
        with patch.object(service, "is_enabled", side_effect=RuntimeError("db")):
            response = _sign_in()
        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE


def _second_user(tenant) -> tuple[User, Client]:
    password = "Second-User-Pass-123"
    user = User.objects.create_user(
        name="second", email="second-mfa@example.com", password=password
    )
    Membership.objects.create(user=user, tenant=tenant)
    with rls_transaction(str(tenant.id)):
        role = Role.objects.create(
            name="viewer", tenant_id=tenant.id, unlimited_visibility=True
        )
        UserRoleRelationship.objects.create(user=user, role=role, tenant_id=tenant.id)
    response = _sign_in(email=user.email, password=password)
    assert response.status_code == status.HTTP_200_OK, response.content
    access = response.json()["data"]["attributes"]["access"]
    return user, Client(HTTP_AUTHORIZATION=f"Bearer {access}")


@pytest.mark.django_db
class TestTenantPolicy:
    def _require(self, client, value=True):
        return client.patch(
            reverse("mfa-policy"),
            data=_body("mfa-policies", {"require_mfa": value}),
            content_type=JSONAPI,
        )

    def test_admin_must_enrol_first(self, authenticated_client):
        response = self._require(authenticated_client)
        assert response.status_code == status.HTTP_409_CONFLICT
        assert response.json()["errors"][0]["code"] == "mfa_enrol_first"

    def test_admin_turns_it_on(self, authenticated_client, tenants_fixture):
        _enrol(authenticated_client)
        response = self._require(authenticated_client)
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["require_mfa"] is True
        assert TenantMfaPolicy.objects.get(tenant=tenants_fixture[0]).require_mfa
        get_response = authenticated_client.get(reverse("mfa-policy"))
        assert get_response.json()["data"]["attributes"]["require_mfa"] is True

    def test_rejects_a_non_boolean(self, authenticated_client):
        response = authenticated_client.patch(
            reverse("mfa-policy"),
            data=_body("mfa-policies", {"require_mfa": "yes"}),
            content_type=JSONAPI,
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_needs_manage_account(self, authenticated_client, tenants_fixture):
        _, client = _second_user(tenants_fixture[0])
        response = self._require(client, False)
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_unenrolled_users_are_held_at_setup(
        self, authenticated_client, tenants_fixture
    ):
        _enrol(authenticated_client)
        self._require(authenticated_client)
        user, client = _second_user(tenants_fixture[0])

        blocked = client.get(reverse("provider-list"))
        assert blocked.status_code == status.HTTP_403_FORBIDDEN
        assert blocked.json()["errors"][0]["code"] == (
            middleware.CODE_MFA_ENROLMENT_REQUIRED
        )
        status_response = client.get(reverse("mfa-status"))
        assert status_response.status_code == status.HTTP_200_OK
        assert status_response.json()["data"]["attributes"]["enrolment_required"]
        assert client.get(reverse("user-me")).status_code == status.HTTP_200_OK

        _enrol(client)
        assert client.get(reverse("provider-list")).status_code != (
            status.HTTP_403_FORBIDDEN
        )

    def test_enrolled_admin_is_not_held(self, authenticated_client):
        _enrol(authenticated_client)
        self._require(authenticated_client)
        response = authenticated_client.get(reverse("provider-list"))
        assert response.status_code == status.HTTP_200_OK

    def test_other_tenants_are_not_affected(
        self, authenticated_client, tenants_fixture
    ):
        _enrol(authenticated_client)
        self._require(authenticated_client)
        other = Tenant.objects.create(name="Other tenant")
        _, client = _second_user(other)
        assert client.get(reverse("provider-list")).status_code != (
            status.HTTP_403_FORBIDDEN
        )

    def test_cannot_disable_while_required(
        self, authenticated_client, create_test_user
    ):
        secret, _ = _enrol(authenticated_client)
        self._require(authenticated_client)
        _force_next_step(create_test_user)
        response = _post(
            authenticated_client, "mfa-disable", {"code": _current_code(secret)}
        )
        assert response.status_code == status.HTTP_409_CONFLICT
        assert response.json()["errors"][0]["code"] == "mfa_required_by_organization"

    def test_sso_users_are_not_held(self, authenticated_client, tenants_fixture):
        _enrol(authenticated_client)
        self._require(authenticated_client)
        _, client = _second_user(tenants_fixture[0])
        cache.clear()
        with patch.object(service, "is_password_user", return_value=False):
            response = client.get(reverse("provider-list"))
        assert response.status_code != status.HTTP_403_FORBIDDEN
