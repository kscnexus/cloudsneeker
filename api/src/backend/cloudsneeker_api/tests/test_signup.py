"""Switch to close self sign-up (EB-002)."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from api.models import Invitation, Membership, User
from cloudsneeker_api import signup
from django.http import HttpResponse
from django.test import RequestFactory
from django.urls import reverse
from rest_framework import status

PASSWORD = "NewPassword123!"


def _payload(email):
    return {"name": "new user", "password": PASSWORD, "email": email}


def _sign_up(client, email, invitation_token=None):
    url = reverse("user-list")
    if invitation_token:
        url = f"{url}?invitation_token={invitation_token}"
    return client.post(url, data=_payload(email), format="json")


@pytest.fixture
def closed_signup(monkeypatch):
    monkeypatch.setenv(signup.ENV_VAR, "false")


@pytest.mark.django_db
class TestSignupGate:
    def test_open_by_default(self, client, create_test_user, monkeypatch):
        monkeypatch.delenv(signup.ENV_VAR, raising=False)
        response = _sign_up(client, "open@example.com")
        assert response.status_code == status.HTTP_201_CREATED

    @pytest.mark.parametrize("value", ["true", "", "yes"])
    def test_any_value_but_false_keeps_signup_open(
        self, client, create_test_user, monkeypatch, value
    ):
        monkeypatch.setenv(signup.ENV_VAR, value)
        response = _sign_up(client, f"open-{value or 'empty'}@example.com")
        assert response.status_code == status.HTTP_201_CREATED

    @pytest.mark.parametrize("value", ["false", "FALSE", " False "])
    def test_closed_refuses_uninvited_signup(
        self, client, create_test_user, monkeypatch, value
    ):
        monkeypatch.setenv(signup.ENV_VAR, value)
        response = _sign_up(client, "blocked@example.com")
        assert response.status_code == status.HTTP_403_FORBIDDEN
        error = response.json()["errors"][0]
        assert error["code"] == signup.CODE_SIGNUP_CLOSED
        assert not User.objects.filter(email="blocked@example.com").exists()

    def test_closed_accepts_valid_invitation(
        self, client, closed_signup, invitations_fixture
    ):
        invitation, _ = invitations_fixture
        response = _sign_up(client, invitation.email, invitation.token)
        assert response.status_code == status.HTTP_201_CREATED
        user = User.objects.get(email=invitation.email)
        membership = Membership.objects.get(user=user)
        assert membership.tenant_id == invitation.tenant_id
        assert membership.role == Membership.RoleChoices.MEMBER
        invitation.refresh_from_db()
        assert invitation.state == Invitation.State.ACCEPTED

    def test_closed_still_rejects_an_expired_invitation(
        self, client, closed_signup, invitations_fixture
    ):
        _, expired = invitations_fixture
        response = _sign_up(client, expired.email, expired.token)
        assert response.status_code >= status.HTTP_400_BAD_REQUEST
        assert not User.objects.filter(email=expired.email).exists()

    def test_closed_allows_the_first_user_of_a_new_install(self, client, closed_signup):
        assert not User.objects.exists()
        response = _sign_up(client, "owner@example.com")
        assert response.status_code == status.HTTP_201_CREATED

    def test_closed_leaves_other_requests_alone(
        self, authenticated_client, closed_signup
    ):
        response = authenticated_client.get(reverse("user-me"))
        assert response.status_code == status.HTTP_200_OK


class TestSignupGateMiddleware:
    def _middleware(self):
        return signup.SignupGateMiddleware(lambda request: HttpResponse("ok"))

    def test_fails_closed_when_the_user_lookup_errors(self, monkeypatch):
        monkeypatch.setenv(signup.ENV_VAR, "false")
        request = RequestFactory().post("/api/v1/users", data={})
        with patch.object(signup, "_has_users", side_effect=RuntimeError("db")):
            response = self._middleware()(request)
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_open_ignores_lookup_errors(self, monkeypatch):
        monkeypatch.delenv(signup.ENV_VAR, raising=False)
        request = RequestFactory().post("/api/v1/users", data={})
        with patch.object(signup, "_has_users", side_effect=RuntimeError("db")):
            response = self._middleware()(request)
        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.parametrize(
        "method,path",
        [
            ("get", "/api/v1/users"),
            ("post", "/api/v1/users/me"),
            ("post", "/api/v1/tokens"),
            ("post", "/api/v1/tenants"),
        ],
    )
    def test_only_user_creation_is_gated(self, monkeypatch, method, path):
        monkeypatch.setenv(signup.ENV_VAR, "false")
        request = getattr(RequestFactory(), method)(path)
        with patch.object(signup, "_has_users", return_value=True):
            response = self._middleware()(request)
        assert response.status_code == status.HTTP_200_OK
