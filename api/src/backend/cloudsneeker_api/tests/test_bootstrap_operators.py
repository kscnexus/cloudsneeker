"""First operator owner from CLOUDSNEEKER_BOOTSTRAP_OPERATOR_EMAILS."""

from __future__ import annotations

import pytest
from api.models import User
from cloudsneeker_api.models import OperatorAuditEvent, PlatformOperator
from cloudsneeker_api.services import bootstrap_operators
from cloudsneeker_api.services import plan_catalog as catalog
from cloudsneeker_api.tasks import operator_daily_task

PASSWORD = "NewPassword123!"
OWNER_EMAIL = "founder@acme.example"


def _signup(email: str, capture) -> User:
    with capture(execute=True):
        return User.objects.create_user(name="Founder", email=email, password=PASSWORD)


@pytest.fixture
def bootstrap_env(monkeypatch):
    monkeypatch.setenv(
        bootstrap_operators.ENV_VAR, f" {OWNER_EMAIL.upper()} , ops@acme.example"
    )


class TestBootstrapEmails:
    def test_unset_is_empty(self, monkeypatch):
        monkeypatch.delenv(bootstrap_operators.ENV_VAR, raising=False)
        assert bootstrap_operators.bootstrap_emails() == set()

    def test_parses_and_lowercases(self, bootstrap_env):
        assert bootstrap_operators.bootstrap_emails() == {
            OWNER_EMAIL,
            "ops@acme.example",
        }


@pytest.mark.django_db
class TestSignupGrant:
    def test_listed_signup_becomes_owner(
        self, bootstrap_env, django_capture_on_commit_callbacks
    ):
        user = _signup(OWNER_EMAIL, django_capture_on_commit_callbacks)
        operator = PlatformOperator.objects.get(user=user)
        assert operator.role == catalog.OPERATOR_ROLE_OWNER
        assert operator.active
        assert operator.granted_by == bootstrap_operators.ENV_ACTOR
        event = OperatorAuditEvent.objects.get(target_id=str(operator.id))
        assert event.actor_email == bootstrap_operators.ENV_ACTOR
        assert event.action == "operator.grant"

    def test_unlisted_signup_gets_nothing(
        self, bootstrap_env, django_capture_on_commit_callbacks
    ):
        user = _signup("someone@else.example", django_capture_on_commit_callbacks)
        assert not PlatformOperator.objects.filter(user=user).exists()

    def test_env_unset_grants_nothing(
        self, monkeypatch, django_capture_on_commit_callbacks
    ):
        monkeypatch.delenv(bootstrap_operators.ENV_VAR, raising=False)
        user = _signup(OWNER_EMAIL, django_capture_on_commit_callbacks)
        assert not PlatformOperator.objects.filter(user=user).exists()

    def test_inert_once_an_owner_exists(
        self, bootstrap_env, create_test_user, django_capture_on_commit_callbacks
    ):
        PlatformOperator.objects.create(
            user=create_test_user, role=catalog.OPERATOR_ROLE_OWNER, active=True
        )
        user = _signup(OWNER_EMAIL, django_capture_on_commit_callbacks)
        assert not PlatformOperator.objects.filter(user=user).exists()

    def test_second_listed_signup_is_not_granted(
        self, bootstrap_env, django_capture_on_commit_callbacks
    ):
        _signup(OWNER_EMAIL, django_capture_on_commit_callbacks)
        second = _signup("ops@acme.example", django_capture_on_commit_callbacks)
        assert not PlatformOperator.objects.filter(user=second).exists()


@pytest.mark.django_db
class TestReconcile:
    def test_existing_listed_user_is_granted(self, monkeypatch):
        # Created before the variable was set, so only reconcile can grant.
        user = User.objects.create_user(
            name="Founder", email=OWNER_EMAIL, password=PASSWORD
        )
        monkeypatch.setenv(bootstrap_operators.ENV_VAR, OWNER_EMAIL)
        assert bootstrap_operators.reconcile() == 1
        assert (
            PlatformOperator.objects.get(user=user).role == catalog.OPERATOR_ROLE_OWNER
        )
        assert bootstrap_operators.reconcile() == 0

    def test_revoked_operator_is_not_reactivated(self, monkeypatch):
        user = User.objects.create_user(
            name="Founder", email=OWNER_EMAIL, password=PASSWORD
        )
        PlatformOperator.objects.create(
            user=user, role=catalog.OPERATOR_ROLE_OWNER, active=False
        )
        monkeypatch.setenv(bootstrap_operators.ENV_VAR, OWNER_EMAIL)
        assert bootstrap_operators.reconcile() == 0
        assert not PlatformOperator.objects.get(user=user).active

    def test_daily_task_reports_bootstrap(self, monkeypatch):
        User.objects.create_user(name="Founder", email=OWNER_EMAIL, password=PASSWORD)
        monkeypatch.setenv(bootstrap_operators.ENV_VAR, OWNER_EMAIL)
        assert operator_daily_task()["bootstrap_operators"] == 1
