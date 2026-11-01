"""Encryption key rotation (EB-016): key ring, re-encryption command."""

from __future__ import annotations

from io import StringIO
from unittest.mock import patch

import pytest
from api.db_router import MainRouter
from api.models import ProviderSecret
from cloudsneeker_api.crypto import build_fernet, previous_keys
from cloudsneeker_api.models import UserMfa
from cloudsneeker_api.services import secret_rotation
from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.core.management import CommandError, call_command

NEW_KEY = Fernet.generate_key().decode()


class TestKeyRing:
    def test_previous_keys_skip_placeholders(self):
        assert previous_keys(" a , unconfigured,,none, b ") == ["a", "b"]
        assert previous_keys("") == []

    def test_encrypts_with_the_primary_and_reads_old_tokens(self):
        old_key = Fernet.generate_key().decode()
        old_token = Fernet(old_key.encode()).encrypt(b"secret")
        ring = build_fernet(NEW_KEY, [old_key])
        assert ring.decrypt(old_token) == b"secret"
        new_token = ring.encrypt(b"secret")
        assert Fernet(NEW_KEY.encode()).decrypt(new_token) == b"secret"
        with pytest.raises(InvalidToken):
            Fernet(old_key.encode()).decrypt(new_token)

    def test_previous_keys_come_from_the_environment(self, monkeypatch):
        old_key = Fernet.generate_key().decode()
        monkeypatch.setenv("DJANGO_SECRETS_ENCRYPTION_KEY_PREVIOUS", old_key)
        old_token = Fernet(old_key.encode()).encrypt(b"x")
        assert build_fernet(NEW_KEY).decrypt(old_token) == b"x"

    def test_api_keys_default_to_the_data_key(self):
        assert settings.DRF_API_KEY["FERNET_SECRET"] == settings.SECRETS_ENCRYPTION_KEY


@pytest.fixture
def rotated_to_new_key():
    """The app now runs on NEW_KEY with the test key as the previous key."""
    old_key = settings.SECRETS_ENCRYPTION_KEY
    with (
        patch.object(
            secret_rotation, "_primary", return_value=Fernet(NEW_KEY.encode())
        ),
        patch.object(
            secret_rotation, "_ring", return_value=build_fernet(NEW_KEY, [old_key])
        ),
    ):
        yield


def _by_label(reports):
    return {report.label: report for report in reports}


@pytest.mark.django_db
class TestRotation:
    def test_everything_is_current_before_a_rotation(
        self, create_test_user, provider_secret_fixture
    ):
        UserMfa(user=create_test_user, secret="JBSWY3DPEHPK3PXP").save()
        for report in secret_rotation.scan():
            assert report.stale == 0
            assert report.unreadable == 0
        reports = _by_label(secret_rotation.scan())
        assert reports["api.ProviderSecret._secret"].current == len(
            provider_secret_fixture
        )
        assert reports["cloudsneeker_api.UserMfa.secret_encrypted"].current == 1

    def test_rotates_stale_values(
        self, create_test_user, provider_secret_fixture, rotated_to_new_key
    ):
        UserMfa(user=create_test_user, secret="JBSWY3DPEHPK3PXP").save()

        before = _by_label(secret_rotation.scan())
        assert before["api.ProviderSecret._secret"].stale == len(
            provider_secret_fixture
        )
        assert before["cloudsneeker_api.UserMfa.secret_encrypted"].stale == 1

        rotated = _by_label(secret_rotation.rotate())
        assert rotated["api.ProviderSecret._secret"].rotated == len(
            provider_secret_fixture
        )

        new = Fernet(NEW_KEY.encode())
        # Outside a tenant context only the admin connection sees every row.
        secrets = ProviderSecret.objects.using(MainRouter.admin_db).all()
        assert len(secrets) == len(provider_secret_fixture)
        for secret in secrets:
            assert new.decrypt(bytes(secret._secret)) == b'{"key": "value"}'
        mfa = UserMfa.objects.get(user=create_test_user)
        assert isinstance(mfa.secret_encrypted, str)
        assert new.decrypt(mfa.secret_encrypted.encode()) == b"JBSWY3DPEHPK3PXP"

        after = secret_rotation.scan()
        assert all(report.stale == 0 for report in after)

    def test_reports_values_no_key_can_read(self, create_test_user):
        stranger = Fernet(Fernet.generate_key()).encrypt(b"x").decode()
        UserMfa.objects.create(user=create_test_user, secret_encrypted=stranger)
        report = _by_label(secret_rotation.rotate())[
            "cloudsneeker_api.UserMfa.secret_encrypted"
        ]
        assert report.unreadable == 1
        assert report.rotated == 0
        assert UserMfa.objects.get(user=create_test_user).secret_encrypted == stranger


@pytest.mark.django_db
class TestCommand:
    def test_check_fails_while_values_are_stale(
        self, create_test_user, rotated_to_new_key
    ):
        UserMfa(user=create_test_user, secret="JBSWY3DPEHPK3PXP").save()
        with pytest.raises(CommandError, match="still need a previous key"):
            call_command("cloudsneeker_rotate_secrets", "--check", stdout=StringIO())

    def test_rotate_then_check_passes(self, create_test_user, rotated_to_new_key):
        UserMfa(user=create_test_user, secret="JBSWY3DPEHPK3PXP").save()
        out = StringIO()
        call_command("cloudsneeker_rotate_secrets", stdout=out)
        assert "UserMfa.secret_encrypted: current=0 stale=1 rotated=1" in (
            out.getvalue()
        )
        out = StringIO()
        call_command("cloudsneeker_rotate_secrets", "--check", stdout=out)
        assert "All stored secrets use the current key." in out.getvalue()
        # Values never reach the output.
        assert "JBSWY3DPEHPK3PXP" not in out.getvalue()

    def test_unreadable_values_fail_the_command(self, create_test_user):
        stranger = Fernet(Fernet.generate_key()).encrypt(b"x").decode()
        UserMfa.objects.create(user=create_test_user, secret_encrypted=stranger)
        with pytest.raises(CommandError, match="cannot be read"):
            call_command("cloudsneeker_rotate_secrets", stdout=StringIO())
