"""SAML hardening (EB-009): signing, signed assertions, IdP-initiated policy."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from allauth.socialaccount.models import SocialApp
from cloudsneeker_api import saml
from cloudsneeker_api.models import TenantSsoPolicy
from cloudsneeker_api.tests.test_mfa import _second_user
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.test import RequestFactory
from django.urls import reverse
from rest_framework import status

JSONAPI = "application/vnd.api+json"


@pytest.fixture(scope="module")
def sp_pem() -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-sp")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem


@pytest.fixture
def sp_keys(monkeypatch, sp_pem):
    cert_pem, key_pem = sp_pem
    monkeypatch.setenv(saml.CERT_ENV, cert_pem)
    monkeypatch.setenv(saml.KEY_ENV, key_pem)
    return sp_pem


@pytest.fixture
def no_sp_keys(monkeypatch):
    monkeypatch.delenv(saml.CERT_ENV, raising=False)
    monkeypatch.delenv(saml.KEY_ENV, raising=False)


class TestKeyPair:
    def test_inlines_pem(self, sp_keys):
        cert, key = saml.sp_key_pair()
        assert "BEGIN" not in cert and "\n" not in cert
        assert "BEGIN" not in key and "\n" not in key

    def test_accepts_escaped_newlines(self, monkeypatch, sp_pem):
        cert_pem, key_pem = sp_pem
        monkeypatch.setenv(saml.CERT_ENV, cert_pem.replace("\n", "\\n"))
        monkeypatch.setenv(saml.KEY_ENV, key_pem.replace("\n", "\\n"))
        cert, _ = saml.sp_key_pair()
        assert "\\" not in cert

    def test_needs_both_halves(self, monkeypatch, sp_pem):
        monkeypatch.setenv(saml.CERT_ENV, sp_pem[0])
        monkeypatch.delenv(saml.KEY_ENV, raising=False)
        assert saml.sp_key_pair() is None


@pytest.mark.django_db
class TestHardenedSettings:
    def test_requires_signed_assertions_without_keys(self, no_sp_keys):
        upstream = {
            "advanced": {
                "reject_idp_initiated_sso": False,
                "private_key": "stale",
                "authn_request_signed": True,
            }
        }
        hardened = saml.hardened_settings(upstream)
        advanced = hardened["advanced"]
        assert advanced["want_assertion_signed"] is True
        assert advanced["authn_request_signed"] is False
        assert "private_key" not in advanced
        assert advanced["reject_idp_initiated_sso"] is False
        # The stored settings are not touched.
        assert upstream["advanced"]["private_key"] == "stale"

    def test_signs_requests_with_keys(self, sp_keys):
        advanced = saml.hardened_settings({})["advanced"]
        cert, key = saml.sp_key_pair()
        assert advanced["x509cert"] == cert
        assert advanced["private_key"] == key
        assert advanced["authn_request_signed"] is True
        assert advanced["logout_request_signed"] is True

    def test_tenant_can_reject_idp_initiated(self, no_sp_keys, tenants_fixture):
        tenant = tenants_fixture[0]
        TenantSsoPolicy.objects.create(tenant=tenant, reject_idp_initiated_sso=True)
        advanced = saml.hardened_settings({}, tenant.id)["advanced"]
        assert advanced["reject_idp_initiated_sso"] is True
        other = saml.hardened_settings({}, tenants_fixture[1].id)["advanced"]
        assert other["reject_idp_initiated_sso"] is False


@pytest.mark.django_db
class TestAdapter:
    def _get_app(self, domain):
        return saml.CloudsneekerSocialAccountAdapter().get_app(
            RequestFactory().get("/"), "saml", client_id=domain
        )

    def test_hardens_the_tenant_app(self, saml_setup, sp_keys):
        TenantSsoPolicy.objects.create(
            tenant_id=saml_setup["tenant_id"], reject_idp_initiated_sso=True
        )
        app = self._get_app(saml_setup["domain"])
        advanced = app.settings["advanced"]
        assert advanced["want_assertion_signed"] is True
        assert advanced["authn_request_signed"] is True
        assert advanced["reject_idp_initiated_sso"] is True
        stored = SocialApp.objects.get(provider="saml", client_id=saml_setup["domain"])
        assert "private_key" not in stored.settings.get("advanced", {})

    def test_is_the_configured_adapter(self, settings):
        assert settings.SOCIALACCOUNT_ADAPTER == (
            "cloudsneeker_api.saml.CloudsneekerSocialAccountAdapter"
        )

    def test_metadata_advertises_signing(self, client, saml_setup, sp_keys, settings):
        # python3-saml refuses single-label hosts such as "testserver".
        settings.ALLOWED_HOSTS = ["app.example.com"]
        response = client.get(
            reverse(
                "saml_metadata", kwargs={"organization_slug": saml_setup["domain"]}
            ),
            HTTP_HOST="app.example.com",
        )
        assert response.status_code == status.HTTP_200_OK
        body = response.content.decode()
        assert 'AuthnRequestsSigned="true"' in body
        assert 'WantAssertionsSigned="true"' in body
        # The certificate may be wrapped across lines in the metadata.
        assert saml.sp_key_pair()[0] in "".join(body.split())


@pytest.mark.django_db
class TestSsoPolicyApi:
    def _patch(self, client, value):
        return client.patch(
            reverse("sso-policy"),
            data={
                "data": {
                    "type": "cloudsneeker-sso-policies",
                    "attributes": {"reject_idp_initiated_sso": value},
                }
            },
            content_type=JSONAPI,
        )

    def test_defaults(self, authenticated_client, no_sp_keys):
        response = authenticated_client.get(reverse("sso-policy"))
        assert response.status_code == status.HTTP_200_OK
        attributes = response.json()["data"]["attributes"]
        assert attributes == {
            "reject_idp_initiated_sso": False,
            "signed_requests": False,
            "signed_assertions_required": True,
        }

    def test_admin_turns_rejection_on_and_off(
        self, authenticated_client, tenants_fixture
    ):
        response = self._patch(authenticated_client, True)
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["data"]["attributes"]["reject_idp_initiated_sso"]
        assert TenantSsoPolicy.objects.get(
            tenant=tenants_fixture[0]
        ).reject_idp_initiated_sso
        response = self._patch(authenticated_client, False)
        assert not response.json()["data"]["attributes"]["reject_idp_initiated_sso"]

    def test_rejects_a_non_boolean(self, authenticated_client):
        response = self._patch(authenticated_client, "yes")
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_needs_manage_account(self, authenticated_client, tenants_fixture):
        _, client = _second_user(tenants_fixture[0])
        response = self._patch(client, True)
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert not TenantSsoPolicy.objects.filter(tenant=tenants_fixture[0]).exists()
