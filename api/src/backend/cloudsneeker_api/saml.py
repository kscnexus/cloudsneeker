"""SAML hardening (EB-009).

Upstream stores each tenant's SAML settings on an allauth ``SocialApp``,
copied from ``SOCIALACCOUNT_PROVIDERS["saml"]`` when the configuration is
saved. ``CloudsneekerSocialAccountAdapter.get_app`` hardens those settings
in memory every time allauth loads the app, so existing configurations get
the same protection without a data migration:

* assertions must be signed by the IdP (``want_assertion_signed``);
* with an SP key pair (``SAML_PUBLIC_CERT`` / ``SAML_PRIVATE_KEY``, from
  Secrets Manager on the hosted stack), AuthnRequests and logout requests are
  signed and the SP metadata publishes the certificate;
* SSO started at the IdP (no matching AuthnRequest) is rejected when the
  tenant turns that on (``TenantSsoPolicy``).

Registered as ``SOCIALACCOUNT_ADAPTER`` in ``config/settings/social_login.py``
(``cloudsneeker-hook``).
"""

from __future__ import annotations

import copy
import logging
import os

from api.adapters import ProwlerSocialAccountAdapter

logger = logging.getLogger(__name__)

SAML_PROVIDER = "saml"
CERT_ENV = "SAML_PUBLIC_CERT"
KEY_ENV = "SAML_PRIVATE_KEY"


def _inline_pem(value: str) -> str:
    """Base64 body of a PEM value, as python3-saml expects it.

    Accepts real newlines or the literal ``\\n`` some secret stores keep.
    """
    text = (value or "").replace("\\n", "\n")
    return "".join(
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.startswith("-----")
    )


def sp_key_pair() -> tuple[str, str] | None:
    """``(certificate, private_key)`` for signing, or ``None`` when unset."""
    cert = _inline_pem(os.environ.get(CERT_ENV, ""))
    key = _inline_pem(os.environ.get(KEY_ENV, ""))
    if cert and key:
        return cert, key
    if cert or key:
        logger.warning("SAML SP signing needs both %s and %s", CERT_ENV, KEY_ENV)
    return None


def tenant_for_domain(email_domain: str):
    """Tenant ID that owns a SAML email domain, or ``None``."""
    from api.db_router import MainRouter
    from api.models import SAMLDomainIndex

    return (
        SAMLDomainIndex.objects.using(MainRouter.admin_db)
        .filter(email_domain=(email_domain or "").strip().lower())
        .values_list("tenant_id", flat=True)
        .first()
    )


def rejects_idp_initiated(tenant_id) -> bool:
    if not tenant_id:
        return False
    from api.db_router import MainRouter
    from cloudsneeker_api.models import TenantSsoPolicy

    return (
        TenantSsoPolicy.objects.using(MainRouter.admin_db)
        .filter(tenant_id=tenant_id, reject_idp_initiated_sso=True)
        .exists()
    )


def hardened_settings(settings: dict | None, tenant_id=None) -> dict:
    """A copy of a SAML ``SocialApp.settings`` with the hardening applied."""
    hardened = copy.deepcopy(settings or {})
    advanced = hardened.setdefault("advanced", {})
    advanced["want_assertion_signed"] = True
    advanced["reject_deprecated_algorithm"] = True
    advanced["reject_idp_initiated_sso"] = rejects_idp_initiated(tenant_id)

    pair = sp_key_pair()
    if pair:
        cert, key = pair
        advanced["x509cert"] = cert
        advanced["private_key"] = key
        advanced["authn_request_signed"] = True
        advanced["logout_request_signed"] = True
    else:
        # Never ask python3-saml to sign without a key.
        advanced.pop("x509cert", None)
        advanced.pop("private_key", None)
        advanced["authn_request_signed"] = False
        advanced["logout_request_signed"] = False
    return hardened


class CloudsneekerSocialAccountAdapter(ProwlerSocialAccountAdapter):
    """Upstream adapter plus SAML hardening on every app lookup."""

    def get_app(self, request, provider, client_id=None):
        app = super().get_app(request, provider, client_id=client_id)
        if getattr(app, "provider", None) == SAML_PROVIDER:
            # In memory only: the stored settings stay as upstream wrote them.
            app.settings = hardened_settings(
                app.settings, tenant_for_domain(app.client_id)
            )
        return app
