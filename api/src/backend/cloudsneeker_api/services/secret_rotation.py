"""Re-encrypt stored secrets with the current key (EB-016).

``scan`` reports, per encrypted field, how many values the current key reads
(``current``), how many only a previous key reads (``stale``) and how many no
configured key reads (``unreadable``). ``rotate`` rewrites the stale ones
with the current key. Values are never logged or returned.

Rows are read and written through the admin connection, across tenants,
with ``QuerySet.update`` so no model ``save`` side effects run.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cryptography.fernet import Fernet, InvalidToken

# (app label, model, field attribute) of every Fernet-encrypted column.
ENCRYPTED_FIELDS: tuple[tuple[str, str, str], ...] = (
    ("api", "ProviderSecret", "_secret"),
    ("api", "Integration", "_credentials"),
    ("api", "LighthouseConfiguration", "api_key"),
    ("api", "LighthouseProviderConfiguration", "credentials"),
    ("cloudsneeker_api", "EmailDeliveryConfig", "_password"),
    ("cloudsneeker_api", "SlackAppConfig", "_client_secret"),
    ("cloudsneeker_api", "UserMfa", "secret_encrypted"),
)


@dataclass
class FieldReport:
    label: str
    current: int = 0
    stale: int = 0
    unreadable: int = 0
    rotated: int = 0
    unreadable_ids: list[str] = field(default_factory=list)


def _token(value) -> bytes | None:
    if value is None:
        return None
    if isinstance(value, memoryview):
        value = value.tobytes()
    if isinstance(value, str):
        value = value.encode()
    return bytes(value) or None


def _stored(original, token: bytes):
    """New token in the column's own type (text columns hold ``str``)."""
    return token.decode() if isinstance(original, str) else token


def _primary() -> Fernet:
    from django.conf import settings

    return Fernet(settings.SECRETS_ENCRYPTION_KEY.encode())


def _ring():
    from api.models import fernet

    return fernet


def _process(app_label, model_name, attr, *, write: bool) -> FieldReport:
    from api.db_router import MainRouter
    from django.apps import apps

    model = apps.get_model(app_label, model_name)
    alias = MainRouter.admin_db
    primary, ring = _primary(), _ring()
    report = FieldReport(label=f"{app_label}.{model_name}.{attr}")

    rows = model.objects.using(alias).values_list("pk", attr).iterator()
    for pk, value in rows:
        token = _token(value)
        if token is None:
            continue
        try:
            primary.decrypt(token)
            report.current += 1
            continue
        except InvalidToken:
            pass
        try:
            rotated = ring.rotate(token)
        except InvalidToken:
            report.unreadable += 1
            report.unreadable_ids.append(str(pk))
            continue
        report.stale += 1
        if write:
            model.objects.using(alias).filter(pk=pk).update(
                **{attr: _stored(value, rotated)}
            )
            report.rotated += 1
    return report


def scan() -> list[FieldReport]:
    return [_process(*spec, write=False) for spec in ENCRYPTED_FIELDS]


def rotate() -> list[FieldReport]:
    return [_process(*spec, write=True) for spec in ENCRYPTED_FIELDS]
