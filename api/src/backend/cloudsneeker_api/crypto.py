"""Encryption key ring for stored secrets (EB-016).

Upstream encrypts every stored secret (provider credentials, integration
credentials, LLM keys) with one Fernet key, ``DJANGO_SECRETS_ENCRYPTION_KEY``.
``build_fernet`` returns a ``MultiFernet`` instead: it encrypts with that key
and still decrypts with the keys in
``DJANGO_SECRETS_ENCRYPTION_KEY_PREVIOUS`` (comma-separated), so the key can
be replaced without downtime. ``manage.py cloudsneeker_rotate_secrets`` then
re-encrypts stored values with the new key. Runbook:
``knowledge-base/encryption-key-rotation.md``.

Registered in ``api/models.py`` (``cloudsneeker-hook``). Imports nothing
from ``api`` so ``api.models`` can import it.
"""

from __future__ import annotations

import os

from cryptography.fernet import Fernet, MultiFernet

PREVIOUS_KEYS_ENV = "DJANGO_SECRETS_ENCRYPTION_KEY_PREVIOUS"
# Placeholders the deploy script stores until a rotation is in progress.
UNSET_VALUES = frozenset({"", "unconfigured", "none"})


def previous_keys(raw: str | None = None) -> list[str]:
    value = os.environ.get(PREVIOUS_KEYS_ENV, "") if raw is None else raw
    keys = [part.strip() for part in value.split(",")]
    return [key for key in keys if key.lower() not in UNSET_VALUES]


def build_fernet(primary: str, previous: list[str] | None = None) -> MultiFernet:
    """Encrypt with ``primary``; decrypt with ``primary`` or any previous key."""
    keys = [primary]
    for key in previous_keys() if previous is None else previous:
        if key not in keys:
            keys.append(key)
    return MultiFernet([Fernet(key.encode()) for key in keys])
