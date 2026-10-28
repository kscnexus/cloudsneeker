"""Pytest fixtures that keep upstream API suites on upstream names.

``conftest.py`` imports :func:`upstream_compat_brand`, so upstream tests see
the brand built from :data:`cloudsneeker.testing.UPSTREAM_COMPAT_ENV` and stay
byte-identical to upstream. Tests under ``cloudsneeker_api`` keep the shipped
brand because they assert the real product identity.

Only values read at call time follow the swap (``pdf_footer()`` and the other
helpers in :mod:`cloudsneeker_api.brand`). Modules that bind ``brand`` at
import time are imported here, before any swap, so a lazy first import during
an upstream test cannot capture the upstream-compatible brand.
"""

import pytest
import tasks.jobs.export  # noqa: F401
import tasks.jobs.integrations  # noqa: F401
from cloudsneeker.brand import load_brand
from cloudsneeker.testing import UPSTREAM_COMPAT_ENV
from django.urls import get_resolver

get_resolver().url_patterns  # loads every view module, cloudsneeker_api.views included

OWN_SUITE_PACKAGE = "cloudsneeker_api"
UPSTREAM_COMPAT_BRAND = load_brand(UPSTREAM_COMPAT_ENV)


@pytest.fixture(autouse=True)
def upstream_compat_brand(request, monkeypatch):
    """Swap the API brand for the upstream-compatible one outside our suites."""
    if OWN_SUITE_PACKAGE in request.node.path.parts:
        return
    from cloudsneeker_api import brand as api_brand

    monkeypatch.setattr(api_brand, "brand", UPSTREAM_COMPAT_BRAND)
