"""Slack OAuth views must resolve tenant from JWT auth, not request.tenant_id."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from cloudsneeker_api.views_slack import _require_manage_integrations, _tenant_id
from rest_framework.exceptions import PermissionDenied


class TestSlackTenantResolution:
    def test_tenant_id_from_auth_payload(self):
        request = SimpleNamespace(
            auth={"tenant_id": "11111111-1111-1111-1111-111111111111"}
        )

        assert _tenant_id(request) == "11111111-1111-1111-1111-111111111111"

    def test_tenant_id_missing_auth_raises(self):
        request = SimpleNamespace(auth=None)

        with pytest.raises(PermissionDenied):
            _tenant_id(request)

    def test_require_manage_integrations_uses_auth_tenant(self):
        request = SimpleNamespace(
            user=MagicMock(),
            auth={"tenant_id": "11111111-1111-1111-1111-111111111111"},
        )

        role = MagicMock()
        with (
            patch("cloudsneeker_api.views_slack.get_role", return_value=role) as get_role,
            patch(
                "cloudsneeker_api.views_slack.roles_have_permissions", return_value=True
            ),
        ):
            assert (
                _require_manage_integrations(request)
                == "11111111-1111-1111-1111-111111111111"
            )

        get_role.assert_called_once_with(
            request.user, "11111111-1111-1111-1111-111111111111"
        )
