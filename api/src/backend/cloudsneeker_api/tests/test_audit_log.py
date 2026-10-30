"""User-action audit log (EB-007): capture, secrets, RLS, API, export, retention."""

from __future__ import annotations

import json
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from api.db_utils import rls_transaction
from cloudsneeker_api import audit
from cloudsneeker_api.models import JSON_API_TYPE_PREFIX, AuditEvent
from cloudsneeker_api.views_audit import EXPORT_COLUMNS
from conftest import TEST_PASSWORD, TEST_USER
from django.test import Client
from django.urls import reverse
from django.utils import timezone

JSONAPI = "application/vnd.api+json"
SECRET_VALUE = "very-secret-value-1234"
AUDIT_TYPE = f"{JSON_API_TYPE_PREFIX}audit-events"


def _events(tenant, **filters):
    with rls_transaction(str(tenant.id)):
        return list(
            AuditEvent.objects.filter(tenant_id=tenant.id, **filters).order_by(
                "inserted_at"
            )
        )


def _event(tenant, **fields):
    defaults = {"action": "role.create", "actor_email": "admin@example.com"}
    defaults.update(fields)
    with rls_transaction(str(tenant.id)):
        return AuditEvent.objects.create(tenant_id=tenant.id, **defaults)


def _match(url_name, *, basename=None, actions=None, kwargs=None):
    func = SimpleNamespace(
        initkwargs={"basename": basename} if basename else {},
        actions=actions or {},
    )
    return SimpleNamespace(url_name=url_name, func=func, kwargs=kwargs or {})


class TestActionMapping:
    @pytest.mark.parametrize(
        ("match", "method", "expected"),
        [
            (
                _match("role-list", basename="role", actions={"post": "create"}),
                "POST",
                "role.create",
            ),
            (
                _match(
                    "role-detail", basename="role", actions={"patch": "partial_update"}
                ),
                "PATCH",
                "role.update",
            ),
            (
                _match(
                    "provider-detail",
                    basename="provider",
                    actions={"delete": "destroy"},
                ),
                "DELETE",
                "provider.delete",
            ),
            (
                _match(
                    "provider-connection",
                    basename="provider",
                    actions={"post": "connection"},
                ),
                "POST",
                "provider.connection_test",
            ),
            (
                _match("scan-list", basename="scan", actions={"post": "create"}),
                "POST",
                "scan.launch",
            ),
            (
                _match("providersecret-list", actions={"post": "create"}),
                "POST",
                "provider_secret.create",
            ),
            (
                _match("invitation-detail", actions={"delete": "destroy"}),
                "DELETE",
                "invitation.delete",
            ),
            (
                _match("invitation-accept", actions={"post": "accept"}),
                "POST",
                "invitation.accept",
            ),
            (
                _match(
                    "tenant-membership-detail",
                    basename="tenant-membership",
                    actions={"delete": "destroy"},
                ),
                "DELETE",
                "membership.delete",
            ),
            (
                _match(
                    "mute-rule-list", basename="mute-rule", actions={"post": "create"}
                ),
                "POST",
                "mute_rule.create",
            ),
            (
                _match(
                    "api-key-revoke", basename="api-key", actions={"delete": "revoke"}
                ),
                "DELETE",
                "api_key.revoke",
            ),
            (
                _match(
                    "report-runs-shares",
                    basename="report-runs",
                    actions={"post": "shares"},
                ),
                "POST",
                "report.share_link.create",
            ),
            (
                _match(
                    "report-share-links-revoke",
                    basename="report-share-links",
                    actions={"post": "revoke"},
                ),
                "POST",
                "report.share_link.revoke",
            ),
            (
                _match(
                    "report-schedules-list",
                    basename="report-schedules",
                    actions={"post": "create"},
                ),
                "POST",
                "report_schedule.create",
            ),
            (
                _match(
                    "email-delivery-config-detail",
                    basename="email-delivery-config",
                    actions={"patch": "partial_update"},
                ),
                "PATCH",
                "email_config.update",
            ),
            (
                _match(
                    "custodian-policies-list",
                    basename="custodian-policies",
                    actions={"post": "create"},
                ),
                "POST",
                "custodian_policy.create",
            ),
            (
                _match(
                    "trivy-targets-detail",
                    basename="trivy-targets",
                    actions={"delete": "destroy"},
                ),
                "DELETE",
                "trivy_target.delete",
            ),
            (_match("user-roles-relationship"), "POST", "user.roles.add"),
            (
                _match("role-provider-groups-relationship"),
                "DELETE",
                "role.provider_groups.remove",
            ),
            # Unknown upstream routes are still audited under a derived name.
            (
                _match(
                    "new-thing-list", basename="new-thing", actions={"post": "create"}
                ),
                "POST",
                "new_thing.create",
            ),
        ],
    )
    def test_routes_map_to_actions(self, match, method, expected):
        assert audit.resolve_action(match, method).action == expected

    @pytest.mark.parametrize(
        "url_name",
        ["token-refresh", "alert-rules-preview", "attack-paths-scans-queries-run"],
    )
    def test_read_only_posts_are_skipped(self, url_name):
        assert audit.resolve_action(_match(url_name), "POST") is None

    def test_no_route_is_skipped(self):
        assert audit.resolve_action(None, "POST") is None


class TestNoSecretsInMetadata:
    def test_field_names_never_include_values(self):
        body = {
            "data": {
                "type": "provider-secrets",
                "attributes": {
                    "name": "prod",
                    "secret": {"aws_secret_access_key": SECRET_VALUE},
                    "password": SECRET_VALUE,
                    "api_key": SECRET_VALUE,
                },
                "relationships": {"provider": {"data": {"id": "x"}}},
            }
        }
        result = audit.field_names(body)
        assert result == {
            "fields": ["name"],
            "relationships": ["provider"],
            "secret_fields_changed": True,
        }
        assert SECRET_VALUE not in json.dumps(result)

    def test_flattened_parser_output(self):
        # What DRF's JSON:API parser hands the view: one flat dict.
        body = {
            "type": "provider-secrets",
            "name": "prod",
            "secret": {"aws_secret_access_key": SECRET_VALUE},
            "provider": {"type": "providers", "id": "x"},
        }
        result = audit.field_names(body)
        assert result == {
            "fields": ["name"],
            "relationships": ["provider"],
            "secret_fields_changed": True,
        }
        assert SECRET_VALUE not in json.dumps(result)

    def test_non_dict_bodies(self):
        assert audit.field_names(None) == {}
        assert audit.field_names([1, 2]) == {}


class TestRequestContext:
    def test_client_ip_prefers_forwarded_for(self):
        request = SimpleNamespace(
            META={
                "HTTP_X_FORWARDED_FOR": "203.0.113.7, 10.0.0.1",
                "REMOTE_ADDR": "10.0.0.2",
            }
        )
        assert audit.client_ip(request) == "203.0.113.7"

    def test_client_ip_skips_garbage(self):
        request = SimpleNamespace(
            META={"HTTP_X_FORWARDED_FOR": "not-an-ip", "REMOTE_ADDR": "10.0.0.2"}
        )
        assert audit.client_ip(request) == "10.0.0.2"

    def test_retention_days_env(self, monkeypatch):
        monkeypatch.delenv("AUDIT_LOG_RETENTION_DAYS", raising=False)
        assert audit.retention_days() == 365
        monkeypatch.setenv("AUDIT_LOG_RETENTION_DAYS", "30")
        assert audit.retention_days() == 30
        monkeypatch.setenv("AUDIT_LOG_RETENTION_DAYS", "0")
        assert audit.retention_days() == 365
        monkeypatch.setenv("AUDIT_LOG_RETENTION_DAYS", "abc")
        assert audit.retention_days() == 365


@pytest.mark.django_db
class TestMiddlewareCapture:
    def test_role_create_is_recorded(self, authenticated_client, tenants_fixture):
        response = authenticated_client.post(
            reverse("role-list"),
            data=json.dumps(
                {
                    "data": {
                        "type": "roles",
                        "attributes": {"name": "Audited Role", "manage_scans": "true"},
                        "relationships": {"provider_groups": {"data": []}},
                    }
                }
            ),
            content_type=JSONAPI,
            HTTP_USER_AGENT="pytest-agent",
            HTTP_X_FORWARDED_FOR="198.51.100.4",
        )
        assert response.status_code == 201, response.content

        (event,) = _events(tenants_fixture[0], action="role.create")
        assert event.outcome == AuditEvent.Outcome.SUCCESS
        assert event.actor_email == TEST_USER
        assert event.target_type == "role"
        assert event.target_id == response.json()["data"]["id"]
        assert event.target_label == "Audited Role"
        assert event.ip_address == "198.51.100.4"
        assert event.user_agent == "pytest-agent"
        # DRF parses JSON:API into one flat dict, so an empty to-many
        # relationship can read as a field name; the named fields must be there.
        assert {"manage_scans", "name"} <= set(event.metadata["fields"])
        assert event.status_code == 201

    def test_failed_mutation_is_recorded_as_failure(
        self, authenticated_client_no_permissions_rbac, tenants_fixture
    ):
        response = authenticated_client_no_permissions_rbac.post(
            reverse("role-list"),
            data=json.dumps(
                {"data": {"type": "roles", "attributes": {"name": "Nope"}}}
            ),
            content_type=JSONAPI,
        )
        assert response.status_code == 403

        (event,) = _events(tenants_fixture[0], action="role.create")
        assert event.outcome == AuditEvent.Outcome.FAILURE
        assert event.status_code == 403

    def test_provider_secret_values_never_stored(
        self, authenticated_client, tenants_fixture, aws_provider
    ):
        authenticated_client.post(
            reverse("providersecret-list"),
            data=json.dumps(
                {
                    "data": {
                        "type": "provider-secrets",
                        "attributes": {
                            "name": "creds",
                            "secret_type": "static",
                            "secret": {
                                "aws_access_key_id": "AKIAEXAMPLEEXAMPLE00",
                                "aws_secret_access_key": SECRET_VALUE,
                            },
                        },
                        "relationships": {
                            "provider": {
                                "data": {
                                    "type": "providers",
                                    "id": str(aws_provider.id),
                                }
                            }
                        },
                    }
                }
            ),
            content_type=JSONAPI,
        )

        (event,) = _events(tenants_fixture[0], action="provider_secret.create")
        stored = json.dumps(
            {
                "metadata": event.metadata,
                "label": event.target_label,
                "path": event.path,
                "agent": event.user_agent,
            }
        )
        assert SECRET_VALUE not in stored
        assert "AKIAEXAMPLEEXAMPLE00" not in stored
        assert event.metadata.get("secret_fields_changed") is True

    def test_reads_are_not_recorded(self, authenticated_client, tenants_fixture):
        authenticated_client.get(reverse("role-list"))
        assert _events(tenants_fixture[0]) == []

    def test_audit_failure_never_breaks_the_request(
        self, authenticated_client, tenants_fixture
    ):
        with patch.object(audit, "resolve_action", side_effect=RuntimeError("boom")):
            response = authenticated_client.post(
                reverse("role-list"),
                data=json.dumps(
                    {"data": {"type": "roles", "attributes": {"name": "Still Works"}}}
                ),
                content_type=JSONAPI,
            )
        assert response.status_code == 201

    def test_write_errors_are_swallowed(self, tenants_fixture):
        with patch("cloudsneeker_api.models.AuditEvent.objects") as manager:
            manager.using.return_value.create.side_effect = RuntimeError("db down")
            assert (
                audit.write_event(
                    audit.AuditRecord(
                        tenant_id=str(tenants_fixture[0].id), action="x.y"
                    )
                )
                is None
            )


@pytest.mark.django_db
class TestSignInCapture:
    def _sign_in(self, email, password, **extra):
        return Client().post(
            reverse("token-obtain"),
            data=json.dumps(
                {
                    "data": {
                        "type": "tokens",
                        "attributes": {"email": email, "password": password},
                    }
                }
            ),
            content_type=JSONAPI,
            **extra,
        )

    def test_success_is_recorded_in_the_token_tenant(
        self, create_test_user, tenants_fixture
    ):
        response = self._sign_in(TEST_USER, TEST_PASSWORD, HTTP_USER_AGENT="browser")
        assert response.status_code == 200

        (event,) = _events(tenants_fixture[0], action="auth.sign_in")
        assert event.outcome == AuditEvent.Outcome.SUCCESS
        assert str(event.actor_id) == str(create_test_user.id)
        assert event.actor_email == TEST_USER
        assert event.metadata == {"method": "password"}
        assert event.user_agent == "browser"
        assert TEST_PASSWORD not in json.dumps(event.metadata)
        assert _events(tenants_fixture[1], action="auth.sign_in") == []

    def test_failure_is_recorded_for_known_users(
        self, create_test_user, tenants_fixture
    ):
        response = self._sign_in(TEST_USER, "wrong-password-Value1!")
        assert response.status_code in (400, 401)

        for tenant in tenants_fixture[:2]:
            (event,) = _events(tenant, action="auth.sign_in_failed")
            assert event.outcome == AuditEvent.Outcome.FAILURE
            assert event.actor_email == TEST_USER
            assert "wrong-password" not in json.dumps(event.metadata)
        assert _events(tenants_fixture[2]) == []

    def test_failure_for_unknown_email_has_no_tenant(self, tenants_fixture):
        self._sign_in("nobody@example.com", "whatever-Value1!")
        for tenant in tenants_fixture:
            assert _events(tenant, action="auth.sign_in_failed") == []


@pytest.mark.django_db
class TestAuditEventsApi:
    def test_lists_only_own_tenant(self, authenticated_client, tenants_fixture):
        own = _event(tenants_fixture[0], action="provider.create")
        _event(tenants_fixture[1], action="provider.create")

        response = authenticated_client.get(reverse("audit-events-list"))
        assert response.status_code == 200
        data = response.json()["data"]
        assert [item["id"] for item in data] == [str(own.id)]
        assert data[0]["type"] == AUDIT_TYPE
        assert data[0]["attributes"]["action"] == "provider.create"

    def test_rls_hides_other_tenants(self, tenants_fixture):
        _event(tenants_fixture[0])
        other = _event(tenants_fixture[1])
        with rls_transaction(str(tenants_fixture[0].id)):
            assert not AuditEvent.objects.filter(
                tenant_id=tenants_fixture[0].id, id=other.id
            ).exists()

    def test_retrieve_and_other_tenant_404(self, authenticated_client, tenants_fixture):
        own = _event(tenants_fixture[0])
        other = _event(tenants_fixture[1])
        ok = authenticated_client.get(
            reverse("audit-events-detail", kwargs={"pk": own.id})
        )
        assert ok.status_code == 200
        assert ok.json()["data"]["id"] == str(own.id)
        missing = authenticated_client.get(
            reverse("audit-events-detail", kwargs={"pk": other.id})
        )
        assert missing.status_code == 404

    def test_filters(self, authenticated_client, tenants_fixture):
        tenant = tenants_fixture[0]
        sign_in = _event(tenant, action="auth.sign_in", actor_email="a@example.com")
        failed = _event(
            tenant,
            action="auth.sign_in_failed",
            outcome="failure",
            actor_email="b@example.com",
        )
        old = _event(tenant, action="role.delete", target_type="role")
        with rls_transaction(str(tenant.id)):
            AuditEvent.objects.filter(id=old.id).update(
                inserted_at=timezone.now() - timedelta(days=10)
            )

        def ids(params):
            response = authenticated_client.get(reverse("audit-events-list"), params)
            assert response.status_code == 200, response.content
            return {item["id"] for item in response.json()["data"]}

        assert ids({"filter[action__startswith]": "auth."}) == {
            str(sign_in.id),
            str(failed.id),
        }
        assert ids({"filter[action]": "auth.sign_in"}) == {str(sign_in.id)}
        assert ids({"filter[outcome]": "failure"}) == {str(failed.id)}
        assert ids({"filter[actor]": "b@example"}) == {str(failed.id)}
        assert ids({"filter[target_type]": "role"}) == {str(old.id)}
        recent = (timezone.now() - timedelta(days=1)).date().isoformat()
        assert str(old.id) not in ids({"filter[inserted_at__gte]": recent})
        before = (timezone.now() - timedelta(days=5)).date().isoformat()
        assert ids({"filter[inserted_at__lte]": before}) == {str(old.id)}

    def test_default_sort_is_newest_first(self, authenticated_client, tenants_fixture):
        first = _event(tenants_fixture[0], action="a.one")
        second = _event(tenants_fixture[0], action="a.two")
        with rls_transaction(str(tenants_fixture[0].id)):
            AuditEvent.objects.filter(id=first.id).update(
                inserted_at=timezone.now() - timedelta(hours=1)
            )
        response = authenticated_client.get(reverse("audit-events-list"))
        assert [item["id"] for item in response.json()["data"]] == [
            str(second.id),
            str(first.id),
        ]

    # The two RBAC client fixtures share Django's ``client``, so each test
    # requests only one of them.
    def test_denied_without_manage_account(
        self, authenticated_client_no_permissions_rbac
    ):
        response = authenticated_client_no_permissions_rbac.get(
            reverse("audit-events-list")
        )
        assert response.status_code == 403

    def test_allowed_with_manage_account(
        self, authenticated_client_rbac_manage_account
    ):
        response = authenticated_client_rbac_manage_account.get(
            reverse("audit-events-list")
        )
        assert response.status_code == 200

    def test_requires_authentication(self, client):
        assert client.get(reverse("audit-events-list")).status_code == 401

    @pytest.mark.parametrize("method", ["post", "patch", "put", "delete"])
    def test_append_only(self, authenticated_client, tenants_fixture, method):
        event = _event(tenants_fixture[0])
        url = (
            reverse("audit-events-list")
            if method == "post"
            else reverse("audit-events-detail", kwargs={"pk": event.id})
        )
        response = getattr(authenticated_client, method)(
            url, data="{}", content_type=JSONAPI
        )
        assert response.status_code == 405
        assert len(_events(tenants_fixture[0], id=event.id)) == 1


@pytest.mark.django_db
class TestAuditExport:
    def _csv(self, response) -> list[str]:
        return b"".join(response.streaming_content).decode().splitlines()

    def test_streams_filtered_csv(self, authenticated_client, tenants_fixture):
        _event(tenants_fixture[0], action="role.create", target_label="=cmd()")
        _event(tenants_fixture[0], action="provider.delete")
        _event(tenants_fixture[1], action="role.create")

        response = authenticated_client.get(
            reverse("audit-events-export"),
            {"format": "csv", "filter[action__startswith]": "role."},
        )
        assert response.status_code == 200
        assert response["Content-Type"].startswith("text/csv")
        assert "attachment" in response["Content-Disposition"]
        lines = self._csv(response)
        assert lines[0].split(",") == [header for _, header in EXPORT_COLUMNS]
        assert len(lines) == 2
        assert "role.create" in lines[1]
        # Spreadsheet formulas are neutralised.
        assert "'=cmd()" in lines[1]

    def test_export_is_audited(self, authenticated_client, tenants_fixture):
        response = authenticated_client.get(reverse("audit-events-export"))
        self._csv(response)
        (event,) = _events(tenants_fixture[0], action="audit_log.export")
        assert event.outcome == AuditEvent.Outcome.SUCCESS

    def test_unknown_format(self, authenticated_client):
        response = authenticated_client.get(
            reverse("audit-events-export"), {"format": "xlsx"}
        )
        assert response.status_code == 400

    def test_requires_manage_account(self, authenticated_client_no_permissions_rbac):
        response = authenticated_client_no_permissions_rbac.get(
            reverse("audit-events-export")
        )
        assert response.status_code == 403


@pytest.mark.django_db
class TestRetention:
    def test_purges_only_old_events(self, tenants_fixture):
        tenant = tenants_fixture[0]
        old = _event(tenant)
        fresh = _event(tenant)
        with rls_transaction(str(tenant.id)):
            AuditEvent.objects.filter(id=old.id).update(
                inserted_at=timezone.now() - timedelta(days=400)
            )

        deleted = audit.purge_all_tenants([str(tenant.id)], 365)

        assert deleted == 1
        assert [event.id for event in _events(tenant)] == [fresh.id]

    def test_migration_registers_the_periodic_task(self):
        import importlib

        from django.apps import apps
        from django_celery_beat.models import PeriodicTask

        migration = importlib.import_module(
            "cloudsneeker_api.migrations.0012_audit_log"
        )
        migration.create_retention_task(apps, None)
        migration.create_retention_task(apps, None)  # idempotent

        task = PeriodicTask.objects.get(name=migration.RETENTION_TASK_NAME)
        assert task.task == "cloudsneeker-purge-audit-events"
        assert task.enabled
        assert task.interval.every == 1 and task.interval.period == "days"

    def test_task_name_is_registered_with_celery(self):
        from cloudsneeker_api.tasks import purge_audit_events_task

        assert purge_audit_events_task.name == "cloudsneeker-purge-audit-events"
