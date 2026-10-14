import pytest
from cloudsneeker_api.brand import brand
from django.apps import apps
from django.conf import settings
from django.urls import resolve, reverse
from rest_framework import status

BRAND_TYPE = "cloudsneeker-brand"


class TestAppRegistration:
    def test_app_is_installed(self):
        assert "cloudsneeker_api" in settings.INSTALLED_APPS

    def test_app_config_loads(self):
        config = apps.get_app_config("cloudsneeker_api")
        assert config.name == "cloudsneeker_api"
        assert config.verbose_name == brand.name

    def test_app_registers_feature_models(self):
        model_names = {
            model.__name__
            for model in apps.get_app_config("cloudsneeker_api").get_models()
        }
        assert {
            "ScanConfiguration",
            "AlertRule",
            "AlertRecipient",
            "FindingIngestion",
            "EmailDeliveryConfig",
            "SlackAppConfig",
        }.issubset(model_names)

    def test_table_prefix_constant(self):
        from cloudsneeker_api.models import TABLE_PREFIX

        assert TABLE_PREFIX == "cloudsneeker_"

    def test_feature_models_point_tenant_at_api_app(self):
        from cloudsneeker_api.models import (
            AlertRecipient,
            AlertRule,
            FindingIngestion,
            ScanConfiguration,
        )

        for model in (ScanConfiguration, AlertRule, AlertRecipient, FindingIngestion):
            remote = model._meta.get_field("tenant").remote_field.model
            assert remote._meta.app_label == "api"
            assert remote._meta.model_name == "tenant"

    def test_feature_models_pass_django_system_checks(self):
        from django.core.checks import run_checks

        errors = [
            error
            for error in run_checks(app_configs=None)
            if error.id in {"fields.E300", "fields.E307"}
            and "cloudsneeker_api" in str(error)
        ]
        assert errors == []


class TestFeatureRoutes:
    """Configuration contracts must import with the same nested routers as upstream."""

    @pytest.mark.parametrize(
        ("url", "url_name"),
        [
            ("/api/v1/scan-configurations", "scan-configurations-list"),
            ("/api/v1/alerts/rules", "alert-rules-list"),
            ("/api/v1/alerts/recipients", "alert-recipients-list"),
            ("/api/v1/ingestions", "ingestions-list"),
        ],
    )
    def test_configuration_routes_resolve(self, url, url_name):
        match = resolve(url)
        assert match.url_name == url_name


class TestBrandEndpoint:
    url = "/api/v1/cloudsneeker/brand"

    def test_route_is_mounted_under_api_v1(self):
        match = resolve(self.url)
        assert match.url_name == "cloudsneeker-brand"
        assert reverse("cloudsneeker-brand") == self.url

    @pytest.mark.django_db
    def test_requires_authentication(self, client):
        response = client.get(self.url)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    @pytest.mark.django_db
    def test_returns_brand_resource(self, authenticated_client):
        response = authenticated_client.get(self.url)
        assert response.status_code == status.HTTP_200_OK
        assert response["Content-Type"].startswith("application/vnd.api+json")

        data = response.json()["data"]
        assert data["type"] == BRAND_TYPE
        assert data["id"] == brand.slug
        attributes = data["attributes"]
        assert attributes["name"] == brand.name
        assert attributes["docs_url"] == brand.docs_url
        assert attributes["support_url"] == brand.support_url
        assert "Prowler" not in response.content.decode()

    def test_openapi_schema_describes_brand_endpoint(self):
        from drf_spectacular.generators import SchemaGenerator

        schema = SchemaGenerator().get_schema(request=None, public=True)
        operation = schema["paths"][self.url]["get"]

        assert operation["tags"] == ["Cloudsneeker"]
        assert "Prowler" not in operation["description"]
        assert "Brand" in schema["components"]["schemas"]
