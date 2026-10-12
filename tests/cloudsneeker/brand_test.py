from cloudsneeker.brand import Brand, load_brand
from cloudsneeker.testing import UPSTREAM_COMPAT_ENV


class TestBrand:
    def test_defaults_do_not_mention_upstream(self):
        for field_name, value in vars(Brand()).items():
            if isinstance(value, str):
                assert "prowler" not in value.lower(), field_name

    def test_default_name(self, default_brand):
        assert default_brand.name == "Cloudsneeker"
        assert default_brand.show_upsell is False

    def test_env_override_string(self):
        loaded = load_brand({"CLOUDSNEEKER_DOCS_URL": "https://docs.example.com/"})

        assert loaded.docs_url == "https://docs.example.com/"
        assert loaded.name == "Cloudsneeker"

    def test_env_override_bool(self):
        assert load_brand({"CLOUDSNEEKER_SHOW_UPSELL": "true"}).show_upsell is True
        assert load_brand({"CLOUDSNEEKER_SHOW_UPSELL": "no"}).show_upsell is False

    def test_empty_env_value_keeps_default(self):
        assert load_brand({"CLOUDSNEEKER_NAME": ""}).name == "Cloudsneeker"

    def test_check_docs_url_strips_trailing_slash(self):
        loaded = load_brand({"CLOUDSNEEKER_DOCS_URL": "https://docs.example.com/"})

        assert (
            loaded.check_docs_url("iam_avoid_root_usage")
            == "https://docs.example.com/checks/iam_avoid_root_usage"
        )

    def test_check_docs_url_template_override(self):
        loaded = load_brand(
            {"CLOUDSNEEKER_CHECK_DOCS_URL_TEMPLATE": "{docs_url}/check/{check_id}"}
        )

        assert loaded.check_docs_url("x").endswith("/check/x")

    def test_version_string(self, default_brand):
        assert default_brand.version_string("5.45.0") == "Cloudsneeker 5.45.0"


class TestUpstreamCompatEnv:
    def test_every_key_is_a_brand_field(self):
        field_names = {name.upper() for name in vars(Brand())}
        for key in UPSTREAM_COMPAT_ENV:
            assert key.startswith("CLOUDSNEEKER_")
            assert key.removeprefix("CLOUDSNEEKER_") in field_names, key

    def test_restores_upstream_identity(self):
        upstream = load_brand(UPSTREAM_COMPAT_ENV)

        assert upstream.name == "Prowler"
        assert upstream.finding_uid_prefix == "prowler"
        assert upstream.check_docs_url("id") == "https://hub.prowler.com/check/id"
        assert upstream.security_hub_integration_name == "prowler/prowler"
