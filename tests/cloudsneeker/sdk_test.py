from unittest import mock

import pytest

from cloudsneeker import sdk
from cloudsneeker.brand import Brand


class TestFindingIdentifiers:
    def test_finding_uid_uses_brand_prefix(self, brand):
        uid = sdk.finding_uid("aws", "check_1", "123456789012", "eu-west-1", "res")
        assert (
            uid == f"{brand.finding_uid_prefix}-aws-check_1-123456789012-eu-west-1-res"
        )
        assert not uid.startswith("prowler")

    def test_asff_ids_use_brand_prefix(self, brand):
        assert sdk.asff_finding_id("check_1", "acct", "us-east-1", "hash") == (
            f"{brand.finding_uid_prefix}-check_1-acct-us-east-1-hash"
        )
        assert sdk.asff_generator_id("check_1") == f"{brand.finding_uid_prefix}-check_1"


class TestSecurityHub:
    def test_default_product_arn_is_account_owned(self, brand):
        arn = sdk.security_hub_product_arn("aws", "eu-west-1", "123456789012")
        assert arn == (
            "arn:aws:securityhub:eu-west-1:123456789012:product/123456789012/default"
        )
        assert sdk.security_hub_uses_default_product() is True
        assert (
            sdk.security_hub_subscription_arn("aws", "eu-west-1", "123456789012") == ""
        )

    def test_default_product_filter_selects_by_arn(self, brand):
        product_filter = sdk.security_hub_product_filter("aws", "eu-west-1", "123")
        assert list(product_filter) == ["ProductArn"]
        assert product_filter["ProductArn"][0]["Value"].endswith("product/123/default")

    def test_partner_integration_when_configured(self, brand):
        partner = Brand(security_hub_integration_name="acme/scanner")
        with mock.patch.object(sdk, "brand", partner):
            assert sdk.security_hub_uses_default_product() is False
            assert sdk.security_hub_product_arn("aws", "us-east-1", "1") == (
                "arn:aws:securityhub:us-east-1::product/acme/scanner"
            )
            assert sdk.security_hub_subscription_arn("aws", "us-east-1", "1") == (
                "arn:aws:securityhub:us-east-1:1:product-subscription/acme/scanner"
            )
            assert list(sdk.security_hub_product_filter("aws", "us-east-1", "1")) == [
                "ProductName"
            ]


class TestReportCopy:
    def test_html_title(self, brand):
        assert sdk.html_title().startswith(brand.name)
        assert "Prowler" not in sdk.html_title()

    def test_slack_title_mentions_brand_and_counts(self, brand):
        title = sdk.slack_title("AWS account 1", 7)
        assert brand.name in title
        assert "*7*" in title
        assert "Prowler" not in title

    def test_slack_footer_blocks_point_at_brand_links(self, brand):
        blocks = sdk.slack_footer_blocks()
        urls = [block["accessory"]["url"] for block in blocks]
        assert brand.docs_url in urls
        assert brand.support_url in urls
        for url in urls:
            assert "prowler" not in url

    def test_slack_footer_omits_support_when_unset(self, brand):
        with mock.patch.object(sdk, "brand", Brand(support_url="")):
            assert len(sdk.slack_footer_blocks()) == 1

    def test_s3_test_object(self, brand):
        assert sdk.s3_test_object_key() == f"test-{brand.slug}-connection.txt"
        assert sdk.s3_test_object_body() == f"Test {brand.name} Connection".encode()

    @pytest.mark.parametrize("providers", ["aws,azure", "aws"])
    def test_cli_usage(self, brand, providers):
        assert sdk.cli_usage(providers) == (
            f"{brand.cli_command} [-h] [--version] {{{providers}}} ..."
        )
