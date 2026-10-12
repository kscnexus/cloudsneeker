from unittest.mock import patch

from boto3 import session

from prowler.providers.aws.lib.security_hub.security_hub import SecurityHub
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_COMMERCIAL_PARTITION,
    AWS_REGION_EU_WEST_1,
)


class TestSecurityHubDefaultProduct:
    def test_region_enabled_without_partner_subscription(self, brand):
        assert brand.security_hub_integration_name == ""

        with patch("boto3.Session.client") as mock_client:
            mock_security_hub_client = mock_client.return_value
            mock_security_hub_client.describe_hub.return_value = {}
            mock_security_hub_client.list_enabled_products_for_import.return_value = {
                "ProductSubscriptions": []
            }

            region, client = SecurityHub._check_region_security_hub(
                region=AWS_REGION_EU_WEST_1,
                session=session.Session(region_name=AWS_REGION_EU_WEST_1),
                aws_account_id=AWS_ACCOUNT_NUMBER,
                aws_partition=AWS_COMMERCIAL_PARTITION,
            )

        assert region == AWS_REGION_EU_WEST_1
        assert client is not None
        mock_security_hub_client.list_enabled_products_for_import.assert_not_called()

    def test_region_disabled_when_hub_is_not_enabled(self, brand):
        with patch("boto3.Session.client") as mock_client:
            mock_client.return_value.describe_hub.side_effect = Exception("no hub")

            region, client = SecurityHub._check_region_security_hub(
                region=AWS_REGION_EU_WEST_1,
                session=session.Session(region_name=AWS_REGION_EU_WEST_1),
                aws_account_id=AWS_ACCOUNT_NUMBER,
                aws_partition=AWS_COMMERCIAL_PARTITION,
            )

        assert region == AWS_REGION_EU_WEST_1
        assert client is None
