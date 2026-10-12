"""Brand-derived values used by SDK (engine and CLI) hooks.

Every function here is a thin wrapper around :data:`cloudsneeker.brand.brand`
so hooked upstream modules stay one-line edits. The module imports only the
standard library and :mod:`cloudsneeker.brand`.
"""

from cloudsneeker.brand import brand


def finding_uid(
    provider_type: str,
    check_id: str,
    account_uid: str,
    region: str,
    resource_name: str,
) -> str:
    """Return the unique identifier written to every finding.

    Args:
        provider_type: Provider short name, for example ``aws``.
        check_id: Check identifier.
        account_uid: Account, subscription, project, or cluster identifier.
        region: Region, location, or namespace.
        resource_name: Resource name or identifier.

    Returns:
        ``"<prefix>-<provider>-<check>-<account>-<region>-<resource>"``.
    """
    return (
        f"{brand.finding_uid_prefix}-{provider_type}-{check_id}-{account_uid}-"
        f"{region}-{resource_name}"
    )


def asff_finding_id(
    check_id: str, account_uid: str, region: str, resource_hash: str
) -> str:
    """Return the ASFF ``Id`` for a finding."""
    return (
        f"{brand.finding_uid_prefix}-{check_id}-{account_uid}-{region}-{resource_hash}"
    )


def asff_generator_id(check_id: str) -> str:
    """Return the ASFF ``GeneratorId`` for a check."""
    return f"{brand.finding_uid_prefix}-{check_id}"


def security_hub_uses_default_product() -> bool:
    """True when findings go to the account's own default Security Hub product."""
    return not brand.security_hub_integration_name


def security_hub_product_arn(partition: str, region: str, account_id: str) -> str:
    """Return the Security Hub ``ProductArn`` findings are imported under.

    Without a registered partner integration the account-owned default product
    is used, which accepts ``BatchImportFindings`` without a subscription.

    Args:
        partition: AWS partition, for example ``aws``.
        region: Region the finding belongs to.
        account_id: Account the finding belongs to.

    Returns:
        A Security Hub product ARN.
    """
    if security_hub_uses_default_product():
        return (
            f"arn:{partition}:securityhub:{region}:{account_id}:"
            f"product/{account_id}/default"
        )
    return (
        f"arn:{partition}:securityhub:{region}::"
        f"product/{brand.security_hub_integration_name}"
    )


def security_hub_subscription_arn(partition: str, region: str, account_id: str) -> str:
    """Return the product-subscription ARN required by a partner integration.

    Returns an empty string when the default product is used because no
    subscription is needed.
    """
    if security_hub_uses_default_product():
        return ""
    return (
        f"arn:{partition}:securityhub:{region}:{account_id}:"
        f"product-subscription/{brand.security_hub_integration_name}"
    )


def security_hub_product_filter(partition: str, region: str, account_id: str) -> dict:
    """Return the ``GetFindings`` filter entry that selects this product's findings."""
    if security_hub_uses_default_product():
        return {
            "ProductArn": [
                {
                    "Value": security_hub_product_arn(partition, region, account_id),
                    "Comparison": "EQUALS",
                }
            ]
        }
    return {
        "ProductName": [
            {"Value": brand.security_hub_product_name, "Comparison": "EQUALS"}
        ]
    }


def html_title() -> str:
    """Return the ``<title>`` of the HTML report."""
    return f"{brand.name} - {brand.tagline}"


def slack_title(identity: str, findings_count: int) -> str:
    """Return the Slack summary headline."""
    return (
        f"Hey there 👋 \n I'm *{brand.name}*, _your cloud security scanner_ "
        ":cloud::key:\n\n I have just finished the security assessment on your "
        f"{identity} with a total of *{findings_count}* findings."
    )


def slack_footer_blocks() -> list[dict]:
    """Return the trailing Slack blocks that point at the product's own links."""
    blocks: list[dict] = [
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": "Read the documentation"},
            "accessory": {
                "type": "button",
                "text": {"type": "plain_text", "text": f"{brand.name} docs"},
                "url": brand.docs_url,
            },
        }
    ]
    if brand.support_url:
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": "Need help? Contact support"},
                "accessory": {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Support"},
                    "url": brand.support_url,
                },
            }
        )
    return blocks


def s3_test_object_key() -> str:
    """Return the object key written when testing S3 bucket access."""
    return f"test-{brand.slug}-connection.txt"


def s3_test_object_body() -> bytes:
    """Return the object body written when testing S3 bucket access."""
    return f"Test {brand.name} Connection".encode()


def cli_usage(providers: str) -> str:
    """Return the top-level argparse usage line."""
    return f"{brand.cli_command} [-h] [--version] {{{providers}}} ..."


__all__ = [
    "asff_finding_id",
    "asff_generator_id",
    "cli_usage",
    "finding_uid",
    "html_title",
    "s3_test_object_body",
    "s3_test_object_key",
    "security_hub_product_arn",
    "security_hub_product_filter",
    "security_hub_subscription_arn",
    "security_hub_uses_default_product",
    "slack_footer_blocks",
    "slack_title",
]
