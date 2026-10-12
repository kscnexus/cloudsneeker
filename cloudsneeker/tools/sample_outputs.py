"""Write a sample scan output in every report format.

Usage::

    python cloudsneeker/tools/sample_outputs.py --output-dir DIR

The release pipeline audits the generated files with ``brand_audit.py
--artifacts`` so a leak in a report writer is caught before an image ships.
No cloud credentials are used; findings are synthetic.
"""

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

TOOLS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOLS_DIR.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from cloudsneeker.brand import brand  # noqa: E402
from cloudsneeker.sdk import finding_uid  # noqa: E402
from prowler.lib.check.models import (  # noqa: E402
    CheckMetadata,
    Code,
    Recommendation,
    Remediation,
)
from prowler.lib.outputs.asff.asff import ASFF  # noqa: E402
from prowler.lib.outputs.csv.csv import CSV  # noqa: E402
from prowler.lib.outputs.finding import Finding  # noqa: E402
from prowler.lib.outputs.html.html import HTML  # noqa: E402
from prowler.lib.outputs.ocsf.ocsf import OCSF  # noqa: E402
from prowler.lib.outputs.sarif.sarif import SARIF  # noqa: E402

ACCOUNT_UID = "123456789012"
REGION = "eu-west-1"


def _metadata(check_id: str, severity: str) -> CheckMetadata:
    return CheckMetadata(
        Provider="aws",
        CheckID=check_id,
        CheckTitle=f"Sample check {check_id}",
        CheckType=["Software and Configuration Checks"],
        ResourceType="AwsS3Bucket",
        ServiceName="s3",
        SubServiceName="",
        ResourceIdTemplate="arn:partition:s3:::bucket_name",
        Severity=severity,
        Description="Synthetic finding used to audit report output.",
        Risk="None; this finding is generated for a brand audit.",
        RelatedUrl="",
        Remediation=Remediation(
            Recommendation=Recommendation(Text="No action required.", Url=""),
            Code=Code(NativeIaC="", Terraform="", Other="", CLI=""),
        ),
        DependsOn=[],
        RelatedTo=[],
        Categories=["encryption"],
        Notes="",
        AdditionalURLs=[],
    )


def _finding(check_id: str, severity: str, status: str, resource: str) -> Finding:
    return Finding(
        auth_method="profile: sample",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        account_uid=ACCOUNT_UID,
        account_name="sample-account",
        account_email="",
        account_organization_uid="o-sample",
        account_organization_name="sample-org",
        account_tags={},
        metadata=_metadata(check_id, severity),
        uid=finding_uid("aws", check_id, ACCOUNT_UID, REGION, resource),
        status=status,
        status_extended=f"Bucket {resource} sample status {status}.",
        resource_uid=f"arn:aws:s3:::{resource}",
        resource_name=resource,
        resource_details="",
        resource_tags={},
        partition="aws",
        region=REGION,
        compliance={"CIS-1.5": ["2.1.1"]},
    )


def sample_findings() -> list[Finding]:
    """Return a small, deterministic set of findings.

    Returns:
        Three findings covering pass, fail, and a second severity.
    """
    return [
        _finding("s3_bucket_default_encryption", "medium", "PASS", "sample-logs"),
        _finding("s3_bucket_public_access", "critical", "FAIL", "sample-public"),
        _finding("s3_bucket_object_versioning", "low", "FAIL", "sample-data"),
    ]


def _sample_provider() -> SimpleNamespace:
    identity = SimpleNamespace(
        profile=None,
        audited_regions=[REGION],
        account=ACCOUNT_UID,
        user_id="AIDASAMPLE",
        identity_arn=f"arn:aws:iam::{ACCOUNT_UID}:user/sample",
    )
    return SimpleNamespace(type="aws", identity=identity)


def _stats(findings: list[Finding]) -> dict:
    total_pass = sum(1 for f in findings if f.status == "PASS")
    total_fail = sum(1 for f in findings if f.status == "FAIL")
    return {
        "findings_count": len(findings),
        "total_pass": total_pass,
        "total_muted_pass": 0,
        "total_fail": total_fail,
        "total_muted_fail": 0,
        "resources_count": len({f.resource_uid for f in findings}),
    }


def write_sample_outputs(output_dir: Path) -> list[Path]:
    """Write CSV, OCSF, ASFF, SARIF, and HTML reports into ``output_dir``.

    Args:
        output_dir: Directory to create files in. Created if missing.

    Returns:
        Paths of the written files.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    findings = sample_findings()
    base = str(output_dir / brand.output_file_prefix)
    written: list[Path] = []

    for cls, extension in (
        (CSV, ".csv"),
        (OCSF, ".ocsf.json"),
        (ASFF, ".asff.json"),
        (SARIF, ".sarif.json"),
    ):
        output = cls(findings=findings, file_path=base, file_extension=extension)
        output.batch_write_data_to_file()
        written.append(Path(output.file_path))

    html = HTML(findings=findings, file_path=base, file_extension=".html")
    html.batch_write_data_to_file(_sample_provider(), _stats(findings))
    written.append(Path(html.file_path))
    return written


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point.

    Args:
        argv: Arguments without the program name.

    Returns:
        Process exit code.
    """
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)

    written = write_sample_outputs(args.output_dir.resolve())
    for path in written:
        print(path)
    print(f"wrote {len(written)} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
