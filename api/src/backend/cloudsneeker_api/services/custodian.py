"""Cloud Custodian dry-run helpers.

Auth and cloud credentials stay on the existing ``Provider`` /
``ProviderSecret`` models. This module never enables apply mode.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

import yaml
from api.db_utils import rls_transaction
from api.models import Provider
from api.utils import initialize_prowler_provider
from cloudsneeker_api.models import CustodianPolicy, CustodianRun
from django.db import transaction
from django.utils import timezone

DRY_RUN_MODE = "dryrun"


class CustodianDryRunError(ValueError):
    """Raised when a Custodian policy or dry-run invocation is invalid."""


def assert_dry_run_only(mode: str) -> None:
    """Reject any execution mode other than dry-run."""
    if mode != DRY_RUN_MODE:
        raise CustodianDryRunError(
            "Cloudsneeker only supports Cloud Custodian dry-run mode."
        )


def parse_policy_yaml(policy_yaml: str) -> dict[str, Any]:
    """Parse and structurally validate a Custodian policy document.

    Args:
        policy_yaml: YAML text containing a ``policies`` list.

    Returns:
        Parsed policy mapping.

    Raises:
        CustodianDryRunError: When YAML is invalid or missing required fields.
    """
    if not policy_yaml or not policy_yaml.strip():
        raise CustodianDryRunError("Policy YAML must define a policies list.")

    try:
        parsed = yaml.safe_load(policy_yaml)
    except yaml.YAMLError as exc:
        raise CustodianDryRunError(f"Invalid YAML: {exc}") from exc

    if not isinstance(parsed, dict):
        raise CustodianDryRunError("Policy YAML must be a mapping with a policies key.")

    policies = parsed.get("policies")
    if not isinstance(policies, list):
        raise CustodianDryRunError("Policy YAML must include a policies list.")
    if len(policies) < 1:
        raise CustodianDryRunError("Policy YAML must include at least one policy.")

    for index, policy in enumerate(policies):
        if not isinstance(policy, dict):
            raise CustodianDryRunError(f"Policy at index {index} must be a mapping.")
        if not policy.get("name"):
            raise CustodianDryRunError(f"Policy at index {index} requires a name.")
        if not policy.get("resource"):
            raise CustodianDryRunError(f"Policy at index {index} requires a resource.")

    return parsed


def aws_credentials_from_provider(provider: Provider) -> dict[str, str]:
    """Build AWS credential env values from a connected cloud provider."""
    cloud_provider = initialize_prowler_provider(provider)
    session = cloud_provider.session.current_session
    credentials = session.get_credentials()
    if credentials is None:
        raise CustodianDryRunError("Provider has no usable AWS credentials.")
    frozen = credentials.get_frozen_credentials()
    result = {
        "aws_access_key_id": frozen.access_key,
        "aws_secret_access_key": frozen.secret_key,
    }
    if frozen.token:
        result["aws_session_token"] = frozen.token
    return result


def _collect_output(output_dir: Path) -> dict[str, Any]:
    """Read Custodian resources.json files under an output directory."""
    resources: list[dict[str, Any]] = []
    policies: list[dict[str, Any]] = []

    for resources_file in output_dir.rglob("resources.json"):
        try:
            payload = json.loads(resources_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, list):
            resources.extend(item for item in payload if isinstance(item, dict))
            policies.append(
                {
                    "name": resources_file.parent.name,
                    "resource_count": len(payload),
                }
            )

    return {
        "mode": DRY_RUN_MODE,
        "resource_count": len(resources),
        "policies": policies,
        "resources": resources[:500],
    }


def _resolve_custodian_bin() -> str:
    """Resolve the Cloud Custodian CLI (separate venv; not the API lock)."""
    configured = os.environ.get("C7N_BIN", "").strip()
    if configured:
        return configured
    default_path = Path("/opt/c7n/bin/custodian")
    if default_path.is_file():
        return str(default_path)
    return "custodian"


def _execute_c7n_dryrun(
    *,
    policy_path: Path,
    output_dir: Path,
    aws_credentials: dict[str, str],
    dryrun: bool,
) -> dict[str, Any]:
    """Invoke Cloud Custodian against a policy file via the CLI.

    ``c7n`` is installed in an isolated venv (``/opt/c7n``) because its pins
    conflict with the API lock (urllib3 / tabulate / boto3). Never call apply.

    Args:
        policy_path: Path to the policy YAML file.
        output_dir: Directory for Custodian output artifacts.
        aws_credentials: AWS key material for the process environment.
        dryrun: Must be True; apply mode is rejected.
    """
    import subprocess

    assert_dry_run_only(DRY_RUN_MODE if dryrun else "apply")
    if dryrun is not True:
        raise CustodianDryRunError(
            "Cloudsneeker only supports Cloud Custodian dry-run mode."
        )

    env = os.environ.copy()
    env["AWS_ACCESS_KEY_ID"] = aws_credentials["aws_access_key_id"]
    env["AWS_SECRET_ACCESS_KEY"] = aws_credentials["aws_secret_access_key"]
    token = aws_credentials.get("aws_session_token")
    if token:
        env["AWS_SESSION_TOKEN"] = token
    else:
        env.pop("AWS_SESSION_TOKEN", None)

    # Always pass --dryrun; never allow apply/mutate flags.
    command = [
        _resolve_custodian_bin(),
        "run",
        "--dryrun",
        "-s",
        str(output_dir),
        str(policy_path),
    ]
    completed = subprocess.run(
        command,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "custodian failed").strip()
        raise CustodianDryRunError(detail[:4000])
    return _collect_output(output_dir)


def run_custodian_dryrun(
    *,
    policy_yaml: str,
    aws_credentials: dict[str, str],
) -> dict[str, Any]:
    """Validate policy YAML and execute Cloud Custodian in dry-run mode only."""
    parse_policy_yaml(policy_yaml)
    assert_dry_run_only(DRY_RUN_MODE)

    with tempfile.TemporaryDirectory(prefix="cs-custodian-") as tmp:
        tmp_path = Path(tmp)
        policy_path = tmp_path / "policy.yml"
        output_dir = tmp_path / "out"
        output_dir.mkdir(parents=True, exist_ok=True)
        policy_path.write_text(policy_yaml, encoding="utf-8")
        return _execute_c7n_dryrun(
            policy_path=policy_path,
            output_dir=output_dir,
            aws_credentials=aws_credentials,
            dryrun=True,
        )


def enqueue_custodian_dry_run(*, tenant_id: str, policy_id: str) -> CustodianRun:
    """Create a pending dry-run and enqueue the Celery worker after commit."""
    from cloudsneeker_api.tasks import custodian_dry_run_task

    with rls_transaction(tenant_id):
        policy = CustodianPolicy.objects.select_related("provider").get(
            tenant_id=tenant_id, id=policy_id
        )
        if policy.provider.provider != Provider.ProviderChoices.AWS.value:
            raise CustodianDryRunError("Cloud Custodian dry-run supports AWS providers only.")
        run = CustodianRun.objects.create(
            tenant_id=tenant_id,
            policy=policy,
            provider=policy.provider,
            status=CustodianRun.Status.PENDING,
            mode=CustodianRun.Mode.DRYRUN,
        )

    run_id = str(run.id)
    transaction.on_commit(
        lambda: custodian_dry_run_task.delay(tenant_id=tenant_id, run_id=run_id)
    )
    return run


def process_custodian_dry_run(*, tenant_id: str, run_id: str) -> dict[str, str]:
    """Execute a pending Custodian dry-run and persist results."""
    with rls_transaction(tenant_id):
        run = (
            CustodianRun.objects.select_related("policy", "provider")
            .filter(tenant_id=tenant_id, id=run_id)
            .first()
        )
        if run is None:
            raise CustodianDryRunError(f"Custodian run {run_id} was not found.")

        assert_dry_run_only(run.mode)
        run.status = CustodianRun.Status.RUNNING
        run.started_at = timezone.now()
        run.error = ""
        run.save(update_fields=["status", "started_at", "error", "updated_at"])

        policy_yaml = run.policy.policy_yaml
        provider = run.provider

    try:
        credentials = aws_credentials_from_provider(provider)
        output = run_custodian_dryrun(
            policy_yaml=policy_yaml,
            aws_credentials=credentials,
        )
        summary = {
            "resource_count": output.get("resource_count", 0),
            "policies": output.get("policies", []),
            "mode": DRY_RUN_MODE,
        }
        with rls_transaction(tenant_id):
            run = CustodianRun.objects.get(tenant_id=tenant_id, id=run_id)
            run.status = CustodianRun.Status.COMPLETED
            run.finished_at = timezone.now()
            run.summary = summary
            run.output = output
            run.error = ""
            run.save(
                update_fields=[
                    "status",
                    "finished_at",
                    "summary",
                    "output",
                    "error",
                    "updated_at",
                ]
            )
        return {"status": CustodianRun.Status.COMPLETED, "run_id": str(run_id)}
    except Exception as exc:  # noqa: BLE001
        with rls_transaction(tenant_id):
            run = CustodianRun.objects.get(tenant_id=tenant_id, id=run_id)
            run.status = CustodianRun.Status.FAILED
            run.finished_at = timezone.now()
            run.error = str(exc)[:4000]
            run.save(update_fields=["status", "finished_at", "error", "updated_at"])
        return {"status": CustodianRun.Status.FAILED, "run_id": str(run_id)}
