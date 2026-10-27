"""Cloud Custodian dry-run helpers.

Auth and cloud credentials stay on the existing ``Provider`` /
``ProviderSecret`` models. This module never enables apply mode.

Supported clouds match Cloud Custodian packages installed in ``/opt/c7n``:
AWS (``c7n``), Azure (``c7n-azure``), GCP (``c7n-gcp``), Kubernetes (``c7n-kube``).
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass, field
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

# Cloudsneeker provider types that map to a Cloud Custodian cloud package.
CUSTODIAN_SUPPORTED_PROVIDERS = frozenset(
    {
        Provider.ProviderChoices.AWS.value,
        Provider.ProviderChoices.AZURE.value,
        Provider.ProviderChoices.GCP.value,
        Provider.ProviderChoices.KUBERNETES.value,
    }
)

# Expected Custodian resource-type prefixes per Cloudsneeker provider.
_RESOURCE_PREFIXES: dict[str, tuple[str, ...]] = {
    Provider.ProviderChoices.AWS.value: ("aws.", "aws"),
    Provider.ProviderChoices.AZURE.value: ("azure.", "azure"),
    Provider.ProviderChoices.GCP.value: ("gcp.", "gcp"),
    Provider.ProviderChoices.KUBERNETES.value: ("k8s.", "kubernetes.", "k8s"),
}


class CustodianDryRunError(ValueError):
    """Raised when a Custodian policy or dry-run invocation is invalid."""


@dataclass
class CustodianCredentialBundle:
    """Environment variables and temp files for one Custodian dry-run."""

    env: dict[str, str]
    cleanup_paths: list[Path] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)

    def close(self) -> None:
        for path in self.cleanup_paths:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass


def assert_dry_run_only(mode: str) -> None:
    """Reject any execution mode other than dry-run."""
    if mode != DRY_RUN_MODE:
        raise CustodianDryRunError(
            "Cloudsneeker only supports Cloud Custodian dry-run mode."
        )


def is_custodian_supported_provider(provider_type: str) -> bool:
    """Return True when Cloud Custodian can dry-run against this provider type."""
    return provider_type in CUSTODIAN_SUPPORTED_PROVIDERS


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


def assert_policy_matches_provider(
    policy_yaml: str, provider_type: str
) -> dict[str, Any]:
    """Validate YAML and that resource types match the connected provider cloud."""
    parsed = parse_policy_yaml(policy_yaml)
    if not is_custodian_supported_provider(provider_type):
        raise CustodianDryRunError(
            "Cloud Custodian supports AWS, Azure, GCP, and Kubernetes providers only."
        )

    prefixes = _RESOURCE_PREFIXES[provider_type]
    for index, policy in enumerate(parsed["policies"]):
        resource = str(policy.get("resource", "")).lower()
        if not any(
            resource == prefix.rstrip(".") or resource.startswith(prefix)
            for prefix in prefixes
        ):
            raise CustodianDryRunError(
                f"Policy at index {index} resource '{policy.get('resource')}' "
                f"does not match provider type '{provider_type}'."
            )
    return parsed


def credentials_from_provider(
    provider: Provider, *, work_dir: Path
) -> CustodianCredentialBundle:
    """Build Custodian process env from a connected provider secret.

    Args:
        provider: Tenant provider row with a ``ProviderSecret``.
        work_dir: Directory for temporary credential files (GCP/K8s).
    """
    provider_type = provider.provider
    if not is_custodian_supported_provider(provider_type):
        raise CustodianDryRunError(
            "Cloud Custodian supports AWS, Azure, GCP, and Kubernetes providers only."
        )

    if provider_type == Provider.ProviderChoices.AWS.value:
        return _aws_credentials(provider)
    if provider_type == Provider.ProviderChoices.AZURE.value:
        return _azure_credentials(provider)
    if provider_type == Provider.ProviderChoices.GCP.value:
        return _gcp_credentials(provider, work_dir=work_dir)
    return _kubernetes_credentials(provider, work_dir=work_dir)


def _aws_regions_for_provider(cloud_provider: Any, provider: Provider) -> list[str]:
    """Resolve AWS regions for Custodian (account-enabled, then session default).

    Without explicit regions Cloud Custodian scans a single default region, so
    unused EBS (and other regional resources) in other regions appear as zero.
    """
    scanner_args = provider.scanner_args or {}
    configured = scanner_args.get("regions") or scanner_args.get("aws_regions")
    if isinstance(configured, (list, tuple, set)) and configured:
        return sorted({str(region).strip() for region in configured if str(region).strip()})

    regions: set[str] = set()
    enabled = getattr(cloud_provider, "_enabled_regions", None)
    if enabled:
        regions.update(str(region) for region in enabled if region)
    identity = getattr(cloud_provider, "identity", None)
    audited = getattr(identity, "audited_regions", None) if identity else None
    if audited:
        regions.update(str(region) for region in audited if region)

    if not regions:
        try:
            session = cloud_provider.session.current_session
            discovered = cloud_provider.get_aws_enabled_regions(session)
            if discovered:
                regions.update(str(region) for region in discovered if region)
        except Exception:  # noqa: BLE001
            pass

    if not regions:
        session = cloud_provider.session.current_session
        fallback = session.region_name or "us-east-1"
        regions.add(fallback)

    return sorted(regions)


def _aws_credentials(provider: Provider) -> CustodianCredentialBundle:
    cloud_provider = initialize_prowler_provider(provider)
    session = cloud_provider.session.current_session
    credentials = session.get_credentials()
    if credentials is None:
        raise CustodianDryRunError("Provider has no usable AWS credentials.")
    frozen = credentials.get_frozen_credentials()
    regions = _aws_regions_for_provider(cloud_provider, provider)
    default_region = regions[0] if regions else (session.region_name or "us-east-1")
    env = {
        "AWS_ACCESS_KEY_ID": frozen.access_key,
        "AWS_SECRET_ACCESS_KEY": frozen.secret_key,
        "AWS_DEFAULT_REGION": default_region,
        "AWS_REGION": default_region,
    }
    if frozen.token:
        env["AWS_SESSION_TOKEN"] = frozen.token
    return CustodianCredentialBundle(env=env, regions=regions)


def _azure_credentials(provider: Provider) -> CustodianCredentialBundle:
    secret = provider.secret.secret
    client_id = secret.get("client_id")
    client_secret = secret.get("client_secret")
    tenant_id = secret.get("tenant_id")
    if not client_id or not client_secret or not tenant_id:
        raise CustodianDryRunError(
            "Azure provider requires client_id, client_secret, and tenant_id."
        )
    env = {
        "AZURE_CLIENT_ID": str(client_id),
        "AZURE_CLIENT_SECRET": str(client_secret),
        "AZURE_TENANT_ID": str(tenant_id),
        "AZURE_SUBSCRIPTION_ID": str(provider.uid),
    }
    return CustodianCredentialBundle(env=env)


def _gcp_credentials(
    provider: Provider, *, work_dir: Path
) -> CustodianCredentialBundle:
    secret = provider.secret.secret
    cred_path = work_dir / "gcp-credentials.json"
    if secret.get("service_account_key"):
        key = secret["service_account_key"]
        if isinstance(key, str):
            cred_path.write_text(key, encoding="utf-8")
        else:
            cred_path.write_text(json.dumps(key), encoding="utf-8")
    elif secret.get("client_id") and secret.get("client_secret") and secret.get(
        "refresh_token"
    ):
        payload = {
            "type": "authorized_user",
            "client_id": secret["client_id"],
            "client_secret": secret["client_secret"],
            "refresh_token": secret["refresh_token"],
        }
        cred_path.write_text(json.dumps(payload), encoding="utf-8")
    else:
        raise CustodianDryRunError(
            "GCP provider requires a service account key or OAuth client credentials."
        )

    env = {
        "GOOGLE_APPLICATION_CREDENTIALS": str(cred_path),
        "GOOGLE_CLOUD_PROJECT": str(provider.uid),
        "GCLOUD_PROJECT": str(provider.uid),
    }
    return CustodianCredentialBundle(env=env, cleanup_paths=[cred_path])


def _kubernetes_credentials(
    provider: Provider, *, work_dir: Path
) -> CustodianCredentialBundle:
    secret = provider.secret.secret
    content = secret.get("kubeconfig_content")
    if not content:
        raise CustodianDryRunError("Kubernetes provider requires kubeconfig_content.")

    kubeconfig_path = work_dir / "kubeconfig"
    if isinstance(content, dict):
        kubeconfig_path.write_text(yaml.safe_dump(content), encoding="utf-8")
    else:
        kubeconfig_path.write_text(str(content), encoding="utf-8")

    env = {"KUBECONFIG": str(kubeconfig_path)}
    return CustodianCredentialBundle(env=env, cleanup_paths=[kubeconfig_path])


_AWS_REGION_RE = re.compile(
    r"^(?:af|ap|ca|eu|il|me|sa|us|cn|us-gov)-[a-z0-9-]+$"
)


def _infer_region_from_path(resources_file: Path, output_dir: Path) -> str | None:
    """Pick a region folder from Custodian's multi-region output layout."""
    try:
        relative = resources_file.relative_to(output_dir)
    except ValueError:
        relative = resources_file
    for part in relative.parts[:-1]:
        if _AWS_REGION_RE.match(part) or part in {"global", "all"}:
            return part
    return None


def _stamp_resource_metadata(
    item: dict[str, Any],
    *,
    policy_name: str,
    region: str | None,
) -> dict[str, Any]:
    """Attach policy/region metadata used by the report UI."""
    stamped = dict(item)
    if policy_name and "c7n:policy" not in stamped:
        stamped["c7n:policy"] = policy_name
    if region and "c7n:region" not in stamped:
        stamped["c7n:region"] = region
    return stamped


def _collect_output(output_dir: Path) -> dict[str, Any]:
    """Read Custodian resources.json files under an output directory."""
    resources: list[dict[str, Any]] = []
    policies: list[dict[str, Any]] = []

    for resources_file in output_dir.rglob("resources.json"):
        try:
            payload = json.loads(resources_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(payload, list):
            continue
        policy_name = resources_file.parent.name
        region = _infer_region_from_path(resources_file, output_dir)
        # Region folder can sit above the policy folder: out/us-east-1/policy/…
        if region and policy_name == region:
            policy_name = (
                resources_file.parent.parent.name
                if resources_file.parent.parent != output_dir
                else policy_name
            )
        stamped = [
            _stamp_resource_metadata(item, policy_name=policy_name, region=region)
            for item in payload
            if isinstance(item, dict)
        ]
        resources.extend(stamped)
        policies.append(
            {
                "name": policy_name,
                "resource_count": len(payload),
                **({"region": region} if region else {}),
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
    credential_env: dict[str, str],
    dryrun: bool,
    regions: list[str] | None = None,
) -> dict[str, Any]:
    """Invoke Cloud Custodian against a policy file via the CLI.

    ``c7n`` and cloud plugins live in an isolated venv (``/opt/c7n``). Never apply.
    """
    import subprocess

    assert_dry_run_only(DRY_RUN_MODE if dryrun else "apply")
    if dryrun is not True:
        raise CustodianDryRunError(
            "Cloudsneeker only supports Cloud Custodian dry-run mode."
        )

    env = os.environ.copy()
    # Drop cloud credential keys first so a prior worker run cannot leak.
    for key in (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_DEFAULT_REGION",
        "AWS_REGION",
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
        "AZURE_TENANT_ID",
        "AZURE_SUBSCRIPTION_ID",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GOOGLE_CLOUD_PROJECT",
        "GCLOUD_PROJECT",
        "KUBECONFIG",
    ):
        env.pop(key, None)
    env.update(credential_env)

    command = [
        _resolve_custodian_bin(),
        "run",
        "--dryrun",
        "-s",
        str(output_dir),
    ]
    for region in regions or []:
        command.extend(["--region", region])
    command.append(str(policy_path))
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
    output = _collect_output(output_dir)
    if regions:
        output["regions"] = list(regions)
    return output


def run_custodian_dryrun(
    *,
    policy_yaml: str,
    provider: Provider,
) -> dict[str, Any]:
    """Validate policy YAML and execute Cloud Custodian in dry-run mode only."""
    assert_policy_matches_provider(policy_yaml, provider.provider)
    assert_dry_run_only(DRY_RUN_MODE)

    with tempfile.TemporaryDirectory(prefix="cs-custodian-") as tmp:
        tmp_path = Path(tmp)
        policy_path = tmp_path / "policy.yml"
        output_dir = tmp_path / "out"
        output_dir.mkdir(parents=True, exist_ok=True)
        policy_path.write_text(policy_yaml, encoding="utf-8")
        bundle = credentials_from_provider(provider, work_dir=tmp_path)
        try:
            return _execute_c7n_dryrun(
                policy_path=policy_path,
                output_dir=output_dir,
                credential_env=bundle.env,
                dryrun=True,
                regions=bundle.regions,
            )
        finally:
            bundle.close()


def enqueue_custodian_dry_run(
    *,
    tenant_id: str,
    policy_id: str,
    trigger: str = CustodianRun.Trigger.MANUAL,
) -> CustodianRun:
    """Create a pending dry-run and enqueue the Celery worker after commit."""
    from cloudsneeker_api.tasks import custodian_dry_run_task

    if trigger not in {
        CustodianRun.Trigger.MANUAL,
        CustodianRun.Trigger.SCHEDULED,
    }:
        raise CustodianDryRunError(f"Unknown Custodian run trigger: {trigger}")

    with rls_transaction(tenant_id):
        policy = CustodianPolicy.objects.select_related("provider").get(
            tenant_id=tenant_id, id=policy_id
        )
        if not is_custodian_supported_provider(policy.provider.provider):
            raise CustodianDryRunError(
                "Cloud Custodian supports AWS, Azure, GCP, and Kubernetes providers only."
            )
        assert_policy_matches_provider(policy.policy_yaml, policy.provider.provider)
        run = CustodianRun.objects.create(
            tenant_id=tenant_id,
            policy=policy,
            provider=policy.provider,
            status=CustodianRun.Status.PENDING,
            mode=CustodianRun.Mode.DRYRUN,
            trigger=trigger,
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
            CustodianRun.objects.select_related("policy", "provider", "provider__secret")
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
        output = run_custodian_dryrun(policy_yaml=policy_yaml, provider=provider)
        summary = {
            "resource_count": output.get("resource_count", 0),
            "policies": output.get("policies", []),
            "mode": DRY_RUN_MODE,
            "provider_type": provider.provider,
            "regions": output.get("regions", []),
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
