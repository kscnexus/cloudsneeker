"""Trivy Hub orchestration.

IaC and Image modes enqueue the existing ``scan-perform`` path.
Filesystem, repository, SBOM, and Kubernetes modes shell out to the Trivy
CLI and import JSON into shared Scan / Finding rows.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

import yaml
from api.db_utils import rls_transaction
from api.models import Provider, Scan, StateChoices
from cloudsneeker_api.models import TrivyRun, TrivyTarget
from django.db import transaction
from django.utils import timezone

TRIVY_MODES = frozenset(
    {
        TrivyTarget.Mode.IAC,
        TrivyTarget.Mode.IMAGE,
        TrivyTarget.Mode.FS,
        TrivyTarget.Mode.REPO,
        TrivyTarget.Mode.SBOM,
        TrivyTarget.Mode.K8S,
    }
)

PROWLER_SCAN_MODES = frozenset({TrivyTarget.Mode.IAC, TrivyTarget.Mode.IMAGE})

MODE_PROVIDER_TYPES: dict[str, frozenset[str]] = {
    TrivyTarget.Mode.IAC: frozenset({Provider.ProviderChoices.IAC.value}),
    TrivyTarget.Mode.IMAGE: frozenset({Provider.ProviderChoices.IMAGE.value}),
    TrivyTarget.Mode.K8S: frozenset({Provider.ProviderChoices.KUBERNETES.value}),
    TrivyTarget.Mode.FS: frozenset(),
    TrivyTarget.Mode.REPO: frozenset(),
    TrivyTarget.Mode.SBOM: frozenset(),
}

DEFAULT_SCANNERS = ("vuln", "misconfig", "secret")
TRIVY_TIMEOUT_SECONDS = int(os.environ.get("TRIVY_HUB_TIMEOUT_SECONDS", "900"))
MAX_ARCHIVE_BYTES = int(os.environ.get("TRIVY_HUB_MAX_ARCHIVE_BYTES", str(50 * 1024 * 1024)))
MAX_SBOM_CHARS = int(os.environ.get("TRIVY_HUB_MAX_SBOM_CHARS", str(5 * 1024 * 1024)))


PROVIDER_SCAN_PATH = "provider_scan"

SCAN_STATE_TO_RUN_STATUS: dict[str, str] = {
    StateChoices.AVAILABLE.value: TrivyRun.Status.PENDING,
    StateChoices.SCHEDULED.value: TrivyRun.Status.PENDING,
    StateChoices.EXECUTING.value: TrivyRun.Status.RUNNING,
    StateChoices.COMPLETED.value: TrivyRun.Status.COMPLETED,
    StateChoices.FAILED.value: TrivyRun.Status.FAILED,
    StateChoices.CANCELLED.value: TrivyRun.Status.FAILED,
}


class TrivyHubError(ValueError):
    """Raised when a Trivy Hub target or run is invalid."""


def effective_run_status(
    run_status: str, summary: dict | None, scan_state: str | None
) -> str:
    """Return the status a run should report to users.

    IaC and image runs finish as soon as they hand off to ``scan-perform``,
    so their real outcome is the linked scan's state.

    Args:
        run_status: Stored ``TrivyRun.status``.
        summary: Stored ``TrivyRun.summary``.
        scan_state: State of the linked ``Scan``, if any.

    Returns:
        The run status to expose.
    """
    if run_status != TrivyRun.Status.COMPLETED or not scan_state:
        return run_status
    if (summary or {}).get("path") != PROVIDER_SCAN_PATH:
        return run_status
    return SCAN_STATE_TO_RUN_STATUS.get(scan_state, run_status)


@dataclass
class TrivyProcessBundle:
    """Temp files and env for one Trivy CLI invocation."""

    work_dir: Path
    env: dict[str, str] = field(default_factory=dict)
    cleanup_paths: list[Path] = field(default_factory=list)

    def close(self) -> None:
        for path in self.cleanup_paths:
            try:
                if path.is_dir():
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    path.unlink(missing_ok=True)
            except OSError:
                pass
        shutil.rmtree(self.work_dir, ignore_errors=True)


def is_valid_trivy_mode(mode: str) -> bool:
    """Return True when mode is a supported Trivy Hub mode."""
    return mode in TRIVY_MODES


def assert_provider_matches_mode(provider: Provider, mode: str) -> None:
    """Ensure the linked provider type is allowed for the target mode."""
    allowed = MODE_PROVIDER_TYPES.get(mode)
    if allowed is None:
        raise TrivyHubError(f"Unknown Trivy mode: {mode}")
    if allowed and provider.provider not in allowed:
        raise TrivyHubError(
            f"Mode '{mode}' requires provider type "
            f"{', '.join(sorted(allowed))}; got '{provider.provider}'."
        )


def validate_target_config(mode: str, config: dict[str, Any] | None) -> dict[str, Any]:
    """Validate and normalize target config for a mode.

    Args:
        mode: Trivy Hub mode.
        config: Raw config JSON from the client.

    Returns:
        Normalized config mapping.

    Raises:
        TrivyHubError: When required fields are missing or invalid.
    """
    if not is_valid_trivy_mode(mode):
        raise TrivyHubError(f"Unknown Trivy mode: {mode}")
    cfg = dict(config or {})

    scanners = cfg.get("scanners")
    if scanners is not None:
        if not isinstance(scanners, list) or not all(
            isinstance(item, str) and item.strip() for item in scanners
        ):
            raise TrivyHubError("config.scanners must be a list of scanner names.")
        cfg["scanners"] = [item.strip() for item in scanners]
    else:
        cfg["scanners"] = list(DEFAULT_SCANNERS)

    if mode == TrivyTarget.Mode.IMAGE:
        images = cfg.get("images") or cfg.get("image")
        if isinstance(images, str):
            images = [images]
        if images is not None and (
            not isinstance(images, list)
            or not all(isinstance(item, str) and item.strip() for item in images)
        ):
            raise TrivyHubError("config.images must be a list of image references.")
        if isinstance(images, list):
            cfg["images"] = [item.strip() for item in images]

    if mode == TrivyTarget.Mode.REPO:
        url = str(cfg.get("repository_url") or cfg.get("url") or "").strip()
        if not url:
            raise TrivyHubError("config.repository_url is required for repo mode.")
        cfg["repository_url"] = url

    if mode == TrivyTarget.Mode.FS:
        has_path = bool(str(cfg.get("path") or "").strip())
        has_archive = bool(cfg.get("archive_b64"))
        if not has_path and not has_archive:
            raise TrivyHubError(
                "config.path or config.archive_b64 is required for fs mode."
            )
        if has_archive:
            archive = str(cfg.get("archive_b64") or "")
            # Rough decoded size check without full decode for huge strings.
            if len(archive) > MAX_ARCHIVE_BYTES * 2:
                raise TrivyHubError("Filesystem archive exceeds the size limit.")

    if mode == TrivyTarget.Mode.SBOM:
        sbom = cfg.get("sbom")
        if not isinstance(sbom, str) or not sbom.strip():
            raise TrivyHubError("config.sbom is required for sbom mode.")
        if len(sbom) > MAX_SBOM_CHARS:
            raise TrivyHubError("SBOM payload exceeds the size limit.")
        cfg["sbom"] = sbom

    if mode == TrivyTarget.Mode.K8S:
        # Cluster identity comes from the linked kubernetes provider.
        pass

    return cfg


def _resolve_trivy_bin() -> str:
    configured = os.environ.get("TRIVY_BIN", "").strip()
    if configured:
        return configured
    found = shutil.which("trivy")
    if not found:
        raise TrivyHubError("Trivy binary was not found on the worker.")
    return found


def _scanners_args(config: dict[str, Any]) -> list[str]:
    scanners = config.get("scanners") or list(DEFAULT_SCANNERS)
    return ["--scanners", ",".join(scanners)]


def _severity_args(config: dict[str, Any]) -> list[str]:
    severities = config.get("severity") or config.get("severities")
    if not severities:
        return []
    if isinstance(severities, list):
        value = ",".join(str(item) for item in severities)
    else:
        value = str(severities)
    return ["--severity", value]


def _extract_archive(archive_b64: str, dest: Path) -> Path:
    raw = base64.b64decode(archive_b64, validate=False)
    if len(raw) > MAX_ARCHIVE_BYTES:
        raise TrivyHubError("Filesystem archive exceeds the size limit.")
    archive_path = dest / "upload.bin"
    archive_path.write_bytes(raw)
    extract_dir = dest / "fs-root"
    extract_dir.mkdir(parents=True, exist_ok=True)
    if zipfile.is_zipfile(archive_path):
        with zipfile.ZipFile(archive_path) as zf:
            zf.extractall(extract_dir)
    else:
        try:
            with tarfile.open(archive_path, mode="r:*") as tf:
                tf.extractall(extract_dir)
        except tarfile.TarError as exc:
            raise TrivyHubError(
                "Filesystem archive must be a zip or tar archive."
            ) from exc
    return extract_dir


def _kubeconfig_env(provider: Provider, work_dir: Path) -> dict[str, str]:
    secret = provider.secret.secret if getattr(provider, "secret", None) else {}
    content = secret.get("kubeconfig_content")
    if not content:
        raise TrivyHubError("Kubernetes provider requires kubeconfig_content.")
    kubeconfig_path = work_dir / "kubeconfig"
    if isinstance(content, dict):
        kubeconfig_path.write_text(yaml.safe_dump(content), encoding="utf-8")
    else:
        kubeconfig_path.write_text(str(content), encoding="utf-8")
    return {"KUBECONFIG": str(kubeconfig_path)}


def _repo_token_env(provider: Provider) -> dict[str, str]:
    secret = {}
    if getattr(provider, "secret", None) is not None:
        secret = provider.secret.secret or {}
    token = (
        secret.get("access_token")
        or secret.get("personal_access_token")
        or secret.get("oauth_app_token")
        or ""
    )
    if not token:
        return {}
    return {
        "GITHUB_TOKEN": str(token),
        "GITLAB_TOKEN": str(token),
    }


def build_trivy_command(
    *,
    mode: str,
    config: dict[str, Any],
    provider: Provider,
    work_dir: Path,
) -> tuple[list[str], dict[str, str]]:
    """Build argv and env for a direct Trivy CLI mode (not iac/image)."""
    binary = _resolve_trivy_bin()
    env = {**os.environ}
    common = [
        binary,
        "--quiet",
        "-f",
        "json",
        *_scanners_args(config),
        *_severity_args(config),
    ]

    if mode == TrivyTarget.Mode.FS:
        if config.get("archive_b64"):
            scan_path = _extract_archive(str(config["archive_b64"]), work_dir)
        else:
            scan_path = Path(str(config["path"])).resolve()
            if not scan_path.exists():
                raise TrivyHubError(f"Filesystem path does not exist: {scan_path}")
        return [*common, "fs", str(scan_path)], env

    if mode == TrivyTarget.Mode.REPO:
        env.update(_repo_token_env(provider))
        return [*common, "repo", str(config["repository_url"])], env

    if mode == TrivyTarget.Mode.SBOM:
        sbom_path = work_dir / "sbom.json"
        sbom_path.write_text(str(config["sbom"]), encoding="utf-8")
        return [*common, "sbom", str(sbom_path)], env

    if mode == TrivyTarget.Mode.K8S:
        env.update(_kubeconfig_env(provider, work_dir))
        context = str(config.get("context") or provider.uid or "").strip()
        namespace = str(config.get("namespace") or "").strip()
        args = [*common, "k8s"]
        if context:
            args.extend(["--context", context])
        if namespace:
            args.extend(["--include-namespaces", namespace])
        args.append("cluster")
        return args, env

    raise TrivyHubError(f"Mode '{mode}' is not a direct Trivy CLI mode.")


def run_trivy_cli(
    *,
    mode: str,
    config: dict[str, Any],
    provider: Provider,
) -> dict[str, Any]:
    """Execute Trivy and return parsed JSON."""
    work_dir = Path(tempfile.mkdtemp(prefix="cloudsneeker-trivy-"))
    bundle = TrivyProcessBundle(work_dir=work_dir)
    try:
        argv, env = build_trivy_command(
            mode=mode, config=config, provider=provider, work_dir=work_dir
        )
        process = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            env=env,
            timeout=TRIVY_TIMEOUT_SECONDS,
            check=False,
        )
        # Trivy exits non-zero when vulnerabilities are found; still parse stdout.
        stdout = process.stdout or ""
        if not stdout.strip():
            stderr = (process.stderr or "").strip()
            raise TrivyHubError(
                stderr or f"Trivy produced no JSON output (exit {process.returncode})."
            )
        try:
            report = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise TrivyHubError(f"Trivy returned invalid JSON: {exc}") from exc
        if not isinstance(report, dict):
            raise TrivyHubError("Trivy JSON root must be an object.")
        return report
    except subprocess.TimeoutExpired as exc:
        raise TrivyHubError("Trivy scan timed out.") from exc
    finally:
        bundle.close()


def _enqueue_provider_scan(
    *,
    tenant_id: str,
    provider: Provider,
    run: TrivyRun,
    scan_name: str,
) -> Scan:
    """Create a Scan and enqueue existing scan-perform for iac/image."""
    from tasks.tasks import create_scan_task_record, enqueue_scan_execution_on_commit

    task_id = str(uuid4())
    scan = Scan.objects.create(
        tenant_id=tenant_id,
        provider=provider,
        name=scan_name[:100],
        trigger=Scan.TriggerChoices.MANUAL,
        state=StateChoices.AVAILABLE,
        scanner_args={"source": "trivy_hub", "mode": run.target.mode},
        task_id=task_id,
    )
    create_scan_task_record(
        tenant_id=tenant_id,
        task_id=task_id,
        task_kwargs={
            "tenant_id": str(tenant_id),
            "scan_id": str(scan.id),
            "provider_id": str(provider.id),
        },
    )
    enqueue_scan_execution_on_commit(
        tenant_id=tenant_id, scan=scan, task_id=task_id
    )
    return scan


def enqueue_trivy_run(
    *,
    tenant_id: str,
    target_id: str,
    trigger: str = TrivyRun.Trigger.MANUAL,
    triggered_by_id: str | None = None,
) -> TrivyRun:
    """Create a pending Trivy run and enqueue the worker after commit."""
    from cloudsneeker_api.tasks import trivy_scan_task

    if trigger not in {TrivyRun.Trigger.MANUAL, TrivyRun.Trigger.SCHEDULED}:
        raise TrivyHubError(f"Unknown Trivy run trigger: {trigger}")

    with rls_transaction(tenant_id):
        target = TrivyTarget.objects.select_related("provider").get(
            tenant_id=tenant_id, id=target_id
        )
        assert_provider_matches_mode(target.provider, target.mode)
        validate_target_config(target.mode, target.config)
        active = TrivyRun.objects.filter(
            tenant_id=tenant_id,
            target_id=target_id,
            status__in=[TrivyRun.Status.PENDING, TrivyRun.Status.RUNNING],
        ).count()
        max_concurrent = int(os.environ.get("TRIVY_HUB_MAX_CONCURRENT_PER_TARGET", "2"))
        if active >= max_concurrent:
            raise TrivyHubError(
                f"Target already has {active} active run(s); limit is {max_concurrent}."
            )
        run = TrivyRun.objects.create(
            tenant_id=tenant_id,
            target=target,
            provider=target.provider,
            status=TrivyRun.Status.PENDING,
            trigger=trigger,
            triggered_by_id=triggered_by_id,
        )

    run_id = str(run.id)
    transaction.on_commit(
        lambda: trivy_scan_task.delay(tenant_id=tenant_id, run_id=run_id)
    )
    return run


def process_trivy_run(*, tenant_id: str, run_id: str) -> dict[str, str]:
    """Execute a pending Trivy Hub run and persist status / scan link."""
    from cloudsneeker_api.services.trivy_import import import_trivy_report

    with rls_transaction(tenant_id):
        run = (
            TrivyRun.objects.select_related(
                "target", "provider", "provider__secret"
            )
            .filter(tenant_id=tenant_id, id=run_id)
            .first()
        )
        if run is None:
            raise TrivyHubError(f"Trivy run {run_id} was not found.")
        if run.status == TrivyRun.Status.FAILED and run.error_class == "cancelled":
            return {"status": TrivyRun.Status.FAILED, "run_id": str(run_id)}

        run.status = TrivyRun.Status.RUNNING
        run.started_at = timezone.now()
        run.error = ""
        run.error_class = ""
        run.save(
            update_fields=[
                "status",
                "started_at",
                "error",
                "error_class",
                "updated_at",
            ]
        )

        target = run.target
        provider = run.provider
        mode = target.mode
        config = validate_target_config(mode, target.config)
        assert_provider_matches_mode(provider, mode)

        try:
            if mode in PROWLER_SCAN_MODES:
                scan = _enqueue_provider_scan(
                    tenant_id=tenant_id,
                    provider=provider,
                    run=run,
                    scan_name=f"Trivy {mode}: {target.name}",
                )
                run.scan_id = scan.id
                run.status = TrivyRun.Status.COMPLETED
                run.finished_at = timezone.now()
                run.summary = {
                    "mode": mode,
                    "path": PROVIDER_SCAN_PATH,
                    "scan_id": str(scan.id),
                    "finding_count": None,
                }
                run.output = {"enqueued": True}
                run.save(
                    update_fields=[
                        "scan_id",
                        "status",
                        "finished_at",
                        "summary",
                        "output",
                        "updated_at",
                    ]
                )
                return {
                    "status": TrivyRun.Status.COMPLETED,
                    "run_id": str(run_id),
                    "scan_id": str(scan.id),
                }

            report = run_trivy_cli(mode=mode, config=config, provider=provider)
            from cloudsneeker_api.services.trivy_import import (
                trivy_results_to_finding_rows,
            )

            finding_rows = trivy_results_to_finding_rows(report, mode=mode)
            scan = import_trivy_report(
                tenant_id=tenant_id,
                provider=provider,
                report=report,
                mode=mode,
                scan_name=f"Trivy {mode}: {target.name}",
                started_at=run.started_at,
            )
            run.scan_id = scan.id
            run.status = TrivyRun.Status.COMPLETED
            run.finished_at = timezone.now()
            run.summary = {
                "mode": mode,
                "path": "trivy_cli",
                "scan_id": str(scan.id),
                "finding_count": len(finding_rows),
            }
            # Keep only compact metadata in output (not full Trivy JSON).
            run.output = {
                "result_targets": [
                    str(item.get("Target") or "")
                    for item in (report.get("Results") or [])
                    if isinstance(item, dict)
                ][:50],
            }
            run.save(
                update_fields=[
                    "scan_id",
                    "status",
                    "finished_at",
                    "summary",
                    "output",
                    "updated_at",
                ]
            )
            return {
                "status": TrivyRun.Status.COMPLETED,
                "run_id": str(run_id),
                "scan_id": str(scan.id),
            }
        except Exception as exc:  # noqa: BLE001
            run.status = TrivyRun.Status.FAILED
            run.finished_at = timezone.now()
            run.error = str(exc)[:4000]
            run.error_class = (
                "trivy_hub" if isinstance(exc, TrivyHubError) else "internal"
            )
            run.save(
                update_fields=[
                    "status",
                    "finished_at",
                    "error",
                    "error_class",
                    "updated_at",
                ]
            )
            if isinstance(exc, TrivyHubError):
                return {"status": TrivyRun.Status.FAILED, "run_id": str(run_id)}
            raise
