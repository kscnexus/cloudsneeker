"""The ECS template can park compute without dropping stored data."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = (ROOT / "cloudsneeker" / "deploy" / "ecs" / "platform.yaml").read_text(
    encoding="utf-8"
)
DESTROY = (ROOT / "cloudsneeker" / "deploy" / "ecs" / "destroy.ps1").read_text(
    encoding="utf-8"
)
REGISTRY = (ROOT / "cloudsneeker" / "deploy" / "ecs" / "registry.yaml").read_text(
    encoding="utf-8"
)
DEPLOY = (ROOT / "cloudsneeker" / "deploy" / "ecs" / "deploy.ps1").read_text(
    encoding="utf-8"
)
IMAGES = (ROOT / ".github" / "workflows" / "cloudsneeker-images.yml").read_text(
    encoding="utf-8"
)


def test_platform_mode_chooses_running_or_parked():
    assert 'PlatformMode:' in TEMPLATE
    assert 'AllowedValues: ["running", "parked"]' in TEMPLATE
    assert "RunCompute: !Equals [!Ref PlatformMode, \"running\"]" in TEMPLATE


def test_stored_data_is_retained_when_the_stack_is_removed():
    database = TEMPLATE.split("  Database:\n", 1)[1].split("  DatabaseParkRole:", 1)[0]
    filesystem = TEMPLATE.split("  FileSystem:\n", 1)[1].split("  OutputAccessPoint:", 1)[0]
    assert "DeletionPolicy: Retain" in database
    assert "UpdateReplacePolicy: Retain" in database
    assert "DeletionProtection: true" in database
    assert "DeletionPolicy: Retain" in filesystem
    assert "UpdateReplacePolicy: Retain" in filesystem


def test_parked_mode_removes_hourly_compute_only():
    cache = TEMPLATE.split("  Cache:\n", 1)[1].split("  FileSystem:", 1)[0]
    nat = TEMPLATE.split("  NatGateway:\n", 1)[1].split("  PrivateRouteTable:", 1)[0]
    assert "Condition: RunCompute" in cache
    assert "Condition: RunCompute" in nat
    assert "Condition: RunTasks" in TEMPLATE
    assert "cloudsneeker:parked" in TEMPLATE


def test_destroy_script_stops_the_database_and_does_not_purge_data():
    assert "PlatformMode\" = \"parked\"" in DESTROY or '["PlatformMode"] = "parked"' in DESTROY
    assert "stop-db-instance" in DESTROY
    assert "Invoke-Aws $deployArgs" in DESTROY
    assert ") + $overrides | Out-Host" not in DESTROY
    forbidden = (
        "delete-db-instance",
        "delete-file-system",
        "delete-secret",
        "delete-stack",
        "s3 rb",
        "batch-delete-image",
        "delete-snapshot",
    )
    for command in forbidden:
        assert command not in DESTROY


def test_registry_trusts_github_actions_instead_of_codebuild():
    assert "AWS::CodeBuild::Project" not in REGISTRY
    assert "CODECOMMIT" not in REGISTRY
    assert "codecommit:GitPull" not in REGISTRY
    assert "token.actions.githubusercontent.com" in REGISTRY
    assert "refs/heads/main" in REGISTRY
    assert "refs/tags/cloudsneeker-v*" in REGISTRY
    assert "repo:${GitHubRepository}:*" not in REGISTRY
    assert "repo:${Owner}@${GitHubOrgId}/${Name}@${GitHubRepoId}:ref:refs/heads/main" in REGISTRY
    assert "iam:GetRole" in REGISTRY
    assert "codebuild" not in DEPLOY.lower()
    assert "GitHub Actions" in DEPLOY


def test_image_workflow_deploys_to_the_azure_vm_after_tests():
    assert "aws" not in IMAGES.lower()
    assert "ecr" not in IMAGES.lower()
    assert "workflows: ['Cloudsneeker: Tests']" in IMAGES
    assert "github.event.workflow_run.conclusion == 'success'" in IMAGES
    assert "github.event.workflow_run.head_repository.full_name == github.repository" in IMAGES
    assert "pull_request:" not in IMAGES
    assert "workflow_dispatch:" in IMAGES
    assert "id-token: write" in IMAGES
    assert "--federated-token" in IMAGES
    assert "az vm run-command invoke" in IMAGES
    assert "cloudsneeker-deploy.service" in IMAGES
    assert "needs: scan" in IMAGES
    assert "docker push" not in IMAGES
    assert "image: [api, mcp, neo4j]" in IMAGES
    assert "--builder default" in IMAGES


def test_image_workflow_scans_each_image_before_the_deploy():
    build = IMAGES.index("- name: Build ${{ matrix.image }}")
    scan = IMAGES.index("uses: ./.github/actions/trivy-scan")
    sbom = IMAGES.index("format: cyclonedx")
    deploy = IMAGES.index("az vm run-command invoke")
    assert build < scan < sbom < deploy
    assert "--push" not in IMAGES
    assert "matrix.image == 'neo4j' && 'none' || 'critical'" in IMAGES
    assert "upload-artifact" in IMAGES


def test_worker_mounts_the_shared_vulnerability_database():
    worker = TEMPLATE.split("  WorkerTaskDefinition:", 1)[1].split(
        "  BeatTaskDefinition:", 1
    )[0]
    assert "AccessPointId: !Ref VulnDbAccessPoint" in worker
    assert "ContainerPath: /var/cache/cloudsneeker/vuln-db" in worker
    assert "Value: /var/cache/cloudsneeker/vuln-db" in worker
    assert "Path: /vuln-db" in TEMPLATE
