<#
.SYNOPSIS
Park Cloudsneeker so the free account can sit idle.

.DESCRIPTION
Removes the running compute: ECS tasks, the load balancer, NAT gateway,
interface endpoints, and the Valkey cache. Stops PostgreSQL. Keeps the
database, EFS files, Secrets Manager secret, container images, and S3
objects. This script never deletes or purges that data.

Say "destroy" to run this. Say "deploy" to start the database and bring
compute back with deploy.ps1.

.EXAMPLE
pwsh cloudsneeker/deploy/ecs/destroy.ps1
#>
[CmdletBinding()]
param(
    [string]$Region = "us-east-1",
    [string]$Profile = "kscnexus"
)

$ErrorActionPreference = "Stop"
if (Test-Path variable:PSNativeCommandUseErrorActionPreference) {
    $PSNativeCommandUseErrorActionPreference = $false
}
$EcsDir = $PSScriptRoot
$Account = "352285844868"
$ArtifactBucket = "cloudsneeker-cfn-$Account-$Region"
$Aws = @("--profile", $Profile, "--region", $Region, "--output", "json")

function Invoke-Aws {
    param([string[]]$AwsArgs)
    $command = @()
    $command += $Aws
    $command += $AwsArgs
    & aws @command
    if ($LASTEXITCODE -ne 0) { throw "aws $($AwsArgs -join ' ') failed" }
}

function Invoke-AwsText {
    param([string[]]$AwsArgs)
    $command = @()
    $command += $Aws[0..($Aws.Length - 2)]
    $command += "text"
    $command += $AwsArgs
    $value = & aws @command
    if ($LASTEXITCODE -ne 0) { throw "aws $($AwsArgs -join ' ') failed" }
    return ($value | Out-String).Trim()
}

Write-Host "==> Reading the current stack"
$raw = Invoke-Aws @("cloudformation", "describe-stacks", "--stack-name", "cloudsneeker", "--query", "Stacks[0].Parameters")
$current = @{}
foreach ($item in ($raw | ConvertFrom-Json)) {
    $current[$item.ParameterKey] = $item.ParameterValue
}
$current["PlatformMode"] = "parked"

$overrides = @()
foreach ($key in @("PlatformMode", "ImageTag", "AppSecretArn", "DomainName", "CertificateArn", "DatabaseMultiAz")) {
    if ($current.ContainsKey($key)) {
        $overrides += "$key=$($current[$key])"
    }
}

Write-Host "==> Removing compute and keeping stored data"
Invoke-Aws @(
    "cloudformation", "deploy",
    "--stack-name", "cloudsneeker",
    "--template-file", (Join-Path $EcsDir "platform.yaml"),
    "--s3-bucket", $ArtifactBucket,
    "--s3-prefix", "ecs",
    "--capabilities", "CAPABILITY_NAMED_IAM",
    "--no-fail-on-empty-changeset",
    "--parameter-overrides"
) + $overrides | Out-Host

Write-Host "==> Stopping the database"
$status = Invoke-AwsText @("rds", "describe-db-instances", "--db-instance-identifier", "cloudsneeker", "--query", "DBInstances[0].DBInstanceStatus")
Write-Host "Database status: $status"
if ($status -eq "available") {
    Invoke-Aws @("rds", "stop-db-instance", "--db-instance-identifier", "cloudsneeker") | Out-Null
} elseif ($status -ne "stopped" -and $status -ne "stopping") {
    Invoke-Aws @("rds", "wait", "db-instance-available", "--db-instance-identifier", "cloudsneeker") | Out-Null
    Invoke-Aws @("rds", "stop-db-instance", "--db-instance-identifier", "cloudsneeker") | Out-Null
}

Write-Host ""
Write-Host "Compute is parked. PostgreSQL is stopped and its data is still there."
Write-Host "Kept: database, EFS files, secrets, container images, and S3 objects."
Write-Host "AWS starts a stopped database after 7 days. A daily check stops it again while this stack stays parked."
Write-Host "Bring it back with: pwsh cloudsneeker/deploy/ecs/deploy.ps1"
