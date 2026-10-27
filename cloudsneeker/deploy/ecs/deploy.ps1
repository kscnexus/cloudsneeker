<#
.SYNOPSIS
Deploy Cloudsneeker on ECS in us-east-1.

.DESCRIPTION
Creates the application secret, the image registry, and the Fargate platform.
GitHub Actions builds the images when main is pushed. This script starts the
data stores and, when -ImageTag is set, rolls the services onto that tag.

.EXAMPLE
pwsh cloudsneeker/deploy/ecs/deploy.ps1
pwsh cloudsneeker/deploy/ecs/deploy.ps1 -GitHubRepository owner/cloudsneeker
pwsh cloudsneeker/deploy/ecs/deploy.ps1 -DomainName app.example.com -CertificateArn arn:aws:acm:...
#>
[CmdletBinding()]
param(
    [string]$Region = "us-east-1",
    [string]$Profile = "kscnexus",
    [string]$DomainName = "",
    [string]$CertificateArn = "",
    [string]$ImageTag = "",
    [string]$GitHubRepository = ""
)

$ErrorActionPreference = "Stop"
if (Test-Path variable:PSNativeCommandUseErrorActionPreference) {
    $PSNativeCommandUseErrorActionPreference = $false
}
$EcsDir = $PSScriptRoot
$Account = "352285844868"
$SecretName = "cloudsneeker/app"
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

Write-Host "==> Application secret"
$secretArn = ""
try {
    $secretArn = Invoke-AwsText @("secretsmanager", "describe-secret", "--secret-id", $SecretName, "--query", "ARN")
    Write-Host "Using existing secret"
} catch {
    $secretArn = ""
}
if (-not $secretArn) {
    $openssl = (Get-Command openssl -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source)
    if (-not $openssl) { $openssl = "C:\Program Files\Git\usr\bin\openssl.exe" }
    if (-not (Test-Path $openssl)) { throw "openssl was not found" }
    $work = Join-Path $env:TEMP "cloudsneeker-secret"
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    $generator = Join-Path $work "generate_secret.py"
    @'
import base64, json, os, secrets, string, subprocess, sys
openssl, key_path, pub_path, out_path = sys.argv[1:5]
alphabet = string.ascii_letters + string.digits
def token(n):
    return "".join(secrets.choice(alphabet) for _ in range(n))
subprocess.check_call([openssl, "genrsa", "-out", key_path, "2048"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
subprocess.check_call([openssl, "rsa", "-in", key_path, "-pubout", "-out", pub_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
def one_line(path):
    return open(path, encoding="ascii").read().strip().replace("\n", "\\n")
neo = token(40)
payload = {
    "postgresPassword": token(40),
    "valkeyAuthToken": token(32),
    "neo4jPassword": neo,
    "neo4jAuth": "neo4j/" + neo,
    "authSecret": base64.b64encode(os.urandom(32)).decode("ascii"),
    "djangoSecretsEncryptionKey": base64.urlsafe_b64encode(os.urandom(32)).decode("ascii"),
    "djangoTokenSigningKey": one_line(key_path),
    "djangoTokenVerifyingKey": one_line(pub_path),
    "slackClientId": "unconfigured",
    "slackClientSecret": "unconfigured",
}
with open(out_path, "w", encoding="ascii") as handle:
    json.dump(payload, handle)
'@ | Set-Content -Path $generator -Encoding ascii
    $secretFile = Join-Path $work "secret.json"
    $keyFile = Join-Path $work "jwt.pem"
    $pubFile = Join-Path $work "jwt.pub"
    & python $generator $openssl $keyFile $pubFile $secretFile
    if ($LASTEXITCODE -ne 0) { throw "secret generation failed" }
    Invoke-Aws @("secretsmanager", "create-secret", "--name", $SecretName, "--description", "Cloudsneeker application credentials", "--secret-string", "file://$secretFile") | Out-Null
    Remove-Item -Force $secretFile, $keyFile, $pubFile, $generator
    $secretArn = Invoke-AwsText @("secretsmanager", "describe-secret", "--secret-id", $SecretName, "--query", "ARN")
} else {
    # Ensure Slack OAuth keys exist on older secrets (empty until an app is configured).
    $current = Invoke-AwsText @("secretsmanager", "get-secret-value", "--secret-id", $SecretName, "--query", "SecretString")
    $mergeWork = Join-Path $env:TEMP "cloudsneeker-secret-merge"
    New-Item -ItemType Directory -Force -Path $mergeWork | Out-Null
    $mergePy = Join-Path $mergeWork "merge_secret.py"
    $mergeIn = Join-Path $mergeWork "in.json"
    $mergeOut = Join-Path $mergeWork "out.json"
    Set-Content -Path $mergeIn -Value $current -Encoding ascii
    @'
import json, sys
src, dst = sys.argv[1:3]
payload = json.load(open(src, encoding="utf-8"))
changed = False
for key in ("slackClientId", "slackClientSecret"):
    if key not in payload:
        payload[key] = "unconfigured"
        changed = True
json.dump(payload, open(dst, "w", encoding="ascii"))
sys.exit(0 if changed else 2)
'@ | Set-Content -Path $mergePy -Encoding ascii
    & python $mergePy $mergeIn $mergeOut
    if ($LASTEXITCODE -eq 0) {
        Invoke-Aws @("secretsmanager", "put-secret-value", "--secret-id", $SecretName, "--secret-string", "file://$mergeOut") | Out-Null
        Write-Host "Added Slack OAuth keys to application secret"
    }
    Remove-Item -Force -ErrorAction SilentlyContinue $mergePy, $mergeIn, $mergeOut
}

Write-Host "==> Template bucket"
$bucketExists = $true
cmd /c "aws --profile $Profile --region $Region s3api head-bucket --bucket $ArtifactBucket >nul 2>&1"
if ($LASTEXITCODE -ne 0) { $bucketExists = $false }
if (-not $bucketExists) {
    Invoke-Aws @("s3api", "create-bucket", "--bucket", $ArtifactBucket) | Out-Null
    Invoke-Aws @("s3api", "put-public-access-block", "--bucket", $ArtifactBucket, "--public-access-block-configuration", "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true") | Out-Null
    Invoke-Aws @("s3api", "put-bucket-encryption", "--bucket", $ArtifactBucket, "--server-side-encryption-configuration", "Rules=[{ApplyServerSideEncryptionByDefault={SSEAlgorithm=AES256}}]") | Out-Null
}

Write-Host "==> Image registry"
$registryArgs = @(
    "cloudformation", "deploy",
    "--stack-name", "cloudsneeker-registry",
    "--template-file", (Join-Path $EcsDir "registry.yaml"),
    "--s3-bucket", $ArtifactBucket,
    "--s3-prefix", "ecs",
    "--capabilities", "CAPABILITY_NAMED_IAM",
    "--no-fail-on-empty-changeset"
)
if ($GitHubRepository) {
    $registryArgs += @("--parameter-overrides", "GitHubRepository=$GitHubRepository")
}
Invoke-Aws $registryArgs | Out-Host
if ($GitHubRepository) {
    $roleArn = Invoke-AwsText @("cloudformation", "describe-stacks", "--stack-name", "cloudsneeker-registry", "--query", "Stacks[0].Outputs[?OutputKey=='GitHubActionsRoleArn'].OutputValue | [0]")
    Write-Host "GitHub Actions role: $roleArn"
}

function Start-RetainedDatabase {
    Write-Host "==> Database"
    $status = ""
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $status = (& aws --profile $Profile --region $Region --output text rds describe-db-instances --db-instance-identifier cloudsneeker --query "DBInstances[0].DBInstanceStatus" 2>$null | Out-String).Trim()
    $describeExit = $LASTEXITCODE
    $ErrorActionPreference = $previous
    if ($describeExit -ne 0 -or -not $status -or $status -eq "None") {
        Write-Host "Database is not created yet"
        return
    }
    Write-Host "Database status: $status"
    if ($status -eq "stopped") {
        Invoke-Aws @("rds", "start-db-instance", "--db-instance-identifier", "cloudsneeker") | Out-Null
    }
    if ($status -ne "available") {
        Invoke-Aws @("rds", "wait", "db-instance-available", "--db-instance-identifier", "cloudsneeker") | Out-Null
    }
}

Start-RetainedDatabase

function Wait-CloudsneekerStackIdle {
    Write-Host "==> Wait for platform stack to finish any in-flight update"
    $deadline = (Get-Date).AddMinutes(45)
    while ((Get-Date) -lt $deadline) {
        $status = ""
        $previous = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $status = (& aws --profile $Profile --region $Region --output text cloudformation describe-stacks --stack-name cloudsneeker --query "Stacks[0].StackStatus" 2>$null | Out-String).Trim()
        $describeExit = $LASTEXITCODE
        $ErrorActionPreference = $previous
        if ($describeExit -ne 0 -or -not $status -or $status -eq "None") {
            Write-Host "Platform stack is not created yet"
            return
        }
        Write-Host "Stack status: $status"
        if ($status -notmatch "IN_PROGRESS") {
            return
        }
        Start-Sleep -Seconds 20
    }
    throw "Timed out waiting for cloudsneeker stack to leave an IN_PROGRESS state"
}

Wait-CloudsneekerStackIdle

$existingTag = ""
try {
    $existingTag = Invoke-AwsText @("cloudformation", "describe-stacks", "--stack-name", "cloudsneeker", "--query", "Stacks[0].Parameters[?ParameterKey=='ImageTag'].ParameterValue | [0]")
} catch {
    $existingTag = ""
}
if ($existingTag -eq "None") { $existingTag = "" }
# Prefer an explicit -ImageTag. Otherwise keep the stack's current tag so a
# concurrent GitHub Actions image publish is not overwritten by an empty/stale value.
if (-not $ImageTag) { $ImageTag = $existingTag }
if (-not $ImageTag) {
    throw "ImageTag is required. Pass -ImageTag <sha> or let GitHub Actions publish images first."
}

Write-Host "==> Platform (data stores and network)"
Invoke-Aws @(
    "cloudformation", "deploy",
    "--stack-name", "cloudsneeker",
    "--template-file", (Join-Path $EcsDir "platform.yaml"),
    "--s3-bucket", $ArtifactBucket,
    "--s3-prefix", "ecs",
    "--capabilities", "CAPABILITY_NAMED_IAM",
    "--no-fail-on-empty-changeset",
    "--parameter-overrides", "PlatformMode=running", "ImageTag=$ImageTag", "AppSecretArn=$secretArn", "DomainName=$DomainName", "CertificateArn=$CertificateArn"
) | Out-Host
Write-Host "GitHub Actions publishes images when main is pushed. Pass -ImageTag to roll the services onto a tag that is already in the registry."

$url = Invoke-AwsText @("cloudformation", "describe-stacks", "--stack-name", "cloudsneeker", "--query", "Stacks[0].Outputs[?OutputKey=='ServiceUrl'].OutputValue | [0]")
Write-Host ""
Write-Host "Cloudsneeker is starting at $url"
Write-Host "Sign-up is open on that address. The first page can take a few minutes while the API finishes database migrations."
