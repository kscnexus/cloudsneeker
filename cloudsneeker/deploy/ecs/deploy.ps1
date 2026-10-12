<#
.SYNOPSIS
Deploy Cloudsneeker on ECS in us-east-1.

.DESCRIPTION
Creates the application secret, the image registry, and the Fargate platform.
CodeBuild builds the images from CodeCommit while the data stores are created,
then the services are started.

.EXAMPLE
pwsh cloudsneeker/deploy/ecs/deploy.ps1
pwsh cloudsneeker/deploy/ecs/deploy.ps1 -DomainName app.example.com -CertificateArn arn:aws:acm:...
#>
[CmdletBinding()]
param(
    [string]$Region = "us-east-1",
    [string]$Profile = "kscnexus",
    [string]$DomainName = "",
    [string]$CertificateArn = "",
    [string]$ImageTag = ""
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$EcsDir = $PSScriptRoot
$Account = "352285844868"
$SecretName = "cloudsneeker/app"
$ArtifactBucket = "cloudsneeker-cfn-$Account-$Region"
$Aws = @("--profile", $Profile, "--region", $Region, "--output", "json")

function Invoke-Aws {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$AwsArgs)
    $command = @($Aws + $AwsArgs)
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
}

Write-Host "==> Template bucket"
$bucketExists = $true
& aws @Aws s3api head-bucket --bucket $ArtifactBucket 2>$null
if ($LASTEXITCODE -ne 0) { $bucketExists = $false }
if (-not $bucketExists) {
    Invoke-Aws @("s3api", "create-bucket", "--bucket", $ArtifactBucket) | Out-Null
    Invoke-Aws @("s3api", "put-public-access-block", "--bucket", $ArtifactBucket, "--public-access-block-configuration", "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true") | Out-Null
    Invoke-Aws @("s3api", "put-bucket-encryption", "--bucket", $ArtifactBucket, "--server-side-encryption-configuration", "Rules=[{ApplyServerSideEncryptionByDefault={SSEAlgorithm=AES256}}]") | Out-Null
}

Write-Host "==> Image registry and build project"
Invoke-Aws @("cloudformation", "deploy", "--stack-name", "cloudsneeker-registry", "--template-file", (Join-Path $EcsDir "registry.yaml"), "--s3-bucket", $ArtifactBucket, "--s3-prefix", "ecs", "--capabilities", "CAPABILITY_NAMED_IAM", "--no-fail-on-empty-changeset") | Out-Host

$sha = (& git -C $Root rev-parse HEAD).Trim()
if (-not $ImageTag) { $ImageTag = $sha.Substring(0, 12) }
Write-Host "==> Starting image build $ImageTag"
$buildJson = Invoke-Aws @("codebuild", "start-build", "--project-name", "cloudsneeker-images", "--source-version", $sha)
$buildId = ($buildJson | ConvertFrom-Json).build.id

Write-Host "==> Platform (data stores and network)"
Invoke-Aws @(
    "cloudformation", "deploy",
    "--stack-name", "cloudsneeker",
    "--template-file", (Join-Path $EcsDir "platform.yaml"),
    "--s3-bucket", $ArtifactBucket,
    "--s3-prefix", "ecs",
    "--capabilities", "CAPABILITY_NAMED_IAM",
    "--no-fail-on-empty-changeset",
    "--parameter-overrides", "ImageTag=", "AppSecretArn=$secretArn", "DomainName=$DomainName", "CertificateArn=$CertificateArn"
) | Out-Host

Write-Host "==> Waiting for image build"
$deadline = (Get-Date).AddHours(2)
do {
    Start-Sleep -Seconds 30
    $status = Invoke-AwsText @("codebuild", "batch-get-builds", "--ids", $buildId, "--query", "builds[0].buildStatus")
    Write-Host "build status: $status"
    if ($status -eq "SUCCEEDED") { break }
    if ($status -ne "IN_PROGRESS") { throw "image build $status ($buildId)" }
} while ((Get-Date) -lt $deadline)
if ($status -ne "SUCCEEDED") { throw "image build timed out ($buildId)" }

Write-Host "==> Starting services with image $ImageTag"
Invoke-Aws @(
    "cloudformation", "deploy",
    "--stack-name", "cloudsneeker",
    "--template-file", (Join-Path $EcsDir "platform.yaml"),
    "--s3-bucket", $ArtifactBucket,
    "--s3-prefix", "ecs",
    "--capabilities", "CAPABILITY_NAMED_IAM",
    "--no-fail-on-empty-changeset",
    "--parameter-overrides", "ImageTag=$ImageTag", "AppSecretArn=$secretArn", "DomainName=$DomainName", "CertificateArn=$CertificateArn"
) | Out-Host

$url = Invoke-AwsText @("cloudformation", "describe-stacks", "--stack-name", "cloudsneeker", "--query", "Stacks[0].Outputs[?OutputKey=='ServiceUrl'].OutputValue | [0]")
Write-Host ""
Write-Host "Cloudsneeker is starting at $url"
Write-Host "Sign-up is open on that address. The first page can take a few minutes while the API finishes database migrations."
