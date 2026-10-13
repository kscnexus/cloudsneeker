<#
.SYNOPSIS
Build the Cloudsneeker images from a rebranded copy of this tree (Windows).

.DESCRIPTION
Mirrors build.sh: export the rebranded tree and SDK wheel, audit them for
upstream brand strings, then build cli, api, ui, and mcp images with the
upstream Dockerfiles from the exported tree.

.EXAMPLE
pwsh cloudsneeker/deploy/scripts/build.ps1 -Tag v1.0.0 -Registry ghcr.io/acme -Push
#>
[CmdletBinding()]
param(
    [string]$Tag,
    [string]$Registry = "cloudsneeker",
    [switch]$Push,
    [switch]$SkipAudit,
    [switch]$SkipCli
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
if (-not $Tag) {
    $Tag = (git -C $Root describe --tags --always --dirty 2>$null)
    if (-not $Tag) { $Tag = "local" }
}
$BuildDir = Join-Path $Root "build"
$Tree = Join-Path $BuildDir "tree"
$Wheels = Join-Path $BuildDir "wheels"
$Artifacts = Join-Path $BuildDir "artifacts"
$SourceDockerfile = Join-Path $Root "cloudsneeker\deploy\docker\source.Dockerfile"

function Invoke-Step([string]$Message, [scriptblock]$Action) {
    Write-Host "`n==> $Message"
    & $Action
    if ($LASTEXITCODE -ne 0) { throw "step failed: $Message" }
}

foreach ($dir in @($Tree, $Wheels, $Artifacts)) {
    if (Test-Path $dir) { Remove-Item -Recurse -Force $dir }
}

Invoke-Step "Exporting rebranded tree to $Tree" {
    docker build -f $SourceDockerfile --target tree --output "type=local,dest=$Tree" $Root
}
Invoke-Step "Exporting SDK wheel to $Wheels" {
    docker build -f $SourceDockerfile --target wheel --output "type=local,dest=$Wheels" $Root
}

if (-not $SkipAudit) {
    Invoke-Step "Auditing build tree" {
        uv run --no-sync python (Join-Path $Root "cloudsneeker\tools\brand_audit.py") --tree $Tree
    }
    Invoke-Step "Generating sample scan output from the rebranded tree" {
        Push-Location $Tree
        try { uv run --no-dev python cloudsneeker/tools/sample_outputs.py --output-dir $Artifacts }
        finally { Pop-Location }
    }
    Invoke-Step "Auditing sample output" {
        uv run --no-sync python (Join-Path $Root "cloudsneeker\tools\brand_audit.py") --artifacts $Artifacts
    }
}

if (-not $SkipCli) {
    Invoke-Step "Building $Registry/cli:$Tag" {
        docker build -t "$Registry/cli:$Tag" $Tree
    }
}
Invoke-Step "Building $Registry/api:$Tag" {
    docker build -t "$Registry/api-base:$Tag" (Join-Path $Tree "api")
    if ($LASTEXITCODE -ne 0) { return }
    docker build -t "$Registry/api:$Tag" --build-arg "BASE_IMAGE=$Registry/api-base:$Tag" `
        -f (Join-Path $Root "cloudsneeker\deploy\docker\api.Dockerfile") $BuildDir
}
Invoke-Step "Building $Registry/ui:$Tag" {
    docker build -t "$Registry/ui:$Tag" --target prod `
        --build-arg "NEXT_PUBLIC_PROWLER_RELEASE_VERSION=$Tag" (Join-Path $Tree "ui")
}
Invoke-Step "Building $Registry/mcp:$Tag" {
    docker build -t "$Registry/mcp:$Tag" (Join-Path $Tree "mcp_server")
}

if ($Push) {
    $images = @("api", "ui", "mcp")
    if (-not $SkipCli) { $images = @("cli") + $images }
    foreach ($image in $images) {
        Invoke-Step "Pushing $Registry/${image}:$Tag" { docker push "$Registry/${image}:$Tag" }
    }
}

Write-Host "`n==> Done: $Registry/{cli,api,ui,mcp}:$Tag"
