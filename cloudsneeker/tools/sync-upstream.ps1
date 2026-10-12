<#
.SYNOPSIS
    Merge an upstream release tag into the Cloudsneeker tree and verify the brand gate.

.DESCRIPTION
    Fetches the `upstream` remote, merges the requested tag, then runs the
    rebrand transform in check mode and the brand audit. Resolve any merge
    conflict by keeping the upstream side and re-applying the hooks listed in
    knowledge-base/upstream-hooks.md before running this script again.

.PARAMETER Tag
    Upstream release tag, for example 5.46.0. Defaults to the newest tag.

.PARAMETER SkipTests
    Skip the component unit suites after the merge.

.EXAMPLE
    pwsh cloudsneeker/tools/sync-upstream.ps1 -Tag 5.46.0
#>
[CmdletBinding()]
param(
    [string]$Tag,
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $repoRoot

if (-not (git remote | Select-String -SimpleMatch "upstream")) {
    throw "Missing 'upstream' remote. Run: git remote add upstream https://github.com/prowler-cloud/prowler.git"
}

if (git status --porcelain | Where-Object { $_ -notmatch '^\?\? ' -and $_ -notmatch '\.env$' }) {
    throw "Commit or stash tracked changes before merging upstream."
}

git fetch upstream --tags --prune

if (-not $Tag) {
    $Tag = git tag --list --sort=-version:refname | Select-Object -First 1
}
Write-Host "Merging upstream tag $Tag"

git merge --no-ff --no-edit $Tag
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Merge stopped on conflicts. Keep the upstream side, re-apply knowledge-base/upstream-hooks.md, then commit and run this script with -Tag $Tag again."
    exit 1
}

python cloudsneeker/tools/rebrand.py --check
python cloudsneeker/tools/brand_audit.py --source

if (-not $SkipTests) {
    uv run pytest tests/cloudsneeker -q
    Push-Location api
    uv run pytest src/backend/cloudsneeker_api -q
    Pop-Location
    Push-Location ui
    pnpm test:unit cloudsneeker config/site.test.ts
    Pop-Location
}

Write-Host "Upstream $Tag merged. Build release images with cloudsneeker/deploy to apply the rebrand transform."
