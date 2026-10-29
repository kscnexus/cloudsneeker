# One-time setup: IAM role + instance profile for a temporary EC2 image
# builder, used when GitHub Actions cannot run. Scoped to the Cloudsneeker
# ECR repositories, the build folder in the template bucket, and rolling the
# Cloudsneeker ECS services.
param([string]$Profile = "kscnexus")

$ErrorActionPreference = "Stop"
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path

aws --profile $Profile iam create-role --role-name cloudsneeker-builder `
  --assume-role-policy-document "file://$dir\trust.json" `
  --description "Temporary Cloudsneeker image builder (EC2)"
aws --profile $Profile iam put-role-policy --role-name cloudsneeker-builder `
  --policy-name build-and-roll --policy-document "file://$dir\policy.json"
aws --profile $Profile iam create-instance-profile --instance-profile-name cloudsneeker-builder
aws --profile $Profile iam add-role-to-instance-profile `
  --instance-profile-name cloudsneeker-builder --role-name cloudsneeker-builder
Write-Host "cloudsneeker-builder role and instance profile are ready."
