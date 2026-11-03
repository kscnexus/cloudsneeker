#!/usr/bin/env bash
# Provision the Cloudsneeker backend VM on Azure.
#
#   export AZURE_CONFIG_DIR="$HOME/.azure-cloudsneeker"   # keep other logins out
#   az login --use-device-code
#   SUBSCRIPTION=<id> ALERT_EMAIL=<you@example.com> \
#     cloudsneeker/deploy/vm/azure/provision.sh
#
# Creates, in one resource group:
#   - VNet + subnet with an NSG: 80/443 from the internet, 22 from ADMIN_IP only
#   - Static Standard public IP with an Azure DNS label (<label>.<region>.cloudapp.azure.com)
#   - Ubuntu 24.04 Trusted Launch VM (secure boot, vTPM), SSH key only,
#     system-assigned identity, managed boot diagnostics, cloud-init hardening
#   - Backup storage account: TLS 1.2, no public or shared-key access, reachable
#     from the VM subnet and ADMIN_IP only, 30-day lifecycle deletion; the VM
#     identity can write blobs
#   - Monthly budget with email alerts, VM-availability alert, CanNotDelete lock
#
# Safe to re-run: existing resources are left as they are.
set -euo pipefail
# Git Bash on Windows rewrites /subscriptions/... arguments into file paths.
export MSYS2_ARG_CONV_EXCL="/subscriptions"

: "${SUBSCRIPTION:?set SUBSCRIPTION to the subscription id}"
: "${ALERT_EMAIL:?set ALERT_EMAIL for budget and health alerts}"
RG="${RG:-cloudsneeker-rg}"
LOCATION="${LOCATION:-eastus}"
VM="${VM:-cloudsneeker}"
SIZE="${SIZE:-Standard_B4ms}"
DNS_LABEL="${DNS_LABEL:-cloudsneeker-api}"
BUDGET="${BUDGET:-150}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/cloudsneeker_azure}"
ADMIN_IP="${ADMIN_IP:-$(curl -fsS https://api.ipify.org)}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TAGS=(app=cloudsneeker env=prod managed-by=provision.sh)

log() { printf '\n==> %s\n' "$*"; }
exists() { "$@" >/dev/null 2>&1; }

az account set --subscription "$SUBSCRIPTION"
SUB_ID="$(az account show --query id -o tsv)"
STORAGE="${STORAGE:-csbak$(printf '%s' "$SUB_ID" | tr -d '-' | cut -c1-14)}"

if [[ ! -f "$SSH_KEY" ]]; then
  log "Generating SSH key $SSH_KEY"
  ssh-keygen -t ed25519 -N "" -C "cloudsneeker-azure" -f "$SSH_KEY"
fi

log "Resource group $RG in $LOCATION"
az group create -n "$RG" -l "$LOCATION" --tags "${TAGS[@]}" -o none

log "Network"
exists az network nsg show -g "$RG" -n "$VM-nsg" || {
  az network nsg create -g "$RG" -n "$VM-nsg" --tags "${TAGS[@]}" -o none
  az network nsg rule create -g "$RG" --nsg-name "$VM-nsg" -n AllowHttp --priority 100 \
    --protocol Tcp --source-address-prefixes Internet --destination-port-ranges 80 -o none
  az network nsg rule create -g "$RG" --nsg-name "$VM-nsg" -n AllowHttps --priority 110 \
    --protocol Tcp --source-address-prefixes Internet --destination-port-ranges 443 -o none
}
az network nsg rule create -g "$RG" --nsg-name "$VM-nsg" -n AllowSshFromAdmin --priority 120 \
  --protocol Tcp --source-address-prefixes "$ADMIN_IP/32" --destination-port-ranges 22 -o none
exists az network vnet show -g "$RG" -n "$VM-vnet" || az network vnet create -g "$RG" -n "$VM-vnet" \
  --address-prefixes 10.20.0.0/16 --subnet-name app --subnet-prefixes 10.20.1.0/24 \
  --tags "${TAGS[@]}" -o none
az network vnet subnet update -g "$RG" --vnet-name "$VM-vnet" -n app \
  --network-security-group "$VM-nsg" --service-endpoints Microsoft.Storage -o none
exists az network public-ip show -g "$RG" -n "$VM-pip" || az network public-ip create -g "$RG" \
  -n "$VM-pip" --sku Standard --allocation-method Static --version IPv4 \
  --dns-name "$DNS_LABEL" --tags "${TAGS[@]}" -o none

log "VM $VM ($SIZE)"
exists az vm show -g "$RG" -n "$VM" || az vm create -g "$RG" -n "$VM" \
  --image Canonical:ubuntu-24_04-lts:server:latest --size "$SIZE" \
  --admin-username azureuser --authentication-type ssh --ssh-key-values "$SSH_KEY.pub" \
  --vnet-name "$VM-vnet" --subnet app --nsg "" --public-ip-address "$VM-pip" \
  --os-disk-size-gb 128 --storage-sku StandardSSD_LRS \
  --security-type TrustedLaunch --enable-secure-boot true --enable-vtpm true \
  --assign-identity "[system]" --custom-data "$HERE/cloud-init.yaml" \
  --tags "${TAGS[@]}" -o none
az vm boot-diagnostics enable -g "$RG" -n "$VM" -o none
PRINCIPAL="$(az vm show -g "$RG" -n "$VM" --query identity.principalId -o tsv)"

log "Backup storage $STORAGE"
exists az storage account show -g "$RG" -n "$STORAGE" || az storage account create -g "$RG" \
  -n "$STORAGE" -l "$LOCATION" --sku Standard_LRS --kind StorageV2 --min-tls-version TLS1_2 \
  --https-only true --allow-blob-public-access false --allow-shared-key-access false \
  --default-action Deny --bypass AzureServices --tags "${TAGS[@]}" -o none
az storage account network-rule add -g "$RG" --account-name "$STORAGE" \
  --vnet-name "$VM-vnet" --subnet app -o none
az storage account network-rule add -g "$RG" --account-name "$STORAGE" --ip-address "$ADMIN_IP" -o none
STORAGE_ID="$(az storage account show -g "$RG" -n "$STORAGE" --query id -o tsv)"
az rest --method put \
  --url "https://management.azure.com${STORAGE_ID}/blobServices/default/containers/pg-backups?api-version=2023-05-01" \
  --body '{"properties":{"publicAccess":"None"}}' -o none
az storage account management-policy create -g "$RG" --account-name "$STORAGE" -o none --policy '{
  "rules": [{"enabled": true, "name": "expire-backups", "type": "Lifecycle",
    "definition": {"filters": {"blobTypes": ["blockBlob"], "prefixMatch": ["pg-backups/"]},
      "actions": {"baseBlob": {"delete": {"daysAfterModificationGreaterThan": 30}}}}}]}'
az role assignment create --assignee-object-id "$PRINCIPAL" --assignee-principal-type ServicePrincipal \
  --role "Storage Blob Data Contributor" --scope "$STORAGE_ID" -o none 2>/dev/null || true

log "Alerts"
exists az monitor action-group show -g "$RG" -n cloudsneeker-ops || az monitor action-group create \
  -g "$RG" -n cloudsneeker-ops --short-name csops --action email owner "$ALERT_EMAIL" -o none
VM_ID="$(az vm show -g "$RG" -n "$VM" --query id -o tsv)"
exists az monitor metrics alert show -g "$RG" -n vm-unavailable || az monitor metrics alert create \
  -g "$RG" -n vm-unavailable --scopes "$VM_ID" --condition "avg VmAvailabilityMetric < 1" \
  --window-size 5m --evaluation-frequency 5m --severity 1 --action cloudsneeker-ops -o none ||
  echo "VM availability alert not created; add it in the portal" >&2
START="$(date -u +%Y-%m-01T00:00:00Z)"
az rest --method put \
  --url "https://management.azure.com/subscriptions/$SUB_ID/providers/Microsoft.Consumption/budgets/cloudsneeker-monthly?api-version=2023-05-01" \
  --body "{\"properties\":{\"category\":\"Cost\",\"amount\":$BUDGET,\"timeGrain\":\"Monthly\",
    \"timePeriod\":{\"startDate\":\"$START\"},
    \"notifications\":{
      \"actual50\":{\"enabled\":true,\"operator\":\"GreaterThan\",\"threshold\":50,\"thresholdType\":\"Actual\",\"contactEmails\":[\"$ALERT_EMAIL\"]},
      \"actual80\":{\"enabled\":true,\"operator\":\"GreaterThan\",\"threshold\":80,\"thresholdType\":\"Actual\",\"contactEmails\":[\"$ALERT_EMAIL\"]},
      \"forecast100\":{\"enabled\":true,\"operator\":\"GreaterThan\",\"threshold\":100,\"thresholdType\":\"Forecasted\",\"contactEmails\":[\"$ALERT_EMAIL\"]}}}}" \
  -o none || echo "Budget not created (some offers don't support budgets); add one in Cost Management" >&2

log "Delete lock"
az lock create -g "$RG" -n cloudsneeker-no-delete --lock-type CanNotDelete \
  --notes "Remove before deleting the deployment" -o none

FQDN="$(az network public-ip show -g "$RG" -n "$VM-pip" --query dnsSettings.fqdn -o tsv)"
IP="$(az network public-ip show -g "$RG" -n "$VM-pip" --query ipAddress -o tsv)"
log "Done"
echo "host:    $FQDN ($IP)"
echo "ssh:     ssh -i $SSH_KEY azureuser@$FQDN"
echo "storage: $STORAGE"
