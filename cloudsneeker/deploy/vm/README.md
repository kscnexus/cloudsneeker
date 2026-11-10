# Vercel + single VM deployment

Low-cost layout used after the AWS stack in `../ecs/` was retired:

| Piece | Where | Cost |
|-------|-------|------|
| Web app (`ui/`) | Vercel, Root Directory `ui` | Hobby $0 (non-commercial; Pro $20/mo before selling) |
| API, worker, beat, MCP | One Linux VM, `../docker-compose.yml` + `compose.yml` here | see below |
| PostgreSQL 16, Valkey 8, Neo4j (DozerDB) | Same VM, same compose project | included |
| HTTPS for the API | Caddy on the VM, Let's Encrypt | $0 |

Neo4j stays self-hosted because attack paths create one database per scan
(`NEO4J_DBMS_MAX__DATABASES=1000`), which managed free tiers do not allow.

The VM needs 4 vCPU and 16 GB or more, Ubuntu 24.04, and 100 GB of disk.
x86-64 and arm64 both work: the API Dockerfile picks the matching Trivy,
PowerShell, and zizmor downloads, and the pinned DozerDB, PostgreSQL, Valkey,
and Caddy images are multi-arch.

The current host is an Azure VM on free-account credit ($200, valid for 30
days). A `Standard_B4ms` (4 vCPU, 16 GB) costs about $120/mo, so the credit
covers the 30 days. The free account allows 4 vCPUs per region, which this
size uses. Take a database backup (see Backups) before day 30: after that the
VM is stopped unless the subscription is upgraded to pay-as-you-go. A Hetzner
VPS (about €10–17/mo) is the cheapest paid follow-on; the steps after
section 1 are the same on any host.

## Hostnames

Without a working DNS zone, use the free names both services hand out:

- Web app: `https://<project>.vercel.app`, the `AUTH_URL` below.
- API: the VM's own DNS name. On Azure that is the public IP's DNS label,
  for example `cloudsneeker-api.southindia.cloudapp.azure.com`. Without one,
  `api.<ip-with-dashes>.sslip.io` resolves to the VM's IP. Either way Caddy
  can get a certificate for it.
- MCP: the same host under `/mcp` (Caddy routes it to the MCP server).

When the domain has a DNS host again, add `cloudsneeker.<domain>` to the
Vercel project, point an `api.` record at the VM, then update the
hostnames in `.env` and the Vercel variables.

## 1. VM

### Scripted (Azure, preferred)

`azure/provision.sh` builds the whole hardened setup: NSG with SSH limited
to the admin IP, Trusted Launch VM with key-only SSH and a managed identity,
an Azure DNS name (`cloudsneeker-api.<region>.cloudapp.azure.com`), a locked
down backup storage account, a budget, a VM-availability alert, and a delete
lock. `azure/cloud-init.yaml` hardens the OS on first boot (ufw, fail2ban,
sshd, unattended upgrades, Docker log rotation, swap). Use a separate CLI
profile so no other Azure login is touched:

```bash
export AZURE_CONFIG_DIR="$HOME/.azure-cloudsneeker"
az login --use-device-code
SUBSCRIPTION=<id> ALERT_EMAIL=<owner email> cloudsneeker/deploy/vm/azure/provision.sh
scp -i ~/.ssh/cloudsneeker_azure cloudsneeker/deploy/vm/bootstrap.sh azureuser@<host>:
ssh -i ~/.ssh/cloudsneeker_azure azureuser@<host> \
  "API_HOST=<host> UI_URL=https://cloudsneeker.vercel.app BACKUP_ACCOUNT=<storage> bash bootstrap.sh"
```

Pass `RG`, `LOCATION`, and `SIZE` to change the defaults. The live
deployment uses `RG=cloudsneeker-in-rg LOCATION=southindia
SIZE=Standard_B4as_v2`. On the free account in November 2026, East US had no
capacity for any B- or v5/v6 D-series 4 vCPU size, and Central India offered
only confidential (DC) sizes. Check before provisioning with
`az vm list-skus -l <region> --resource-type virtualMachines` (empty
`restrictions` means available) and `az vm list-usage -l <region>`.

`bootstrap.sh` replaces sections 2–4 below: it builds the images, writes
`.env` with generated secrets, starts the stack, and installs the nightly
backup timer. Then continue with section 5.

The account owner also turns on MFA for the Azure sign-in (Microsoft
Authenticator; new tenants have security defaults that require it).

### By hand (Azure portal)

The account owner does these in the Azure portal (azure.microsoft.com/free,
then portal.azure.com):

1. Virtual machines, Create, Azure virtual machine:
   - Resource group: new, `cloudsneeker`. Name `cloudsneeker`. Region
     `East US` (or the closest one that offers the size).
   - Image: Ubuntu Server 24.04 LTS, x64. Size: `Standard_B4ms`.
   - Authentication: SSH public key, user `azureuser`, generate a new key
     pair (download the `.pem` when asked).
   - Inbound ports: allow HTTP (80), HTTPS (443), and SSH (22).
   - Disks: OS disk 128 GiB, Standard SSD.
   - Networking: keep the new public IP (Standard SKU, which is static).
2. Review + create, Create, download the private key, and note the public IP
   address on the VM's Overview page.
3. Networking, Network settings: change the SSH (22) rule's source from Any
   to "My IP address". Leave 5432, 6379, 7687, 8000, and 8080 closed.
4. Connect from the PC: `ssh -i <downloaded>.pem azureuser@<public ip>`.

Elsewhere: Google Compute Engine needs "Allow HTTP/HTTPS traffic" ticked and
a reserved static IP; Hetzner and most VPS hosts need only the firewall rule
for 80 and 443. Oracle Cloud images also block those ports in iptables, so
run `sudo iptables -I INPUT 6 -p tcp -m multiport --dports 80,443 -j ACCEPT`
and `sudo netfilter-persistent save` there.

On the VM:

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"   # log out and back in
curl -LsSf https://astral.sh/uv/install.sh | sh
git clone https://github.com/kscnexus/cloudsneeker.git && cd cloudsneeker
```

## 2. Build the images on the VM

```bash
SKIP_CLI=1 cloudsneeker/deploy/scripts/build.sh "$(git rev-parse --short=12 HEAD)"
```

This produces `cloudsneeker/api:<tag>`, `cloudsneeker/ui:<tag>` (unused), and
`cloudsneeker/mcp:<tag>` and runs the brand audit. It takes a while the
first time.

## 3. Configure

```bash
cd cloudsneeker/deploy
cp ../.env.example .env && chmod 600 .env
```

Set these in `.env` (leave the rest at their defaults). `.env` is gitignored;
never commit it.

| Variable | Value |
|----------|-------|
| `CLOUDSNEEKER_API_VERSION`, `CLOUDSNEEKER_MCP_VERSION` | the build tag |
| `CLOUDSNEEKER_API_HOST` | the API hostname above |
| `AUTH_URL` | `https://<project>.vercel.app` |
| `DJANGO_ALLOWED_HOSTS` | `<api host>,localhost,127.0.0.1,cloudsneeker-api` |
| `DJANGO_CORS_ALLOWED_ORIGINS` | `https://<project>.vercel.app` |
| `DJANGO_JWT_ISSUER`, `DJANGO_JWT_AUDIENCE` | `https://<api host>` |
| `DJANGO_SECURE_HSTS_SECONDS` | `31536000` |
| `CLOUDSNEEKER_SELF_REGISTRATION_ENABLED` | `true` until the first owner exists, then `false` |
| `POSTGRES_ADMIN_PASSWORD`, `POSTGRES_PASSWORD`, `NEO4J_PASSWORD` | `openssl rand -hex 24` each |
| `DJANGO_SECRETS_ENCRYPTION_KEY`, `DJANGO_API_KEY_FERNET_SECRET` | `python3 -c "import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())"` each |
| `DJANGO_TOKEN_SIGNING_KEY`, `DJANGO_TOKEN_VERIFYING_KEY` | the private and public PEM from the commands below, newlines written as `\n` |

```bash
openssl genrsa -out /tmp/jwt.pem 2048
openssl rsa -in /tmp/jwt.pem -pubout -out /tmp/jwt.pub
awk 'NF {printf "%s\\n", $0}' /tmp/jwt.pem; echo; awk 'NF {printf "%s\\n", $0}' /tmp/jwt.pub; echo
rm /tmp/jwt.pem /tmp/jwt.pub
```

## 4. Start

```bash
docker compose -f docker-compose.yml -f vm/compose.yml up -d
docker compose -f docker-compose.yml -f vm/compose.yml ps
curl -fsS https://<api host>/health/live
```

The API runs migrations on start. Compose 2.24 or later is required for
`!override`; `docker compose version` shows it.

## 5. Vercel project

The account owner signs in to Vercel and imports `kscnexus/cloudsneeker`:

| Setting | Value |
|---------|-------|
| Root Directory | `ui` (keep "Include files outside the root directory" on) |
| Framework | Next.js |
| Install Command | `npx -y pnpm@11.1.3 install --frozen-lockfile` |
| Build Command | `bash ../cloudsneeker/deploy/vercel/build.sh` |
| Node.js Version | 22.x or later |

Vercel's corepack does not pick up `packageManager` with a Root Directory
set and falls back to its bundled pnpm 6, which `engineStrict` rejects, and a
global `npm install -g pnpm` does not take precedence on its PATH. The install
command runs the pinned pnpm through npx, and `build.sh` calls `next`
directly.

`build.sh` runs the same rebrand and brand audit as the container build, so
the deployed app shows no upstream branding.

Environment variables (Production):

| Variable | Value |
|----------|-------|
| `AUTH_SECRET` | `openssl rand -base64 32` (mark Sensitive) |
| `AUTH_URL` | `https://<project>.vercel.app` |
| `AUTH_TRUST_HOST` | `true` |
| `UI_API_BASE_URL` | `https://<api host>/api/v1` |
| `UI_API_DOCS_URL` | `https://<api host>/api/v1/docs` |
| `UI_CLOUD_ENABLED` | `false` |
| `CLOUDSNEEKER_SELF_REGISTRATION_ENABLED` | same as the API |
| `CLOUDSNEEKER_HSTS_SECONDS` | `31536000` |
| `PROWLER_MCP_SERVER_URL` | `https://<api host>/mcp` |

Disable Vercel Deployment Protection for Production, or the sign-in page is
behind a Vercel login.

## 6. First owner

1. Sign up on the Vercel URL with the owner's email.
2. Grant the operator role:

   ```bash
   docker compose -f docker-compose.yml -f vm/compose.yml exec cloudsneeker-api \
     uv run python manage.py cloudsneeker_operator grant you@company.com --role owner
   ```

3. Set `CLOUDSNEEKER_SELF_REGISTRATION_ENABLED=false` in `.env` and in Vercel,
   then `docker compose ... up -d` and redeploy on Vercel. Later users join by
   invitation.

## Updating

Every push to `main` deploys itself once **Cloudsneeker: Tests** passes:

- Vercel rebuilds the web app.
- **Cloudsneeker: Deploy to Azure** (`.github/workflows/cloudsneeker-images.yml`)
  signs in to Azure with OIDC and starts `cloudsneeker-deploy.service` on the
  VM. That service pulls `main` and re-runs `bootstrap.sh` with the settings
  it saved in `/etc/cloudsneeker/deploy.env`.

GitHub stores no Azure secret. The managed identity `cloudsneeker-github-deploy`
trusts only `main` of this repository and can only manage this VM. The workflow
reads these repository variables, which `provision.sh` prints:
`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`,
`AZURE_RESOURCE_GROUP`, `AZURE_VM`. Until `AZURE_CLIENT_ID` is set the workflow
does nothing.

To deploy by hand on the VM:

```bash
sudo systemctl start cloudsneeker-deploy
journalctl -u cloudsneeker-deploy -f
```

## Running window

**Cloudsneeker: VM schedule** (`.github/workflows/cloudsneeker-vm-schedule.yml`)
keeps the VM inside its running window. Since 2026-11-10 the window is the
whole day (`WINDOW_START: '0000'`, `WINDOW_END: '2400'`), so the VM runs
24/7 and an hourly check starts it if it is ever found off. To bring back
the overnight pause, set the window to `0630`-`2030` UTC, which deallocates
the VM at 02:00 and starts it at 12:00 India Standard Time. While
it is off, Azure bills only the disk and the static IP, and the web app shows
the API as unreachable. The containers restart on boot. Scheduled scans and
reports set for that window do not run. A push to `main` during the pause
starts the VM for the deploy and pauses it again. Run the workflow by hand
with `start` or `stop` to change the state outside the schedule. The workflow
reads the repository variable `CLOUDSNEEKER_API_HOST` to wait for the API
after a start.

## Vulnerability database cache

The worker keeps the shared CVE database in `cloudsneeker/deploy/_data/vuln-db`
(about 1 GB). The beat task refreshes it every 6 hours; until the first
refresh, scans download their own copy. The API mounts it read-only for
Settings → Content versions. To refresh now:

```bash
docker compose -f docker-compose.yml -f vm/compose.yml exec cloudsneeker-worker \
  uv run python manage.py cloudsneeker_vuln_db --refresh
```

It can be rebuilt at any time, so it needs no backup.

## Backups

PostgreSQL is the only data that cannot be rebuilt. `bootstrap.sh` installs
`cloudsneeker-backup.timer`, which dumps it at 20:00 UTC (01:30 IST, before
the nightly pause) and uploads the dump to Blob Storage. By hand:

```bash
docker compose -f docker-compose.yml -f vm/compose.yml exec -T postgres \
  pg_dump -U "$POSTGRES_ADMIN_USER" -Fc "$POSTGRES_DB" > ~/backups/cloudsneeker-$(date +%F).dump
```

Copy the dumps off the VM too, for example to a Cloud Storage bucket or your PC with `scp`.
