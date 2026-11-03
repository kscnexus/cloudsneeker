# Vercel + Oracle Cloud deployment

Low-cost layout used after the AWS stack in `../ecs/` was retired:

| Piece | Where | Cost |
|-------|-------|------|
| Web app (`ui/`) | Vercel, Root Directory `ui` | Hobby $0 (non-commercial; Pro $20/mo before selling) |
| API, worker, beat, MCP | Oracle Cloud Always Free Ampere A1 VM, `../docker-compose.yml` + `compose.yml` here | $0 |
| PostgreSQL 16, Valkey 8, Neo4j (DozerDB) | Same VM, same compose project | $0 |
| HTTPS for the API | Caddy on the VM, Let's Encrypt | $0 |

Neo4j stays self-hosted because attack paths create one database per scan
(`NEO4J_DBMS_MAX__DATABASES=1000`), which managed free tiers do not allow.

The VM is arm64. Every image builds natively there: the API Dockerfile picks
the arm64 Trivy, PowerShell, and zizmor downloads, and the pinned DozerDB,
PostgreSQL, Valkey, and Caddy images are multi-arch.

## Hostnames

Without a working DNS zone, use the free names both services hand out:

- Web app: `https://<project>.vercel.app`, the `AUTH_URL` below.
- API: `api.<ip-with-dashes>.sslip.io`, for example `api.140-238-1-2.sslip.io`.
  sslip.io resolves it to the VM's IP, so Caddy can get a certificate for it.
- MCP: `mcp.<ip-with-dashes>.sslip.io`.

When the domain has a DNS host again, add `cloudsneeker.<domain>` to the
Vercel project, point `api.` and `mcp.` A records at the VM, then update the
hostnames in `.env` and the Vercel variables.

## 1. Oracle VM

The account owner does these in the Oracle Cloud console:

1. Create the account in a home region with A1 capacity. The home region
   cannot be changed later.
2. Compute, Instances, Create: image Ubuntu 24.04, shape `VM.Standard.A1.Flex`
   with 4 OCPU and 24 GB, boot volume 100 GB or more (200 GB is free). Add
   an SSH public key.
3. Networking, the instance's subnet, Security List: add ingress TCP 80 and
   443 from `0.0.0.0/0`. Do not open 5432, 6379, 7687, 8000, or 8080.
4. Upgrade the account to Pay As You Go, which keeps Always Free resources
   free but stops idle A1 instances from being reclaimed. Optional.

On the VM:

```bash
sudo iptables -I INPUT 6 -p tcp -m multiport --dports 80,443 -j ACCEPT
sudo netfilter-persistent save
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
| `CLOUDSNEEKER_API_HOST` | `api.<ip-with-dashes>.sslip.io` |
| `CLOUDSNEEKER_MCP_HOST` | `mcp.<ip-with-dashes>.sslip.io` |
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
docker compose -f docker-compose.yml -f oracle/compose.yml up -d
docker compose -f docker-compose.yml -f oracle/compose.yml ps
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
| Install Command | `pnpm install --frozen-lockfile` |
| Build Command | `bash ../cloudsneeker/deploy/vercel/build.sh` |
| Node.js Version | 22.x |

`build.sh` runs the same rebrand and brand audit as the container build, so
the deployed app shows no upstream branding.

Environment variables (Production):

| Variable | Value |
|----------|-------|
| `ENABLE_EXPERIMENTAL_COREPACK` | `1`, so Vercel uses the `packageManager` pnpm 11 |
| `AUTH_SECRET` | `openssl rand -base64 32` (mark Sensitive) |
| `AUTH_URL` | `https://<project>.vercel.app` |
| `AUTH_TRUST_HOST` | `true` |
| `UI_API_BASE_URL` | `https://<api host>/api/v1` |
| `UI_API_DOCS_URL` | `https://<api host>/api/v1/docs` |
| `UI_CLOUD_ENABLED` | `false` |
| `CLOUDSNEEKER_SELF_REGISTRATION_ENABLED` | same as the API |
| `CLOUDSNEEKER_HSTS_SECONDS` | `31536000` |
| `PROWLER_MCP_SERVER_URL` | `https://<mcp host>/mcp` |

Disable Vercel Deployment Protection for Production, or the sign-in page is
behind a Vercel login.

## 6. First owner

1. Sign up on the Vercel URL with the owner's email.
2. Grant the operator role:

   ```bash
   docker compose -f docker-compose.yml -f oracle/compose.yml exec cloudsneeker-api \
     uv run python manage.py cloudsneeker_operator grant you@company.com --role owner
   ```

3. Set `CLOUDSNEEKER_SELF_REGISTRATION_ENABLED=false` in `.env` and in Vercel,
   then `docker compose ... up -d` and redeploy on Vercel. Later users join by
   invitation.

## Updating

```bash
git pull
SKIP_CLI=1 cloudsneeker/deploy/scripts/build.sh "$(git rev-parse --short=12 HEAD)"
# set the new tag in .env, then
docker compose -f docker-compose.yml -f oracle/compose.yml up -d
```

Vercel redeploys the web app on every push to `main`.

## Backups

PostgreSQL is the only data that cannot be rebuilt. A nightly dump to the
boot volume:

```bash
docker compose -f docker-compose.yml -f oracle/compose.yml exec -T postgres \
  pg_dump -U "$POSTGRES_ADMIN_USER" -Fc "$POSTGRES_DB" > ~/backups/cloudsneeker-$(date +%F).dump
```

Copy the dumps off the VM too (Oracle Object Storage has 20 GB free).
