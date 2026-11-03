#!/usr/bin/env bash
# Build and start the Cloudsneeker backend on a fresh VM, as azureuser.
#
#   API_HOST=cloudsneeker-api.eastus.cloudapp.azure.com \
#   UI_URL=https://cloudsneeker.vercel.app \
#   BACKUP_ACCOUNT=<storage account> \
#   OPERATOR_EMAILS=<first operator owner email> \
#     bash bootstrap.sh
#
# Clones or updates ~/cloudsneeker (deploy) and ~/cloudsneeker-src (build),
# builds the images natively, writes
# cloudsneeker/deploy/.env once with freshly generated secrets (mode 600,
# never printed), starts the stack, and installs a nightly PostgreSQL dump
# that is uploaded to Blob Storage with the VM's managed identity.
# Re-running rebuilds and restarts with the current commit and keeps .env.
set -euo pipefail

: "${API_HOST:?set API_HOST to the public API hostname}"
: "${UI_URL:?set UI_URL to the web app origin}"
REPO_URL="${REPO_URL:-https://github.com/kscnexus/cloudsneeker.git}"
BRANCH="${BRANCH:-main}"
CHECKOUT="$HOME/cloudsneeker"
# Images build from a separate clean clone: the deploy checkout holds live,
# container-owned data under deploy/_data that docker build cannot read.
SOURCE="$HOME/cloudsneeker-src"
DEPLOY="$CHECKOUT/cloudsneeker/deploy"
COMPOSE=(docker compose -f docker-compose.yml -f vm/compose.yml)

log() { printf '\n==> %s\n' "$*"; }

if command -v cloud-init >/dev/null; then
  log "Waiting for cloud-init"
  cloud-init status --wait >/dev/null || true
fi

if ! command -v uv >/dev/null && [[ ! -x "$HOME/.local/bin/uv" ]]; then
  log "Installing uv"
  curl -LsSf https://astral.sh/uv/install.sh | sh
fi
export PATH="$HOME/.local/bin:$PATH"

sync_checkout() {
  if [[ -d "$1/.git" ]]; then
    git -C "$1" fetch --quiet origin "$BRANCH"
    git -C "$1" checkout --quiet "$BRANCH"
    git -C "$1" reset --quiet --hard "origin/$BRANCH"
  else
    git clone --quiet --branch "$BRANCH" "$REPO_URL" "$1"
  fi
}

log "Fetching $BRANCH"
sync_checkout "$CHECKOUT"
sync_checkout "$SOURCE"
git -C "$SOURCE" checkout --quiet "$(git -C "$CHECKOUT" rev-parse HEAD)"
TAG="$(git -C "$CHECKOUT" rev-parse --short=12 HEAD)"

log "Building images $TAG"
# Package downloads inside docker build sometimes time out; finished layers are
# cached, so a retry resumes where the last attempt stopped.
for attempt in 1 2 3; do
  if SKIP_CLI=1 SKIP_UI=1 bash "$SOURCE/cloudsneeker/deploy/scripts/build.sh" "$TAG"; then
    break
  fi
  [[ $attempt -eq 3 ]] && exit 1
  log "Build attempt $attempt failed; retrying"
  sleep 30
done

if [[ ! -f "$DEPLOY/.env" ]]; then
  log "Writing .env with new secrets"
  umask 077
  python3 - "$DEPLOY/../.env.example" "$DEPLOY/.env" <<PY
import base64, os, secrets, subprocess, sys

src, dst = sys.argv[1], sys.argv[2]

def fernet():
    return base64.urlsafe_b64encode(os.urandom(32)).decode()

def rsa_pair():
    key = subprocess.run(["openssl", "genrsa", "2048"], check=True,
                         capture_output=True, text=True).stdout
    pub = subprocess.run(["openssl", "rsa", "-pubout"], input=key, check=True,
                         capture_output=True, text=True).stdout
    return key.strip().replace("\n", "\\\\n"), pub.strip().replace("\n", "\\\\n")

signing, verifying = rsa_pair()
values = {
    "CLOUDSNEEKER_API_VERSION": "$TAG",
    "CLOUDSNEEKER_MCP_VERSION": "$TAG",
    "CLOUDSNEEKER_API_HOST": "$API_HOST",
    "AUTH_URL": "$UI_URL",
    "DJANGO_UI_BASE_URL": "$UI_URL",
    "DJANGO_ALLOWED_HOSTS": "$API_HOST,localhost,127.0.0.1,cloudsneeker-api",
    "DJANGO_CORS_ALLOWED_ORIGINS": "$UI_URL",
    "DJANGO_JWT_ISSUER": "https://$API_HOST",
    "DJANGO_JWT_AUDIENCE": "https://$API_HOST",
    "DJANGO_SECURE_HSTS_SECONDS": "31536000",
    "CLOUDSNEEKER_SELF_REGISTRATION_ENABLED": "true",
    "POSTGRES_ADMIN_PASSWORD": secrets.token_hex(24),
    "POSTGRES_PASSWORD": secrets.token_hex(24),
    "NEO4J_PASSWORD": secrets.token_hex(24),
    "DJANGO_SECRETS_ENCRYPTION_KEY": fernet(),
    "DJANGO_API_KEY_FERNET_SECRET": fernet(),
    "DJANGO_TOKEN_SIGNING_KEY": '"' + signing + '"',
    "DJANGO_TOKEN_VERIFYING_KEY": '"' + verifying + '"',
}
seen = set()
out = []
for line in open(src):
    key = line.split("=", 1)[0].strip()
    if "=" in line and not line.lstrip().startswith("#") and key in values:
        out.append(f"{key}={values[key]}\n")
        seen.add(key)
    else:
        out.append(line)
out += [f"{k}={v}\n" for k, v in values.items() if k not in seen]
open(dst, "w").writelines(out)
PY
  chmod 600 "$DEPLOY/.env"
else
  log "Keeping existing .env; updating image tags"
  sed -i "s/^CLOUDSNEEKER_API_VERSION=.*/CLOUDSNEEKER_API_VERSION=$TAG/; s/^CLOUDSNEEKER_MCP_VERSION=.*/CLOUDSNEEKER_MCP_VERSION=$TAG/" "$DEPLOY/.env"
fi

if [[ -n "${OPERATOR_EMAILS:-}" ]]; then
  # First operator owner on sign-up; inert once an owner exists.
  sed -i '/^CLOUDSNEEKER_BOOTSTRAP_OPERATOR_EMAILS=/d' "$DEPLOY/.env"
  echo "CLOUDSNEEKER_BOOTSTRAP_OPERATOR_EMAILS=$OPERATOR_EMAILS" >> "$DEPLOY/.env"
fi

log "Starting the stack"
cd "$DEPLOY"
mkdir -p _data/api _data/caddy
"${COMPOSE[@]}" up -d --remove-orphans
"${COMPOSE[@]}" ps

if [[ -n "${BACKUP_ACCOUNT:-}" ]]; then
  log "Installing nightly backup to $BACKUP_ACCOUNT"
  sudo tee /usr/local/bin/cloudsneeker-backup >/dev/null <<SH
#!/usr/bin/env bash
# Nightly pg_dump, kept 7 days on disk and 30 days in Blob Storage.
set -euo pipefail
cd "$DEPLOY"
env_value() { grep -m1 "^\$1=" .env | cut -d= -f2- | tr -d '"'; }
POSTGRES_ADMIN_USER="\$(env_value POSTGRES_ADMIN_USER)"
POSTGRES_DB="\$(env_value POSTGRES_DB)"
mkdir -p /var/backups/cloudsneeker
file="/var/backups/cloudsneeker/cloudsneeker-\$(date -u +%Y%m%dT%H%M%SZ).dump"
docker compose -f docker-compose.yml -f vm/compose.yml exec -T postgres \
  pg_dump -U "\$POSTGRES_ADMIN_USER" -Fc "\$POSTGRES_DB" > "\$file"
token="\$(curl -fsS -H Metadata:true \
  'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')"
curl -fsS -X PUT -T "\$file" -H "Authorization: Bearer \$token" -H "x-ms-version: 2021-08-06" \
  -H "x-ms-blob-type: BlockBlob" \
  "https://$BACKUP_ACCOUNT.blob.core.windows.net/pg-backups/\$(basename "\$file")"
find /var/backups/cloudsneeker -name '*.dump' -mtime +7 -delete
SH
  sudo chmod 755 /usr/local/bin/cloudsneeker-backup
  sudo tee /etc/systemd/system/cloudsneeker-backup.service >/dev/null <<UNIT
[Unit]
Description=Cloudsneeker PostgreSQL backup
After=docker.service

[Service]
Type=oneshot
User=$USER
Group=docker
ExecStartPre=+/usr/bin/install -d -o $USER -m 700 /var/backups/cloudsneeker
ExecStart=/usr/local/bin/cloudsneeker-backup
UNIT
  sudo tee /etc/systemd/system/cloudsneeker-backup.timer >/dev/null <<UNIT
[Unit]
Description=Nightly Cloudsneeker PostgreSQL backup

[Timer]
OnCalendar=*-*-* 03:15:00 UTC
Persistent=true

[Install]
WantedBy=timers.target
UNIT
  sudo systemctl daemon-reload
  sudo systemctl enable --now cloudsneeker-backup.timer
fi

log "Done: https://$API_HOST/health/live"
