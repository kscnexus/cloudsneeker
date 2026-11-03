#!/usr/bin/env bash
# Vercel build command for the Cloudsneeker web app.
#
# The Vercel project's Root Directory is `ui`, so this runs from ui/. The
# checkout is thrown away after the build, so the display copy is rewritten in
# place, the same as docker/source.Dockerfile does for the container images.
#
#   Build Command: bash ../cloudsneeker/deploy/vercel/build.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

# The brand tools need Python 3.11+ (tomllib). Fall back to a uv-managed
# interpreter when the build image ships an older python3.
if python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null; then
  PYTHON=(python3)
else
  python3 -m pip install --quiet --user "uv==0.12.0"
  PYTHON=("$(python3 -m site --user-base)/bin/uv" run --no-project --python 3.12 python)
fi

echo "==> Rewriting display copy"
"${PYTHON[@]}" "$ROOT/cloudsneeker/tools/rebrand.py" --apply --allow-git-tree --root "$ROOT"

# Same gate as the release workflow's build/tree audit. That tree is exported
# without .github, so drop it here too.
echo "==> Auditing the build tree"
rm -rf "$ROOT/.github"
"${PYTHON[@]}" "$ROOT/cloudsneeker/tools/brand_audit.py" --tree "$ROOT"

echo "==> Building"
cd "$ROOT/ui"
export NEXT_PUBLIC_PROWLER_RELEASE_VERSION="${NEXT_PUBLIC_PROWLER_RELEASE_VERSION:-${VERCEL_GIT_COMMIT_SHA:0:12}}"
# Vercel's own pnpm is too old for this project, and the install command's
# pnpm is not on PATH here, so call next directly (same as `pnpm run build`).
node_modules/.bin/next build
