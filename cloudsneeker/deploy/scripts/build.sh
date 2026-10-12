#!/usr/bin/env bash
# Build the Cloudsneeker images from a rebranded copy of this tree.
#
# Steps:
#   1. Export the rebranded tree and the SDK wheel (source.Dockerfile).
#   2. Audit the tree and a sample scan output for upstream brand strings.
#   3. Build cli, api, ui, and mcp images from the exported tree with the
#      upstream Dockerfiles, then layer the SDK wheel into the API image.
#
# Usage:
#   cloudsneeker/deploy/scripts/build.sh [TAG]            # default TAG: git describe
#   REGISTRY=ghcr.io/acme PUSH=1 cloudsneeker/deploy/scripts/build.sh v1.0.0
#
# Environment:
#   REGISTRY   image prefix (default: cloudsneeker)
#   PUSH       set to 1 to push after a successful audit and build
#   SKIP_AUDIT set to 1 to skip the brand audit (never in CI)
#   SKIP_CLI   set to 1 to skip the CLI image (service images still build)
#   PLATFORMS  passed to --platform (default: current platform)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TAG="${1:-$(git -C "$ROOT" describe --tags --always --dirty 2>/dev/null || echo local)}"
REGISTRY="${REGISTRY:-cloudsneeker}"
BUILD_DIR="$ROOT/build"
TREE="$BUILD_DIR/tree"
WHEELS="$BUILD_DIR/wheels"
ARTIFACTS="$BUILD_DIR/artifacts"
PLATFORM_ARGS=()
if [[ -n "${PLATFORMS:-}" ]]; then
  PLATFORM_ARGS=(--platform "$PLATFORMS")
fi

log() { printf '\n==> %s\n' "$*"; }

log "Exporting rebranded tree to $TREE"
rm -rf "$TREE" "$WHEELS" "$ARTIFACTS"
docker build -f "$ROOT/cloudsneeker/deploy/docker/source.Dockerfile" \
  --target tree --output "type=local,dest=$TREE" "$ROOT"
docker build -f "$ROOT/cloudsneeker/deploy/docker/source.Dockerfile" \
  --target wheel --output "type=local,dest=$WHEELS" "$ROOT"

if [[ "${SKIP_AUDIT:-0}" != "1" ]]; then
  log "Auditing build tree"
  python3 "$ROOT/cloudsneeker/tools/brand_audit.py" --tree "$TREE"

  log "Generating sample scan output from the rebranded tree"
  (cd "$TREE" && uv run --no-dev python cloudsneeker/tools/sample_outputs.py --output-dir "$ARTIFACTS")
  python3 "$ROOT/cloudsneeker/tools/brand_audit.py" --artifacts "$ARTIFACTS"
fi

if [[ "${SKIP_CLI:-0}" != "1" ]]; then
  log "Building $REGISTRY/cli:$TAG"
  docker build "${PLATFORM_ARGS[@]}" -t "$REGISTRY/cli:$TAG" "$TREE"
fi

log "Building $REGISTRY/api:$TAG"
docker build "${PLATFORM_ARGS[@]}" -t "$REGISTRY/api-base:$TAG" "$TREE/api"
docker build "${PLATFORM_ARGS[@]}" -t "$REGISTRY/api:$TAG" \
  --build-arg "BASE_IMAGE=$REGISTRY/api-base:$TAG" \
  -f "$ROOT/cloudsneeker/deploy/docker/api.Dockerfile" "$BUILD_DIR"

log "Building $REGISTRY/ui:$TAG"
docker build "${PLATFORM_ARGS[@]}" -t "$REGISTRY/ui:$TAG" --target prod \
  --build-arg "NEXT_PUBLIC_PROWLER_RELEASE_VERSION=$TAG" "$TREE/ui"

log "Building $REGISTRY/mcp:$TAG"
docker build "${PLATFORM_ARGS[@]}" -t "$REGISTRY/mcp:$TAG" "$TREE/mcp_server"

if [[ "${PUSH:-0}" == "1" ]]; then
  images=(api ui mcp)
  if [[ "${SKIP_CLI:-0}" != "1" ]]; then
    images=(cli "${images[@]}")
  fi
  for image in "${images[@]}"; do
    log "Pushing $REGISTRY/$image:$TAG"
    docker push "$REGISTRY/$image:$TAG"
  done
fi

log "Done: $REGISTRY/{cli,api,ui,mcp}:$TAG"
