# syntax=docker/dockerfile:1
#
# Cloudsneeker API image.
#
# The upstream api/Dockerfile installs the SDK from the upstream GitHub repository.
# This layer replaces it with the wheel built from this tree, which carries the
# brand hooks and the `cloudsneeker` package the API imports.
#
# Build context: a directory containing `wheels/prowler-*.whl` (see
# cloudsneeker/deploy/scripts/build.sh). BASE_IMAGE is the image produced by
# the upstream Dockerfile from the rebranded tree.

ARG BASE_IMAGE=cloudsneeker/api-base:local
FROM ${BASE_IMAGE}

# Cloud Custodian lives in an isolated venv: its urllib3/tabulate/boto3 pins
# conflict with the API lock. Workers invoke it via ``C7N_BIN`` / PATH.
# Install every Custodian cloud package Cloudsneeker can attach providers for.
ARG C7N_VERSION=0.9.53
ARG C7N_AZURE_VERSION=0.7.52
ARG C7N_GCP_VERSION=0.4.52
ARG C7N_KUBE_VERSION=0.2.52
USER root
RUN python -m venv /opt/c7n \
    && /opt/c7n/bin/pip install --no-cache-dir \
        "c7n==${C7N_VERSION}" \
        "c7n-azure==${C7N_AZURE_VERSION}" \
        "c7n-gcp==${C7N_GCP_VERSION}" \
        "c7n-kube==${C7N_KUBE_VERSION}" \
    && chown -R prowler:prowler /opt/c7n
ENV C7N_BIN=/opt/c7n/bin/custodian
ENV PATH="/opt/c7n/bin:${PATH}"

# Static analysis (SAST) engine: OpenGrep, the LGPL-2.1 fork of Semgrep OSS
# (https://github.com/opengrep/opengrep). The release binary is self-contained
# (no Python dependencies), so it lives in /opt/opengrep beside the API venv.
#
# Rules: GitLab sast-rules (https://gitlab.com/gitlab-org/security-products/sast-rules),
# pinned to a tag and vendored at build time. Only the top-level language
# folders are kept; their rules are MIT (c) GitLab, except go/, which also has
# Apache-2.0 rules ported from gosec. Everything else in that repository is
# dropped: rules/lgpl-cc (Commons Clause), rules/lgpl, rules/gitlab (GitLab EE
# license), and c/ (ported from GPL-2.0 flawfinder).
#
# Never ship these rule sources in a hosted Cloudsneeker image:
# - Semgrep registry rules (`p/...`, semgrep/semgrep-rules): Semgrep Rules
#   License forbids use in a competing hosted product.
# - opengrep/opengrep-rules: LGPL-2.1 plus the Commons Clause, which forbids
#   selling a product or hosting service whose value derives from the rules.
#
# Checksums are the GitHub release asset digests and the tarball digest at the
# pinned tag. A set checksum that does not match fails the build; an empty one
# skips the check (only for local experiments with another version).
ARG OPENGREP_VERSION=1.30.2
ARG OPENGREP_SHA256_AMD64=a66aa3278457f02b287b985a45b6762aebcaba5000f2689245fd1ed86d1456c7
ARG OPENGREP_SHA256_ARM64=90acea5df4b733083f388d4feeb250ca802f671b33d1f222653d1e571dd2b0d8
ARG SAST_RULES_REF=v2.10.1
ARG SAST_RULES_SHA256=627a73135374fdb9122eb3dcca268ea0fbb11d889d1126c6c52fd28b9df2236b
ARG SAST_RULES_DIRS="csharp go java javascript python scala"
RUN python - <<'PY'
import hashlib
import io
import os
import platform
import tarfile
import urllib.request
from pathlib import Path


def fetch(url: str, expected: str) -> bytes:
    with urllib.request.urlopen(url, timeout=300) as response:
        data = response.read()
    digest = hashlib.sha256(data).hexdigest()
    if expected and digest != expected:
        raise SystemExit(f"checksum mismatch for {url}: {digest} != {expected}")
    if not expected:
        print(f"WARNING: no checksum pinned for {url} (sha256 {digest})")
    return data


machine = platform.machine()
if machine in ("x86_64", "amd64"):
    asset, expected = "opengrep_manylinux_x86", os.environ["OPENGREP_SHA256_AMD64"]
elif machine in ("aarch64", "arm64"):
    asset, expected = "opengrep_manylinux_aarch64", os.environ["OPENGREP_SHA256_ARM64"]
else:
    raise SystemExit(f"Unsupported architecture for OpenGrep: {machine}")
version = os.environ["OPENGREP_VERSION"]
root = Path("/opt/opengrep")
root.mkdir(parents=True, exist_ok=True)
binary = root / "opengrep"
binary.write_bytes(
    fetch(
        f"https://github.com/opengrep/opengrep/releases/download/v{version}/{asset}",
        expected,
    )
)
binary.chmod(0o755)

ref = os.environ["SAST_RULES_REF"]
keep = set(os.environ["SAST_RULES_DIRS"].split())
rules = root / "rules"
rules.mkdir(exist_ok=True)
archive = fetch(
    "https://gitlab.com/gitlab-org/security-products/sast-rules/-/archive/"
    f"{ref}/sast-rules-{ref}.tar.gz",
    os.environ["SAST_RULES_SHA256"],
)
count = 0
with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
    for member in tar.getmembers():
        parts = Path(member.name).parts
        if not member.isfile() or len(parts) < 2 or ".." in parts:
            continue
        relative = Path(*parts[1:])
        is_rule = relative.parts[0] in keep and relative.suffix in (".yml", ".yaml")
        if not is_rule and str(relative) != "LICENSE":
            continue
        target = rules / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(tar.extractfile(member).read())
        count += is_rule
if count == 0:
    raise SystemExit("no SAST rules were vendored")
(rules / "SOURCE").write_text(
    f"gitlab-org/security-products/sast-rules {ref}; folders: {' '.join(sorted(keep))}\n"
)
print(f"vendored {count} SAST rule files")
PY
# Root-owned and read-only for the prowler user, so a scan cannot change the
# engine or its rules.
RUN /opt/opengrep/opengrep --version \
    && chmod -R a+rX,go-w /opt/opengrep
ENV OPENGREP_BIN=/opt/opengrep/opengrep
ENV OPENGREP_RULES_DIR=/opt/opengrep/rules

USER prowler
WORKDIR /home/prowler

COPY --chown=prowler:prowler wheels/ /tmp/sdk-wheels/

# `--no-deps`: the lock already pinned every transitive dependency.
RUN uv pip install --python /home/prowler/.venv/bin/python --no-deps --reinstall \
        /tmp/sdk-wheels/prowler-*.whl \
    && rm -rf /tmp/sdk-wheels /home/prowler/.cache/uv

# The entrypoint runs `uv run`, which would otherwise re-sync the environment
# from uv.lock at start-up and put the upstream SDK back.
ENV UV_NO_SYNC=1

WORKDIR /home/prowler/backend
