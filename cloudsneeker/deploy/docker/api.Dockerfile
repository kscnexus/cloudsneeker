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
