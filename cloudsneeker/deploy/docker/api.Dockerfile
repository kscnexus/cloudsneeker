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
