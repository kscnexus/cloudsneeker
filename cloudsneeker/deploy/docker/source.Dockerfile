# syntax=docker/dockerfile:1
#
# Produce the Cloudsneeker build tree.
#
# Copies the repository, rewrites upstream display copy with
# cloudsneeker/tools/rebrand.py, and builds the SDK wheel that the API image
# installs instead of upstream prowler. Nothing here is run as a container;
# the stages are exported with `docker build --output`:
#
#   docker build -f cloudsneeker/deploy/docker/source.Dockerfile \
#       --target tree  --output type=local,dest=build/tree  .
#   docker build -f cloudsneeker/deploy/docker/source.Dockerfile \
#       --target wheel --output type=local,dest=build/wheels .
#
# The component images are then built from build/tree with the upstream
# Dockerfiles, so those files stay byte-identical to upstream.

FROM python:3.12-slim AS rebrand

ARG UV_VERSION=0.12.0

WORKDIR /src
COPY . /src

# Fails when a required rule matched nothing, which means an upstream merge
# moved the text a rule was written for; fix the rule rather than skip it.
RUN python cloudsneeker/tools/rebrand.py --apply --root /src

RUN pip install --no-cache-dir "uv==${UV_VERSION}" \
    && uv build --wheel --out-dir /wheels /src \
    && rm -rf /root/.cache

FROM scratch AS tree
COPY --from=rebrand /src /

FROM scratch AS wheel
COPY --from=rebrand /wheels /
