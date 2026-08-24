# Container definition for the CLI/control plane.
# Building this image is separate from proving any live model, MCP, target, or production capability.
# The exact base subject is mirrored in requirements/base-image.lock and verified in CI.
FROM python:3.11.16-slim@sha256:9c900dea9e8fb7e16277c179b555cc72d29a352dbc33cff48ad5a0412fd5bfc7 AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SOURCE_DATE_EPOCH=315532800

WORKDIR /build

# Build authority is isolated from runtime authority. Every downloaded package must match
# a repository-owned SHA-256 entry; project dependencies are deliberately not installed here.
COPY requirements/build-py311.lock ./requirements/build-py311.lock
RUN python -m pip install --require-hashes -r requirements/build-py311.lock

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m pip wheel --no-deps --no-build-isolation . --wheel-dir /wheelhouse

FROM python:3.11.16-slim@sha256:9c900dea9e8fb7e16277c179b555cc72d29a352dbc33cff48ad5a0412fd5bfc7 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --system aiqa && useradd --system --gid aiqa --create-home aiqa
WORKDIR /opt/ai-qa

# Runtime dependencies are a separate hash-locked graph; build-only tooling never enters
# this stage. The project wheel was produced in the isolated builder stage above.
COPY requirements/runtime-py311.lock ./requirements/runtime-py311.lock
RUN python -m pip install --require-hashes -r requirements/runtime-py311.lock
COPY --from=builder /wheelhouse/*.whl /tmp/ai-qa-dist/
RUN python -m pip install --no-deps /tmp/ai-qa-dist/*.whl && rm -rf /tmp/ai-qa-dist

# The container's default control root must contain the same trusted project markers
# required by validate_runtime_roots()/ai-qa doctor. Target workspaces are mounted separately.
COPY CLAUDE.md .mcp.json ./
COPY .claude ./.claude

RUN mkdir -p /opt/ai-qa/artifacts && chown -R aiqa:aiqa /opt/ai-qa/artifacts
USER aiqa

ENTRYPOINT ["ai-qa"]
CMD ["doctor"]
