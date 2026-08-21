# Container definition for the CLI/control plane.
# Building this image is separate from proving any live model, MCP, target, or production capability.
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --system aiqa && useradd --system --gid aiqa --create-home aiqa
WORKDIR /opt/ai-qa

# Package metadata is complete before installation: README + declared MIT license.
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m pip install --upgrade pip && python -m pip install .

# The container's default control root must contain the same trusted project markers
# required by validate_runtime_roots()/ai-qa doctor. Target workspaces are mounted separately.
COPY CLAUDE.md .mcp.json ./
COPY .claude ./.claude

RUN mkdir -p /opt/ai-qa/artifacts && chown -R aiqa:aiqa /opt/ai-qa
USER aiqa

ENTRYPOINT ["ai-qa"]
CMD ["doctor"]
