# Production-shaped container example. Image build/runtime remains NOT_VERIFIED until actually exercised.
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --system aiqa && useradd --system --gid aiqa --create-home aiqa
WORKDIR /opt/ai-qa

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m pip install --upgrade pip && python -m pip install .

RUN mkdir -p /opt/ai-qa/artifacts && chown -R aiqa:aiqa /opt/ai-qa
USER aiqa

ENTRYPOINT ["ai-qa"]
CMD ["doctor"]
