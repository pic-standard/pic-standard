# Pinned on 2026-04-01 for reproducible builds.
FROM python:3.12-slim@sha256:3d5ed973e45820f5ba5e46bd065bd88b3a504ff0724d85980dcd05eab361fcf4

LABEL org.opencontainers.image.source="https://github.com/pic-standard/pic-standard" \
    org.opencontainers.image.description="PIC Standard HTTP Bridge" \
    org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --gid 10001 pic \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin pic

WORKDIR /app

COPY pyproject.toml README.md LICENSE /app/
COPY sdk-python /app/sdk-python

RUN pip install --upgrade pip setuptools wheel \
    && pip install ".[langgraph,mcp,crypto]"

COPY . /app

USER pic

EXPOSE 7580

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:7580/health')"]

ENTRYPOINT ["pic-cli", "serve"]
CMD ["--host", "0.0.0.0", "--port", "7580", "--repo-root", "/workspace"]
