# syntax=docker/dockerfile:1
# Pinned, supported base image. For a release, additionally pin the digest:
#   docker buildx imagetools inspect python:3.12.11-slim-bookworm   →   FROM python:3.12.11-slim-bookworm@sha256:<digest>
FROM python:3.12.11-slim-bookworm AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 UV_LINK_MODE=copy UV_COMPILE_BYTECODE=1
RUN pip install "uv==0.12.17"
WORKDIR /srv
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

FROM python:3.12.11-slim-bookworm
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PATH="/srv/.venv/bin:$PATH"
RUN groupadd --gid 10001 agentdesk && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin agentdesk
WORKDIR /srv
COPY --from=build /srv/.venv /srv/.venv
COPY app ./app
COPY migrations ./migrations
COPY alembic.ini ./
COPY scripts ./scripts
COPY deploy/ans_register.py ./deploy/ans_register.py
USER 10001:10001
EXPOSE 8000
# No shell form, no reload, no debug. Forwarded headers are interpreted by the app against TRUSTED_PROXY_CIDRS.
CMD ["uvicorn", "--factory", "app.main:app_factory", "--host", "0.0.0.0", "--port", "8000", "--no-server-header", "--no-access-log", "--no-proxy-headers"]
