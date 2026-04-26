## regaudit-fhe HTTP audit server (production reference build)
##
## Two-stage Docker build. The runtime image runs as a non-root user,
## ships the bundled JSON Schemas, and exposes the FastAPI server on
## port 8080. Encrypted execution requires the [fhe] extra; uncomment
## the install line below if you want it baked in.

# syntax=docker/dockerfile:1.7

FROM python:3.12-slim-bookworm AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md MANIFEST.in LICENSE LICENSING.md \
     SECURITY.md CONTRIBUTING.md COMPLIANCE.md ./
COPY src ./src
COPY schemas ./schemas
COPY docs ./docs

RUN python -m pip install --upgrade pip wheel \
 && python -m pip install --prefix=/install ".[server]"
# Uncomment to bake in the encrypted backend (adds ~120 MB to the image):
# RUN python -m pip install --prefix=/install ".[fhe]"


FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1

# OCI labels — overridden by CI when building.
LABEL org.opencontainers.image.title="regaudit-fhe" \
      org.opencontainers.image.description="Encrypted regulatory audit primitives at CKKS depth six." \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.vendor="VaultBytes Innovations Ltd" \
      org.opencontainers.image.source="https://github.com/BAder82t/regaudit-fhe"

# Run as a dedicated non-root user.
RUN groupadd --system --gid 10001 regaudit \
 && useradd --system --uid 10001 --gid regaudit --shell /sbin/nologin regaudit

COPY --from=builder /install /usr/local

USER regaudit
WORKDIR /home/regaudit

EXPOSE 8080

# Built-in container healthcheck calls the liveness probe; orchestrators
# (Kubernetes, ECS, Nomad) should also configure /readyz.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys;\
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3).status==200 else 1)" \
        || exit 1

ENTRYPOINT ["regaudit-fhe", "serve", "--host", "0.0.0.0", "--port", "8080"]
