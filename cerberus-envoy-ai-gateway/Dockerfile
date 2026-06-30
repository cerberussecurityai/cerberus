FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir .

EXPOSE 4318

# Liveness: GET /health, readiness: GET /ready (see src/.../app.py).
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://localhost:4318/health', timeout=2).status == 200 else 1)"
CMD ["cerberus-envoy-ai-gateway"]
