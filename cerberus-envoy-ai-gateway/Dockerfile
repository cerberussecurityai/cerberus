FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir .

EXPOSE 4318

# Liveness: GET /health, readiness: GET /ready (see src/.../app.py).
CMD ["cerberus-envoy-ai-gateway"]
