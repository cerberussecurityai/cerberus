# LiteLLM proxy with cerberus-litellm installed. Pin the base by digest in
# production: docker pull ghcr.io/berriai/litellm:v1.105.1 && docker inspect …
FROM ghcr.io/berriai/litellm:v1.105.1

COPY dist/cerberus_litellm-*.whl /tmp/
# The image's venv is uv-managed and may not ship pip; try uv first.
RUN (command -v uv >/dev/null 2>&1 && uv pip install --python /app/.venv/bin/python --no-cache /tmp/cerberus_litellm-*.whl) \
 || (/app/.venv/bin/python -m ensurepip --upgrade && /app/.venv/bin/python -m pip install --no-cache-dir /tmp/cerberus_litellm-*.whl)
RUN /app/.venv/bin/python -c "import cerberus_litellm; print('cerberus-litellm', cerberus_litellm.__version__)"
