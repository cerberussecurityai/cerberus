# cerberus-litellm — developer workflow (mirrors cerberus-envoy-ai-gateway).
VENV := .venv
PY := $(VENV)/bin/python

.PHONY: venv test lint typecheck fmt build run image clean fixtures

venv:
	uv venv --clear $(VENV)
	uv pip install --python $(PY) -e ".[dev]" -e ../cerberus-core

test: $(VENV)
	$(PY) -m pytest tests/ -v

lint: $(VENV)
	$(PY) -m ruff check src/ tests/
	$(PY) -m black --check src/ tests/

fmt: $(VENV)
	$(PY) -m black src/ tests/
	$(PY) -m ruff check --fix src/ tests/

typecheck: $(VENV)
	$(PY) -m mypy src/

build:
	rm -rf dist && uv build

# Regenerate tests/fixtures/litellm/*.json from a directory of spike captures.
fixtures: $(VENV)
	$(PY) tests/fixtures/trim_from_spike.py $(CAPTURES)

# Local playground: LiteLLM with the plugin installed + mocks + stub ingest.
run:
	cd playground && ./run.sh

image: build
	docker build -t cerberus-litellm-proxy:dev -f playground/Dockerfile .

clean:
	rm -rf $(VENV) dist build .pytest_cache .ruff_cache .mypy_cache

$(VENV):
	$(MAKE) venv
