# cerberus-envoy-ai-gateway — developer workflow.
#
# Mirrors the sibling packages: uv-managed venv, pytest, black/ruff/mypy.

VENV := .venv
PY := $(VENV)/bin/python

.PHONY: venv test lint typecheck fmt run image clean

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

# Local end-to-end playground: bridge + stub ingest + mock LLM + mock MCP
# behind a standalone (no-Kubernetes) Envoy AI Gateway. See playground/README
# section in ../README.md for prerequisites (aigw binary, docker).
run:
	cd playground && ./run.sh

image:
	docker build -t cerberus-envoy-ai-gateway:dev .

clean:
	rm -rf $(VENV) dist build .pytest_cache .ruff_cache .mypy_cache

$(VENV):
	$(MAKE) venv
