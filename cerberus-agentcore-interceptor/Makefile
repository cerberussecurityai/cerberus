# cerberus-agentcore-interceptor — developer workflow.
#
# Mirrors the sibling packages: uv-managed venv, pytest, black/ruff/mypy.

VENV := .venv
PY := $(VENV)/bin/python

.PHONY: venv test lint typecheck fmt clean

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

clean:
	rm -rf $(VENV) dist build .pytest_cache .ruff_cache .mypy_cache

$(VENV):
	$(MAKE) venv
