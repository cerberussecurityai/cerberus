# cerberus-agentcore-interceptor — developer workflow.
#
# Mirrors the sibling packages: uv-managed venv, pytest, black/ruff/mypy.

VENV := .venv
PY := $(VENV)/bin/python

.PHONY: venv test lint typecheck fmt zip clean

venv:
	uv venv --clear --python 3.13 $(VENV)
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

# Deployment package for the Lambda: this package plus cerberus-core, nothing
# else. boto3 comes from the runtime.
ZIP := dist/cerberus-agentcore-interceptor.zip

zip:
	rm -rf build/zip dist
	mkdir -p build/zip dist
	uv pip install --target build/zip --no-deps . ../cerberus-core
	find build/zip -name '__pycache__' -type d -prune -exec rm -rf {} +
	find build/zip -name '*.dist-info' -type d -prune -exec rm -rf {} +
	rm -f build/zip/.lock
	cd build/zip && zip -qr ../../$(ZIP) .
	@echo "$(ZIP)"

clean:
	rm -rf $(VENV) dist build .pytest_cache .ruff_cache .mypy_cache

$(VENV):
	$(MAKE) venv
