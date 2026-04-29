# Cerberus Flex Gateway custom policy — PDK Makefile.
#
# Standard PDK targets:
#   make setup       — install cargo-anypoint, llvm-cov; cargo fetch
#   make build       — compile to wasm32-wasip1 + emit GCL artifacts
#   make test        — cargo test (parity + unit)
#   make run         — local-mode Flex Gateway (Docker Compose) for dev
#   make publish     — push a `*-dev` Exchange asset (mutable)
#   make release     — push an immutable Exchange release
#
# This file is adapted from the metrics/ example in the PDK examples repo.
# When the anypoint-cli scaffolds a fresh project with the same crate name,
# the generated Makefile is interchangeable with this one — keep them in
# sync so `cargo anypoint` upgrades land here without drift.

TARGET                 := wasm32-wasip1
TARGET_DIR             := target/$(TARGET)/release
CARGO_ANYPOINT         := cargo-anypoint
POLICY_REF_NAME_SUFFIX := -impl
DEFINITION_NAME         = $(shell anypoint-cli-v4 pdk policy-project definition get gcl-metadata-name)
DEFINITION_NAMESPACE    = $(shell anypoint-cli-v4 pdk policy-project definition get gcl-metadata-namespace)
DEFINITION_GCL_PATH     = $(shell anypoint-cli-v4 pdk policy-project locate-gcl definition)
CRATE_NAME              = $(shell cargo anypoint get-name)
OAUTH_TOKEN             = $(shell anypoint-cli-v4 pdk get-token)
POLICY_REF_NAME         = $(DEFINITION_NAME)$(POLICY_REF_NAME_SUFFIX)
ANYPOINT_METADATA_JSON  = $(shell cargo anypoint get-anypoint-metadata)

.PHONY: setup
setup: install-cargo-anypoint install-llvm-cov ## Install build prerequisites
	cargo fetch

.PHONY: install-cargo-anypoint
install-cargo-anypoint:
	cargo install --locked cargo-anypoint

.PHONY: install-llvm-cov
install-llvm-cov:
	cargo install --locked cargo-llvm-cov

.PHONY: build-asset-files
build-asset-files:
	@cargo anypoint config

.PHONY: build
build: build-asset-files ## Compile the policy to WASM + emit GCL definition/implementation
	@cargo build --target $(TARGET) --release
	@cp "$(DEFINITION_GCL_PATH)" "$(TARGET_DIR)/$(CRATE_NAME)_definition.yaml"
	@cargo anypoint gcl-gen \
		-d $(DEFINITION_NAME) \
		-n $(DEFINITION_NAMESPACE) \
		-w $(TARGET_DIR)/$(CRATE_NAME).wasm \
		-o $(TARGET_DIR)/$(CRATE_NAME)_implementation.yaml
	@echo $(POLICY_REF_NAME) > target/policy-ref-name.txt

.PHONY: test
test: ## Run all tests (unit + parity)
	@cargo test -- --nocapture

.PHONY: run
run: build ## Boot a local-mode Flex Gateway with the policy attached
	@anypoint-cli-v4 pdk patch-gcl -f playground/config/api.yaml \
		-p "spec.policies[0].policyRef.name" -v "$(POLICY_REF_NAME)"
	@anypoint-cli-v4 pdk patch-gcl -f playground/config/api.yaml \
		-p "spec.policies[0].policyRef.namespace" -v "$(DEFINITION_NAMESPACE)"
	rm -f playground/config/custom-policies/*.yaml
	cp "$(TARGET_DIR)/$(CRATE_NAME)_implementation.yaml" "playground/config/custom-policies/"
	cp "$(TARGET_DIR)/$(CRATE_NAME)_definition.yaml"     "playground/config/custom-policies/"
	-docker compose -f ./playground/docker-compose.yaml down
	docker compose -f ./playground/docker-compose.yaml up

.PHONY: publish
publish: build ## Push a *-dev Exchange asset (mutable, for iteration)
	@cargo anypoint asset publish-implementation --binary $(TARGET_DIR)/$(CRATE_NAME).wasm

.PHONY: release
release: build ## Push an immutable Exchange release (production-ready)
	@cargo anypoint asset release-implementation --binary $(TARGET_DIR)/$(CRATE_NAME).wasm

.PHONY: sync-fixtures
sync-fixtures: ## Symlink ../parity-fixtures into tests/fixtures
	@rm -f tests/fixtures
	@ln -s ../../parity-fixtures tests/fixtures
	@echo "tests/fixtures -> ../parity-fixtures"

.PHONY: clean
clean: ## Remove build artifacts
	cargo clean

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
