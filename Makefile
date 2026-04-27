# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

SHELL := bash
NIX := nix --extra-experimental-features 'flakes nix-command'

define target_success
	@printf "\033[32m==> Target \"$(1)\" passed\033[0m\n\n"
endef

.DEFAULT_GOAL := help

TARGET: ## DESCRIPTION
	@echo "TARGET is here only to provide the header for 'help'"

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?##.*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[32m%-30s\033[0m %s\n", $$1, $$2}'

pre-push: check-fast  ## Run fast local formatter, flake, and test checks
	$(call target_success,$@)

check-fast:  ## Run fast local formatter, eval, and test checks
	./scripts/check-fast.sh
	$(call target_success,$@)

check-ci:  ## Run CI-aligned eval and test checks
	./scripts/check-ci.sh
	$(call target_success,$@)

check-full:  ## Run full flake and pytest checks
	./scripts/check-full.sh
	$(call target_success,$@)

test-ci:  ## Run CI test lane
	./scripts/run-pytest-lane.sh ci
	$(call target_success,$@)

check: check-full  ## Run full flake and pytest checks

test-smoke: ## Run fast non-network test lane
	./scripts/run-pytest-lane.sh fast
	$(call target_success,$@)

test: ## Run full test lane
	./scripts/run-pytest-lane.sh full
	$(call target_success,$@)

release-asset: clean ## Build release asset
	mkdir -p build/
	$(NIX) run .#sbomnix -- . \
        --cdx=./build/sbom.runtime.cdx.json \
        --spdx=./build/sbom.runtime.spdx.json \
        --csv=./build/sbom.runtime.csv
	$(NIX) run .#sbomnix -- --buildtime . \
        --cdx=./build/sbom.buildtime.cdx.json \
        --spdx=./build/sbom.buildtime.spdx.json \
        --csv=./build/sbom.buildtime.csv
	@echo ""
	@echo "Built release asset:"
	ls -la build
	$(call target_success,$@)

clean: ## Remove build artifacts
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +
	find . -name '.eggs' -exec rm -rf {} +
	rm -fr dist/
	rm -fr build/
	rm -fr .pytest_cache/
	$(call target_success,$@)

pristine: clean ## Pristine clean: remove all untracked files and folders
	git clean -f -d -x
	$(call target_success,$@)
