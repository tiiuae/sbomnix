# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
#
# SPDX-License-Identifier: Apache-2.0

SHELL := bash
PYTHON_TARGETS := $(shell find . -name "*.py" ! -path "*venv*" ! -path "*eggs*")

define target_success
	@printf "\033[32m==> Target \"$(1)\" passed\033[0m\n\n"
endef

.DEFAULT_GOAL := help

TARGET: ## DESCRIPTION
	@echo "TARGET is here only to provide the header for 'help'"

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?##.*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[32m%-30s\033[0m %s\n", $$1, $$2}'

pre-push: test black check  ## Run tests, black, and flake checks
	$(call target_success,$@)

test-ci: check  ## Run CI tests
	pytest -vx -k "not skip_in_ci" tests/
	$(call target_success,$@)

check: clean
	nix --extra-experimental-features flakes flake check

test: ## Run tests
	pytest -vx tests/
	$(call target_success,$@)

black: clean ## Reformat with black
	@for py in $(PYTHON_TARGETS); \
		do echo "$$py:"; \
		black -q $$py; \
	done
	$(call target_success,$@)

release-asset: clean ## Build release asset
	nix-shell -p nix-info --run "nix-info -m"
	nix-env -qa --meta --json -f $(shell nix-shell -p nix-info --run "nix-info -m" | grep "nixpkgs: " | cut -d'`' -f2) '.*' >meta.json
	mkdir -p build/
	nix run .#sbomnix -- result --type=runtime \
		--meta=./meta.json \
        --cdx=./build/sbom.runtime.cdx.json \
        --spdx=./build/sbom.runtime.spdx.json \
        --csv=./build/sbom.runtime.csv
	nix run .#sbomnix -- result --type=buildtime \
		--meta=./meta.json \
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
