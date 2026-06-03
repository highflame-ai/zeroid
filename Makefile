.PHONY: help build run test test-integration lint docker-build docker-up setup-keys migrate clean cli-install cli-build cli-dev cli-test next-version prepare-release tag-release

BINARY := zeroid
CMD := ./cmd/zeroid
KEYS_DIR := ./keys

# jwx v4 requires the experimental encoding/json/v2 stack (Go 1.26+).
# Exporting here so every recipe inherits it; CI does the same via GOEXPERIMENT
# in pr-check.yml / release.yml.
export GOEXPERIMENT = jsonv2

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the zeroid binary
	go build -ldflags="-s -w" -o $(BINARY) $(CMD)

run: build ## Build and run zeroid locally
	./$(BINARY) -config zeroid.yaml

test: ## Run all tests (unit + integration)
	go test ./... -v -race -count=1 -timeout=120s

test-integration: ## Run integration tests only (requires Docker)
	go test ./tests/integration/ -v -count=1 -timeout=120s

lint: ## Run go vet
	go vet ./...

docker-build: ## Build Docker image
	docker build -t zeroid:latest .

docker-up: ## Start zeroid + postgres via docker compose
	docker compose up --build -d

setup-keys: ## Generate ECDSA P-256 + RSA 2048 signing keys
	@mkdir -p $(KEYS_DIR)
	@echo "Generating ECDSA P-256 key pair..."
	openssl ecparam -genkey -name prime256v1 -noout -out $(KEYS_DIR)/private.pem
	openssl ec -in $(KEYS_DIR)/private.pem -pubout -out $(KEYS_DIR)/public.pem
	@echo "Generating RSA 2048 key pair..."
	openssl genrsa -out $(KEYS_DIR)/rsa_private.pem 2048
	openssl rsa -in $(KEYS_DIR)/rsa_private.pem -pubout -out $(KEYS_DIR)/rsa_public.pem
	@echo "Keys written to $(KEYS_DIR)/"

migrate: ## Run migrations (starts server, applies, exits)
	go run $(CMD) -config zeroid.yaml

cli-install: ## Install CLI dependencies
	cd cli && npm install

cli-build: cli-install ## Build the zeroid CLI
	cd cli && npm run build

cli-dev: cli-install ## Run CLI from source (no build needed)
	cd cli && npx tsx src/index.ts $(ARGS)

cli-test: cli-install ## Run CLI tests
	cd cli && npm test

next-version: ## Print svu-computed next semver from commits since last v* tag
	@command -v svu >/dev/null 2>&1 || go install github.com/caarlos0/svu/v3@latest
	@echo "current : $$(svu current)"
	@echo "next    : $$(svu next)"
	@echo
	@echo "Cut a release with:"
	@echo "  make prepare-release VERSION=\$$(svu next)"
	@echo "  # ...review + merge the release-prep PR, then:"
	@echo "  make tag-release VERSION=\$$(svu next)"

# ── Release flow ─────────────────────────────────────────────────────
# Two-step PR-based release flow (see RELEASING.md):
#
#   1. `make prepare-release VERSION=v1.7.0`
#      → triggers prepare-release.yml which opens a release-prep PR
#      → maintainer reviews + merges
#   2. `make tag-release VERSION=v1.7.0`
#      → triggers tag-release.yml which creates the root tag + GH
#         release (the downstream release.yml then runs validate,
#         tests, goreleaser, docker)
#
# Both targets require `gh` CLI installed + authenticated against
# highflame-ai/zeroid. Both pin VERSION on the command line; no
# global config to drift.

prepare-release: ## Open release-prep PR via prepare-release.yml (requires VERSION=vX.Y.Z)
	@command -v gh >/dev/null 2>&1 || { echo "::error::gh CLI is required (https://cli.github.com/)"; exit 1; }
	@if [ -z "$(VERSION)" ]; then \
		echo "::error::VERSION is required, e.g. make prepare-release VERSION=v1.7.0"; \
		exit 1; \
	fi
	@if ! printf '%s' "$(VERSION)" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$$'; then \
		echo "::error::VERSION must match vMAJOR.MINOR.PATCH; got $(VERSION)"; \
		exit 1; \
	fi
	@echo "Triggering prepare-release.yml with version=$(VERSION)..."
	gh workflow run prepare-release.yml \
		--repo highflame-ai/zeroid \
		--field version=$(VERSION)
	@echo
	@echo "Watch progress:"
	@echo "  gh run watch --repo highflame-ai/zeroid"
	@echo "Find the opened PR:"
	@echo "  gh pr list --repo highflame-ai/zeroid --head release-prep/$(VERSION)"

tag-release: ## Create root tag + GH release via tag-release.yml after release-prep PR merges (requires VERSION=vX.Y.Z)
	@command -v gh >/dev/null 2>&1 || { echo "::error::gh CLI is required (https://cli.github.com/)"; exit 1; }
	@if [ -z "$(VERSION)" ]; then \
		echo "::error::VERSION is required, e.g. make tag-release VERSION=v1.7.0"; \
		exit 1; \
	fi
	@if ! printf '%s' "$(VERSION)" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$$'; then \
		echo "::error::VERSION must match vMAJOR.MINOR.PATCH; got $(VERSION)"; \
		exit 1; \
	fi
	@echo "Triggering tag-release.yml with version=$(VERSION)..."
	gh workflow run tag-release.yml \
		--repo highflame-ai/zeroid \
		--field version=$(VERSION)
	@echo
	@echo "Watch progress:"
	@echo "  gh run watch --repo highflame-ai/zeroid"
	@echo "After completion, release.yml fires on release:published (validate, tests, goreleaser, docker)."

clean: ## Remove binary, keys, and docker volumes
	rm -f $(BINARY)
	rm -rf $(KEYS_DIR)
	docker compose down -v 2>/dev/null || true
