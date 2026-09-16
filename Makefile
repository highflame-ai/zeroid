.PHONY: help build run test test-integration test-all lint docker-build docker-up setup-keys migrate clean cli-install cli-build cli-dev cli-test next-version release-prep

BINARY := zeroid
CMD := ./cmd/zeroid
KEYS_DIR := ./keys


help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the zeroid binary
	go build -ldflags="-s -w" -o $(BINARY) $(CMD)

run: build ## Build and run zeroid locally
	./$(BINARY) -config zeroid.yaml

# The test targets below mirror .github/workflows/pr-check.yml exactly — same
# package split, same flags, same timeouts. They had drifted into a single
# `go test ./... -v -race -count=1 -timeout=120s`, which could not pass on ANY
# checkout: the integration suite alone takes ~127s under -race, so the 120s Go
# timeout panicked the binary before it finished. A target that always fails
# teaches people to stop running it, and the gap it hid is the one that matters
# — CI splits these two jobs and gives them 300s and 600s respectively.

# NOTE: the exclusion below is a substring match, so it would also drop a
# nested helper package such as internal/foo/tests. Deliberately left matching
# CI byte-for-byte anyway. The obvious tightening — anchoring to $(go list -m)
# — does NOT work here: this is a multi-module repo (go list -m prints three
# modules), make's $(shell) joins them with spaces, and the resulting regex
# matches nothing, silently un-excluding tests/integration so `make test` runs
# the integration suite and dies on its own timeout. Ask for the main module
# path explicitly if you tighten this, and re-run `make -n test` to check what
# the recipe actually expands to.
test: ## Run unit tests (mirrors the CI unit job; excludes ./tests)
	go test $$(go list ./... | grep -v '/tests') -race -count=1 -timeout=300s

test-integration: ## Run integration tests only, requires Docker (mirrors the CI integration job)
	go test ./tests/... -v -race -count=1 -timeout=600s

test-all: test test-integration ## Run both suites, the way CI does

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
	@SVU=$$(command -v svu 2>/dev/null || echo "$$(go env GOPATH)/bin/svu"); \
		echo "current : $$($${SVU} current)"; \
		echo "next    : $$($${SVU} next)"
	@echo
	@echo "Cut a zeroid release: draft a new release in the GitHub UI with tag = svu's recommendation"
	@echo "(or higher). See RELEASING.md."
	@echo
	@echo "LOCKSTEP: zeroid, pkg/authjwt and pkg/dpop all release at the SAME version,"
	@echo "tagged at the same commit. Run 'make release-prep VERSION=vX.Y.Z' first so"
	@echo "go.mod names the version being released — release.yml refuses otherwise."

release-prep: ## Bump go.mod's nested-module pins to the next release version (lockstep). Requires VERSION=vX.Y.Z.
	@if [ -z "$(VERSION)" ]; then \
		echo "::error::VERSION is required, e.g. make release-prep VERSION=v1.9.4"; \
		exit 1; \
	fi
	@if ! printf '%s' "$(VERSION)" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$$'; then \
		echo "::error::VERSION must match vMAJOR.MINOR.PATCH; got $(VERSION)"; \
		exit 1; \
	fi
	@# LOCKSTEP: zeroid, pkg/authjwt and pkg/dpop all carry the same version and
	@# are tagged at the same commit. go.mod must therefore name the version being
	@# released BEFORE the release is cut — release.yml refuses to proceed
	@# otherwise. This target makes that a one-liner instead of a hand edit.
	sed -i.bak -E 's|(github.com/highflame-ai/zeroid/pkg/(authjwt\|dpop\|jwks)) v[0-9]+\.[0-9]+\.[0-9]+|\1 $(VERSION)|' go.mod
	@rm -f go.mod.bak
	@go build ./... >/dev/null
	@echo "go.mod pins bumped to $(VERSION):"
	@grep -E 'zeroid/pkg/(authjwt|dpop|jwks)' go.mod
	@echo
	@echo "Commit this, merge it, then cut the $(VERSION) release normally."


clean: ## Remove binary, keys, and docker volumes
	rm -f $(BINARY)
	rm -rf $(KEYS_DIR)
	docker compose down -v 2>/dev/null || true
