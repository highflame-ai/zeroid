.PHONY: help build run test test-integration lint docker-build docker-up setup-keys migrate clean

BINARY := zeroid
CMD := ./cmd/zeroid
KEYS_DIR := ./keys

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

clean: ## Remove binary, keys, and docker volumes
	rm -f $(BINARY)
	rm -rf $(KEYS_DIR)
	docker compose down -v 2>/dev/null || true
