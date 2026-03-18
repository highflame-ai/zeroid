.PHONY: build run test test-integration lint docker-build docker-up setup-keys migrate clean

BINARY := zeroid
CMD := ./cmd/zeroid
KEYS_DIR := ./keys

build:
	go build -ldflags="-s -w" -o $(BINARY) $(CMD)

run: build
	./$(BINARY) -config zeroid.yaml

test:
	go test ./... -v -race -count=1 -timeout=120s

test-integration:
	go test ./tests/integration/ -v -count=1 -timeout=120s

lint:
	go vet ./...

docker-build:
	docker build -t zeroid:latest .

docker-up:
	docker compose up --build -d

setup-keys:
	@mkdir -p $(KEYS_DIR)
	@echo "Generating ECDSA P-256 key pair..."
	openssl ecparam -genkey -name prime256v1 -noout -out $(KEYS_DIR)/private.pem
	openssl ec -in $(KEYS_DIR)/private.pem -pubout -out $(KEYS_DIR)/public.pem
	@echo "Keys written to $(KEYS_DIR)/"

migrate:
	go run $(CMD) -config zeroid.yaml

clean:
	rm -f $(BINARY)
	rm -rf $(KEYS_DIR)
	docker compose down -v 2>/dev/null || true
