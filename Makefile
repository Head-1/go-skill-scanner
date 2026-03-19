BINARY_NAME=gss-daemon
CMD_PATH=./cmd/scanner/main.go

BUILD_TAGS=-tags yara_static
LDFLAGS=-ldflags "-s -w"

.PHONY: all build clean test help

all: build

help: ## Exibe ajuda
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

check-env: ## Valida dependências
	@pkg-config --exists yara || (echo "❌ libyara-dev faltando"; exit 1)

build: check-env ## Compila o binário industrial
	@echo "🔨 Forjando binário soberano..."
	@mkdir -p bin
	CGO_ENABLED=1 go build $(BUILD_TAGS) $(LDFLAGS) -o bin/$(BINARY_NAME) $(CMD_PATH)
	@echo "✅ Pronto: ./bin/$(BINARY_NAME)"

test: ## Executa testes com Race Detection
	go test -v -race $(BUILD_TAGS) ./internal/...

clean: ## Limpa ambiente
	rm -rf bin/ coverage.out
	go clean
