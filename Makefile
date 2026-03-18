BINARY_NAME=scanner
CMD_PATH=./cmd/scanner
VERSION=1.0.0
BUILD_TAGS=-tags yara_static

.PHONY: all build clean run prepare-rules update-tree

all: prepare-rules build

# Verifica integridade das regras locais (NÃO baixa nada)
prepare-rules:
	@echo "📦 Verificando regras YARA locais..."
	@if [ ! -d "internal/yara/rules" ] || [ -z "$$(find internal/yara/rules -name '*.yar' 2>/dev/null | head -1)" ]; then \
		echo "⚠️  Regras YARA não encontradas."; \
		echo "   O GO-SKILL-SCANNER requer regras locais em internal/yara/rules/"; \
		echo "   Execute ./bootstrap.sh para verificar a estrutura."; \
		exit 1; \
	else \
		echo "✅ Regras YARA locais encontradas."; \
	fi

build: prepare-rules
	@echo "🔨 Construindo binário de elite..."
	go build $(BUILD_TAGS) -o $(BINARY_NAME) $(CMD_PATH)
	@echo "✅ Pronto! Execute com: ./$(BINARY_NAME) scan [arquivo]"
	@echo "   Para modo MCP: ./$(BINARY_NAME) mcp --addr=:8081"

clean:
	@echo "🧹 Limpando..."
	rm -f $(BINARY_NAME)
	go clean -cache

run: build
	./$(BINARY_NAME) scan test_payload.py

# Executa em modo MCP
run-mcp: build
	@echo "🚀 Iniciando MCP server na porta 8081..."
	./$(BINARY_NAME) mcp --addr=:8081

# Testa a integração MCP (requer jq instalado)
test-mcp: build
	@echo "🧪 Testando integração MCP..."
	@./scripts/test_mcp_integration.sh

# Atualiza o mapa da arquitetura do projeto
update-tree:
	@echo "📂 Atualizando mapa da arquitetura..."
	@mkdir -p docs/architecture
	@echo "# Estrutura do Projeto - Go-Skill-Scanner\n" > docs/architecture/PROJECT_STRUCTURE.md
	@echo "Gerado em: $$(date)\n" >> docs/architecture/PROJECT_STRUCTURE.md
	@echo "\`\`\`" >> docs/architecture/PROJECT_STRUCTURE.md
	@tree -I "vendor|node_modules|.git|scanner|tmp" >> docs/architecture/PROJECT_STRUCTURE.md
	@echo "\`\`\`" >> docs/architecture/PROJECT_STRUCTURE.md
	@echo "✅ Mapa atualizado em docs/architecture/PROJECT_STRUCTURE.md"

# Build com debug
build-debug:
	@echo "🔨 Construindo com debug..."
	go build -tags yara_static -v -x -o $(BINARY_NAME) $(CMD_PATH)

# Limpa tudo e reconstrói
rebuild: clean prepare-rules build
	@echo "✅ Reconstruído com sucesso"

# Mostra ajuda
help:
	@echo "Comandos disponíveis:"
	@echo "  make            : Verifica regras e constrói"
	@echo "  make build      : Constrói o binário"
	@echo "  make clean      : Remove binário e cache"
	@echo "  make run        : Executa scan no test_payload.py"
	@echo "  make run-mcp    : Executa em modo MCP server"
	@echo "  make test-mcp   : Testa integração MCP"
	@echo "  make update-tree: Atualiza documentação da estrutura"
	@echo "  make rebuild    : Limpa e reconstrói do zero"
