BINARY_NAME=scanner
CMD_PATH=./cmd/scanner
VERSION=1.0.0
BUILD_TAGS=-tags yara_static

.PHONY: all build clean run

all: build

build:
	@echo "🔨 Construindo binário de elite..."
	go build $(BUILD_TAGS) -o $(BINARY_NAME) $(CMD_PATH)
	@echo "✅ Pronto! Execute com: ./$(BINARY_NAME) scan [arquivo]"

clean:
	@echo "🧹 Limpando..."
	rm -f $(BINARY_NAME)

run: build
	./$(BINARY_NAME) scan test_payload.py

# Atualiza o mapa da arquitetura do projeto
update-tree:
	@echo "📂 Atualizando mapa da arquitetura..."
	@echo "# Estrutura do Projeto - Go-Skill-Scanner\n" > docs/architecture/PROJECT_STRUCTURE.md
	@echo "Gerado em: $$(date)\n" >> docs/architecture/PROJECT_STRUCTURE.md
	@echo "\`\`\`" >> docs/architecture/PROJECT_STRUCTURE.md
	@tree -I "vendor|node_modules|.git|scanner" >> docs/architecture/PROJECT_STRUCTURE.md
	@echo "\`\`\`" >> docs/architecture/PROJECT_STRUCTURE.md
	@echo "✅ Mapa atualizado em docs/architecture/PROJECT_STRUCTURE.md"
