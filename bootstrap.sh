#!/bin/bash
# ==============================================================================
# Script de Inicialização NPCAIA-Daemon - go-skill-scanner
# Função: Prover infraestrutura, dependências e corpus de regras YARA.
# ==============================================================================

set -e # Abortar em caso de erro

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}🏗️  Iniciando Scaffolding Profissional: go-skill-scanner${NC}"

# 1. Verificação de Dependências Críticas
echo -e "${YELLOW}🔍 Verificando ambiente de desenvolvimento...${NC}"

check_dep() {
    if ! command -v $1 &> /dev/null; then
        echo -e "${RED}❌ ERRO: $1 não encontrado. Instale-o para prosseguir.${NC}"
        exit 1
    fi
}

check_dep "go"
check_dep "curl"
check_dep "gcc"
check_dep "pkg-config"

# Verificação específica para desenvolvimento YARA (CGO)
if ! pkg-config --exists yara; then
    echo -e "${YELLOW}⚠️  Aviso: libyara-dev não detectada via pkg-config.${NC}"
    echo -e "Para builds CGO, execute: sudo apt-get install -y libyara-dev"
fi

# 2. Criação da Estrutura de Diretórios (Hierarquia Estrita)
echo -e "${YELLOW}📁 Criando hierarquia de diretórios...${NC}"

DIRS=(
    "cmd/scanner"
    "internal/engine"
    "internal/yara/rules/cisco_official"
    "internal/yara/rules/custom"
    "internal/ast"
    "internal/cache"
    "internal/manifest"
    "internal/llm"
    "internal/sandbox"
    "internal/privacy"
    "internal/audit"
    "internal/transport/mcp"
    "internal/transport/cli"
    "pkg/schema"
    "docs/examples"
    "docs/memorandos"
    "build"
    "configs"
)

for dir in "${DIRS[@]}"; do
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
        echo -e "  ${GREEN}✓${NC} Criado: $dir"
    fi
done

# 3. Importação do Corpus de Regras (Tier 1)
echo -e "${YELLOW}📥 Sincronizando regras YARA (Cisco Talos / Community)...${NC}"

RULES_DEST="internal/yara/rules/cisco_official/cisco_official.yar"
# URL oficial das regras do projeto original
RULES_URL="https://raw.githubusercontent.com/cisco-open/skill-scanner/main/skill_scanner/rules/malicious_patterns.yar"

curl -sSL "$RULES_URL" -o "$RULES_DEST"

if [ $? -eq 0 ] && [ -s "$RULES_DEST" ]; then
    RULE_COUNT=$(grep -c "rule " "$RULES_DEST")
    echo -e "${GREEN}✅ Regras importadas: $RULE_COUNT assinaturas detectadas.${NC}"
    echo -e "${BLUE}Hash MD5:${NC} $(md5sum "$RULES_DEST" | cut -d' ' -f1)"
else
    echo -e "${RED}❌ Erro crítico: Falha ao baixar ou validar o arquivo de regras.${NC}"
    exit 1
fi

# 4. Inicialização de Módulos (se necessário)
if [ ! -f "go.mod" ]; then
    echo -e "${YELLOW}📦 Inicializando módulo Go...${NC}"
    go mod init github.com/Head-1/go-skill-scanner
fi

# 5. Finalização
echo -e "\n${GREEN}🚀 Scaffolding concluído com sucesso.${NC}"
echo -e "Próximos passos:"
echo -e "  1. Rode ${BLUE}go mod tidy${NC} para sincronizar dependências."
echo -e "  2. Teste o motor com ${BLUE}go test ./internal/yara/... -v${NC}"
echo -e "  3. Compile o scanner: ${BLUE}go build -o scanner ./cmd/scanner${NC}\n"
