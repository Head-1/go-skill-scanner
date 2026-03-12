#!/bin/bash
# Script de Inicialização NPCAIA-Daemon - go-skill-scanner

echo "🏗️  Iniciando Scaffolding do go-skill-scanner..."

# 1. Criar estrutura de diretórios
mkdir -p cmd/scanner \
internal/engine \
internal/yara/rules/cisco_official \
internal/yara/rules/custom \
internal/ast \
internal/cache \
internal/manifest \
internal/llm \
internal/sandbox \
internal/privacy \
internal/audit \
internal/transport/mcp \
internal/transport/cli \
pkg/schema \
build \
configs \
.github/workflows

# 2. Baixar as regras YARA originais da Cisco (O "Combustível")
echo "📥 Buscando regras YARA da Cisco..."
rules_url="https://raw.githubusercontent.com/cisco-open/skill-scanner/main/skill_scanner/rules/malicious_patterns.yar"
curl -sSL $rules_url -o internal/yara/rules/cisco_official/cisco_official.yar

if [ $? -eq 0 ]; then
    echo "✅ Regras importadas com sucesso."
else
    echo "❌ Erro ao baixar regras. Verifique a conexão."
fi

echo "🚀 Estrutura pronta. Próximo passo: Implementar os arquivos .go"
