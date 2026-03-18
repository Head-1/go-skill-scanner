#!/bin/bash
set -e

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  GO-SKILL-SCANNER - Bootstrap (Curadoria Interna)       ║"
echo "║  Verificando integridade das regras YARA locais         ║"
echo "╚══════════════════════════════════════════════════════════╝"

RULES_DIR="internal/yara/rules"

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Verificar se diretório de regras existe
if [ ! -d "$RULES_DIR" ]; then
    echo -e "${YELLOW}📁 Criando diretório de regras...${NC}"
    mkdir -p "$RULES_DIR"/{capabilities,core,custom,malicious}
fi

# Verificar se existem arquivos .yar
YAR_COUNT=$(find "$RULES_DIR" -name "*.yar" 2>/dev/null | wc -l)

if [ "$YAR_COUNT" -eq 0 ]; then
    echo -e "${RED}❌ Nenhuma regra YARA encontrada em $RULES_DIR${NC}"
    echo ""
    echo "A arquitetura do GO-SKILL-SCANNER requer regras locais embutidas via go:embed."
    echo "Por favor, adicione regras YARA manualmente em:"
    echo "  $RULES_DIR/capabilities/"
    echo "  $RULES_DIR/core/"
    echo "  $RULES_DIR/custom/"
    echo "  $RULES_DIR/malicious/"
    echo ""
    echo "Regras mínimas recomendadas:"
    echo "  - system_risk.yar (detecção de chamadas de sistema)"
    echo "  - network_risk.yar (detecção de atividade de rede)"
    echo "  - obfuscation.yar  (detecção de ofuscação)"
    echo ""
    exit 1
fi

# Verificar regras obrigatórias mínimas
MISSING=0
REQUIRED_PATTERNS=("system_risk" "network_risk")

for pattern in "${REQUIRED_PATTERNS[@]}"; do
    if ! find "$RULES_DIR" -name "*${pattern}*.yar" | grep -q .; then
        echo -e "${YELLOW}⚠️  Regra recomendada não encontrada: ${pattern}${NC}"
        MISSING=$((MISSING + 1))
    fi
done

# Verificar estrutura de diretórios
echo -e "\n${GREEN}✅ Estrutura de regras verificada:${NC}"
for dir in capabilities core custom malicious; do
    if [ -d "$RULES_DIR/$dir" ]; then
        COUNT=$(find "$RULES_DIR/$dir" -name "*.yar" 2>/dev/null | wc -l)
        echo "   - $dir: $COUNT regras"
    else
        echo -e "   - $dir: ${YELLOW}não existe${NC}"
        mkdir -p "$RULES_DIR/$dir"
    fi
done

echo ""
echo -e "${GREEN}📊 Total de regras: $YAR_COUNT${NC}"
echo -e "${GREEN}🔒 Modo offline: Regras embutidas via go:embed${NC}"

# Gerar arquivo de manifesto (opcional)
cat > "$RULES_DIR/.manifest" << EOF
# Manifesto das Regras YARA
# Gerado em: $(date)
# Total: $YAR_COUNT regras
# Curadoria: Interna (sem dependências externas)
EOF

echo -e "${GREEN}✅ Bootstrap concluído. Pronto para build.${NC}"
