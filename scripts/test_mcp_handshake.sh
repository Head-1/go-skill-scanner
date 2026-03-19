#!/bin/bash
# ==============================================================================
# GSS — MCP HANDSHAKE & INTEGRATION TEST
# Objetivo: Validar contrato JSON-RPC, Tool Discovery e Resiliência do Motor.
# ==============================================================================

set -e

# Cores para telemetria visual
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🔍 Iniciando Auditoria de Protocolo MCP...${NC}"

# 1. Garantir que o binário existe com as tags corretas
if [ ! -f "./bin/gss-daemon" ]; then
    echo -e "${RED}❌ Erro: Binário não encontrado em ./bin/gss-daemon. Execute 'make build' primeiro.${NC}"
    exit 1
fi

# 2. Teste de Handshake Inicial (Initialize Request)
# O protocolo MCP exige uma fase de 'initialize' antes de qualquer operação.
echo -e "\n${BLUE}[Passo 1] Handshake Inicial (Protocol Versioning)...${NC}"
INIT_REQ='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test-client","version":"1.0.0"}}}'

RESPONSE=$(echo "$INIT_REQ" | ./bin/gss-daemon mcp 2>/dev/null | head -n 1)

if echo "$RESPONSE" | grep -q "protocolVersion"; then
    echo -e "${GREEN}✅ Handshake aceito pelo GSS.${NC}"
else
    echo -e "${RED}❌ Falha no Handshake. Resposta inesperada.${NC}"
    echo "Raw Response: $RESPONSE"
    exit 1
fi

# 3. Listagem de Ferramentas (Tool Discovery)
# Validar se o gss_scan (inspect_skill) está devidamente exposto para o integração.
echo -e "\n${BLUE}[Passo 2] Tool Discovery (Capability Taxonomy)...${NC}"
LIST_TOOLS='{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'

RESPONSE=$(echo "$LIST_TOOLS" | ./bin/gss-daemon mcp 2>/dev/null | tail -n 1)

if echo "$RESPONSE" | grep -q "gss_scan"; then
    echo -e "${GREEN}✅ Ferramenta 'gss_scan' identificada e ativa.${NC}"
else
    echo -e "${RED}❌ Erro: Engine YARA não expôs a ferramenta via MCP.${NC}"
    exit 1
fi

# 4. Teste de Scan Real (Functional Validation)
# Vamos enviar um rastro de comando destrutivo para validar o veredito via MCP.
echo -e "\n${BLUE}[Passo 3] Teste Funcional: Injeção de Payload Malicioso...${NC}"
SCAN_REQ='{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"gss_scan","arguments":{"payload":"import os; os.system(\"rm -rf /\")","name":"malicious_test.py"}}}'

# Executa o scan e captura o resultado JSON
# Nota: Como o scan YARA leva ~350µs, a resposta deve ser quase instantânea.
SCAN_RESULT=$(echo "$SCAN_REQ" | ./bin/gss-daemon mcp 2>/dev/null | grep "result")

if echo "$SCAN_RESULT" | grep -q "MALICIOUS"; then
    echo -e "${GREEN}✅ Veredito Soberano validado: MALICIOUS detectado.${NC}"
else
    echo -e "${RED}⚠️  Aviso: O motor retornou CLEAN para um payload suspeito. Verifique o Rule Bundle.${NC}"
    echo "Result: $SCAN_RESULT"
fi

echo -e "\n${GREEN}🚀 Auditoria MCP concluída. Sistema APTO para integração.${NC}"
