# Memorando 07: Unificação de Tiers e Estabilização MCP
**Data:** 19/03/2026
**Status:** Concluído
**Versão:** 1.2

## 1. Objetivo
Unificar a análise de assinaturas (Tier 1 - YARA) com a análise comportamental (Tier 2 - AST) sob o protocolo Model Context Protocol (MCP), garantindo detecção de ameaças complexas via IA.

## 2. Implementações Técnicas
- **Tier 2 (AST):** Implementação do `astAnalyzer` utilizando `tree-sitter-python`.
- **Query de Precisão:** Detecção de chamadas de sistema ocultas e injeções de código (`os.system`, `eval`, `subprocess.run`).
- **Engine Unificado:** O motor de análise agora orquestra YARA e AST de forma síncrona, consolidando achados em um veredito único.
- **MCP Stabilization:** Ajuste manual do JSON Schema no servidor MCP para compatibilidade com o SDK `mcp-go` v0.45.0.

## 3. Vereditos de Segurança
O sistema agora diferencia:
- **CLEAN:** Nenhum padrão binário ou estrutura lógica perigosa.
- **MALICIOUS:** Detecção via Tier 1 (Byte-matching) ou Tier 2 (Pattern-recognition).

## 4. Validação
- Handshake MCP aprovado.
- Tool Discovery operacional.
- Detecção funcional de payload `rm -rf /` confirmada via JSON-RPC.
