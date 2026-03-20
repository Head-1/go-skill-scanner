# MEMORANDO TÉCNICO: MCP & ENGINE EVOLUTION (v1.1)

**PARA:** Desenvolvedores e Mantenedores do go-skill-scanner (GSS)  
**DE:** Arquiteto de Sistemas  
**PROJETO:** go-skill-scanner  
**DATA:** 2026-03-19  
**STATUS:** 🟡 EM ANDAMENTO (Bloqueio de Build Resolvido Parcialmente)

---

## 1. RESUMO DA EVOLUÇÃO

Desde o memorando anterior (Fase 5), o GSS deixou de ser apenas uma ferramenta CLI simples e evoluiu para um **Daemon Reativo**. As principais conquistas foram:

- Consolidação do **Tier 1 (YARA)** com regras embutidas via `go:embed`, garantindo operação *air-gapped*.
- Início do scaffolding do **Tier 2 (AST)** para análise estrutural, com instalação de gramáticas C para Python e Bash.
- Implementação de um **EventBus** nativo para orquestração assíncrona dos tiers.
- Atingimos **78,8% de cobertura de código**, com o motor processando scans em microssegundos.
- Criação de um **Makefile industrial** que força a vinculação estática da `libyara`, assegurando portabilidade total do binário `gss-daemon`.

---

## 2. PROBLEMAS ENCONTRADOS (CAUSA DO BUILD QUEBRADO)

Durante a última tentativa de build, identificamos três problemas de sincronização arquitetural:

### 2.1 Drift de Versão do SDK MCP
O comando `go mod tidy` atualizou o SDK `github.com/mark3labs/mcp-go` para a versão **v0.45.0+**. Esta versão introduziu mudanças de quebra (*breaking changes*):

- A função `server.NewServer` foi substituída por `server.NewMCPServer`.
- A definição de propriedades no esquema da ferramenta passou a exigir o tipo `mcp.Property` em vez de mapas genéricos.

**Impacto:** O servidor MCP não compilava mais, gerando erros como `undefined: server.NewServer` e `undefined: mcp.Property`.

### 2.2 Dessincronização do Contrato com o Engine
O motor (Engine) evoluiu: o método `ScanFile` agora aceita uma struct `engine.ScanRequest` (contendo `Name`, `Payload` e `CallerID`) para garantir rastreabilidade forense. No entanto, o handler MCP ainda tentava passar apenas uma `string` simples, causando o erro `cannot use payload as engine.ScanRequest`.

### 2.3 Entropia de Namespace
Identificamos que a interface `Scanner` estava definida em dois lugares:
- `internal/yara/interface.go`
- `internal/yara/scanner.go`

Isso gerava o erro `redeclared in this block` ao tentar compilar o pacote `yara`.

---

## 3. SOLUÇÕES APLICADAS

### 3.1 Sincronização do Transporte MCP
- Refatoramos `internal/transport/mcp/server.go` para usar `server.NewMCPServer` e ajustamos o esquema da ferramenta para utilizar `map[string]any` compatível com a nova versão do SDK.
- O handler agora converte o payload recebido em uma `engine.ScanRequest` antes de chamar o motor.

### 3.2 Unificação dos Contratos
- Removemos o arquivo `internal/yara/interface.go`, mantendo a definição da interface `Scanner` unicamente em `scanner.go` (Single Source of Truth).

### 3.3 Ajustes de Tipagem Forte
- Aplicamos casts explícitos (`string(result.Verdict.Status)`) nas funções de log e formatação de ícones, conforme exigido pelo compilador Go.

Após essas correções, o build voltou a funcionar e os testes passaram, porém ainda existem pontos de melhoria.

---

## 4. ESTADO DOS "AIRBAGS" DE BORDA

Os 21,2% de cobertura restantes referem-se principalmente a proteções de falha crítica:

- **`isClosed` / `markClosed`:** Verificações atômicas que impedem o acesso à memória C após o desligamento do daemon. Ainda não foram adequadamente exercitadas nos testes.
- **Backpressure Handlers:** Lógica de descarte de eventos quando o buffer do EventBus (1000 mensagens) está saturado. Os caminhos de erro ainda não foram cobertos por testes.

---

## 5. PRÓXIMOS PASSOS (ROADMAP)

1. **Testar os Airbags de Borda:** Criar testes que simulem shutdown concorrente e estouro de buffer, para elevar a cobertura das funções de ciclo de vida.
2. **Completar o Context Sharing:** No handler MCP, substituir a resposta textual pelo JSON completo de `schema.ScanResult`.
3. **Implementar Trace ID Obrigatório:** Exigir um identificador único em cada requisição MCP e propagá-lo até o Audit Store.
4. **Adicionar mTLS opcional:** Para quem desejar usar o transporte HTTP, disponibilizar uma flag de configuração para ativar Mutual TLS.

---

**Assinatura:**
Arquiteto de Sistemas
Projeto go-skill-scanner
2026-03-19

