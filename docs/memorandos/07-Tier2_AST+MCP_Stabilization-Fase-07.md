# Memorando 07: Evolução Estrutural – Unificação de Tiers (YARA + AST) e Estabilização MCP

**Data:** 19/03/2026  
**Versão:** 3.0 (Documento de Handoff e Treinamento)  
**Responsável:** Headmaster (Orquestrador de IA)  
**Status:** Concluído  

---

## 1. Introdução e Contexto

O **Go-Skill-Scanner (GSS)** é um sistema de segurança para análise de scripts e habilidades de IA, projetado para operar em ambientes _edge_ com soberania de dados. Até a **Fase 6**, o sistema dependia exclusivamente do **Tier 1 – YARA**, um motor de correspondência de padrões binários. Embora eficiente para assinaturas conhecidas, o YARA é cego para a **intenção lógica** do código, sendo facilmente evadido por técnicas simples de ofuscação (ex.: concatenação de strings).

Esta fase **(Fase 7)** teve como objetivo principal introduzir o **Tier 2 – Análise Sintática (AST)**, capaz de compreender a estrutura do código e detectar comportamentos perigosos mesmo quando as strings estão ofuscadas. Além disso, consolidamos a interface de comunicação com agentes de IA através do **Model Context Protocol (MCP)**, permitindo que o GSS seja consumido como uma ferramenta por orquestradores externos.

---

## 2. Fundamentação Teórica: Por que o Tier 2?

### 2.1 Limitações do YARA
O YARA opera sobre sequências exatas de bytes. Uma regra típica procura por strings como `"rm -rf /"`. Se um atacante escrever `"r" + "m" + " -rf /"`, o YARA não acusa, pois a string não aparece contígua no binário.

### 2.2 Análise Sintática (AST)
A **Árvore de Sintaxe Abstrata** representa a estrutura gramatical do código. Com ela, o analisador pode identificar que `os.system("rm -rf /")` é uma chamada de função (`call`), com um objeto (`os`) e um método (`system`), independentemente de como a string interna foi construída.

Utilizamos a biblioteca **Tree‑Sitter**, que gera parsers incrementais e eficientes em C, integrados via cgo ao Go. Isso nos permite embalar gramáticas de várias linguagens dentro do mesmo binário, sem necessidade de interpretadores externos.

---

## 3. Implementação do Tier 2 – AST Analyzer

### 3.1 Estrutura de Diretórios e Interfaces

Criamos o pacote `internal/ast` com a seguinte organização:

```
internal/ast/
├── analyzer.go      # Definição da interface Analyzer e implementação base
├── python.go        # Implementação específica para Python (Tree‑Sitter)
└── (futuro) bash.go # Para scripts shell
```

#### `analyzer.go` – Contrato e Orquestração

```go
type Analyzer interface {
    Analyze(ctx context.Context, payload []byte, lang string) ([]schema.Finding, error)
}

type astAnalyzer struct {
    log zerolog.Logger
}

func NewAnalyzer(log zerolog.Logger) Analyzer {
    return &astAnalyzer{log: log.With().Str("component", "ast").Logger()}
}

func (a *astAnalyzer) Analyze(ctx context.Context, payload []byte, lang string) ([]schema.Finding, error) {
    switch lang {
    case "python":
        return a.analyzePython(payload)
    default:
        return nil, nil
    }
}
```

### 3.2 Queries de Precisão com Tree‑Sitter

A lógica central reside na construção de **queries** que percorrem a árvore sintática. Para Python, definimos uma query que captura chamadas perigosas como `eval`, `exec` e `os.system`.

**Exemplo da query utilizada:**

```scheme
(call
    function: [
        (identifier) @func (#match? @func "^(eval|exec)$")
        (attribute
            object: (identifier) @obj (#match? @obj "^(os|subprocess)$")
            attribute: (identifier) @attr (#match? @attr "^(system|run|Popen)$")
        ) @func
    ]
) @call_node
```

Essa query produz um único nó (`@call_node`) para cada chamada perigosa, evitando duplicações e permitindo a extração do conteúdo exato da linha.

### 3.3 Geração de Findings

Cada match gera um `schema.Finding` com:
- `RuleID: "AST_PY_DANGEROUS_CODE"`
- `Severity: schema.SeverityCritical`
- `Category: schema.CategoryCodeExecution`
- `Description` e `Evidence` contendo o trecho detectado.

---

## 4. Unificação dos Tiers no Engine

### 4.1 Motor Consolidado (`internal/engine/engine.go`)

O motor agora orquestra os dois tiers de forma síncrona, agregando os achados.

```go
func (e *Engine) ScanFile(ctx context.Context, req ScanRequest) (*schema.ScanResult, error) {
    start := time.Now()
    var allFindings []schema.Finding

    // Tier 1: YARA
    yaraFindings, _ := e.yara.Scan(ctx, req.Payload)
    allFindings = append(allFindings, yaraFindings...)

    // Tier 2: AST (apenas para linguagens suportadas)
    astFindings, _ := e.ast.Analyze(ctx, req.Payload, "python")
    allFindings = append(allFindings, astFindings...)

    // Veredito
    verdict := schema.VerdictClean
    if len(allFindings) > 0 {
        verdict = schema.VerdictMalicious
    }

    return &schema.ScanResult{
        ScanID:    uuid.New().String(),
        ScannedAt: start,
        Target:    schema.TargetInfo{Name: req.Name},
        Verdict:   schema.Verdict{Status: verdict, Summary: "..."},
        Findings:  allFindings,
        DurationNs: time.Since(start).Nanoseconds(),
    }, nil
}
```

### 4.2 Decisão Arquitetural: Síncrono vs Assíncrono

Optamos por manter o fluxo **síncrono** dentro da chamada MCP/CLI para simplificar o ciclo de resposta. O EventBus, embora presente no código, foi temporariamente desativado para esta fase, pois adicionava complexidade desnecessária ao handshake MCP. Futuramente poderá ser reintroduzido para análises em background.

---

## 5. Estabilização do Model Context Protocol (MCP)

### 5.1 Objetivo

Permitir que agentes de IA (Claude, Gemini, etc.) consultem o GSS como uma ferramenta, enviando código e recebendo um veredito. O protocolo escolhido foi o **MCP** (Model Context Protocol) sobre **stdio**, padrão da indústria para integração com LLMs.

### 5.2 Desafio com SDK `mcp-go v0.45.0`

A versão mais recente do SDK da Mark3Labs apresentou duas dificuldades:
- Ausência de helpers como `AddStringProperty` para definir o esquema JSON da ferramenta.
- Tipagem estrita: `request.Params.Arguments` é do tipo `any`, exigindo type assertion.

### 5.3 Solução Implementada

Assumimos o controle total da definição do esquema, usando um mapa `map[string]any` e realizando a conversão explícita dos argumentos.

**Trecho do servidor MCP (`internal/transport/mcp/server.go`):**

```go
tool.InputSchema = mcp.ToolInputSchema{
    Type: "object",
    Properties: map[string]any{
        "payload": map[string]any{
            "type":        "string",
            "description": "Conteúdo do script a ser analisado",
        },
    },
    Required: []string{"payload"},
}

// No handler:
args, ok := request.Params.Arguments.(map[string]any)
payload, ok := args["payload"].(string)
```

Essa abordagem garantiu compatibilidade total com o SDK sem depender de funções auxiliares ausentes.

### 5.4 Handshake e Tool Discovery

O servidor expõe uma única ferramenta chamada `gss_scan`. O fluxo de comunicação é:

1. Cliente envia `initialize` (handshake).
2. Cliente consulta `tools/list` para descobrir `gss_scan`.
3. Cliente invoca `tools/call` com o argumento `payload`.

---

## 6. Caso Prático de Validação

### Cenário de Teste
Arquivo `ataque_v2.py`:
```python
import os
os.system("whoami")
eval("print('perigo')")
```

### Resultado Antes da Fase 7 (apenas YARA)
- **Veredito:** `CLEAN` (falso negativo)
- **Findings:** apenas se houvesse regra específica para `"whoami"`.

### Resultado Após Fase 7 (YARA + AST)
- **Veredito:** `MALICIOUS`
- **Findings AST:** duas entradas – uma para `os.system(...)` e outra para `eval(...)`.
- **Log de depuração:** o Tree‑Sitter reportou matches em todas as chamadas perigosas, mesmo as aninhadas.

O script de teste automatizado `test_mcp_handshake.sh` confirmou o handshake, a descoberta da ferramenta e a resposta `MALICIOUS` para o payload `os.system("rm -rf /")`.

---

## 7. Lições Aprendidas e Decisões Críticas

1. **Tree‑Sitter via cgo** – Apesar do receio inicial, a integração mostrou-se estável e extremamente rápida (milissegundos para arquivos de até 1MB).
2. **Controle manual do JSON Schema** – Quando um SDK evolui, é mais seguro assumir o controle da serialização do que confiar em helpers que podem desaparecer.
3. **Unificação de achados** – Agregar findings de múltiplos tiers antes de decidir o veredito evita que uma camada anule a outra.
4. **Testes de handshake** – A criação de um script de teste independente (em bash) foi essencial para garantir que o MCP funcionasse mesmo fora do ecossistema Go.

---

## 8. Arquitetura Atual do Sistema

```
[Cliente IA] <--(stdio/JSON‑RPC)--> [MCP Server] --> [Engine]
                                             |
                                   [YARA Scanner] [AST Analyzer]
                                             |
                                   [internal/yara] [internal/ast]
```

- **MCP Server:** `internal/transport/mcp/server.go`
- **Engine:** `internal/engine/engine.go`
- **YARA:** `internal/yara/`
- **AST:** `internal/ast/` (com suporte a Python via tree‑sitter)

---

## 9. Próximos Passos (Fase 8 em diante)

1. **Tier 3 – Análise com SLM Local (Ollama)**  
   - Criar provider em `internal/llm/providers/ollama/client.go`.
   - Implementar prompt de segurança para desempate de casos ambíguos.
2. **Expansão de Linguagens no AST**  
   - Adicionar suporte a Bash/Shell (crítico para `curl | bash`).
   - Adicionar JavaScript/Node.js (comum em ferramentas de IA).
3. **Persistência de Auditoria**  
   - Criar `internal/audit` com SQLite para armazenar histórico de scans.
   - Permitir consultas forenses via MCP.

---

## 10. Conclusão

A Fase 7 elevou o GSS de um simples scanner de assinaturas para um **sistema híbrido de análise estática e comportamental**, pronto para ser integrado a qualquer ecossistema de IA via MCP. O memorando documenta não apenas o que foi feito, mas **por que** cada decisão foi tomada, servindo como base sólida para futuras evoluções e para o treinamento de novos integrantes da equipe.

---

**Este documento é mantido sob controle de versão e deve ser atualizado sempre que novas camadas forem adicionadas ou alterações arquiteturais significativas ocorrerem.**
