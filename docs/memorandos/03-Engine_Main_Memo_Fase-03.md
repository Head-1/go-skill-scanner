**MEMORANDO TÉCNICO — ENGINE & CORE ORCHESTRATION (v3.0)**

**PARA:** Desenvolvedores e Mantenedores
**DE:** Headmaster Orquestrador de IA
**PROJETO:** `go-skill-scanner` — Engine Refactoring & Async Orchestration
**DATA DE REVISÃO:** 17 de Março de 2026
**STATUS:** ✅ OPERACIONAL — INTEGRADO AO WORKER POOL

---

## 1. RESUMO EXECUTIVO

O **Engine** foi transformado no coração reativo do GSS. Abandonamos o modelo de execução sequencial em favor de um sistema de **despacho e escuta**. 
Agora, o Engine é responsável por validar a entrada, gerar identidades únicas de scan e orquestrar a passagem do payload pelos múltiplos Tiers de 
segurança sem bloquear a interface de chamada (CLI ou MCP).

### Evoluções Chave:
- **Identidade Única:** Todo scan agora nasce com um `ScanID` (UUID v4) para rastreabilidade forense.
- **Desacoplamento via Interfaces:** O Engine implementa `ScanExecutor`, permitindo que o `events.WorkerPool` o utilize sem criar ciclos de importação.
- **Orquestração de Tiers:** Preparado para o pipeline YARA (Tier 1) → AST (Tier 2) → LLM (Tier 3).

---

## 2. ARQUITETURA DE FLUXO (PIPELINE)

O Engine opera como o maestro do barramento de eventos:



1. **Entrada (AsyncScan):** Recebe o caminho do arquivo, valida existência e publica um evento `ScanRequested`.
2. **Processamento (ScanFile):** O Worker (em background) chama este método para realizar o trabalho pesado.
3. **Enriquecimento:** O Engine anexa metadados de telemetria (`LayerTrace`) para cada nível de análise.
4. **Saída:** O resultado consolidado é publicado como `ScanCompleted`.

---

## 3. IMPLEMENTAÇÃO DO ENGINE CONCRETO

### 3.1 Estrutura de Dados (`internal/engine/engine.go`)
O Engine agora carrega o Logger estruturado e o Scanner YARA injetado, focando em manter o estado limpo:

```go
type Engine struct {
    cfg    Config
    log    zerolog.Logger
    yara   yara.Scanner // Tier 1
    // Próximos: ast.Analyzer (Tier 2)
}
```

### 3.2 O Contrato de Execução
Refatoramos o método de análise para garantir a **Soberania de Dados**:
- **`AsyncScan`**: Retorno imediato do ID.
- **`ScanFile`**: Execução síncrona dentro da goroutine do Worker.

---

## 4. TELEMETRIA E RASTREABILIDADE (PIPELINE TRACE)

Cada análise gera um rastro detalhado no `schema.ScanResult`. Isso permite saber exatamente quanto tempo cada camada levou e por que falhou:

| Camada   | Status       | Responsabilidade 			    |
| :------- | :----------- | :-------------------------------------- |
| **YARA** | ✅ Pass/Fail | Assinaturas estáticas e binárias.       |
| **AST**  | ⏳ Pendente  | Lógica estrutural e intenção do código. |
| **LLM**  | ⏳ Pendente  | Heurística final e análise de contexto. |

---

## 5. GERENCIAMENTO DE RECURSOS E PERFORMANCE

### 5.1 Otimização Ryzen 7 / 12GB RAM
- **Zero-Copy Intent:** O Engine foca em passar referências de memória sempre que possível.
- **Concurrency Control:** O número de workers (atualmente 4) é o ponto de controle para não sobrecarregar o CPU durante o processamento de regras YARA complexas.

### 5.2 Graceful Shutdown
Implementamos o encerramento em cascata:
1. Engine para de aceitar novos `AsyncScan`.
2. Worker Pool limpa a fila atual.
3. `Engine.Close()` é chamado, encerrando o motor CGO do YARA com segurança.

---

## 6. ESTADO DE CONFORMIDADE (CHECKLIST)

- [x] Geração de UUID para cada Scan.
- [x] Integração com Event Bus (Pub/Sub).
- [x] Quebra de Import Cycle via interface `ScanExecutor`.
- [x] Implementação de `LayerTrace` para auditoria.
- [x] Suporte a Graceful Shutdown.

---

## 7. PRÓXIMOS MARCOS (ROADMAP)

O Engine está pronto para receber o **Tier 2 (AST Analyzer)**. A infraestrutura de eventos já permite que, ao finalizar o YARA, o Engine decida se deve despachar o payload para o próximo Worker de análise sintática.

**Próxima Sprint:** `internal/ast` — Implementação do motor Tree-Sitter para detecção de obfuscação.

---

**Assinatura Digital:**
By: Headmaster  
CTO Integrador & Arquiteto de Sistemas Críticos  
Projeto: go-skill-scanner  
2026-03-17T22:45:00Z

---

