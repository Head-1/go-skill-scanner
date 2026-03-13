# 📋 GO-SKILL-SCANNER — CHECKLIST COMPLETO DO PROJETO (REVISÃO SOBERANA)

**Projeto:** go-skill-scanner  
**Responsável:** Headmaster Orquestrador de IA  
**Última Atualização:** 2026-03-12 (Revisão Soberana v2)  
**Status Geral:** 🟢 **Sprint 1 Completa | Sprint 2 Iniciando**

**Princípios Arquiteturais:**
- 🛡️ **Soberania Tecnológica** — Zero dependências de vendor único
- 🔌 **Agnosticismo de Provedores** — Interfaces para todos os backends
- ⚡ **Performance de Borda** — Async pipeline para alta carga
- 📊 **Auditoria Forense** — Persistência completa de telemetria

---

## 🎯 FASE 0: FUNDAÇÃO & SCAFFOLDING

### Arquitetura & Planejamento
- [x] Definir escolha da linguagem (Go vs Python)
- [x] Estabelecer modelo de tiering (YARA → AST → LLM)
- [x] Definir ambiente de desenvolvimento (**Ubuntu 24.04, Go 1.22+ LTS, libyara v4.5.0+**)
- [x] Escolher biblioteca YARA (hillu/go-yara/v4 com CGO)
- [x] Definir estratégia de isolamento (go:embed para regras)
- [x] Documentar decisões arquiteturais (Memorando Fase 01)
- [ ] **Definir arquitetura de eventos (Event Bus interno)**
- [ ] **Definir estratégia de agnosticismo de LLM (Provider Interface)**
- [ ] **Definir modelo de persistência dual (Cache + Audit Store)**

### Estrutura de Diretórios
- [x] Criar estrutura seguindo Standard Go Project Layout
- [x] Configurar diretório `cmd/scanner/`
- [x] Configurar diretório `internal/engine/`
- [x] Configurar diretório `internal/yara/`
- [x] Configurar diretório `internal/yara/rules/`
- [x] Configurar diretório `pkg/schema/`
- [x] Configurar diretório `build/`
- [x] Configurar diretório `configs/`
- [x] Configurar diretório `docs/`
- [ ] Criar diretório `internal/ast/`
- [ ] Criar diretório `internal/cache/` (performance cache)
- [ ] **Criar diretório `internal/audit/` (audit store de longo prazo)**
- [ ] **Criar diretório `internal/llm/` (provider-agnostic)**
- [ ] **Criar diretório `internal/llm/providers/` (Anthropic, OpenAI, Gemini, etc.)**
- [ ] **Criar diretório `internal/events/` (event bus & messaging)**
- [ ] **Criar diretório `internal/transport/mcp/` (Model Context Protocol)**
- [ ] Criar diretório `internal/manifest/`
- [ ] Criar diretório `internal/sandbox/`

### Configuração Inicial
- [x] Inicializar `go.mod` com módulo `github.com/Head-1/go-skill-scanner`
- [x] Criar `build/Dockerfile` com multi-stage build
- [x] Criar `configs/default_manifest.json`
- [x] Criar script `bootstrap.sh` para fetch de regras YARA
- [x] Configurar `.gitignore` para Go
- [ ] **Criar `configs/providers.yaml` (LLM provider configs)**
- [ ] **Criar `configs/eventbus.yaml` (async pipeline config)**

---

## 🛡️ SPRINT 1: MÓDULO YARA (TIER 1)

### Interface & Contratos
- [x] Definir interface `yara.Scanner` canônica
- [x] Documentar contrato com GoDoc completo
- [x] Definir struct `ScanStatistics` para métricas
- [x] Estabelecer garantias de thread-safety
- [x] Documentar lifecycle management (Close())

### Implementação Core
- [x] Implementar `scanner.go` (build tag: yara_static/yara_dynamic)
- [x] Implementar `scanner_stub.go` (build tag: default)
- [x] Implementar sistema de métricas lock-free (`metrics.go`)
- [x] Implementar `go:embed` para regras YARA
- [x] Implementar compilação de regras com namespace
- [x] Implementar método `Scan()` context-aware
- [x] Implementar método `Close()` com graceful shutdown
- [x] Implementar método `RuleCount()`
- [x] Implementar método `BundleHash()` (SHA-256)
- [x] Implementar método `ScanStats()`

### Métricas & Observabilidade
- [x] Implementar counters atômicos (TotalScans, TotalBytes, etc.)
- [x] Implementar tracking de duração média
- [x] Implementar error rate calculation
- [x] Implementar scanGuard (WaitGroup) para graceful shutdown
- [x] Documentar integração Prometheus (helpers prontos)

### Regras YARA
- [x] Criar estrutura `internal/yara/rules/cisco_official/`
- [x] Criar estrutura `internal/yara/rules/custom/`
- [x] Estabelecer Curadoria Interna de Regras (Remoção de dependências externas falhas)
- [x] Testar embed de regras no binário
- [x] Validar bundle hash determinístico

### Testes
- [x] Teste: Interface compliance
- [x] Teste: Basic lifecycle (New → Scan → Close)
- [x] Teste: Empty payload handling
- [x] Teste: Clean payload scanning
- [x] Teste: Context cancellation
- [x] Teste: Context timeout
- [x] Teste: Scan after close (error case)
- [x] Teste: Close idempotency
- [x] Teste: ScanStats tracking
- [x] Teste: Concurrent scans (thread-safety)
- [x] Benchmark: Small payload (18 bytes)
- [x] Benchmark: Large payload (1MB)
- [x] Validar 100% pass rate em `go test ./internal/yara/...`

### Documentação YARA
- [x] Criar `internal/yara/README.md` técnico
- [x] Documentar build tags (static/dynamic/stub)
- [x] Documentar API completa
- [x] Criar exemplos de integração
- [x] Documentar troubleshooting comum
- [x] Criar memorando de refatoração (Fase 02)

---

## ⚙️ SPRINT 1: ENGINE & CLI INTEGRATION

### Engine Core
- [x] Refatorar `internal/engine/engine.go`
- [x] Remover interface duplicada `YARAScanner`
- [x] Integrar `internal/yara.Scanner` nativo
- [x] Corrigir import paths (`github.com/Head-1/go-skill-scanner`)
- [x] Implementar método `Engine.Close()` com lifecycle
- [x] Implementar método `Engine.YARAStats()`
- [x] Adicionar logging enriquecido na inicialização
- [x] Implementar pipeline YARA → AST → LLM (tiering)

### Stub Implementations (Temporários)
- [x] Implementar `noopCache` stub
- [x] Implementar `noopAST` stub
- [x] Implementar `noopManifest` stub
- [x] Implementar `noopProbe` (default SecurityProbe)
- [x] Exportar stubs via `NewNoopCache()`, `NewNoopAST()`, etc.

### CLI com Cobra
- [x] Refatorar `cmd/scanner/main.go` com Cobra
- [x] Implementar comando `rootCmd` (help + version)
- [x] Implementar comando `scanCmd` (scan file/stdin)
- [x] Implementar comando `versionCmd`
- [x] Adicionar flags: `--timeout`, `--llm`, `--wasm`, `--verbose`
- [x] Implementar signal handling (SIGINT/SIGTERM)
- [x] Implementar graceful shutdown com context
- [x] Implementar `defer engine.Close()` pattern
- [x] Implementar Makefile industrial (build, clean, run, update-tree)

### Output & Observabilidade
- [x] Implementar rich output formatting (box drawing)
- [x] Implementar ícones por severidade (🔴🟠🟡🔵✅⚠️)
- [x] Implementar exibição de findings detalhados
- [x] Implementar exibição de pipeline trace (verbose mode)
- [x] Implementar `printYARAStats()` ao final
- [x] Implementar exit codes semânticos (0/1/2/3)

### Funcionalidades CLI
- [x] Suporte a scan de arquivo (`scanner scan file.py`)
- [x] Suporte a scan de stdin (`cat file | scanner scan -`)
- [x] Suporte a timeout configurável
- [x] Suporte a help automático (`--help`)
- [x] Suporte a version display
- [ ] Suporte a scan de diretório recursivo
- [ ] Suporte a output JSON (`--json`)
- [ ] Suporte a output HTML report

### Documentação Engine & CLI
- [x] Criar memorando técnico ENGINE_MAIN_MEMO.md
- [x] Documentar fluxo de execução completo
- [x] Documentar exemplos de uso
- [x] Documentar integração YARA → Engine
- [x] Documentar signal handling
- [x] Documentar graceful shutdown

---

## 🧬 SPRINT 2: AST ANALYZER (TIER 2)

### Planejamento AST
- [ ] Definir interface `ASTAnalyzer`
- [ ] Escolher biblioteca de parsing (**tree-sitter para multi-language**)
- [ ] Definir linguagens suportadas (Python, JavaScript, Bash, Go)
- [ ] Mapear padrões heurísticos perigosos
- [ ] Documentar estratégia de detecção
- [ ] **Definir integração com Event Bus (async analysis)**

### Implementação AST
- [ ] Criar `internal/ast/analyzer.go`
- [ ] Implementar parser para Python (tree-sitter-python)
- [ ] Implementar parser para JavaScript (tree-sitter-javascript)
- [ ] Implementar parser para Bash/Shell (tree-sitter-bash)
- [ ] Implementar parser para Go (tree-sitter-go)
- [ ] Implementar detecção de `eval()` e variantes
- [ ] Implementar detecção de `os.system()` / `subprocess`
- [ ] Implementar detecção de pipe chains perigosos
- [ ] Implementar detecção de base64 decode + exec
- [ ] Implementar scoring por padrão
- [ ] **Implementar async processing via Event Bus**

### Padrões Heurísticos
- [ ] Detectar: Remote code execution patterns
- [ ] Detectar: File system manipulation (`rm -rf`, `chmod 777`)
- [ ] Detectar: Network activity suspeita (`curl | bash`)
- [ ] Detectar: Credential harvesting
- [ ] Detectar: Process spawning excessivo
- [ ] Detectar: Obfuscação de código
- [ ] Detectar: Environment variable manipulation
- [ ] Detectar: Path traversal attempts

### Testes AST
- [ ] Teste: Detecção de eval() em Python
- [ ] Teste: Detecção de exec() em JavaScript
- [ ] Teste: Detecção de pipe chain em Bash
- [ ] Teste: False positives (código legítimo)
- [ ] Teste: Obfuscação básica
- [ ] Teste: Multi-language parsing
- [ ] Benchmark: Performance em arquivos grandes (>1MB)
- [ ] Benchmark: Async processing throughput

### Integração AST → Engine
- [ ] Integrar ASTAnalyzer no Engine
- [ ] Implementar fallback AST quando YARA clean
- [ ] Implementar agregação de findings (YARA + AST)
- [ ] Ajustar thresholds de tiering
- [ ] Validar pipeline YARA → AST
- [ ] **Validar comunicação via Event Bus**

---

## 💾 SPRINT 2: CACHE & REPUTATION SYSTEM (Performance Cache)

### Planejamento Cache
- [ ] Definir interface `Cache`
- [ ] Escolher backend (**BadgerDB para performance + in-memory tier**)
- [ ] Definir schema de armazenamento
- [ ] Implementar TLSH fuzzy hashing
- [ ] Documentar estratégia de cache hit/miss
- [ ] **Separar claramente: Cache (TTL curto) vs Audit Store (persistência)**

### Implementação Cache
- [ ] Criar `internal/cache/store.go`
- [ ] Implementar `GetBySHA256()` (exact match)
- [ ] Implementar `GetByTLSH()` (fuzzy match)
- [ ] Implementar `Put()` com TTL (default: 24h)
- [ ] Implementar TLSH hash computation
- [ ] Implementar similarity threshold (default: 30)
- [ ] Implementar eviction policy (LRU)
- [ ] Implementar in-memory tier (LRU cache) para hot data

### Persistência (Cache Layer)
- [ ] Configurar BadgerDB backend
- [ ] Implementar compaction/cleanup automático
- [ ] Implementar backup/restore (opcional)
- [ ] Implementar cache warming (preload hot keys)
- [ ] **Implementar TTL automático (24h default)**

### Testes Cache
- [ ] Teste: Exact SHA-256 match
- [ ] Teste: Fuzzy TLSH match
- [ ] Teste: Cache miss
- [ ] Teste: TTL expiration
- [ ] Teste: Eviction policy (LRU)
- [ ] Teste: In-memory tier hit rate
- [ ] Benchmark: Lookup performance (<1ms)
- [ ] Benchmark: Write throughput (>10K ops/sec)

### Integração Cache → Engine
- [ ] Integrar Cache no Engine
- [ ] Implementar lookup antes de YARA scan
- [ ] Implementar write-back após scan (async via Event Bus)
- [ ] Implementar cache statistics
- [ ] Validar performance gain (>80% hit rate em workloads típicos)

---

## ⚡ SPRINT 2.5: ASYNC PIPELINE & MESSAGING (Arquitetura de Eventos)

**NOVA SEÇÃO — Processamento Assíncrono para Alta Carga**

### Planejamento Event Bus
- [ ] Definir arquitetura de eventos (pub/sub interno)
- [ ] Escolher backend (**Go channels para single-node, NATS para cluster**)
- [ ] Definir event schemas (ScanRequested, YARACompleted, ASTCompleted, etc.)
- [ ] Documentar topologia de mensagens
- [ ] Estabelecer garantias de entrega (at-least-once vs exactly-once)

### Implementação Event Bus (Single-Node)
- [ ] Criar `internal/events/bus.go`
- [ ] Implementar EventBus usando Go channels
- [ ] Implementar `Publish(event Event)` method
- [ ] Implementar `Subscribe(topic string) <-chan Event` method
- [ ] Implementar `Unsubscribe()` cleanup
- [ ] Implementar buffer sizes configuráveis
- [ ] Implementar backpressure handling
- [ ] Implementar graceful shutdown (drain events)

### Event Types
- [ ] Definir: `ScanRequestedEvent` (payload + metadata)
- [ ] Definir: `YARACompletedEvent` (matches + metrics)
- [ ] Definir: `ASTCompletedEvent` (findings + score)
- [ ] Definir: `LLMRequestedEvent` (ambiguous case)
- [ ] Definir: `LLMCompletedEvent` (verdict + confidence)
- [ ] Definir: `ScanCompletedEvent` (final result)
- [ ] Definir: `CacheWriteEvent` (async cache update)
- [ ] Definir: `AuditLogEvent` (audit store write)

### Worker Pools
- [ ] Implementar YARA worker pool (concurrent scans)
- [ ] Implementar AST worker pool
- [ ] Implementar LLM worker pool (rate limiting)
- [ ] Implementar Cache worker (batch writes)
- [ ] Implementar Audit worker (batch writes)
- [ ] Configurar pool sizes via config (default: NumCPU)

### NATS Integration (Cluster Mode — Opcional)
- [ ] Criar `internal/events/nats.go`
- [ ] Implementar NATS client wrapper
- [ ] Implementar JetStream persistence
- [ ] Implementar stream configuration
- [ ] Implementar consumer groups
- [ ] Documentar deployment com NATS cluster

### Testes Event Bus
- [ ] Teste: Publish/Subscribe básico
- [ ] Teste: Multiple subscribers
- [ ] Teste: Event ordering (FIFO)
- [ ] Teste: Backpressure handling
- [ ] Teste: Graceful shutdown (no event loss)
- [ ] Teste: Worker pool concurrency
- [ ] Benchmark: Throughput (>100K events/sec)
- [ ] Benchmark: Latency (p99 <10ms)

### Integração Event Bus → Engine
- [ ] Refatorar Engine para async pipeline
- [ ] YARA scan → publish `YARACompletedEvent`
- [ ] AST analysis → subscribe `YARACompletedEvent`
- [ ] LLM judge → subscribe ambiguous cases
- [ ] Cache updates → async via events
- [ ] Audit logging → async via events
- [ ] Validar end-to-end async flow

### Monitoring & Observability
- [ ] Implementar métricas de event bus
- [ ] Monitorar: Queue depth por topic
- [ ] Monitorar: Event processing latency
- [ ] Monitorar: Worker pool utilization
- [ ] Monitorar: Backpressure incidents
- [ ] Alertar: Queue depth >1000 events

---

## 📊 SPRINT 2.5: AUDIT STORE (Persistência de Longo Prazo)

**NOVA SEÇÃO — Auditoria Forense & Compliance**

### Planejamento Audit Store
- [ ] Definir interface `AuditStore`
- [ ] Escolher backend (**SQLite para single-node, PostgreSQL para cluster**)
- [ ] Definir schema relacional completo
- [ ] Documentar retention policy (default: 90 dias)
- [ ] Estabelecer compliance requirements (GDPR, SOC2)

### Schema de Banco de Dados
- [ ] Tabela: `scans` (scan_id, timestamp, target_sha256, verdict, risk_score, etc.)
- [ ] Tabela: `findings` (finding_id, scan_id, source, severity, rule_id, etc.)
- [ ] Tabela: `pipeline_traces` (scan_id, tier, status, duration_ns, etc.)
- [ ] Tabela: `yara_matches` (scan_id, rule_name, namespace, etc.)
- [ ] Tabela: `ast_patterns` (scan_id, pattern_type, evidence, etc.)
- [ ] Tabela: `llm_analyses` (scan_id, provider, model, tokens_used, etc.)
- [ ] Tabela: `cache_events` (timestamp, operation, key, hit_type, etc.)
- [ ] Índices: timestamp, scan_id, target_sha256, verdict

### Implementação Audit Store (SQLite)
- [ ] Criar `internal/audit/store.go`
- [ ] Implementar migrations (golang-migrate)
- [ ] Implementar `RecordScan(result *ScanResult)` method
- [ ] Implementar `RecordFindings(scanID, findings)` method
- [ ] Implementar `RecordPipelineTrace(scanID, trace)` method
- [ ] Implementar `RecordCacheEvent(event)` method
- [ ] Implementar batch inserts (performance)
- [ ] Implementar connection pooling

### Queries & Analytics
- [ ] Query: Scan history por target SHA-256
- [ ] Query: Threat trends (malicious detections over time)
- [ ] Query: Top matched YARA rules
- [ ] Query: False positive candidates (SUSPECT verdicts)
- [ ] Query: LLM escalation rate
- [ ] Query: Cache hit rate over time
- [ ] Implementar full-text search em findings

### Retention & Archival
- [ ] Implementar retention policy configurable
- [ ] Implementar purge automático (scans >90 dias)
- [ ] Implementar archival para cold storage (S3/MinIO)
- [ ] Implementar data export (JSON/CSV)
- [ ] Implementar GDPR compliance (right to erasure)

### PostgreSQL Migration (Cluster Mode — Opcional)
- [ ] Criar `internal/audit/postgres.go`
- [ ] Migrar schema para PostgreSQL
- [ ] Implementar partitioning por timestamp
- [ ] Implementar replication (leader-follower)
- [ ] Implementar connection pooling (pgx)
- [ ] Documentar deployment PostgreSQL HA

### Testes Audit Store
- [ ] Teste: Insert scan result
- [ ] Teste: Insert findings (batch)
- [ ] Teste: Query scan history
- [ ] Teste: Retention policy enforcement
- [ ] Teste: Concurrent writes
- [ ] Teste: Migration rollback
- [ ] Benchmark: Insert throughput (>1K scans/sec)
- [ ] Benchmark: Query performance (<100ms)

### Integração Audit Store → Engine
- [ ] Integrar AuditStore no Engine
- [ ] Implementar async writes via Event Bus
- [ ] Subscribe `ScanCompletedEvent` → audit log
- [ ] Subscribe `CacheWriteEvent` → cache telemetry
- [ ] Implementar retry logic (transient failures)
- [ ] Validar zero data loss

### Compliance & Security
- [ ] Implementar encryption at rest (SQLCipher para SQLite)
- [ ] Implementar PII redaction (opcional)
- [ ] Implementar audit trail immutability (append-only)
- [ ] Documentar compliance framework (GDPR, SOC2)
- [ ] Implementar access control (RBAC)

---

## 🤖 SPRINT 3: LLM INTEGRATION (TIER 3 — Provider-Agnostic)

**REFATORADO — Agnosticismo Total de Provedores**

### Planejamento LLM (Arquitetura Soberana)
- [ ] Definir interface `LLMProvider` (vendor-agnostic)
- [ ] Definir interface `LLMJudge` (orquestrador)
- [ ] Documentar provider selection strategy (config-driven)
- [ ] Implementar fallback chain (primary → secondary → local)
- [ ] Estabelecer rate limits por provider
- [ ] Documentar prompt engineering patterns

### Interface Abstrata de Provedores
- [ ] Criar `internal/llm/provider.go` (interface canônica)
- [ ] Definir métodos: `Analyze(ctx, payload, findings)` → (verdict, confidence, meta)
- [ ] Definir métodos: `HealthCheck()` → bool
- [ ] Definir métodos: `GetCapabilities()` → (maxTokens, models, features)
- [ ] Definir métodos: `EstimateCost(tokens)` → float64
- [ ] Implementar provider registry (plugin system)

### Implementação: Anthropic Claude Provider
- [ ] Criar `internal/llm/providers/anthropic.go`
- [ ] Implementar client Anthropic API
- [ ] Implementar prompt template (malware detection)
- [ ] Implementar response parsing (structured output)
- [ ] Implementar retry logic com exponential backoff
- [ ] Implementar timeout handling
- [ ] Implementar token usage tracking
- [ ] Implementar cost estimation

### Implementação: OpenAI GPT Provider
- [ ] Criar `internal/llm/providers/openai.go`
- [ ] Implementar client OpenAI API
- [ ] Implementar prompt adaptation (GPT-specific)
- [ ] Implementar function calling (structured output)
- [ ] Implementar retry logic
- [ ] Implementar token tracking
- [ ] Implementar cost estimation

### Implementação: Google Gemini Provider
- [ ] Criar `internal/llm/providers/gemini.go`
- [ ] Implementar client Gemini API
- [ ] Implementar prompt adaptation (Gemini-specific)
- [ ] Implementar multimodal support (futuro: code screenshots)
- [ ] Implementar retry logic
- [ ] Implementar token tracking
- [ ] Implementar cost estimation

### Implementação: DeepSeek Provider
- [ ] Criar `internal/llm/providers/deepseek.go`
- [ ] Implementar client DeepSeek API
- [ ] Implementar prompt adaptation
- [ ] Implementar retry logic
- [ ] Implementar token tracking
- [ ] Implementar cost estimation (baixo custo)

### Implementação: Local LLM via Ollama
- [ ] Criar `internal/llm/providers/ollama.go`
- [ ] Implementar client Ollama API
- [ ] Suportar modelos: llama3, codellama, deepseek-coder
- [ ] Implementar prompt adaptation
- [ ] Implementar health check (Ollama running?)
- [ ] Implementar fallback (se Ollama offline)
- [ ] **Benefício: Soberania total, zero custos, offline-first**

### Model Context Protocol (MCP) Integration
- [ ] Criar `internal/transport/mcp/client.go`
- [ ] Implementar MCP protocol para context sharing
- [ ] Implementar serialização de scan context
- [ ] Implementar desserialização de LLM responses
- [ ] Documentar MCP schema (context structure)
- [ ] Validar interoperabilidade com MCP servers

### LLM Judge (Orquestrador)
- [ ] Criar `internal/llm/judge.go`
- [ ] Implementar provider selection logic (config-driven)
- [ ] Implementar fallback chain (primary fail → secondary)
- [ ] Implementar circuit breaker (provider health)
- [ ] Implementar rate limiting global
- [ ] Implementar cost tracking agregado
- [ ] Implementar A/B testing (compare providers)

### Prompts & Análise
- [ ] Criar prompt template base (provider-agnostic)
- [ ] Implementar few-shot examples (malware detection)
- [ ] Implementar chain-of-thought reasoning
- [ ] Implementar structured output (JSON schema)
- [ ] Validar accuracy vs false positives
- [ ] Implementar prompt versioning (A/B testing)

### Configuração de Provedores
- [ ] Criar `configs/providers.yaml`
- [ ] Configurar: Anthropic (API key, model, max_tokens)
- [ ] Configurar: OpenAI (API key, model, max_tokens)
- [ ] Configurar: Gemini (API key, model, max_tokens)
- [ ] Configurar: DeepSeek (API key, model, max_tokens)
- [ ] Configurar: Ollama (endpoint, model, fallback)
- [ ] Configurar: Fallback chain (order of preference)
- [ ] Configurar: Rate limits por provider

### Testes LLM
- [ ] Teste: Provider interface compliance (todos)
- [ ] Teste: Análise de código limpo (todos providers)
- [ ] Teste: Análise de código malicioso (todos providers)
- [ ] Teste: Casos ambíguos → SUSPECT (todos providers)
- [ ] Teste: Timeout handling (todos providers)
- [ ] Teste: Rate limit handling (todos providers)
- [ ] Teste: Fallback chain (primary fail → secondary)
- [ ] Teste: Circuit breaker (unhealthy provider)
- [ ] Teste: A/B testing (compare provider accuracy)
- [ ] Validar accuracy metrics (>85% agreement entre providers)

### Integração LLM → Engine
- [ ] Integrar LLMJudge no Engine (provider-agnostic)
- [ ] Implementar tiering (score entre thresholds)
- [ ] Implementar async request via Event Bus
- [ ] Implementar fallback quando todos providers offline
- [ ] Implementar cost tracking (tokens + $$$)
- [ ] Implementar provider metrics (latency, accuracy, cost)
- [ ] Validar pipeline YARA → AST → LLM

### Monitoring & Cost Control
- [ ] Monitorar: Token usage por provider
- [ ] Monitorar: Cost acumulado ($ por dia)
- [ ] Monitorar: Latency por provider (p50, p95, p99)
- [ ] Monitorar: Error rate por provider
- [ ] Alertar: Cost diário >$100 USD
- [ ] Alertar: Provider health degradation
- [ ] Implementar budget enforcement (hard limit)
- [ ] Monitorar: VRAM/RAM Usage (Evitar OOM Kill em Edge Devices ao usar Ollama)

---

## 🏗️ SPRINT 3: MANIFEST VALIDATION

### Planejamento Manifest
- [ ] Definir interface `ManifestValidator`
- [ ] Criar schema JSON para manifest
- [ ] Documentar campos obrigatórios/opcionais
- [ ] Definir capability taxonomy

### Implementação Manifest
- [ ] Criar `internal/manifest/validator.go`
- [ ] Implementar parser de manifest.json
- [ ] Implementar validação de schema (JSON Schema)
- [ ] Implementar capability matching
- [ ] Implementar detection de undeclared capabilities

### Capabilities
- [ ] Mapear: File system access (read/write/delete)
- [ ] Mapear: Network access (http/https/tcp/udp)
- [ ] Mapear: Process spawning (exec/system)
- [ ] Mapear: Environment variables (read/write)
- [ ] Mapear: Shell execution (bash/sh)
- [ ] Mapear: Sensitive data access (credentials/tokens)
- [ ] Mapear: System information (os/hostname/user)

### Testes Manifest
- [ ] Teste: Manifest válido
- [ ] Teste: Manifest inválido (schema error)
- [ ] Teste: Capability mismatch
- [ ] Teste: Undeclared capability detection
- [ ] Teste: Over-declared capabilities (false positives)

### Integração Manifest → Engine
- [ ] Integrar ManifestValidator no Engine
- [ ] Implementar cross-check com findings (YARA + AST)
- [ ] Implementar warnings para mismatches
- [ ] Implementar auto-discovery de capabilities (AST)
- [ ] Validar workflow completo

---

## 🐳 BUILD & DEPLOYMENT

### Docker
- [x] Criar Dockerfile multi-stage
- [x] Stage 1: Builder com YARA static (libyara v4.5.0+)
- [x] Stage 2: Runtime mínimo (Alpine)
- [ ] Otimizar tamanho da imagem (<50MB)
- [ ] Implementar health check endpoint (`/health`)
- [ ] **Stage 3: Adicionar Ollama runtime (opcional, imagem separada)**
- [ ] Criar docker-compose para stack completa (scanner + NATS + PostgreSQL + Ollama)
- [ ] Documentar deploy em produção

### CI/CD
- [ ] Criar GitHub Actions workflow
- [ ] Implementar: Lint (golangci-lint)
- [ ] Implementar: Testes unitários (all packages)
- [ ] Implementar: Testes de integração (E2E)
- [ ] Implementar: Build de binário (Go 1.22+)
- [ ] Implementar: Build de Docker image
- [ ] Implementar: Dogfooding (scanner no próprio código)
- [ ] Implementar: Release automation (tags semver)
- [ ] **Implementar: Provider integration tests (todos LLM providers)**
- [ ] **Implementar: Event Bus stress tests (throughput)**

### Distribuição
- [ ] Criar releases no GitHub
- [ ] Gerar binários para: linux/amd64
- [ ] Gerar binários para: linux/arm64 (Raspberry Pi, edge devices)
- [ ] Gerar binários para: darwin/amd64
- [ ] Gerar binários para: darwin/arm64 (Apple Silicon)
- [ ] Publicar Docker image no registry (DockerHub/GHCR)
- [ ] Criar install script (`curl | bash`)
- [ ] Criar Helm chart (Kubernetes deployment)

---

## 📊 OBSERVABILIDADE & MONITORING

### Métricas (Prometheus)
- [x] YARA: TotalScans, TotalBytes, AvgDuration
- [ ] Engine: Scans per tier (YARA/AST/LLM)
- [ ] Cache: Hit rate, miss rate, size
- [ ] **Audit Store: Writes per second, retention size**
- [ ] **Event Bus: Queue depth, throughput, latency**
- [ ] LLM: Token usage por provider, cost tracking, latency
- [ ] System: Memory usage, CPU usage, goroutines

### Logging (Structured)
- [x] Structured logging com zerolog
- [x] Log levels (debug, info, warn, error)
- [ ] Correlation IDs (scan_id, request_id tracking)
- [ ] **Event tracing (distributed tracing via OpenTelemetry)**
- [ ] Log aggregation (stdout JSON format)
- [ ] Integration com ELK/Loki stack

### Prometheus Exporter
- [ ] Implementar `/metrics` HTTP endpoint
- [ ] Exportar YARA counters
- [ ] Exportar Engine counters
- [ ] Exportar Cache counters
- [ ] **Exportar Event Bus metrics (queue depth, latency)**
- [ ] **Exportar Audit Store metrics (write rate, retention)**
- [ ] Exportar LLM counters (tokens, cost, latency por provider)
- [ ] Criar Grafana dashboards

### Alerting
- [ ] Alert: YARA error rate >5%
- [ ] Alert: Avg scan duration >100ms
- [ ] Alert: Cache hit rate <50%
- [ ] **Alert: Event Bus queue depth >1000 events**
- [ ] **Alert: Audit Store write failures**
- [ ] Alert: LLM timeout rate >10% (por provider)
- [ ] Alert: LLM cost diário >$100 USD
- [ ] Alert: Memory leak detection (RSS growth >10%/hour)
- [ ] **Alert: Provider health degradation (circuit breaker open)**

---

## 🔒 SEGURANÇA & HARDENING

### Security Hardening
- [ ] Implementar WASM sandbox (opcional, tier 4)
- [ ] Implementar rate limiting (global + per-client)
- [ ] Implementar input validation (size, type, encoding)
- [ ] Implementar size limits (max payload: 10MB)
- [ ] Implementar secure defaults (least privilege)
- [ ] Implementar capability dropping (Linux capabilities)
- [ ] Implementar seccomp-bpf filtering

### Audit & Compliance
- [x] Implementar audit logging (Audit Store)
- [ ] Implementar scan history tracking (90 dias)
- [ ] Implementar GDPR compliance (right to erasure)
- [ ] Implementar data retention policies
- [ ] Documentar security assumptions
- [ ] Realizar security review (penetration test)
- [ ] Implementar SOC2 compliance framework

### eBPF Probe (Opcional — Linux Only)
- [ ] Definir interface `SecurityProbe`
- [ ] Implementar eBPF syscall monitoring (cilium/ebpf)
- [ ] Detectar: Suspicious syscalls (execve, fork, socket)
- [ ] Detectar: File tampering (open/write/unlink)
- [ ] Detectar: Network anomalies (connect/sendto)
- [ ] Integrar com Engine pipeline
- [ ] Documentar kernel version requirements (5.10+)

---

## 📚 DOCUMENTAÇÃO

### Documentação Técnica
- [x] Memorando Fase 01 (Fundação)
- [x] Memorando Fase 02 (YARA Refactoring)
- [x] Memorando Fase 03 (Engine & Main)
- [x] README.md do módulo YARA
- [ ] **Memorando Fase 04 (Event Bus & Async Pipeline)**
- [ ] **Memorando Fase 05 (Audit Store & Compliance)**
- [ ] **Memorando Fase 06 (LLM Agnosticism & MCP)**
- [ ] README.md do projeto completo
- [ ] API Documentation (GoDoc completo)
- [x] Architecture Decision Records (ADRs)
- [ ] Deployment Guide (Docker, K8s, bare metal)
- [ ] Troubleshooting Guide
- [ ] Security Playbook

### Documentação de Uso
- [ ] Quick Start Guide (5 minutos para primeiro scan)
- [ ] CLI Reference (todos comandos + flags)
- [ ] Configuration Guide (YAML configs explicados)
- [ ] LLM Provider Setup Guide (API keys, Ollama install)
- [ ] Event Bus Configuration Guide (channels vs NATS)
- [ ] Audit Store Query Guide (SQL examples)
- [ ] Examples & Tutorials
- [ ] FAQ

### Diagramas
- [ ] Diagrama de arquitetura geral (componentes + event flow)
- [ ] Diagrama de fluxo de execução (YARA → AST → LLM)
- [ ] Diagrama de tiering (decision tree)
- [ ] **Diagrama de Event Bus topology (publishers/subscribers)**
- [ ] **Diagrama de LLM Provider fallback chain**
- [ ] Diagrama de deployment (single-node vs cluster)
- [ ] Sequence diagrams (async pipeline)

---

## 🧪 TESTES & VALIDAÇÃO

### Unit Tests
- [x] YARA Scanner: 12 testes, 2 benchmarks ✅
- [ ] Engine: Core logic tests
- [ ] AST Analyzer: Pattern detection tests (multi-language)
- [ ] Cache: Lookup/storage tests (BadgerDB)
- [ ] **Audit Store: CRUD tests (SQLite/PostgreSQL)**
- [ ] **Event Bus: Pub/sub tests (channels/NATS)**
- [ ] LLM: Provider interface tests (todos providers)
- [ ] LLM: Judge orchestration tests (fallback chain)
- [ ] Manifest: Validation tests

### Integration Tests
- [ ] End-to-end: Clean payload scan (sync + async)
- [ ] End-to-end: Malicious payload detection (full pipeline)
- [ ] End-to-end: Cache hit/miss flow
- [ ] End-to-end: LLM escalation (ambiguous case)
- [ ] End-to-end: Graceful shutdown (Ctrl+C, event drain)
- [ ] **End-to-end: Event Bus async pipeline (YARA → AST → LLM)**
- [ ] **End-to-end: Audit Store persistence (write + query)**
- [ ] **End-to-end: Provider fallback (primary fail → secondary)**
- [ ] **End-to-end: Multi-provider comparison (A/B test)**

### Performance Tests
- [ ] Benchmark: 1000 scans/second throughput (sync)
- [ ] **Benchmark: 10K scans/second throughput (async Event Bus)**
- [ ] Benchmark: Memory usage under load (<500MB for 10K concurrent)
- [ ] Benchmark: Cold start time (<100ms)
- [ ] Stress test: 100K concurrent scans (Event Bus)
- [ ] Stress test: 1GB payload handling
- [ ] **Stress test: Event Bus queue saturation (backpressure)**

### Security Tests
- [ ] Fuzzing: Malformed payloads (AFL/go-fuzz)
- [ ] Fuzzing: YARA rule injection attempts
- [ ] Penetration test: DoS attempts (rate limiting)
- [ ] Penetration test: Sandbox escape (WASM/eBPF)
- [ ] Penetration test: LLM prompt injection

---

## 🎯 MILESTONES

### ✅ Milestone 1: Foundation (COMPLETO)
- [x] Scaffolding completo
- [x] Go module inicializado (Go 1.22+)
- [x] Dockerfile configurado (libyara v4.5.0+)
- [x] Documentação inicial

### ✅ Milestone 2: YARA Engine (COMPLETO)
- [x] Módulo YARA production-ready
- [x] Testes 100% passing
- [x] Métricas implementadas
- [x] Documentação completa

### ✅ Milestone 3: Engine & CLI (COMPLETO)
- [x] Engine refatorado com YARA integration
- [x] CLI Cobra implementado
- [x] Signal handling implementado
- [x] Graceful shutdown implementado

### 🔄 Milestone 4: AST & Cache (EM PROGRESSO)
- [ ] AST Analyzer implementado (tree-sitter multi-language)
- [ ] Cache system implementado (BadgerDB + in-memory)
- [ ] Pipeline YARA → AST validado
- [ ] Performance targets atingidos

### 🔄 Milestone 4.5: Event Bus & Audit (EM PROGRESSO)
- [ ] **Event Bus implementado (Go channels + NATS opcional)**
- [ ] **Async pipeline validado (YARA → AST → LLM)**
- [ ] **Audit Store implementado (SQLite + PostgreSQL opcional)**
- [ ] **Retention policies configuradas**
- [ ] **Throughput target: >10K scans/sec**

### ⏳ Milestone 5: LLM Agnostic (PENDENTE)
- [ ] **Interface LLMProvider implementada**
- [ ] **Providers implementados: Anthropic, OpenAI, Gemini, DeepSeek, Ollama**
- [ ] **MCP integration completa**
- [ ] **Fallback chain validado**
- [ ] **Accuracy metrics validados (>85% agreement)**

### ⏳ Milestone 6: Manifest & Sandbox (PENDENTE)
- [ ] Manifest validation implementado
- [ ] WASM sandbox implementado (opcional)
- [ ] eBPF probe implementado (opcional)
- [ ] Pipeline completo (YARA → AST → LLM → Manifest)

### ⏳ Milestone 7: Production Ready (PENDENTE)
- [ ] CI/CD completo (GitHub Actions)
- [ ] Monitoring & alerting (Prometheus + Grafana)
- [ ] Security hardening (seccomp, capabilities)
- [ ] Documentação completa (ADRs + guides)
- [ ] First production deployment

---

## 📈 MÉTRICAS DE SUCESSO

### Qualidade
- [x] Test coverage YARA: >90% ✅
- [ ] Test coverage geral: >80%
- [ ] Zero memory leaks (valgrind clean)
- [ ] Zero race conditions (go test -race)
- [ ] Linter: golangci-lint clean
- [ ] **Zero event loss (Event Bus graceful shutdown)**

### Performance
- [ ] Cold start: <100ms
- [ ] Avg scan time: <10ms (payloads <1MB, sync)
- [ ] **Async throughput: >10K scans/second (Event Bus)**
- [ ] Memory footprint: <100MB (single-node)
- [ ] **Memory footprint: <500MB (cluster mode, 10K concurrent)**
- [ ] Binary size: <20MB (static)
- [ ] **Event Bus latency: p99 <10ms**

### Accuracy
- [ ] True positive rate: >95%
- [ ] False positive rate: <5%
- [ ] YARA detection: 100% known malware
- [ ] AST detection: >90% obfuscated malware
- [ ] **LLM accuracy: >85% ambiguous cases (cross-provider agreement)**
- [ ] **LLM provider parity: <10% variance entre providers**

### Cost & Efficiency
- [ ] **LLM cost per scan: <$0.01 USD (average)**
- [ ] **Cache hit rate: >80% (production workloads)**
- [ ] **Ollama fallback success: >99% uptime (soberania)**
- [ ] **Event Bus throughput: >100K events/sec**

---

## 🚀 ROADMAP

### Q1 2026 (Atual)
- [x] Sprint 0: Fundação ✅
- [x] Sprint 1: YARA Engine ✅
- [x] Sprint 1: Engine & CLI ✅
- [ ] Sprint 2: AST & Cache 🔄

### Q2 2026
- [ ] **Sprint 2.5: Event Bus & Audit Store 🔄**
- [ ] Sprint 3: LLM Agnostic Integration
- [ ] Sprint 3: Manifest Validation
- [ ] Sprint 3: MCP Integration

### Q3 2026
- [ ] Sprint 4: WASM Sandbox (opcional)
- [ ] Sprint 4: eBPF Probe (opcional)
- [ ] Production deployment (single-node)
- [ ] Monitoring dashboard (Grafana)

### Q4 2026
- [ ] Cluster mode (NATS + PostgreSQL)
- [ ] MCP server integration (context sharing)
- [ ] First public release (v1.0.0)
- [ ] Multi-language support expansion

### 2027
- [ ] Rule marketplace (community rules)
- [ ] Web UI dashboard (React + API)
- [ ] Enterprise features (RBAC, SSO)
- [ ] SaaS offering (optional)

---

## 🛠️ AMBIENTE DE DESENVOLVIMENTO (ATUALIZADO)

### Requisitos de Sistema
- **OS:** Ubuntu Server 24.04 LTS
- **Go:** 1.22+ LTS (latest stable)
- **libyara:** v4.5.0+ (YARA engine)
- **Docker:** 29.3.0+ (container runtime)
- **Git:** 2.40+

### Dependências Opcionais
- **NATS Server:** 2.10+ (Event Bus cluster mode)
- **PostgreSQL:** 16+ (Audit Store cluster mode)
- **Ollama:** 0.1.20+ (Local LLM runtime)

### Ferramentas de Desenvolvimento
- **golangci-lint:** 1.55+ (linting)
- **golang-migrate:** 4.17+ (database migrations)
- **go-fuzz:** Latest (fuzzing)
- **valgrind:** 3.22+ (memory leak detection)

---

**Legenda:**
- ✅ **Completo e Testado**
- 🔄 **Em Progresso**
- ⏳ **Pendente**
- 🔴 **Bloqueado**

**Última Atualização:** 2026-03-12 (Revisão Soberana v2)  
**Responsável:** Headmaster Orquestrador de IA  
**Próxima Revisão:** Sprint 2.5 Planning (Event Bus & Audit Store)

---

**MANIFESTO DE SOBERANIA TECNOLÓGICA:**

✊ **Agnosticismo Total** — Nenhum vendor lock-in  
🛡️ **Offline-First** — Ollama garante operação sem internet  
⚡ **High Performance** — Event Bus para cargas extremas  
📊 **Auditoria Completa** — Compliance e forensics nativos  
🌍 **Multi-Provider** — Escolha o melhor LLM para cada caso  

**"O scanner que não pertence a ninguém, pertence a todos."**
