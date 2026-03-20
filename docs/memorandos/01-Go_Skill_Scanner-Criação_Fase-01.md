# MEMORANDO TÉCNICO DE FUNDAÇÃO — FASE 01

**PARA:** Desenvolvedores e Mantenedores do `go-skill-scanner`
**DE:** Headmaster Orquestrador de IA
**PROJETO:** `go-skill-scanner` (GSS) – Daemon de Segurança Soberano
**DATA DA CRIAÇÃO INICIAL:** 2026-03-12
**ÚLTIMA REVISÃO:** 2026-03-19
**STATUS:** ✅ FUNDAÇÃO CONSOLIDADA, TESTADA E DOCUMENTADA

---

## 1. RESUMO EXECUTIVO (INCEPTION)

O **go-skill-scanner** nasceu da necessidade de criar um motor de segurança de código aberto, soberano e ultrarrápido, capaz de analisar scripts e “skills” de IA (Python, Bash, etc.) em busca de comportamentos maliciosos. Diferentemente de ferramentas puramente baseadas em assinaturas, o GSS foi concebido com uma arquitetura em camadas (tiering) que combina análise estática de alta velocidade (YARA) com análise sintática (AST) e, futuramente, com heurística via LLMs locais.

A diretriz principal desde o início foi o **isolamento total e zero trust**: o scanner não deve depender de chamadas de rede externas em tempo de execução, e todo o conhecimento (regras) deve estar embutido no binário, permitindo operação em ambientes **air-gapped** e com a máxima performance.

---

## 2. DECISÕES ARQUITETURAIS FUNDACIONAIS

### 2.1 A Escolha da Linguagem: Go (Golang)
A opção pelo Go em vez de Python foi baseada em critérios rigorosos de engenharia:

- **Binário estático único:** facilita deploy em qualquer Linux (incluindo containers mínimos), sem dependências de interpretador.
- **Performance de borda:** inicialização em milissegundos e baixo consumo de memória – crucial para dispositivos como Jetson Nano.
- **Segurança de tipos e concorrência nativa:** tratamento de erros explícito, ausência de exceções, e suporte a *goroutines* para processamento paralelo eficiente.
- **Ecossistema maduro para CGO:** necessário para integrar bibliotecas C críticas (YARA).

### 2.2 O Motor Base: YARA via CGO (`github.com/hillu/go-yara/v4`)
O YARA é o padrão da indústria para correspondência de padrões em binários e texto. A decisão de usá-lo como primeira camada (Tier 1) trouxe desafios:

- **CGO obrigatório:** a ligação com a biblioteca C `libyara` exige flags de compilação específicas (`-tags yara_static`) e cuidados com gerenciamento de memória.
- **Soberania de regras:** optamos por embutir as regras no binário via `//go:embed`, eliminando a necessidade de acesso externo para carregar assinaturas.

### 2.3 Estrutura de Diretórios (Standard Go Layout)
Adotamos o layout padrão da comunidade Go para garantir escalabilidade e clareza:

.
├── cmd/ # Pontos de entrada (binários)
│ └── scanner/ # CLI principal
├── internal/ # Código privado (não importável por outros módulos)
│ ├── engine/ # Orquestrador dos tiers de análise
│ ├── yara/ # Módulo YARA (CGO, métricas, stubs)
│ ├── ast/ # (planejado) Analisador sintático
│ ├── cache/ # (planejado) Sistema de reputação
│ ├── audit/ # (planejado) Persistência forense
│ ├── transport/ # Camada de comunicação (MCP, CLI)
│ └── events/ # Barramento assíncrono (Worker Pool)
├── pkg/ # Código público reutilizável
│ └── schema/ # Contratos de dados (ScanResult, Finding...)
├── build/ # Artefatos de build (Dockerfile, scripts)
├── configs/ # Arquivos de configuração exemplo
└── docs/ # Documentação e memorandos

### 2.4 Modelo de Defesa em Profundidade (Tiering)
O sistema foi projetado com múltiplas camadas de análise, cada uma com responsabilidades distintas:

| Camada | Responsabilidade | Status |
|--------|------------------|--------|
| **Tier 1 (YARA)** | Correspondência rápida de padrões (assinaturas). | ✅ Concluído |
| **Tier 2 (AST)** | Análise sintática para detectar ofuscação e lógica perigosa. | 🔄 Em progresso |
| **Tier 3 (LLM/WASM)** | Heurística avançada e sandboxing (futuro). | ⏳ Pendente |

### 2.5 Arquitetura de Eventos e Concorrência
Para tornar o GSS um daemon escalável, implementamos um **barramento de eventos assíncrono**:

- **Event Bus:** canal de comunicação desacoplado entre componentes.
- **Worker Pool:** processa scans em paralelo, respeitando limites de recursos.
- **Graceful Shutdown:** captura de sinais (`SIGINT`, `SIGTERM`) com `signal.NotifyContext` para encerramento limpo, garantindo que o método `Close()` do motor YARA seja chamado antes da saída.

---

## 3. FUNDAMENTAÇÃO TÉCNICA DAS ESCOLHAS

### 3.1 Por que YARA (e não apenas expressões regulares)?
YARA permite:
- **Contexto de strings:** busca por padrões em diferentes partes do payload.
- **Módulos:** possibilidade de estender com lógica adicional (ex: módulo `pe` para executáveis).
- **Compilação e otimização:** as regras são compiladas uma única vez e reutilizadas em todos os scans.

### 3.2 Gerenciamento de Memória em CGO
A integração com C via CGO é a maior fonte de riscos em sistemas Go. As medidas adotadas foram:

- **Lifecycle management explícito:** método `Close()` obrigatório que libera recursos C (destrói regras, fecha handles).
- **Flag atômica `isClosed`:** para impedir novos scans após o fechamento.
- **`sync.WaitGroup` no `guard`:** aguarda conclusão de scans ativos antes de destruir recursos.
- **Idempotência:** `Close()` pode ser chamado múltiplas vezes com segurança.

### 3.3 Observabilidade (Métricas)
Implementamos contadores lock-free com `sync/atomic` para:
- `TotalScans`, `TotalBytesScanned`, `TotalMatches`, `TotalErrors`, `AvgScanDurationMs`.
- Essas métricas são exportáveis via `ScanStats()` e podem ser integradas futuramente com Prometheus.

---

## 4. LIÇÕES APRENDIDAS E ADAPTAÇÕES

### 4.1 A Armadilha da Cadeia de Suprimentos de Regras
Inicialmente, tentamos baixar regras da Cisco via `curl` em um script `bootstrap.sh`. Isso se mostrou frágil: URLs mudam, e arquivos inválidos (ex: página 404) quebravam a compilação do YARA.

**Solução definitiva:** curadoria interna e `go:embed`. Todas as regras agora residem em `internal/yara/rules/` e são embutidas no binário. Isso garante reprodutibilidade e funcionamento em ambientes sem acesso à internet.

### 4.2 A Importância do `Close()` e da Flag Atômica
Durante os primeiros testes, esquecemos de chamar `Close()` em alguns caminhos, o que levou a vazamentos de memória (detectados por `valgrind`). Implementamos então:

- `defer engine.Close()` no `main.go`.
- Verificação `if s.metrics.isClosed()` no início de `Scan()`.

### 4.3 Ciclos de Importação e Interfaces
No início, o pacote `engine` importava `events` e vice-versa, criando um ciclo. Resolvemos com **injeção de dependência** e interfaces locais: o `engine` agora define interfaces como `ScanExecutor` que são implementadas por outros pacotes, mas não os importa diretamente.

---

## 5. ESTADO ATUAL DO PROJETO (PÓS-SPRINT 1)

- ✅ Módulo YARA completo, testado e integrado.
- ✅ CLI profissional com Cobra, signal handling e graceful shutdown.
- ✅ Event Bus e Worker Pool funcionais (testados com concorrência).
- ✅ Saída rica com ícones, estatísticas e códigos de saída semânticos (0=clean, 1=malicious, 2=suspect, 3=error).
- ✅ Binário estático com regras embutidas, pronto para deploy em containers.

---

**Próximos Passos (Sprint 2):**
- Implementar AST Analyzer (Tier 2).
- Implementar Cache de Reputação (TLSH + SQLite).
- Expandir cobertura de testes e documentação.

---

**Assinatura Digital:**
Headmaster Orquestrador IA
Arquiteto de Sistemas Críticos
go-skill-scanner
2026-03-19
