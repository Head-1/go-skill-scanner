**MEMORANDO TÉCNICO DE FUNDAÇÃO — FASE 01 (REFATORADO E ATUALIZADO)**

**PARA:** Desenvolvedores e Mantenedores
**DE:** Headmaster Orquestrador de IA
**PROJETO:** `go-skill-scanner` (Daemon de Segurança Soberano)
**DATA DE REVISÃO:** 17 de Março de 2026
**AMBIENTE:** Ubuntu Server 24.04 LTS | Go 1.25+ | Docker 29.3.0+
**STATUS:** ✅ FUNDAÇÃO CONSOLIDADA, TESTADA E DOCUMENTADA

---

## 1. RESUMO EXECUTIVO (INCEPTION)

O projeto `go-skill-scanner` (GSS) nasceu da necessidade de criar um daemon de segurança de código soberano, ultrarrápido e isolado. Projetado para rodar em ambientes Linux restritos e de Edge AI (como VMs Ubuntu Server e hardwares dedicados como o Jetson Orin Nano), o sistema deve identificar padrões maliciosos em scripts (Python, Bash, Node) antes que eles sejam executados.

**A Diretriz Principal:** Isolamento total e Zero Trust. O scanner não deve ter dependências ou correlações diretas com outros sistemas externos não autorizados, atuando como o executor rigoroso das leis digitais definidas pela governança do SUTA-IA.

## 2. DECISÕES ARQUITETURAIS FUNDACIONAIS

Na Fase 01, estabelecemos os pilares tecnológicos que permitiram o sucesso da compilação e estabilização do daemon.

### 2.1 A Escolha da Linguagem: Go (Golang)
Em vez de Python (comum em segurança, porém lento e consumidor de RAM), optamos pelo Go pelos seguintes motivos táticos:
* **Binário Estático Único:** Facilidade de deploy em qualquer máquina Linux sem necessidade de instalar interpretadores, garantindo uma imagem Docker mínima (~15MB).
* **Performance de Borda:** Tempos de inicialização em milissegundos e consumo de memória altamente otimizado para hardwares com restrição de recursos.
* **Segurança de Tipos e Concorrência:** Tratamento rigoroso de erros nativo e uso de *goroutines* e *channels* para suportar altíssimas cargas de scans paralelos sem bloqueio.

### 2.2 O Motor Base: YARA via CGO (`hillu/go-yara/v4`)
A primeira camada de defesa foi definida como o YARA, o padrão da indústria para correspondência de padrões (Pattern Matching).
* **O Desafio do CGO:** Estabelecemos a necessidade de usar CGO para conectar o código Go à biblioteca C nativa do YARA (`libyara`). Isso ditou a necessidade de flags de compilação rigorosas (`-tags yara_static`) estabelecidas para garantir portabilidade.
* **Soberania de Regras:** O sistema foi desenhado para usar a diretiva `//go:embed` do Go, embutindo as regras YARA diretamente no binário final, eliminando a necessidade de buscar assinaturas na internet em tempo de execução (Air-Gapped Ready).

### 2.3 Arquitetura de Eventos (Event-Driven)
Para transformar o GSS de uma ferramenta CLI simples em um daemon industrial, adotamos uma arquitetura orientada a eventos:
* **Desacoplamento Assíncrono:** A implementação de um *Event Bus* interno e um *Worker Pool* garante que o motor principal não seja bloqueado durante a análise, permitindo enfileirar milhares de pedidos (buffer de 1000 eventos).

### 2.4 Transporte Universal (Model Context Protocol - MCP)
* **Integração Agnóstica:** O GSS expõe suas capacidades de scan nativamente através de um servidor MCP JSON-RPC sobre stdio/HTTP. Isso permite que qualquer IA governante (como o AEGIS no SUTA-IA) utilize o scanner como uma ferramenta segura sem acoplamento de código.

## 3. O MODELO DE TIERING (DEFESA EM PROFUNDIDADE)

A arquitetura foi concebida para não depender de uma única tecnologia. Desenhamos um funil de análise em múltiplos estágios:

1. **Camada 1: YARA (Assinaturas Rápidas - Concluído):** Varre o payload em microssegundos procurando padrões conhecidos (ex: `rm -rf /`, `os.system`). Cobertura de testes blindada (>78%).
2. **Camada 2: AST Analyzer (Árvore Sintática - Próximo Foco):** Se o YARA for evadido por ofuscação (ex: `base64.decode`), o AST desmonta o script para entender sua verdadeira *intenção* estrutural.
3. **Camada 3: LLM/WASM (Heurística Avançada - Futuro):** Para casos ambíguos, um modelo de linguagem local analisa a semântica do código, submetido a rigoroso controle de provedores e custos.

## 4. LIÇÕES APRENDIDAS E PONTOS DE ATENÇÃO (A PONTE PARA A FASE 2)

Durante a estabilização da Fase 1 e Sprint 2.5, desafios críticos arquiteturais foram mapeados e superados:

* **Gerenciamento de Memória C e Segfaults:** Ao acoplar Go com C (YARA), o Go não consegue limpar a memória alocada pelo C automaticamente. Falhas catastróficas de segmentação (SIGSEGV) foram mitigadas exigindo o método `Close()` em todos os motores via `defer` e implementando flags atômicas (`isClosed`) para impedir acessos a ponteiros destruídos.
* **Import Cycles e Interfaces:** A separação estrita de pacotes (`engine` vs `events`) gerou ciclos de importação. Isso consolidou a adoção do *Dependency Inversion Principle*, forçando o uso de interfaces locais (ex: `ScanExecutor`) para manter a soberania e a modularidade de cada pacote.
* **Supply Chain de Regras:** A ideia inicial de baixar regras externas via script provou-se frágil. A decisão final foi manter a **Curadoria Interna**, escrevendo e embutindo as regras dentro do próprio repositório.
* **Interface do Usuário:** A necessidade de parâmetros escaláveis levou à adoção da biblioteca Cobra CLI, abandonando argumentos simples em favor de um padrão industrial com suporte a *Graceful Shutdown* via interrupções de contexto.

## 5. ESTADO ATUAL DA ÁRVORE DE DIRETÓRIOS (MARÇO/2026)

O scaffolding inicial evoluiu para uma estrutura funcional e validada:

```text
go-skill-scanner/
├── cmd/scanner/          # (Implementado: main.go com CLI Cobra)
├── internal/
│   ├── engine/           # (Implementado: Orquestrador Assíncrono - engine.go)
│   ├── yara/             # (Implementado: Wrapper CGO, metrics.go, scanner_test.go)
│   ├── events/           # (Implementado: Event Bus, Worker Pool, Pipeline Async)
│   ├── transport/mcp/    # (Implementado: JSON-RPC Server & Handler)
│   ├── ast/              # (Pendente: analisador de árvore sintática)
│   └── audit/            # (Pendente: persistência forense SQLite)
├── internal/yara/rules/  # (Implementado: Regras embutidas via go:embed)
├── pkg/schema/           # (Implementado: scan_result.go e contratos)
├── build/                # (Implementado: Dockerfile multi-stage estático)
├── configs/              # (Implementado: default_manifest.json)
└── go.mod                # (Configurado e Pinado)
```

---
**Assinatura Digital:**
By: Headmaster     
CTO Integrador & Arquiteto de Sistemas Críticos  
Projeto: go-skill-scanner
Documento Fundacional V2
