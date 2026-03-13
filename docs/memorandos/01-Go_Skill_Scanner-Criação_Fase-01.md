**MEMORANDO TÉCNICO DE FUNDAÇÃO — FASE 01 (REFATORADO)

**PARA:** Desenvolvedores
**DE:** Headmaster Orquestrador de IA
**PROJETO:** `go-skill-scanner` (Refatoração do Cisco Skill Scanner para Go)
**DATA DE REVISÃO:** 12 de Março de 2026
**AMBIENTE:** Ubuntu Server 24.04 LTS | Go 1.25.8 | Docker 29.3.0
**STATUS:** ✅ FUNDAÇÃO CONSOLIDADA E DOCUMENTADA

---

## 1. RESUMO EXECUTIVO (INCEPTION)

O projeto `go-skill-scanner` nasceu da necessidade de criar um daemon de segurança de código soberano, ultrarrápido 
e isolado. Projetado para rodar em ambientes Linux restritos e de Edge AI (como VMs Ubuntu Server e hardwares dedicados), 
o sistema deve identificar padrões maliciosos em scripts (Python, Bash, Node) antes que eles sejam executados.

**A Diretriz Principal:** Isolamento total. O scanner não deve ter dependências ou correlações com 
outros sistemas externos não autorizados.

## 2. DECISÕES ARQUITETURAIS FUNDACIONAIS

Na Fase 01, estabelecemos os pilares tecnológicos que permitiram o sucesso das fases subsequentes.

### 2.1 A Escolha da Linguagem: Go (Golang)
Em vez de Python (comum em segurança, porém lento e consumidor de RAM), optamos pelo Go pelos seguintes motivos táticos:
* **Binário Estático Único:** Facilidade de deploy em qualquer máquina Linux sem necessidade de instalar interpretadores.
* **Performance de Borda:** Tempos de inicialização em milissegundos e consumo de memória na casa dos megabytes.
* **Segurança de Tipos e Concorrência:** Tratamento rigoroso de erros nativo e goroutines para futuros scans paralelos.

### 2.2 O Motor Base: YARA via CGO (`hillu/go-yara/v4`)
A primeira camada de defesa foi definida como o YARA, o padrão da indústria para correspondência de padrões (Pattern Matching).
* **O Desafio do CGO:** Estabelecemos a necessidade de usar CGO para conectar o código Go à biblioteca C nativa do YARA (`libyara`). 
Isso ditou a necessidade de flags de compilação rigorosas (`-tags yara_static`) estabelecidas logo no início.

* **Soberania de Regras:** O sistema foi desenhado para usar a diretiva `//go:embed` do Go, embutindo 
as regras YARA diretamente no binário final, eliminando a necessidade de buscar regras na internet em tempo de execução.

### 2.3 Estrutura de Diretórios (Standard Go Layout)
Adotamos o layout padrão da comunidade Go para garantir escalabilidade:
* `cmd/scanner/`: O ponto de entrada do binário (`main.go`).
* `internal/`: Código privado e soberano da aplicação (motores, regras, lógicas de negócio).
* `internal/yara/rules/`: O "cérebro" das assinaturas, categorizado por `core`, `capabilities` e `malicious`.
* `pkg/`: (Futuro) Schemas e contratos que poderiam ser compartilhados.
* `docs/architecture/`: Repositório central de memorandos e blueprints.

## 3. O MODELO DE TIERING (DEFESA EM PROFUNDIDADE)

A arquitetura foi concebida para não depender de uma única tecnologia. Desenhamos um funil de análise de três estágios:

1. **Camada 1: YARA (Assinaturas Rápidas - Implementado na Fase 1/2):** Varre o código em microssegundos procurando padrões conhecidos (ex: `rm -rf /`, `os.system`).
2. **Camada 2: AST Analyzer (Árvore Sintática - Sprint 2):** Se o YARA for enganado por ofuscação de código, o AST desmonta o script para entender sua verdadeira *intenção* estrutural.
3. **Camada 3: LLM/WASM (Heurística Avançada - Sprint 3):** Para empates ou casos altamente suspeitos (Score > 0.6 e < 0.8), um modelo de linguagem local analisa o contexto.

## 4. LIÇÕES APRENDIDAS E PONTOS DE ATENÇÃO (A PONTE PARA A FASE 2)

Durante a concepção da Fase 1, alguns desafios foram mapeados e resolvidos durante a maturação do sistema (Fase 2):

* **Supply Chain de Regras:** A ideia inicial de baixar regras externas via script (ex: Cisco) provou-se frágil (links quebrados / Erro 404). 
A decisão final da arquitetura foi manter a **Curadoria Interna**, escrevendo e mantendo as regras dentro do repositório (`internal/yara/rules`).

* **Gerenciamento de Memória C:** Ao acoplar Go com C (YARA), o Go não consegue limpar a memória alocada pelo C automaticamente (Garbage Collector). 
A arquitetura precisou ser rigidamente desenhada para exigir o método `Close()` em todos os motores (Lifecycle Management) via `defer`, prevenindo vazamentos letais (Memory Leaks).

* **Interface do Usuário:** A necessidade de parâmetros escaláveis levou à adoção da biblioteca Cobra CLI logo na transição para a Fase 2, 
abandonando lógicas simples de leitura de argumentos em favor de um padrão industrial com Graceful Shutdown (captura de `Ctrl+C`).

## 5.Estado Atual da Árvore de Diretórios

```text
go-skill-scanner/
├── cmd/scanner/          # (Pendente: main.go)
├── internal/
│   ├── engine/           # (Implementado: engine.go)
│   ├── yara/             # (Pendente: scanner.go | Regras Cisco baixadas)
│   ├── ast/              # (Pendente: patterns.go)
│   └── ...               # Outros módulos em scaffolding
├── pkg/schema/           # (Implementado: scan_result.go)
├── build/                # (Implementado: Dockerfile)
├── configs/              # (Implementado: default_manifest.json)
└── go.mod                # (Configurado e Pinado)

---
**Assinatura Digital:**
By: Headmaster     
CTO Integrador & Arquiteto de Sistemas Críticos  
Projeto: go-skill-scanner
Documento Fundacional
