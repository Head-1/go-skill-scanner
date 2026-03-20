Projeto: go‑skill‑scanner (GSS)
Daemon de Segurança Soberano para Análise de Skills de IA
Data: 19 de Março de 2026
Versão: 1.0 (Documento de Consolidação)
Autor: Headmaster (Arquiteto e Orquestrador)
Colaboração: CTO Integrador / Lead Tech

1. SUMÁRIO EXECUTIVO
O go‑skill‑scanner (GSS) é um motor de segurança independente, de alto desempenho, escrito em Go, que analisa scripts e “skills” de IA em busca de comportamentos maliciosos. Inspirado no Cisco AI Skill Scanner, foi totalmente refatorado para operar como um binário estático, ultrarrápido e soberano, capaz de ser invocado via CLI ou integrado a qualquer ecossistema de agentes através do Model Context Protocol (MCP).

Este memorando documenta toda a jornada de criação do sistema: desde a concepção da arquitetura, passando pelas inúmeras iterações de desenvolvimento, os desafios técnicos enfrentados (especialmente com CGO e tipagem forte), as soluções adotadas, os testes de cobertura e o estado atual do projeto. O objetivo é servir como um guia completo para qualquer desenvolvedor que precise entender, manter ou evoluir o GSS.

2. HISTÓRICO E MOTIVAÇÃO
O projeto nasceu da necessidade de um scanner de segurança leve, portátil e com alta performance para executar em ambientes de borda (edge) e ser facilmente acoplado a orquestradores de IA (como o AEGIS no ecossistema SUTA‑IA). A escolha pelo Go se deu por sua capacidade de gerar binários estáticos, sua eficiência em concorrência e sua segurança de tipos.

A base foi o Cisco AI Skill Scanner, originalmente em Python, que já fornecia um bom conjunto de regras YARA e uma lógica de detecção multi‑camadas. A refatoração para Go não foi uma simples tradução, mas uma reestruturação completa para atender aos princípios de Zero Trust, isolamento e rastreabilidade forense.

3. PRINCÍPIOS ARQUITETURAIS
Soberania e Independência: O GSS é um binário único, sem dependências externas em tempo de execução (as regras são embutidas via go:embed). Pode ser executado em qualquer Linux, dentro ou fora de containers.

Defesa em Profundidade (Tiering): A análise é dividida em camadas:

Tier 1 – YARA: correspondência rápida de assinaturas.

Tier 2 – AST: análise sintática para detectar lógica maliciosa ofuscada (em desenvolvimento).

Tier 3 – LLM: heurística avançada via modelos locais (planejado).

Arquitetura Orientada a Eventos: Um barramento interno (EventBus) desacopla os componentes, permitindo processamento assíncrono e escalável.

Comunicação Agnóstica: O GSS expõe suas capacidades via MCP, podendo ser consumido por qualquer cliente que entenda o protocolo (IA, CLI, outros serviços).

Qualidade e Testabilidade: Cobertura de testes rigorosa (acima de 78% atualmente) e tratamento explícito de erros para garantir robustez.

4. ROADMAP DE IMPLEMENTAÇÃO (FASES)
Fase 0 – Fundação e Scaffolding
Decisões iniciais: Adoção do Go 1.22+, estrutura de diretórios seguindo o Standard Go Project Layout.

Criação da base:

cmd/scanner/ – ponto de entrada.

internal/engine/ – orquestrador principal.

internal/yara/ – módulo de integração com YARA.

pkg/schema/ – contratos de dados (ScanResult, Finding, etc.).

Ferramentas de build: Makefile industrial com targets para build, testes e atualização da árvore de diretórios.

Script de bootstrap: inicialmente para baixar regras externas (Cisco), mas posteriormente abandonado em favor de curadoria interna.

Fase 1 – Motor YARA (Tier 1)
Integração CGO: Uso da biblioteca github.com/hillu/go-yara/v4 para ligação com a libyara em C.

Gerenciamento de memória C: Implementação de métodos Close() com sync.WaitGroup e flags atômicas (isClosed) para evitar vazamentos de memória e segfaults.

Embutimento de regras: Utilização de go:embed para incluir os arquivos .yar diretamente no binário, garantindo operação air‑gapped.

Métricas e observabilidade: Criação do pacote metrics com contadores atômicos (lock‑free) para TotalScans, TotalBytesScanned, AvgScanDurationMs, etc.

Testes de unidade e benchmarks: Cobertura inicial do pacote yara atingindo cerca de 78% após vários ajustes.

Desafios superados:

Erro syntax error, unexpected integer number devido a regras corrompidas → solução: curadoria interna e regras de teste próprias.

Ponteiros de interface (*yara.Scanner) causando panics → correção: uso correto da interface sem ponteiros desnecessários.

Métodos GetRulesCount e RuleCount duplicados → unificação na interface.

Fase 2 – Event Bus e Pipeline Assíncrono (Sprint 2.5)
Implementação do internal/events/bus.go:

Barramento baseado em canais Go com buffer configurável.

Assinatura de handlers com Subscribe e publicação não‑bloqueante com timeout (Publish).

sync.RWMutex para proteção dos mapas de handlers.

Graceful shutdown com Shutdown e sync.WaitGroup.

Definição dos eventos canônicos: ScanRequested, YARACompleted, ASTAnalysisRequested.

Integração com o Engine:

O Engine agora recebe um *events.EventBus no construtor.

Após o scan YARA, o método publishYARACompletedEvent é chamado para notificar o barramento.

Desafios superados:

Incompatibilidade de tipos entre o Handler do bus e as funções de teste → solução: uso de structs mock que implementam a interface corretamente.

Deadlocks em testes devido à falta de consumo dos eventos → ajuste nos testes com canais e timeouts.

Fase 3 – Engine e CLI (Cobra)
Refatoração do internal/engine/engine.go:

Método Scan agora recebe um io.Reader e retorna *schema.ScanResult.

Integração com o yara.Scanner (via interface) e com o EventBus.

Cálculo de LayerTrace para cada camada, preparando para futuros tiers.

CLI profissional com Cobra:

Comandos root, scan e version.

Flags como --timeout, --llm, --wasm, --verbose.

Signal handling (SIGINT, SIGTERM) com signal.NotifyContext para graceful shutdown.

Saída rica: formatação com ícones, estatísticas e códigos de saída semânticos (0=clean, 1=malicious, 2=suspect, 3=error).

Fase 4 – Integração MCP (Transporte Agnóstico)
Servidor MCP em internal/transport/mcp/server.go: utilizando o SDK github.com/mark3labs/mcp-go.

Handler de ferramentas (handler.go):

Ferramenta única gss_scan que recebe um payload e retorna o veredito.

Suporte a payloads do tipo string (código) ou file (caminho de arquivo).

Tool Discovery: método tools/list implementado, permitindo que clientes MCP descubram a ferramenta.

Ajustes de versão do SDK: após upgrade para v0.45+, foi necessário refatorar o servidor para usar server.NewMCPServer e o esquema de propriedades com map[string]any.

Cobertura atual do pacote MCP: 71,1%.

Fase 5 – AST Analyzer (Início)
Criação da estrutura de diretórios internal/ast/.

Instalação de gramáticas C para Python e Bash (via tree-sitter).

Implementação inicial de queries para detecção de padrões suspeitos (ex: os.system, eval).

Estado atual: em desenvolvimento, com stubs (noopAST) para não quebrar a compilação.

5. ESTRUTURA DE DIRETÓRIOS (ÁRVORE SINTÉTICA)
text
go-skill-scanner/
├── cmd/
│   └── scanner/               # CLI principal
│       └── main.go
├── internal/
│   ├── ast/                   # Analisador sintático (em andamento)
│   ├── engine/                 # Orquestrador principal
│   │   └── engine.go
│   ├── events/                  # Barramento de eventos
│   │   ├── bus.go
│   │   └── bus_test.go
│   ├── transport/
│   │   └── mcp/                 # Servidor MCP
│   │       ├── handler.go
│   │       ├── server.go
│   │       └── types.go
│   └── yara/                    # Módulo YARA
│       ├── metrics.go
│       ├── scanner.go
│       ├── scanner_stub.go
│       └── scanner_test.go
├── pkg/
│   └── schema/                  # Contratos de dados
│       └── scan_result.go
├── build/
│   └── Dockerfile               # Build multi‑stage com libyara estática
├── configs/
│   └── default_manifest.json    # Exemplo de manifesto
├── docs/
│   ├── memorandos/              # Documentação histórica
│   └── architecture/             # Diagramas e ADRs
├── Makefile
├── go.mod
└── README.md
6. DECISÕES TÉCNICAS E LIÇÕES APRENDIDAS
6.1. CGO e Gerenciamento de Memória C
Problema: a libyara aloca memória que o GC do Go não alcança.

Solução: métodos Close() explícitos, com sync.WaitGroup para aguardar scans ativos e flags atômicas (isClosed) para impedir novos usos.

Lições: nunca confiar apenas no GC; sempre projetar interfaces com lifecycle explícito.

6.2. Tipagem Forte e Interfaces
Problema: múltiplas definições da mesma interface (em interface.go e scanner.go) causavam erros de redeclaração.

Solução: unificar a interface em um único arquivo (scanner.go) e remover o duplicado.

Lições: manter a Single Source of Truth para contratos; evitar fragmentação.

6.3. Testes e Cobertura
Problema: cobertura inicial baixa, especialmente nos caminhos de erro e no pacote events.

Solução: criação de testes dedicados para cada método, incluindo cenários de falha (payload nulo, shutdown, buffer cheio).

Resultado atual: 78,8% de cobertura global, com picos de 86,4% no engine e 81,2% no events.

6.4. Evolução do SDK MCP
Problema: atualização do mcp-go para v0.45+ quebrou o servidor.

Solução: refatoração para usar server.NewMCPServer e ajuste do esquema de propriedades com map[string]any.

Lições: sempre fixar versões de dependências críticas no go.mod ou preparar o código para ser resiliente a mudanças.

6.5. Regras YARA e Supply Chain
Problema: download automático de regras da Cisco (via bootstrap.sh) era frágil (404, arquivos corrompidos).

Solução: abandonar dependência externa e adotar curadoria interna de regras, embutindo-as no binário.

Lições: em sistemas de segurança, controle total sobre as assinaturas é essencial.

7. ESTADO ATUAL E MÉTRICAS
Pacote  Cobertura       Status
internal/engine 86,4%   ✅ Estável
internal/events 81,2%   ✅ Estável
internal/transport/mcp  71,1%   🟡 Melhorias pendentes (mTLS, trace ID)
internal/yara   78,4%   ✅ Estável
Total global    78,8%   🟢 Quase na meta (80%)
Binário gerado: scanner (estático, ~15MB).
Modos de operação: CLI (scan) e servidor MCP (mcp).

8. PRÓXIMOS PASSOS (ROADMAP FUTURO)
Completar o Tier 2 (AST): implementar analisadores para Python e Bash usando tree-sitter, com queries para detecção de ofuscação e lógica maliciosa.

Persistência de Auditoria: criar internal/audit com SQLite para armazenar histórico de scans e alimentar o HCA (Histórico de Conduta do Agente) no ecossistema SUTA‑IA.

Integração com LLMs locais: adicionar suporte a Ollama e outros provedores via interface LLMJudge.

Melhorias no MCP: implementar trace ID obrigatório, mTLS para transporte HTTP e retorno completo do ScanResult em JSON.

Testes de estresse e performance: validar o sistema sob alta carga (múltiplos scans concorrentes).

9. CONCLUSÃO
O go‑skill‑scanner evoluiu de um conceito para um produto de engenharia sólido, com código limpo, cobertura de testes respeitável e uma arquitetura preparada para o futuro. A jornada documentada neste memorando mostra não apenas o que foi construído, mas também as dificuldades enfrentadas e as soluções adotadas – um verdadeiro legado para quem der continuidade ao projeto.

Que este documento sirva como bússola para novos desenvolvedores e como prova da excelência técnica alcançada.

Assinatura:


Headmaster
Arquiteto e Orquestrador
go‑skill‑scanner Project
2026-03-19
