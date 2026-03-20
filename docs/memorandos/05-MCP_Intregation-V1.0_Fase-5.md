📄 MEMORANDO TÉCNICO: HANDOFF — MCP INTEGRATION (v1.0)
PARA: Desenvolvedores e Mantenedores do GSS
DE: Lead Tech & Arquiteto de Sistemas Críticos
PROJETO: go-skill-scanner (GSS)
CONTEXTO: Transporte agnóstico para integração com IAs
STATUS: 🟢 OPERACIONAL (Transporte Base & Discovery)

--------------------------------------------------------------------------------
1. OBJETIVO EXECUTIVO
O MCP foi implementado no GSS para atuar como o conduíte de soberania. Ele permite que o scanner funcione como uma ferramenta plug-and-play para qualquer IA, sem acoplamento direto de código, utilizando o padrão JSON-RPC sobre stdio ou HTTP. O foco é manter a latência de inicialização sub-50ms e o isolamento total em containers Docker
.
2. O QUE FOI REALIZADO (CONQUISTAS DE ELITE)
A Sprint de transporte MCP consolidou os seguintes artefatos industriais:
SDK e Protocolo: Adotamos o SDK mcp-go (mark3labs) para acelerar a conformidade com o protocolo oficial da Anthropic
.
Servidor de Transporte: Implementado em internal/transport/mcp/server.go. Priorizamos o modo stdio por design de isolamento, mas o sistema suporta --addr para chamadas via rede
.
Handler de Ferramentas: O handler.go orquestra a ferramenta canônica gss_scan, que recebe payloads de scripts e retorna vereditos do motor Engine
.
Qualidade e Cobertura: Atingimos 71.1% de cobertura no pacote de transporte. O pipeline foi validado contra "ponteiros nulos de interface", um erro comum em Go que já foi blindado
.
Tool Discovery: A IA já consegue descobrir dinamicamente a capacidade gss_scan via o método tools/list do protocolo
.
3. DÉBITOS TÉCNICOS E PENDÊNCIAS (O BACKLOG SÊNIOR)
Embora o "encanamento" esteja pronto, ainda não atingimos o estado de "Fortaleza Digital". Estes itens são mandatários para a próxima fase:
Refinamento do Context Sharing: Atualmente, o retorno para a IA é uma string de texto simplificada. Precisamos injetar o JSON completo do schema.ScanResult para permitir o Veto Cognitivo baseado em evidências forenses
.
Rastreabilidade (Trace ID): Implementar a obrigatoriedade do trace_id (UUID) em todas as requisições recebidas para garantir que o Audit Store possa correlacionar eventos MCP com o rastro do YARA
.
Segurança (mTLS): Para deploys que utilizam transporte HTTP, a implementação de Mutual TLS é necessária para evitar agentes impostores no ecossistema
.
Airbags de Borda: Os métodos isClosed() e markClosed() do ciclo de vida CGO precisam de testes de estresse dentro dos handlers MCP para garantir que uma requisição no exato momento do shutdown não cause um Segmentation Fault
.
4. NOTAS DE ARQUITETURA (POR QUE É ASSIM?)
Zero Trust: O scanner nunca lê arquivos do disco do host via MCP; ele exige o payload via rastro de contexto. Isso impede ataques de Path Traversal
.
Isolamento de Canais: O logger (zerolog) foi configurado para escrever exclusivamente em os.Stderr durante o modo MCP, preservando o os.Stdout para as mensagens JSON-RPC puras
.
Agnosticismo: O GSS não conhece outros sistemas na camada MCP. Ele fala apenas a língua do protocolo, permitindo que qualquer orquestrador (Claude Desktop, AEGIS, GPT) o utilize.

Assinado,
Lead Tech & Arquiteto de Sistemas Críticos
GSS Sovereign Daemon Project — 2026
Headmaster-Orquestrador
