# MEMORANDO TÉCNICO: MCP INTEGRATION (v1.0)

**PARA:** Desenvolvedores e Mantenedores do go-skill-scanner (GSS)  
**DE:** Arquiteto de Sistemas  
**PROJETO:** go-skill-scanner  
**CONTEXTO:** Transporte agnóstico para integração com IAs  
**DATA:** 2026-03-19  
**STATUS:** 🟢 OPERACIONAL (Transporte Base e Tool Discovery)

---

## 1. OBJETIVO

O Model Context Protocol (MCP) foi implementado no GSS para atuar como o conduíte de soberania. Ele permite que o scanner funcione como uma ferramenta plug-and-play para qualquer agente de IA, utilizando o padrão JSON‑RPC sobre stdio (e opcionalmente HTTP), sem acoplamento direto de código. Os principais requisitos são:

- Latência de inicialização abaixo de 50ms.
- Isolamento total em contêineres Docker.
- Exposição de uma ferramenta canônica (`gss_scan`) para análise de payloads.

---

## 2. IMPLEMENTAÇÃO REALIZADA

### 2.1 SDK e Protocolo
Adotamos o SDK [`mcp-go`](https://github.com/mark3labs/mcp-go) para garantir conformidade com o protocolo oficial da Anthropic, acelerando o desenvolvimento e reduzindo a superfície de erros.

### 2.2 Servidor de Transporte
O servidor MCP está implementado em `internal/transport/mcp/server.go`. Por padrão, opera em modo stdio (mais seguro para isolamento), mas também suporta o parâmetro `--addr` para comunicação via rede.

### 2.3 Handler de Ferramentas
O arquivo `handler.go` orquestra a ferramenta canônica `gss_scan`. Ela recebe um payload (código a ser analisado) e retorna um veredito estruturado, encapsulando a chamada ao `engine.Scan`.

### 2.4 Qualidade e Cobertura
- O pacote de transporte atingiu **71,1% de cobertura** nos testes.
- Foram blindados erros comuns de Go, como ponteiros nulos de interface, garantindo robustez mesmo sob concorrência.

### 2.5 Tool Discovery
O método `tools/list` do protocolo MCP está implementado, permitindo que qualquer cliente descubra dinamicamente a ferramenta `gss_scan` e seu esquema de entrada.

---

## 3. DÉBITOS TÉCNICOS E PENDÊNCIAS

Embora o encanamento básico esteja funcional, os seguintes itens são necessários para elevar o sistema ao nível de fortaleza digital:

- **Refinamento do Context Sharing:** Atualmente a resposta para a IA é uma string textual. Devemos retornar o JSON completo de `schema.ScanResult`, permitindo decisões baseadas em evidências forenses.
- **Rastreabilidade (Trace ID):** Tornar obrigatório o envio de um `trace_id` (UUID) em cada requisição MCP, para que o Audit Store possa correlacionar eventos com o rastro do YARA.
- **Segurança (mTLS):** Para deploys que utilizam transporte HTTP, implementar Mutual TLS a fim de evitar que agentes impostores se passem por clientes legítimos.
- **Airbags de Borda:** Testar exaustivamente os métodos `isClosed()` e `markClosed()` do ciclo de vida CGO dentro dos handlers MCP, garantindo que uma requisição no momento do desligamento do daemon não cause segmentation fault.

---

## 4. NOTAS DE ARQUITETURA

- **Zero Trust:** O scanner nunca lê arquivos do disco do host via MCP; ele exige que o payload seja enviado diretamente no corpo da requisição, prevenindo ataques de path traversal.
- **Isolamento de Canais:** O logger (`zerolog`) foi configurado para escrever exclusivamente em `os.Stderr` durante o modo MCP, preservando `os.Stdout` para as mensagens JSON‑RPC puras.
- **Agnosticismo:** O GSS não conhece nenhum orquestrador específico na camada MCP. Ele se comunica apenas por meio do protocolo padrão, podendo ser consumido por Claude Desktop, qualquer servidor MCP customizado ou até mesmo scripts simples.

---

**Assinatura:**
Arquiteto de Sistemas
Projeto go-skill-scanner
2026-03-19
