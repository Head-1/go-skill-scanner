# Memorando 07: Unificação de Tiers e Arquitetura de Mensageria Persistente

**Data:** 19/03/2026 | **Versão:** 2.1 | **Status:** Concluído

## 1. Visão Geral
A Fase 07 introduziu uma arquitetura de mensageria persistente utilizando SQLite, garantindo que nenhum pedido de scan seja perdido em caso de falha do processo. Essa camada de resiliência é fundamental para operações críticas onde a rastreabilidade e a integridade dos dados são exigidas.

## 2. Benefícios da Abordagem
- **Resiliência**: Pedidos são armazenados em disco antes do processamento, permitindo recuperação após reinicialização.
- **Backpressure**: A fila pode acumular requisições sem sobrecarregar os workers, proporcionando controle de fluxo.
- **Auditoria**: Resultados são registados de forma imutável para consulta futura, atendendo requisitos de compliance.

## 3. Componentes
- **Queue Manager**: Gerencia a fila de scans pendentes e os registros de auditoria, utilizando SQLite como backend.
- **Workers**: Consomem a fila e processam os scans (YARA, AST, LLM) de forma concorrente e segura.
- **Índices e transações**: Garantem performance e atomicidade nas operações.

## 4. Implementação Técnica
O driver `modernc.org/sqlite` foi escolhido por ser uma implementação puramente em Go, eliminando a necessidade de CGO adicional e mantendo o binário estático. As tabelas são criadas com índices apropriados para consultas eficientes:

- `scan_queue`: armazena pedidos pendentes com status (`PENDING`, `PROCESSING`, `FAILED`) e contador de retentativas.
- `audit_logs`: guarda os resultados finais dos scans, com carimbo de tempo.

Métodos como `Dequeue`, `MarkDone` e `RetryPending` garantem a correta gestão do ciclo de vida dos scans.

## 5. Conclusão
Esta arquitetura eleva o go‑skill‑scanner ao nível de um daemon industrial, capaz de operar em ambientes adversos sem perda de dados. A escolha por SQLite puro Go assegura portabilidade e simplicidade de deploy.
