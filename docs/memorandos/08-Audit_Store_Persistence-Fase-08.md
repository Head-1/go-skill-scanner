# MEMORANDO 08: AUDIT STORE & PERSISTÊNCIA FORENSE

**Data:** 19 de Março de 2026  
**Versão:** 1.0  
**Responsável:** Headmaster  
**Status:** ✅ Concluído  

---

## 1. OBJETIVO

Implementar um sistema de auditoria persistente para o go‑skill‑scanner, garantindo que todos os resultados de scan sejam armazenados de forma imutável e consultável, mesmo após reinicializações do daemon.

---

## 2. ARQUITETURA IMPLEMENTADA
[CLI/MCP] → [Engine.ScanFile] → [QueueManager.LogResult] → [SQLite]
↓ ↓
[schema.ScanResult] [audit_logs]


### 2.1 Componentes Criados

| Componente 		| Arquivo | Responsabilidade 									    |
|-----------------------|-----------------------------|---------------------------------------------------------------------|
| `QueueManager`        | `internal/audit/queue.go`   | Gerencia conexão SQLite, criação de tabelas, inserção de resultados |
| Integração com Engine | `internal/engine/engine.go` | Chama `LogResult` após cada scan, se audit ativo                    |
| Flag `--audit-db`     | `cmd/scanner/main.go`       | Permite ativar persistência via linha de comando                    |

### 2.2 Schema do Banco de Dados

```sql
CREATE TABLE IF NOT EXISTS audit_logs (
    scan_id TEXT PRIMARY KEY,
    verdict TEXT,
    duration_ns INTEGER,
    timestamp DATETIME
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);

- scan_id: UUID gerado pelo engine.
- verdict: CLEAN, SUSPECT ou MALICIOUS.
- duration_ns: tempo total de análise em nanossegundos.
- timestamp: momento da conclusão do scan.

3. DECISÕES TÉCNICAS
3.1 Por que SQLite?

- Binário único: não requer servidor externo.
- Driver puro Go: modernc.org/sqlite elimina dependência CGO, mantendo o binário estático.
- Performance: suficiente para dezenas de milhares de registos.
- Portabilidade: o banco pode ser copiado entre sistemas.

3.2 Por que não usar CGO?

- O YARA já exige CGO; adicionar outra dependência C aumentaria a complexidade de build.
- O driver modernc.org/sqlite é uma implementação puramente em Go da máquina SQLite, garantindo compilação cruzada sem dor de cabeça.

3.3 Estrutura de Tabelas

Optou-se por uma tabela simples (audit_logs) em vez de uma modelagem mais complexa (como separar findings) por dois motivos:

- Simplicidade: o foco era provar o conceito de persistência.
- Extensibilidade: no futuro, podemos adicionar uma tabela audit_findings relacionada por scan_id.

4. INTEGRAÇÃO COM O ENGINE

No método ScanFile, após a construção do schema.ScanResult:

go
if e.audit != nil {
    if err := e.audit.LogResult(res); err != nil {
        e.log.Error().Err(err).Str("scan_id", res.ScanID).Msg("failed to log result to audit")
    }
}
Apenas erros de escrita são registados; o scan nunca falha por causa do audit.

5. USO NA PRÁTICA

5.1 Ativando a auditoria
bash
./scanner scan --audit-db gss.db ./arquivo.py

5.2 Consultando resultados
bash
sqlite3 gss.db "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 10;"

5.3 Exemplo de saída:

scan_id                              | verdict   | duration_ns | timestamp
-------------------------------------+-----------+-------------+--------------------------
550e8400-e29b-41d4-a716-446655440000 | MALICIOUS | 8000955     | 2026-03-19 23:38:58.115

6. TESTES REALIZADOS

Teste	                       Comando	                                Resultado
Scan sem auditoria	./scanner scan ./file.go                 	✅ Banco não criado
Scan com auditoria	./scanner scan --audit-db test.db ./file.go	✅ Banco criado, registo inserido
Consulta SQLite	         sqlite3 test.db "SELECT * FROM audit_logs;"	✅ Dados retornados
Reexecução	         Mesmo comando novamente                	✅ Novo registo inserido

7. LIMITAÇÕES CONHECIDAS

- Não há retenção automática (purge de registos antigos).
- A tabela é única; findings não são persistidos separadamente.
- Não há criptografia em repouso.

Estas limitações podem ser endereçadas em fases futuras (Sprint 5+).

8. PRÓXIMOS PASSOS (SUGESTÃO)

- Enriquecer o TargetInfo com SHA256 e tamanho do arquivo.
- Adicionar índices adicionais (ex: por verdict).
- Implementar retenção (ex: apagar registos com mais de 90 dias).

Criar um comando gss audit query para consultar o histórico sem usar SQLite diretamente.

9. CONCLUSÃO

A Fase 08 estabeleceu uma base sólida para auditoria forense no go‑skill‑scanner. Com a flag --audit-db, 
qualquer scan pode ser persistido, permitindo rastreabilidade completa das análises realizadas.
A escolha do SQLite com driver puro Go mantém o binário leve e a experiência do utilizador simples.

Assinatura Digital:

text
Headmaster Orquestrador
Arquiteto de Sistemas
go‑skill‑scanner
2026-03-19
