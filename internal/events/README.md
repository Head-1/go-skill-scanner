# Módulo de Eventos (Event Bus)

**Status:** Sprint 2.5 - Em implementação
**Propósito:** Orquestração assíncrona entre os motores de scan (YARA, AST, LLM).
**Tecnologia:** Go Channels, sync.Pool, Generics.

## Fluxo de Dados
YARA_SCAN -> [Event Bus] -> AST_ANALYZER (Sub)
                         -> AUDIT_STORE (Sub)
                         -> METRICS (Sub)
