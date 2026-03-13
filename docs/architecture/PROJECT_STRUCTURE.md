# Estrutura do Projeto - Go-Skill-Scanner

Gerado em: sex 13 mar 2026 04:35:28 UTC

```
.
├── bootstrap.sh
├── build
│   └── Dockerfile
├── cmd
├── configs
│   └── default_manifest.json
├── docs
│   ├── architecture
│   │   ├── ENGINE_MAIN_REFACTORING.md
│   │   └── PROJECT_STRUCTURE.md
│   ├── CHECKLIST_OFICIAL.md
│   ├── examples
│   │   └── yara_integration.go
│   ├── memorandos
│   │   ├── 01-Go_Skill_Scanner-Criação_Fase-01.md
│   │   └── 02-YARA_Refactoring_Fase-2.md
│   └── README.md
├── go.mod
├── go.sum
├── internal
│   ├── ast
│   ├── audit
│   ├── cache
│   ├── engine
│   │   └── engine.go
│   ├── llm
│   ├── manifest
│   ├── privacy
│   ├── sandbox
│   ├── transport
│   │   ├── cli
│   │   └── mcp
│   └── yara
│       ├── interface.go
│       ├── metrics.go
│       ├── README.md
│       ├── rules
│       │   ├── capabilities
│       │   │   └── system_access.yar
│       │   ├── core
│       │   │   ├── network_risk.yar
│       │   │   └── system_risk.yar
│       │   ├── custom
│       │   └── malicious
│       │       └── patterns.yar
│       ├── scanner.go
│       ├── scanner_stub.go
│       └── scanner_test.go
├── LICENSE
├── Makefile
├── pkg
│   └── schema
│       └── scan_result.go
├── README.md
└── test_payload.py

28 directories, 28 files
```
