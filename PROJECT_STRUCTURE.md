.
├── bin
│   └── gss-daemon
├── bootstrap.sh
├── build
│   └── Dockerfile
├── cmd
├── configs
│   └── default_manifest.json
├── coverage_full.out
├── coverage.out
├── docker-compose.integration.yml
├── docs
│   ├── architecture
│   │   ├── ENGINE_MAIN_REFACTORING.md
│   │   └── PROJECT_STRUCTURE.md
│   ├── CHECKLIST_OFICIAL.md
│   ├── examples
│   │   └── yara_integration.go
│   ├── memorandos
│   │   ├── 01-Go_Skill_Scanner-Criação_Fase-01.md
│   │   ├── 02-YARA_Refactoring_Fase-2.md
│   │   ├── 03-Engine_Main_Memo_Fase-03.md
│   │   └── 04-Event_Bus+Async_Pipeline-V4-Fase-04.md
│   └── README.md
├── go.mod
├── go.sum
├── internal
│   ├── analyzer
│   │   └── ast
│   ├── ast
│   ├── audit
│   ├── cache
│   ├── engine
│   │   ├── engine.go
│   │   └── engine_test.go
│   ├── events
│   │   ├── bus.go
│   │   ├── bus_test.go
│   │   ├── README.md
│   │   ├── types.go
│   │   └── worker.go
│   ├── llm
│   ├── manifest
│   ├── privacy
│   ├── sandbox
│   ├── transport
│   │   ├── cli
│   │   └── mcp
│   │       ├── handler.go
│   │       ├── handler_test.go
│   │       ├── server.go
│   │       ├── server_test.go
│   │       └── types.go
│   └── yara
│       ├── metrics.go
│       ├── README.md
│       ├── rules
│       │   ├── capabilities
│       │   │   └── system_access.yar
│       │   ├── cisco_official
│       │   │   └── cisco_official.yar
│       │   ├── core
│       │   │   ├── network_risk.yar
│       │   │   └── system_risk.yar
│       │   ├── custom
│       │   ├── malicious
│       │   │   └── patterns.yar
│       │   └── test
│       │       └── test_coverage.yar
│       ├── scanner.go
│       ├── scanner_stub.go
│       ├── scanner_test.go
│       └── yara.go
├── LICENSE
├── Makefile
├── pkg
│   └── schema
│       └── scan_result.go
├── PROJECT_STRUCTURE.md
├── README.md
├── scripts
│   └── test_mcp_integration.sh
├── test_malicious.py
└── test_payload.py

35 directories, 50 files
