.
├── ataque.py
├── ataque_v2.py
├── bootstrap.sh
├── build
│   └── Dockerfile
├── cmd
│   └── scanner
│       └── main.go
├── configs
│   └── default_manifest.json
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
│   │   ├── 04-Event_Bus+Async_Pipeline-V4-Fase-04.md
│   │   ├── 05-MCP_Intregation-V1.0_Fase-5.md
│   │   ├── 06-MCP+Engine_Evolution-V1.1_Fase6.md
│   │   └── 07-Tier2_AST+MCP_Stabilization-Fase-07.md
│   └── README.md
├── go.mod
├── go.sum
├── internal
│   ├── analyzer
│   │   └── ast
│   ├── archive_tests
│   │   ├── bus_test.go
│   │   └── engine_test.go
│   ├── ast
│   │   ├── analyzer.go
│   │   └── python.go
│   ├── audit
│   ├── cache
│   ├── engine
│   │   └── engine.go
│   ├── events
│   │   ├── bus.go
│   │   ├── README.md
│   │   ├── types.go
│   │   └── worker.go
│   ├── llm
│   ├── manifest
│   ├── privacy
│   ├── sandbox
│   ├── service
│   │   └── watcher.go
│   ├── transport
│   │   ├── cli
│   │   └── mcp
│   │       ├── handler.go.bak
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
│       └── scanner_test.go
├── LICENSE
├── Makefile
├── pkg
│   └── schema
│       └── scan_result.go
├── PROJECT_STRUCTURE.md
├── README.md
├── scanner
├── scripts
│   ├── test_mcp_handshake.sh
│   └── test_mcp_integration.sh
├── test_malicious.py
├── test_payload.py
└── trigger.py

37 directories, 58 files
