.
├── 6.5-Memorando_Único.md
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
│   ├── CHECK_LIST_PROJECT.md
│   ├── examples
│   │   └── yara_integration.go
│   ├── memorandos
│   │   ├── 01-Go_Skill_Scanner-Criação_Fase-01.md
│   │   ├── 02-YARA_Refactoring_Fase-2.md
│   │   ├── 03-Engine_Main_Memo_Fase-03.md
│   │   ├── 04-Event_Bus+Async_Pipeline-V4-Fase-04.md
│   │   ├── 05-MCP_Intregation-V1.0_Fase-5.md
│   │   ├── 06,5-Memorando_Único.md
│   │   ├── 06-MCP+Engine_Evolution-V1.1_Fase6.md
│   │   ├── 07-Tier2_AST+MCP_Stabilization-Fase-07.md
│   │   └── 08-Audit_Store_Persistence-Fase-08.md
│   └── README.md
├── go.mod
├── go.sum
├── gss.db
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
│   │   └── queue.go
│   ├── cache
│   ├── engine
│   │   └── engine.go
│   ├── events
│   │   ├── bus.go
│   │   ├── README.md
│   │   ├── types.go
│   │   └── worker.go
│   ├── llm
│   │   ├── llm.go
│   │   ├── provider.go
│   │   └── providers
│   │       ├── anthropic
│   │       ├── gemini
│   │       ├── ollama
│   │       │   └── client.go
│   │       └── openai
│   ├── manifest
│   ├── privacy
│   ├── sandbox
│   ├── service
│   │   └── watcher.go
│   ├── transport
│   │   ├── cli
│   │   └── mcp
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
├── test_payload.py
└── tests
    └── payloads
        ├── ataque.py
        ├── ataque_v2.py
        ├── test_malicious.py
        └── trigger.py

44 directories, 65 files
