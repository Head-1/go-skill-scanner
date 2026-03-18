package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Head-1/go-skill-scanner/internal/engine"
	"github.com/Head-1/go-skill-scanner/internal/events"
	"github.com/Head-1/go-skill-scanner/internal/yara"
	"github.com/rs/zerolog"
)

func TestMCPHandler_Integration(t *testing.T) {
	// 1. Setup do ambiente
	logger := zerolog.New(nil)
	bus := events.NewEventBus(10)
	
	// 2. Instancia o Scanner Real
	realScanner, err := yara.New(logger)
	if err != nil {
		t.Fatalf("Erro ao carregar Scanner YARA real: %v", err)
	}
	defer realScanner.Close()

	// 3. Instancia o Engine Real
	var eCfg engine.Config
	eng, err := engine.New(eCfg, logger, realScanner, bus)
	if err != nil {
		t.Fatalf("Erro ao criar Engine: %v", err)
	}

	// 4. Cria o Handler MCP
	h := NewMCPHandler(realScanner, eng, logger)

	// 5. Simula payload JSON do MCP para uma varredura
	params := map[string]interface{}{
		"name": "gss_scan",
		"arguments": map[string]interface{}{
			"payload":      "dGVzdGU=", // "test" em base64
			"payload_type": "string",
		},
	}
	rawParams, _ := json.Marshal(params)

	// 6. Execução dos fluxos
	ctx := context.Background()
	
	// HandleCallTool devolve (resp, error) - Aqui mantemos os dois
	_, _ = h.HandleCallTool(ctx, rawParams)
	
	// HandleListTools devolve apenas (resp) - CORRIGIDO AQUI
	_ = h.HandleListTools()
}
