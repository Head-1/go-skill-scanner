package engine

import (
	"context"
	"testing"

	"github.com/rs/zerolog"
	"github.com/Head-1/go-skill-scanner/internal/events"
	"github.com/Head-1/go-skill-scanner/internal/yara"
)

func TestEngine_ScanWorkflow(t *testing.T) {
	log := zerolog.Nop()
	ctx := context.Background()

	yaraScanner, err := yara.New(log)
	if err != nil {
		t.Fatalf("Erro ao iniciar YARA: %v", err)
	}
	
	bus := events.NewEventBus(10)
	cfg := Config{Debug: true}
	
	e, err := New(cfg, log, yaraScanner, bus)
	if err != nil {
		t.Fatalf("Erro ao iniciar Engine: %v", err)
	}
	defer e.Close()

	req := ScanRequest{
		Name:     "test_payload.bin",
		Payload:  []byte("GSS_TEST_PAYLOAD_STRICT"),
		CallerID: "test-suite",
	}

	result, err := e.Scan(ctx, req)
	if err != nil {
		t.Fatalf("Engine Scan falhou: %v", err)
	}

	if result.ScanID == "" {
		t.Error("ScanID não foi gerado")
	}
	
	if len(result.Findings) == 0 {
		t.Error("Engine não reportou os achados do YARA")
	}

	// O schema.LayerFail geralmente renderiza como "FAIL" em string
	if string(result.Pipeline.YARA.Status) != "FAIL" {
		t.Errorf("Esperava status FAIL, recebeu: %s", result.Pipeline.YARA.Status)
	}
}
