package mcp

import (
	"testing"

	"github.com/Head-1/go-skill-scanner/internal/engine"
	"github.com/Head-1/go-skill-scanner/internal/events"
	"github.com/Head-1/go-skill-scanner/internal/yara"
	"github.com/rs/zerolog"
)

func TestNewServer(t *testing.T) {
	logger := zerolog.New(nil)
	bus := events.NewEventBus(5)
	
	// 1. Preparar Scanner Real
	realScanner, err := yara.New(logger)
	if err != nil {
		t.Fatalf("Erro ao carregar Scanner: %v", err)
	}
	defer realScanner.Close()

	// 2. Preparar Engine Real
	var eCfg engine.Config
	eng, err := engine.New(eCfg, logger, realScanner, bus)
	if err != nil {
		t.Fatalf("Erro ao criar Engine: %v", err)
	}
	
	// 3. Preparar Config do MCP
	// Como o erro indicou que NewServer quer 'Config' (do próprio pacote mcp)
	var mcpCfg Config 
	// Se o campo de endereço for 'Addr', podemos tentar: mcpCfg.Addr = ":8081"
	// Mas como vamos apenas testar a criação, a struct zerada deve bastar.

	// 4. Teste de Inicialização (Seguindo a ordem do 'want' no erro)
	// want (Config, yara.Scanner, *engine.Engine, zerolog.Logger)
	srv := NewServer(mcpCfg, realScanner, eng, logger)

	if srv == nil {
		t.Fatal("Falha ao instanciar o servidor MCP: retornou nil")
	}

	t.Log("Servidor MCP GSS orquestrado com sucesso.")
}
