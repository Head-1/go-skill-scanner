package mcp

import (
	"context"
	"fmt"
	"github.com/Head-1/go-skill-scanner/internal/engine"
	"github.com/Head-1/go-skill-scanner/internal/yara"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/rs/zerolog"
)

type Config struct { Addr string }

type MCPServer struct {
	engine  *engine.Engine
	scanner yara.Scanner
	logger  zerolog.Logger
	server  *server.MCPServer
}

func NewServer(cfg Config, scanner yara.Scanner, eng *engine.Engine, logger zerolog.Logger) *MCPServer {
	s := server.NewMCPServer("go-skill-scanner", "1.0.0")
	
	mcpSrv := &MCPServer{
		engine:  eng,
		scanner: scanner,
		logger:  logger.With().Str("component", "mcp-server").Logger(),
		server:  s,
	}
	mcpSrv.registerTools()
	return mcpSrv
}

func (s *MCPServer) registerTools() {
	tool := mcp.NewTool("gss_scan",
		mcp.WithDescription("Analisa um script Python/Bash em busca de intenções maliciosas"),
	)

	// Ajuste para map[string]any para satisfazer o SDK v0.45.0
	tool.InputSchema = mcp.ToolInputSchema{
		Type: "object",
		Properties: map[string]any{
			"payload": map[string]any{
				"type":        "string",
				"description": "Conteúdo bruto do script para análise",
			},
		},
		Required: []string{"payload"},
	}

	s.server.AddTool(tool, s.handleScan)
}

func (s *MCPServer) handleScan(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Type assertion para extrair os argumentos do tipo 'any'
	args, ok := request.Params.Arguments.(map[string]any)
	if !ok {
		return mcp.NewToolResultError("formato de argumentos inválido"), nil
	}

	payload, ok := args["payload"].(string)
	if !ok {
		return mcp.NewToolResultError("argumento 'payload' é obrigatório e deve ser string"), nil
	}

	// Execução via Engine
	res, err := s.engine.ScanFile(ctx, engine.ScanRequest{
		Name:    "mcp_inline_scan",
		Payload: []byte(payload),
	})
	
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Erro no motor GSS: %v", err)), nil
	}

	statusEmoji := "✅"
	if res.Verdict.Status == "MALICIOUS" {
		statusEmoji = "🚨"
	}

	msg := fmt.Sprintf("%s Veredito: %s\nID: %s\nResumo: %s", 
		statusEmoji, res.Verdict.Status, res.ScanID, res.Verdict.Summary)

	return mcp.NewToolResultText(msg), nil
}

func (s *MCPServer) Start() error {
	s.logger.Info().Msg("🔌 GSS-MCP: Pronto para Handshake via STDIO")
	return server.ServeStdio(s.server)
}
