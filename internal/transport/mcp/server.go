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

type Config struct {
	Addr string
}

type MCPServer struct {
	engine  *engine.Engine
	scanner yara.Scanner
	logger  zerolog.Logger
	server  *server.MCPServer
}

func NewServer(cfg Config, scanner yara.Scanner, eng *engine.Engine, logger zerolog.Logger) *MCPServer {
	s := server.NewMCPServer("go-skill-scanner", "1.0.0", server.WithLogging())
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
		mcp.WithDescription("Analisa um payload em busca de intenções maliciosas"),
	)

	tool.InputSchema = mcp.ToolInputSchema{
		Type: "object",
		Properties: map[string]interface{}{
			"payload": map[string]interface{}{
				"type":        "string",
				"description": "Conteúdo bruto do script ou comando a ser analisado",
			},
		},
		Required: []string{"payload"},
	}

	s.server.AddTool(tool, s.handleScan)
}

func (s *MCPServer) handleScan(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args, ok := request.Params.Arguments.(map[string]interface{})
	if !ok {
		return mcp.NewToolResultError("argumentos inválidos"), nil
	}

	payload, ok := args["payload"].(string)
	if !ok {
		return mcp.NewToolResultError("argumento 'payload' é obrigatório e deve ser string"), nil
	}

	res, err := s.engine.ScanFile(ctx, engine.ScanRequest{
		Name:    "mcp_inline_scan",
		Payload: []byte(payload),
	})
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Erro no motor: %v", err)), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf("Veredito: %s | ID: %s | Risk: %.2f",
		res.Verdict.Status, res.ScanID, res.RiskScore)), nil
}

func (s *MCPServer) Start() error {
	s.logger.Info().Msg("🚀 Servidor MCP Operacional via STDIO")
	return server.ServeStdio(s.server)
}
