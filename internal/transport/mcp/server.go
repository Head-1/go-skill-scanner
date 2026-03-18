package mcp

import (
	"github.com/Head-1/go-skill-scanner/internal/engine"
	"github.com/Head-1/go-skill-scanner/internal/yara"
	"github.com/rs/zerolog"
)

type MCPServer struct {
	config  Config
	handler *MCPHandler
	logger  zerolog.Logger
}

// NewServer recebe a interface Scanner diretamente (sem *)
func NewServer(cfg Config, scanner yara.Scanner, eng *engine.Engine, logger zerolog.Logger) *MCPServer {
	return &MCPServer{
		config:  cfg,
		handler: NewMCPHandler(scanner, eng, logger),
		logger:  logger.With().Str("component", "mcp-server").Logger(),
	}
}
