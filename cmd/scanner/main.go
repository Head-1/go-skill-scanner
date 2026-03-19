package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/Head-1/go-skill-scanner/internal/ast"
	"github.com/Head-1/go-skill-scanner/internal/engine"
	"github.com/Head-1/go-skill-scanner/internal/transport/mcp"
	"github.com/Head-1/go-skill-scanner/internal/yara"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

var (
	mcpAddr string
	debug   bool
)

var rootCmd = &cobra.Command{
	Use:   "gss-daemon",
	Short: "🛡️ Sovereign Security Daemon for AI Skills",
}

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Inicia o transporte Model Context Protocol",
	Run:   runMCP,
}

func init() {
	mcpCmd.Flags().StringVar(&mcpAddr, "addr", ":8081", "Endereço MCP")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Enable debug mode")
	rootCmd.AddCommand(mcpCmd)
}

func runMCP(cmd *cobra.Command, args []string) {
	log := zerolog.New(os.Stderr).With().Timestamp().Logger()
	if debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	// 1. Inicialização dos Tiers
	yaraScanner, err := yara.New(log)
	if err != nil {
		log.Fatal().Err(err).Msg("Falha no YARA")
	}
	defer yaraScanner.Close()

	astAnalyzer := ast.NewAnalyzer(log)

	// 2. Motor Unificado (YARA + AST)
	eng, _ := engine.New(engine.Config{Debug: debug}, log, yaraScanner, astAnalyzer)

	// 3. Servidor MCP
	srv := mcp.NewServer(mcp.Config{Addr: mcpAddr}, yaraScanner, eng, log)

	// Setup de interrupção (O contexto 'ctx' é usado apenas para logar o encerramento)
	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-sigCtx.Done()
		log.Info().Msg("Shutting down GSS-Daemon...")
	}()

	log.Info().Msg("🔌 Servidor MCP operacional via STDIO")
	if err := srv.Start(); err != nil {
		log.Fatal().Err(err).Msg("Erro no MCP")
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
