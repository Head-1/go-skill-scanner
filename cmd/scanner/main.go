package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Head-1/go-skill-scanner/internal/ast"
	"github.com/Head-1/go-skill-scanner/internal/audit"
	"github.com/Head-1/go-skill-scanner/internal/engine"
	"github.com/Head-1/go-skill-scanner/internal/events"
	"github.com/Head-1/go-skill-scanner/internal/transport/mcp"
	"github.com/Head-1/go-skill-scanner/internal/yara"
	"github.com/Head-1/go-skill-scanner/pkg/schema"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	debug   bool
	timeout int
	auditDB string
)

var rootCmd = &cobra.Command{
	Use:   "gss",
	Short: "go-skill-scanner - Security scanner for AI agent skills",
}

// scanCmd representa o comando de scan síncrono (CLI)
var scanCmd = &cobra.Command{
	Use:   "scan [file]",
	Short: "Scan a file for malicious patterns",
	Args:  cobra.ExactArgs(1),
	Run:   runScan,
}

// mcpCmd inicia o servidor MCP (modo daemon)
var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Start MCP server (daemon mode)",
	Run:   runMCP,
}

func init() {
	// Flags globais
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "enable debug logging")
	rootCmd.PersistentFlags().IntVarP(&timeout, "timeout", "t", 30, "timeout in seconds")

	// Flag específica do scan
	scanCmd.Flags().StringVar(&auditDB, "audit-db", "", "path to SQLite audit database (if empty, audit is disabled)")
        fmt.Println("DEBUG: audit-db flag registered")

	// Adiciona comandos
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(mcpCmd)
}

func setupLogger() zerolog.Logger {
	level := zerolog.InfoLevel
	if debug {
		level = zerolog.DebugLevel
	}
	zerolog.SetGlobalLevel(level)
	return log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.Kitchen})
}

// runScan executa o scan síncrono (modo CLI)
func runScan(cmd *cobra.Command, args []string) {
	logger := setupLogger()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	// Inicializa YARA
	yaraScanner, err := yara.New(logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to initialize YARA scanner")
	}
	defer yaraScanner.Close()

	// Inicializa AST (pode ser stub por enquanto)
	astAnalyzer := ast.NewAnalyzer(logger)

	// Inicializa audit (se caminho fornecido)
	var auditQueue *audit.QueueManager
	if auditDB != "" {
		auditQueue, err = audit.NewQueueManager(auditDB)
		if err != nil {
			logger.Fatal().Err(err).Str("path", auditDB).Msg("failed to open audit database")
		}
		defer auditQueue.Close()
		logger.Info().Str("path", auditDB).Msg("audit persistence enabled")
	} else {
		logger.Info().Msg("audit disabled (no --audit-db)")
	}

	// Cria engine com audit
	cfg := engine.Config{Debug: debug}
	eng, err := engine.New(cfg, logger, yaraScanner, astAnalyzer, auditQueue)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to create engine")
	}
	defer eng.Close()

	// Lê o arquivo
	payload, err := os.ReadFile(args[0])
	if err != nil {
		logger.Fatal().Err(err).Str("file", args[0]).Msg("failed to read file")
	}

	// Cria a requisição de scan
	req := engine.ScanRequest{
		Name:    args[0],
		Payload: payload,
		CallerID: "cli",
	}

	// Executa o scan
	result, err := eng.ScanFile(ctx, req)
	if err != nil {
		logger.Fatal().Err(err).Msg("scan failed")
	}

	// Exibe o resultado
	displayResult(result)

	// O audit já foi registrado dentro do engine (se habilitado)
}

// runMCP inicia o servidor MCP (modo daemon)
func runMCP(cmd *cobra.Command, args []string) {
	logger := setupLogger()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Inicializa YARA
	yaraScanner, err := yara.New(logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to initialize YARA scanner")
	}
	defer yaraScanner.Close()

	// Inicializa AST
	astAnalyzer := ast.NewAnalyzer(logger)

	// Inicializa audit (se caminho fornecido)
	var auditQueue *audit.QueueManager
	if auditDB != "" {
		auditQueue, err = audit.NewQueueManager(auditDB)
		if err != nil {
			logger.Fatal().Err(err).Str("path", auditDB).Msg("failed to open audit database")
		}
		defer auditQueue.Close()
		logger.Info().Str("path", auditDB).Msg("audit persistence enabled")
	} else {
		logger.Info().Msg("audit disabled (no --audit-db)")
	}

	// Cria engine
	cfg := engine.Config{Debug: debug}
	eng, err := engine.New(cfg, logger, yaraScanner, astAnalyzer, auditQueue)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to create engine")
	}
	defer eng.Close()

        // Cria event bus e worker pool (modo assíncrono)
        bus := events.NewEventBus(1000)
        adapter := &engineAdapter{engine: eng}
        workerPool := events.NewWorkerPool(bus, adapter, 4)


	// Inicia o worker pool
	workerPool.StartWithBus(ctx)

	// Servidor MCP
	srv := mcp.NewServer(mcp.Config{}, yaraScanner, eng, logger)

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		logger.Info().Msg("shutting down...")
		cancel()
                // workerPool.Stop() // não existe
                
	}()

	logger.Info().Msg("MCP server started")
	if err := srv.Start(); err != nil {
		logger.Fatal().Err(err).Msg("MCP server error")
	}
}

// engineAdapter adapta o Engine para implementar events.ScanExecutor
type engineAdapter struct {
	engine *engine.Engine
}

func (a *engineAdapter) ScanFile(ctx context.Context, path string) (*schema.ScanResult, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	req := engine.ScanRequest{
		Name:    path,
		Payload: payload,
		CallerID: "worker",
	}
	return a.engine.ScanFile(ctx, req)
}

func displayResult(res *schema.ScanResult) {
	sep := strings.Repeat("=", 50)
	fmt.Println(sep)
	fmt.Println("📋 SCAN RESULT")
	fmt.Println(sep)
	fmt.Printf("📁 Path:     %s\n", res.Target.Name)
	fmt.Printf("⏱️  Duration: %d µs\n", res.DurationNs/1000)
	fmt.Printf("🔍 Findings: %d\n", len(res.Findings))
	if len(res.Findings) == 0 {
		fmt.Println("\n✅ No threats detected")
	} else {
		fmt.Println("\n🔴 FINDINGS:")
		for i, f := range res.Findings {
			fmt.Printf("  %d. [%s] %s\n", i+1, f.Severity, f.RuleID)
		}
	}
	fmt.Println(sep)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
