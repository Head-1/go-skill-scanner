package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"encoding/json"
	"net/http"

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

var scanCmd = &cobra.Command{
	Use:   "scan [file]",
	Short: "Scan a file for malicious patterns",
	Args:  cobra.ExactArgs(1),
	Run:   runScan,
}

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Start MCP server (daemon mode)",
	Run:   runMCP,
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "enable debug logging")
	rootCmd.PersistentFlags().IntVarP(&timeout, "timeout", "t", 30, "timeout in seconds")
	scanCmd.Flags().StringVar(&auditDB, "audit-db", "", "path to SQLite audit database")
	mcpCmd.Flags().StringVar(&auditDB, "audit-db", "gss.db", "path to SQLite audit database for daemon")

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

func runScan(cmd *cobra.Command, args []string) {
	logger := setupLogger()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Setup YARA Scanner
	yaraScanner, err := yara.New(logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to initialize YARA scanner")
	}
	defer yaraScanner.Close()

	// 2. Setup Engine (apenas com YARA, AST será integrado depois)
	eng, err := engine.New(engine.Config{Debug: debug}, logger, yaraScanner)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to create engine")
	}
	defer eng.Close()

	// 3. Setup Event Bus e Audit Store (opcional)
	bus := events.NewEventBus(1000)
	if auditDB != "" {
		store, err := audit.NewSQLiteStore(auditDB)
		if err != nil {
			logger.Fatal().Err(err).Msg("failed to open audit database")
		}
		auditWorker := audit.NewWorker(bus, store, logger)
		auditWorker.Start(ctx)
	}

	// 4. Executar scan
	payload, err := os.ReadFile(args[0])
	if err != nil {
		logger.Fatal().Err(err).Str("file", args[0]).Msg("failed to read file")
	}

	result, err := eng.ScanFile(ctx, engine.ScanRequest{
		Name:     args[0],
		Payload:  payload,
		CallerID: "cli",
	})
	if err != nil {
		logger.Fatal().Err(err).Msg("scan failed")
	}

	displayResult(result)
	// Pequena pausa para garantir persistência assíncrona
	time.Sleep(300 * time.Millisecond)
}

func runMCP(cmd *cobra.Command, args []string) {
	logger := setupLogger()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Setup YARA Scanner
	yaraScanner, err := yara.New(logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to initialize YARA scanner")
	}
	defer yaraScanner.Close()

	// 2. Setup Engine (apenas com YARA)
	eng, err := engine.New(engine.Config{Debug: debug}, logger, yaraScanner)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to create engine")
	}
	defer eng.Close()

	// 3. Setup Event Bus e Audit Store
	bus := events.NewEventBus(2000)
	if auditDB != "" {
		store, err := audit.NewSQLiteStore(auditDB)
		if err != nil {
			logger.Fatal().Err(err).Msg("failed to open audit database")
		}
		auditWorker := audit.NewWorker(bus, store, logger)
		auditWorker.Start(ctx)
	}

	// 4. Setup MCP Server (passando yaraScanner e engine)
	srv := mcp.NewServer(mcp.Config{}, yaraScanner, eng, logger)

	// 5. Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		logger.Info().Msg("shutting down gracefully...")
		cancel()
	}()

	logger.Info().Msg("MCP server starting...")
	if err := srv.Start(); err != nil {
		logger.Fatal().Err(err).Msg("MCP server error")
	}
}

func displayResult(res *schema.ScanResult) {
	sep := strings.Repeat("=", 50)
	fmt.Println(sep)
	fmt.Println("📋 SCAN RESULT")
	fmt.Println(sep)
	fmt.Printf("📁 Path:      %s\n", res.Target.Name)
	fmt.Printf("⏱️  Duration: %d µs\n", res.DurationNs/1000)
	fmt.Printf("🔍 Findings: %d\n", len(res.Findings))
	if len(res.Findings) == 0 {
		fmt.Println("\n✅ No threats detected")
	} else {
		fmt.Println("\n🔴 FINDINGS DETECTED")
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

// ─── HTTP Server ──────────────────────────────────────────────────────────────

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start HTTP server for GSS scanning (containerized mode)",
	Run:   runServe,
}

func init() {
	serveCmd.Flags().StringVar(&auditDB, "audit-db", "gss.db", "path to SQLite audit database")
	serveCmd.Flags().String("addr", ":9090", "HTTP listen address")
	rootCmd.AddCommand(serveCmd)
}

func runServe(cmd *cobra.Command, args []string) {
	logger := setupLogger()
	addr, _ := cmd.Flags().GetString("addr")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup YARA + Engine (carregados uma vez, reutilizados por todos os requests)
	yaraScanner, err := yara.New(logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to initialize YARA scanner")
	}
	defer yaraScanner.Close()

	eng, err := engine.New(engine.Config{Debug: debug}, logger, yaraScanner)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to create engine")
	}
	defer eng.Close()

	// Audit store opcional
	bus := events.NewEventBus(2000)
	if auditDB != "" {
		store, err := audit.NewSQLiteStore(auditDB)
		if err != nil {
			logger.Fatal().Err(err).Msg("failed to open audit database")
		}
		auditWorker := audit.NewWorker(bus, store, logger)
		auditWorker.Start(ctx)
	}

	// Handler HTTP
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"healthy","service":"gss"}`)
	})

	http.HandleFunc("/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Payload string `json:"payload"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Payload == "" {
			http.Error(w, `{"error":"payload is required"}`, http.StatusBadRequest)
			return
		}

		result, err := eng.ScanFile(r.Context(), engine.ScanRequest{
			Name:     "http_inline_scan",
			Payload:  []byte(req.Payload),
			CallerID: r.Header.Get("X-Agent-ID"),
		})
		if err != nil {
			logger.Error().Err(err).Msg("scan failed")
			http.Error(w, `{"error":"scan failed"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		logger.Info().Msg("shutting down gracefully...")
		cancel()
	}()

	logger.Info().Str("addr", addr).Msg("🚀 GSS HTTP server starting")
	if err := http.ListenAndServe(addr, nil); err != nil {
		logger.Fatal().Err(err).Msg("HTTP server error")
	}
}
