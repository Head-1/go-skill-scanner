package main

import (
    "context"
    "fmt"
    "os"
    "os/signal"
    "strings"
    "syscall"
    "time"

    "github.com/rs/zerolog"
    "github.com/rs/zerolog/log"
    "github.com/spf13/cobra"

    "github.com/Head-1/go-skill-scanner/internal/engine"
    "github.com/Head-1/go-skill-scanner/internal/events"
    "github.com/Head-1/go-skill-scanner/internal/yara"
    "github.com/Head-1/go-skill-scanner/pkg/schema"
)

var (
    debug   bool
    timeout int
)

var rootCmd = &cobra.Command{
    Use:   "scanner",
    Short: "go-skill-scanner - Security scanner for AI agent skills",
}

var versionCmd = &cobra.Command{
    Use:   "version",
    Short: "Print the version number",
    Run: func(cmd *cobra.Command, args []string) {
        fmt.Println("go-skill-scanner v0.1.0")
    },
}

var scanCmd = &cobra.Command{
    Use:   "scan [file]",
    Short: "Scan a file for malicious patterns",
    Args:  cobra.ExactArgs(1),
    Run: func(cmd *cobra.Command, args []string) {
        filePath := args[0]

        // Configurar logger
        zerolog.SetGlobalLevel(zerolog.InfoLevel)
        if debug {
            zerolog.SetGlobalLevel(zerolog.DebugLevel)
        }

        // 1. Inicializar YARA scanner
        yaraScanner, err := yara.NewScanner()
        if err != nil {
            log.Fatal().Err(err).Msg("failed to initialize YARA scanner")
        }
        defer yaraScanner.Close()

        // 2. Criar EventBus
        bus := events.NewEventBus(1000)

        // 3. Inicializar Engine
        engineConfig := engine.Config{
            Debug: debug,
        }
        eng, err := engine.New(engineConfig, log.Logger, yaraScanner, bus)
        if err != nil {
            log.Fatal().Err(err).Msg("failed to initialize engine")
        }
        defer eng.Close()

        // 4. Criar canal para receber o resultado
        resultChan := make(chan *events.ScanCompleted, 1)

        // 5. Subscrever para eventos ScanCompleted
        bus.Subscribe(events.EventTypeScanCompleted, func(ctx context.Context, event events.Event) error {
            log.Debug().Msg("📥 ScanCompleted event received!")
            if scanCompleted, ok := event.(events.ScanCompleted); ok {
                select {
                case resultChan <- &scanCompleted:
                    log.Debug().Msg("✅ Result sent to channel")
                default:
                    log.Warn().Msg("⚠️ Result channel full, dropping event")
                }
            }
            return nil
        })

        // 6. Criar WorkerPool
        workerPool := events.NewWorkerPool(bus, eng, 4)

        // Contexto base
        ctx, cancel := context.WithCancel(context.Background())
        defer cancel()

        // 7. Iniciar worker pool COM INSCRIÇÃO NO BARramento
        workerPool.StartWithBus(ctx) // ← MUDANÇA AQUI

        // Configurar signal handling
        sigChan := make(chan os.Signal, 1)
        signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

        // 8. Disparar scan assíncrono
        scanID, err := eng.AsyncScan(ctx, filePath)
        if err != nil {
            log.Fatal().Err(err).Msg("failed to dispatch scan")
        }

        log.Info().
            Str("scan_id", scanID).
            Int("timeout", timeout).
            Msg("scan dispatched, waiting for completion")

        // 9. Aguardar resultado, sinal OU timeout
        timeoutDuration := time.Duration(timeout) * time.Second
        timeoutTimer := time.NewTimer(timeoutDuration)
        defer timeoutTimer.Stop()

        select {
        case result := <-resultChan:
            timeoutTimer.Stop()
            displayResult(result)

        case <-sigChan:
            log.Info().Msg("interrupted by user, shutting down...")

        case <-timeoutTimer.C:
            log.Warn().
                Int("timeout", timeout).
                Msg("scan timed out, no result received")
        }

        // 10. Shutdown
        log.Info().Msg("shutting down...")
        workerPool.Stop()
        
        shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer shutdownCancel()
        
        if err := bus.Shutdown(shutdownCtx); err != nil {
            log.Error().Err(err).Msg("error shutting down event bus")
        }
    },
}

func displayResult(result *events.ScanCompleted) {
    separator := strings.Repeat("=", 50)
    fmt.Println("\n" + separator)
    fmt.Println("📋 SCAN RESULT")
    fmt.Println(separator)
    fmt.Printf("📁 Path:     %s\n", result.Path)
    fmt.Printf("⏱️  Duration: %v\n", result.Duration)
    fmt.Printf("🔍 Findings: %d\n", len(result.Result.Findings))
    
    if len(result.Result.Findings) > 0 {
        fmt.Println("\n🔴 FINDINGS DETECTED:")
        fmt.Println(strings.Repeat("-", 40))
        for i, finding := range result.Result.Findings {
            severityColor := "🟡"
            switch finding.Severity {
            case schema.SeverityCritical, schema.SeverityHigh:
                severityColor = "🔴"
            case schema.SeverityMedium:
                severityColor = "🟠"
            case schema.SeverityLow:
                severityColor = "🟡"
            default:
                severityColor = "⚪"
            }
            
            fmt.Printf("%s  %d. [%s] %s\n", 
                severityColor, 
                i+1, 
                finding.Severity, 
                finding.RuleID)
            
            if finding.Description != "" {
                fmt.Printf("      📝 %s\n", finding.Description)
            }
        }
    } else {
        fmt.Println("\n✅ No malicious patterns detected - file appears clean")
    }
    
    if yaraStats := result.Result.Pipeline.YARA; yaraStats.DurationNs > 0 {
        fmt.Printf("\n📊 YARA Analysis: %dms\n", yaraStats.DurationNs/1_000_000)
        fmt.Printf("   Status: %s\n", yaraStats.Status)
    }
    
    fmt.Println(strings.Repeat("=", 50))
}

func init() {
    scanCmd.Flags().BoolVarP(&debug, "debug", "d", false, "enable debug logging")
    scanCmd.Flags().IntVarP(&timeout, "timeout", "t", 30, "timeout in seconds (default: 30)")
    rootCmd.AddCommand(scanCmd)
    rootCmd.AddCommand(versionCmd)
}

func main() {
    if err := rootCmd.Execute(); err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
}
