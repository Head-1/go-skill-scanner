package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Head-1/go-skill-scanner/internal/engine"
	"github.com/Head-1/go-skill-scanner/internal/yara"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// Version and build metadata (injected via -ldflags).
var (
	version   = "dev"
	buildTime = "unknown"
	commit    = "unknown"
)

func main() {
	// Initialize pretty console logging
	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
	})

	// Execute root command
	if err := rootCmd.Execute(); err != nil {
		log.Fatal().Err(err).Msg("Command execution failed")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Cobra CLI Structure
// ─────────────────────────────────────────────────────────────────────────────

var rootCmd = &cobra.Command{
	Use:   "scanner",
	Short: "🛡️  GO-SKILL-SCANNER — Production-Grade Malware Detection for Claude Skills",
	Long: `
╔═══════════════════════════════════════════════════════════════╗
║   GO-SKILL-SCANNER — Multi-Tier Security Analysis Engine     ║
║   Built for: NPCAIA-Daemon Ecosystem                          ║
╚═══════════════════════════════════════════════════════════════╝

Analysis Pipeline:
  1. YARA → Static pattern matching (Cisco TALOS rules)
  2. AST  → Structural code analysis
  3. LLM  → Probabilistic threat assessment (optional)
  4. Wasm → Behavioral sandbox (optional)

For detailed documentation, visit:
  https://github.com/Head-1/go-skill-scanner
`,
	Version: fmt.Sprintf("%s (built: %s, commit: %s)", version, buildTime, commit),
}

var scanCmd = &cobra.Command{
	Use:   "scan [file or directory]",
	Short: "Scan a file or directory for malicious patterns",
	Long: `
Scan executes the full analysis pipeline on the target payload.

Examples:
  # Scan a single file
  scanner scan suspicious_skill.py

  # Scan with custom timeout
  scanner scan --timeout 10s payload.js

  # Scan from stdin
  cat skill.sh | scanner scan -
`,
	Args: cobra.ExactArgs(1),
	Run:  runScan,
}

var (
	// Scan command flags
	scanTimeout   time.Duration
	enableLLM     bool
	enableWasm    bool
	verboseOutput bool
)

func init() {
	// Add subcommands
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(versionCmd)

	// Scan flags
	scanCmd.Flags().DurationVar(&scanTimeout, "timeout", 30*time.Second, "Maximum scan duration")
	scanCmd.Flags().BoolVar(&enableLLM, "llm", false, "Enable LLM analysis tier (requires backend)")
	scanCmd.Flags().BoolVar(&enableWasm, "wasm", false, "Enable Wasm sandbox tier")
	scanCmd.Flags().BoolVarP(&verboseOutput, "verbose", "v", false, "Verbose output (show all findings)")

	// Global flags
	rootCmd.PersistentFlags().Bool("json", false, "Output in JSON format")
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("go-skill-scanner %s\n", version)
		fmt.Printf("  Built:  %s\n", buildTime)
		fmt.Printf("  Commit: %s\n", commit)
	},
}

// ─────────────────────────────────────────────────────────────────────────────
// Scan Command Implementation
// ─────────────────────────────────────────────────────────────────────────────

func runScan(cmd *cobra.Command, args []string) {
	targetPath := args[0]

	log.Info().
		Str("version", version).
		Str("target", targetPath).
		Msg("🛡️  GO-SKILL-SCANNER STARTING")

	// ── 1. Initialize YARA Scanner ─────────────────────────────────────────
	log.Info().Msg("Initializing YARA engine...")
	yaraScanner, err := yara.New(log.Logger)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize YARA scanner")
	}

	log.Info().
		Int("rules_loaded", yaraScanner.RuleCount()).
		Str("bundle_hash", yaraScanner.BundleHash()[:16]+"...").
		Msg("YARA engine ready")

	// ── 2. Initialize Engine ───────────────────────────────────────────────
	cfg := engine.DefaultConfig()
	cfg.EnableLLM = enableLLM
	cfg.EnableWasm = enableWasm

	scanEngine, err := engine.New(
		cfg,
		log.Logger,
		yaraScanner,
		engine.NewNoopAST(),      // Stub: AST not yet implemented
		engine.NewNoopCache(),    // Stub: Cache not yet implemented
		engine.NewNoopManifest(), // Stub: Manifest validation not yet implemented
		nil, // LLM: disabled by default
		nil, // Wasm: disabled by default
		nil, // SecurityProbe: uses noop default
	)
	if err != nil {
		yaraScanner.Close()
		log.Fatal().Err(err).Msg("Failed to initialize engine")
	}

	// CRITICAL: Ensure engine.Close() is called on exit
	defer func() {
		log.Info().Msg("Shutting down engine...")
		if err := scanEngine.Close(); err != nil {
			log.Error().Err(err).Msg("Engine shutdown failed")
		} else {
			log.Info().Msg("Engine shutdown complete")
		}

		// Print YARA scanner statistics
		printYARAStats(scanEngine.YARAStats())
	}()

	// ── 3. Setup Signal Handling for Graceful Shutdown ────────────────────
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Warn().
			Str("signal", sig.String()).
			Msg("Shutdown signal received — initiating graceful shutdown")
		cancel()
	}()

	// ── 4. Load Target Payload ─────────────────────────────────────────────
	var payload []byte
	if targetPath == "-" {
		// Read from stdin
		log.Info().Msg("Reading payload from stdin...")
		payload, err = os.ReadFile("/dev/stdin")
	} else {
		// Read from file
		log.Info().Str("file", targetPath).Msg("Loading target file...")
		payload, err = os.ReadFile(targetPath)
	}

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to read target payload")
	}

	log.Info().Int("bytes", len(payload)).Msg("Payload loaded")

	// ── 5. Execute Scan ────────────────────────────────────────────────────
	scanCtx, scanCancel := context.WithTimeout(ctx, scanTimeout)
	defer scanCancel()

	req := engine.ScanRequest{
		Name:     targetPath,
		Payload:  payload,
		CallerID: "cli-user",
	}

	log.Info().Msg("🚀 Starting scan...")
	startTime := time.Now()

	result, err := scanEngine.Scan(scanCtx, req)
	if err != nil {
		if err == context.Canceled {
			log.Warn().Msg("Scan canceled by user")
			os.Exit(130) // 128 + SIGINT
		}
		if err == context.DeadlineExceeded {
			log.Error().Msg("Scan timeout exceeded")
			os.Exit(1)
		}
		log.Fatal().Err(err).Msg("Scan failed")
	}

	duration := time.Since(startTime)

	// ── 6. Display Results ─────────────────────────────────────────────────
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println("                    SCAN RESULTS")
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Printf("Target:       %s\n", result.Target.Name)
	fmt.Printf("SHA-256:      %s\n", result.Target.SHA256)
	fmt.Printf("Size:         %d bytes\n", result.Target.SizeBytes)
	fmt.Printf("Language:     %s\n", result.Target.Language)
	fmt.Printf("Scan ID:      %s\n", result.ScanID)
	fmt.Printf("Duration:     %v\n", duration)
	fmt.Println("───────────────────────────────────────────────────────────")

	// Verdict
	verdictIcon := getVerdictIcon(string(result.Verdict.Status))
	fmt.Printf("VERDICT:      %s %s\n", verdictIcon, result.Verdict.Status)
	fmt.Printf("Risk Score:   %.2f / 1.00\n", result.RiskScore)
	fmt.Printf("Confidence:   %.2f%%\n", result.Verdict.Confidence*100)
	fmt.Printf("Decided By:   %s\n", result.Verdict.DecidedBy)
	fmt.Println()
	fmt.Printf("Summary:      %s\n", result.Verdict.Summary)
	fmt.Println("═══════════════════════════════════════════════════════════")

	// Findings
	if len(result.Findings) > 0 {
		fmt.Println()
		fmt.Printf("FINDINGS: %d issue(s) detected\n", len(result.Findings))
		fmt.Println("───────────────────────────────────────────────────────────")

		for _, f := range result.Findings {
			severityIcon := getSeverityIcon(string(f.Severity))
			fmt.Printf("\n[%s] %s %s\n", f.ID, severityIcon, f.Severity)
			fmt.Printf("    Source:      %s\n", f.Source)
			fmt.Printf("    Category:    %s\n", f.Category)
			if f.RuleID != "" {
				fmt.Printf("    Rule:        %s\n", f.RuleID)
			}
			fmt.Printf("    Description: %s\n", f.Description)
			if verboseOutput && f.Evidence != "" {
				fmt.Printf("    Evidence:    %s\n", f.Evidence)
			}
		}
		fmt.Println()
	} else {
		fmt.Println()
		fmt.Println("✅ No threats detected — payload is clean")
		fmt.Println()
	}

	// Pipeline trace
	if verboseOutput {
		fmt.Println("═══════════════════════════════════════════════════════════")
		fmt.Println("                 PIPELINE TRACE")
		fmt.Println("═══════════════════════════════════════════════════════════")
		printLayerTrace("YARA", result.Pipeline.YARA)
		printLayerTrace("AST", result.Pipeline.AST)
		if result.Pipeline.LLM != nil {
			printLayerTrace("LLM", *result.Pipeline.LLM)
		}
		if result.Pipeline.Wasm != nil {
			printLayerTrace("Wasm", *result.Pipeline.Wasm)
		}
		fmt.Println()
	}

	// Exit with appropriate code
	switch result.Verdict.Status {
	case "CLEAN":
		os.Exit(0)
	case "SUSPECT":
		os.Exit(2)
	case "MALICIOUS":
		os.Exit(1)
	default:
		os.Exit(3)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Display Helpers
// ─────────────────────────────────────────────────────────────────────────────

func getVerdictIcon(status string) string {
	switch status {
	case "CLEAN":
		return "✅"
	case "SUSPECT":
		return "⚠️"
	case "MALICIOUS":
		return "🔴"
	default:
		return "❓"
	}
}

func getSeverityIcon(severity string) string {
	switch severity {
	case "CRITICAL":
		return "🔴"
	case "HIGH":
		return "🟠"
	case "MEDIUM":
		return "🟡"
	case "LOW":
		return "🔵"
	case "INFO":
		return "ℹ️"
	default:
		return "❓"
	}
}

func printLayerTrace(name string, trace interface{}) {
	// Type assertion to access LayerTrace fields
	// This is a simplified version - adjust based on actual schema.LayerTrace structure
	fmt.Printf("%s Layer:\n", name)
	fmt.Printf("  Status: %v\n", trace)
	fmt.Println()
}

func printYARAStats(stats yara.ScanStatistics) {
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println("              YARA SCANNER STATISTICS")
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Printf("Total Scans:        %d\n", stats.TotalScans)
	fmt.Printf("Total Bytes:        %d (%.2f MB)\n",
		stats.TotalBytesScanned,
		float64(stats.TotalBytesScanned)/1024/1024)
	fmt.Printf("Total Matches:      %d\n", stats.TotalMatches)
	fmt.Printf("Total Errors:       %d\n", stats.TotalErrors)
	fmt.Printf("Avg Scan Duration:  %.2f ms\n", stats.AvgScanDurationMs)

	if stats.TotalScans > 0 {
		errorRate := float64(stats.TotalErrors) / float64(stats.TotalScans) * 100
		fmt.Printf("Error Rate:         %.2f%%\n", errorRate)
	}
	fmt.Println("═══════════════════════════════════════════════════════════")
}
