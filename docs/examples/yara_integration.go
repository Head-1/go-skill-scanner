// Package main demonstrates YARA scanner integration with the engine.
//
// This example shows:
//   - Scanner initialization
//   - Error handling
//   - Context management
//   - Metrics collection
//   - Graceful shutdown
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Head-1/go-skill-scanner/internal/yara"
	"github.com/rs/zerolog"
)

func main() {
	// Initialize structured logger
	log := zerolog.New(os.Stderr).
		With().
		Timestamp().
		Str("service", "yara-example").
		Logger()

	// Initialize YARA scanner
	scanner, err := yara.New(log)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize YARA scanner")
	}

	// CRITICAL: Always defer Close() to prevent memory leaks
	defer func() {
		log.Info().Msg("Shutting down scanner...")
		if err := scanner.Close(); err != nil {
			log.Error().Err(err).Msg("Scanner close failed")
		}
	}()

	// Log scanner metadata
	log.Info().
		Int("rules_loaded", scanner.RuleCount()).
		Str("bundle_hash", scanner.BundleHash()[:16]+"...").
		Msg("YARA scanner initialized")

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Example 1: Scan a clean payload
	exampleCleanScan(scanner, log)

	// Example 2: Scan with timeout
	exampleTimeoutScan(scanner, log)

	// Example 3: Concurrent scans
	exampleConcurrentScans(scanner, log)

	// Example 4: Metrics reporting
	exampleMetrics(scanner, log)

	log.Info().Msg("Examples completed. Press Ctrl+C to exit.")
	<-sigChan
}

// exampleCleanScan demonstrates a basic scan of benign content.
func exampleCleanScan(scanner yara.Scanner, log zerolog.Logger) {
	log.Info().Msg("=== Example 1: Clean Payload Scan ===")

	payload := []byte(`
		package main
		
		import "fmt"
		
		func main() {
			fmt.Println("Hello, World!")
		}
	`)

	ctx := context.Background()
	matches, err := scanner.Scan(ctx, payload)
	if err != nil {
		log.Error().Err(err).Msg("Scan failed")
		return
	}

	if len(matches) > 0 {
		log.Warn().Strs("rules", matches).Msg("Malware detected")
	} else {
		log.Info().Msg("✅ Payload is clean")
	}
}

// exampleTimeoutScan demonstrates context timeout handling.
func exampleTimeoutScan(scanner yara.Scanner, log zerolog.Logger) {
	log.Info().Msg("=== Example 2: Scan with Timeout ===")

	// Large payload (1MB of random data)
	payload := make([]byte, 1024*1024)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	// Set a reasonable timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	matches, err := scanner.Scan(ctx, payload)
	duration := time.Since(start)

	if err != nil {
		if err == context.DeadlineExceeded {
			log.Warn().
				Dur("duration", duration).
				Msg("⚠️  Scan timeout exceeded")
		} else {
			log.Error().Err(err).Msg("Scan failed")
		}
		return
	}

	log.Info().
		Int("matches", len(matches)).
		Dur("duration", duration).
		Msg("✅ Scan completed within timeout")
}

// exampleConcurrentScans demonstrates thread-safety.
func exampleConcurrentScans(scanner yara.Scanner, log zerolog.Logger) {
	log.Info().Msg("=== Example 3: Concurrent Scans ===")

	const numWorkers = 10
	const scansPerWorker = 5

	done := make(chan bool, numWorkers)
	errorCount := 0

	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			for j := 0; j < scansPerWorker; j++ {
				payload := []byte(fmt.Sprintf("Worker %d scan %d", workerID, j))
				ctx := context.Background()

				_, err := scanner.Scan(ctx, payload)
				if err != nil {
					log.Error().
						Err(err).
						Int("worker", workerID).
						Int("scan", j).
						Msg("Concurrent scan failed")
					errorCount++
				}
			}
			done <- true
		}(i)
	}

	// Wait for all workers
	for i := 0; i < numWorkers; i++ {
		<-done
	}

	totalScans := numWorkers * scansPerWorker
	log.Info().
		Int("total_scans", totalScans).
		Int("errors", errorCount).
		Msg("✅ Concurrent scans completed")
}

// exampleMetrics demonstrates metrics collection.
func exampleMetrics(scanner yara.Scanner, log zerolog.Logger) {
	log.Info().Msg("=== Example 4: Metrics Reporting ===")

	stats := scanner.ScanStats()

	log.Info().
		Uint64("total_scans", stats.TotalScans).
		Uint64("total_bytes", stats.TotalBytesScanned).
		Uint64("total_matches", stats.TotalMatches).
		Uint64("total_errors", stats.TotalErrors).
		Float64("avg_duration_ms", stats.AvgScanDurationMs).
		Msg("📊 Scanner statistics")

	// Example: Alert if average scan time is too high
	if stats.AvgScanDurationMs > 100 {
		log.Warn().
			Float64("avg_duration_ms", stats.AvgScanDurationMs).
			Msg("⚠️  Average scan time is high — consider optimizing payloads or rules")
	}

	// Example: Alert if error rate is too high
	if stats.TotalScans > 0 {
		errorRate := float64(stats.TotalErrors) / float64(stats.TotalScans) * 100
		if errorRate > 5.0 {
			log.Warn().
				Float64("error_rate_pct", errorRate).
				Msg("⚠️  High error rate detected")
		}
	}
}
