//go:build !yara_static && !yara_dynamic

// Package yara provides a no-op stub implementation for environments where
// libyara is not available.
//
// Use Cases:
//   - Running `go test ./...` without CGO
//   - Running `go vet` in CI before Docker build stage
//   - Local development without YARA installed
//
// This stub satisfies the Scanner interface but always returns zero matches.
// It exists purely to allow `go build` and `go test` to succeed without
// the C toolchain.
//
// PRODUCTION BUILDS MUST use -tags yara_static (enforced by Dockerfile).
package yara

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"
)

// ─────────────────────────────────────────────────────────────────────────────
// stubScanner implementation
// ─────────────────────────────────────────────────────────────────────────────

// stubScanner is the no-op implementation (no CGO, no libyara).
type stubScanner struct {
	metrics *metrics
	log     zerolog.Logger
}

// New returns a stub scanner and logs a prominent warning.
//
// The stub scanner:
//   - Always returns 0 matches (no malware detection)
//   - Logs every scan attempt with a warning
//   - Tracks basic metrics (scans performed, bytes processed)
//   - Cannot be used in production
func New(log zerolog.Logger) (Scanner, error) {
	log = log.With().Str("component", "yara.Stub").Logger()

	log.Warn().
		Msg("⚠️  YARA STUB ACTIVE — NO MALWARE DETECTION ⚠️")
	log.Warn().
		Msg("Build with -tags yara_static for production use")

	return &stubScanner{
		metrics: newMetrics(0, "stub-no-rules-loaded"),
		log:     log,
	}, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Scanner interface implementation
// ─────────────────────────────────────────────────────────────────────────────

// Scan is a no-op that always returns zero matches.
func (s *stubScanner) Scan(ctx context.Context, payload []byte) ([]string, error) {
	if s.metrics.isClosed() {
		return nil, fmt.Errorf("yara: scanner is closed")
	}

	// Check context
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Log every scan attempt to make it obvious this is the stub
	s.log.Warn().
		Int("payload_size", len(payload)).
		Msg("Stub scanner invoked — no actual YARA scan performed")

	// Record metrics (0 matches)
	s.metrics.recordScan(len(payload), 0, 0, nil)

	return []string{}, nil
}

// RuleCount always returns 0 (no rules loaded).
func (s *stubScanner) RuleCount() int {
	return 0
}

// BundleHash returns a sentinel value indicating this is the stub.
func (s *stubScanner) BundleHash() string {
	return "stub-no-rules-loaded"
}

// ScanStats returns metrics (mostly zeros).
func (s *stubScanner) ScanStats() ScanStatistics {
	return s.metrics.snapshot()
}

// Close is a no-op for the stub (no resources to release).
func (s *stubScanner) Close() error {
	if s.metrics.isClosed() {
		return nil
	}

	s.metrics.markClosed()
	s.log.Info().Msg("Stub scanner closed")
	return nil
}
