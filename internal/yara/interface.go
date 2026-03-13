// Package yara provides malware detection capabilities using YARA rules.
//
// This package implements a thread-safe, production-grade YARA scanner with:
//   - Embedded rule corpus (no external files at runtime)
//   - Context-aware scanning with timeout enforcement
//   - Prometheus metrics integration
//   - Graceful resource lifecycle management
//   - Build-time validation (stub vs full implementation)
//
// Architecture:
//   The Scanner implements engine.YARAScanner interface and serves as Tier 1
//   in the security pipeline: YARA → AST → LLM.
//
// Build Tags:
//   - yara_static:  Production build, links against libyara.a
//   - yara_dynamic: Development build, links against libyara.so
//   - (none):       Stub implementation for `go test` without CGO
package yara

import (
	"context"
	"io"
)

// Scanner is the interface that all YARA scanner implementations must satisfy.
//
// Implementations:
//   - scanner.go (yara_static/yara_dynamic): Full YARA engine with go-yara v4
//   - scanner_stub.go (default):             No-op stub for testing without CGO
//
// Thread Safety:
//   All methods must be safe for concurrent use by multiple goroutines.
//
// Resource Management:
//   Callers MUST call Close() when done to prevent memory leaks.
//   The underlying YARA engine allocates C memory that Go's GC cannot reclaim.
type Scanner interface {
	// Scan executes all compiled YARA rules against the payload.
	//
	// Returns:
	//   - []string: Names of matched rules (empty slice if clean, never nil)
	//   - error:    Scan failure or context cancellation
	//
	// Context Handling:
	//   The scan respects ctx.Done() and will abort if the context is canceled
	//   or times out. This prevents runaway scans on malicious payloads.
	//
	// Thread Safety:
	//   Safe for concurrent calls. Each scan is isolated.
	//
	// Example:
	//   ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	//   defer cancel()
	//   matches, err := scanner.Scan(ctx, payload)
	//   if err != nil { /* handle */ }
	//   if len(matches) > 0 { /* malware detected */ }
	Scan(ctx context.Context, payload []byte) ([]string, error)

	// RuleCount returns the total number of compiled YARA rules.
	//
	// This is useful for:
	//   - Health checks (0 rules = blind scanner)
	//   - Logging/metrics (rule corpus size tracking)
	//   - Validation after hot-reload (future feature)
	//
	// Thread Safety:
	//   Safe for concurrent calls. Returns a cached value.
	RuleCount() int

	// BundleHash returns the SHA-256 hash of all rule file contents.
	//
	// Properties:
	//   - Deterministic: Same rules → same hash
	//   - Content-based: Different rule text → different hash
	//   - Order-independent: Rule file load order doesn't affect hash
	//
	// Use Cases:
	//   - Detecting rule updates in CI/CD
	//   - Cache invalidation keyed on rule version
	//   - Audit trail for compliance (which rule version scanned this?)
	//
	// Format:
	//   64-character hex string (SHA-256)
	//
	// Thread Safety:
	//   Safe for concurrent calls. Returns a cached value.
	BundleHash() string

	// Close releases all resources held by the scanner.
	//
	// CRITICAL:
	//   Failure to call Close() will leak C memory (YARA rules compiled by libyara).
	//   Go's garbage collector CANNOT reclaim this memory.
	//
	// Behavior:
	//   - Idempotent: safe to call multiple times
	//   - After Close(), subsequent Scan() calls will return an error
	//   - Blocks until all in-flight scans complete (graceful shutdown)
	//
	// Usage:
	//   defer scanner.Close()
	//
	// Thread Safety:
	//   Safe to call concurrently with Scan(). Close() will wait for
	//   active scans to finish before destroying YARA resources.
	io.Closer

	// ScanStats returns runtime statistics about scanner usage.
	//
	// Metrics include:
	//   - Total scans performed
	//   - Total bytes scanned
	//   - Total matches found
	//   - Average scan duration
	//
	// Thread Safety:
	//   Safe for concurrent calls. Returns a snapshot.
	//
	// Returns:
	//   ScanStatistics struct with current counters
	ScanStats() ScanStatistics
}

// ScanStatistics holds runtime metrics for observability.
type ScanStatistics struct {
	// TotalScans is the number of Scan() calls completed (success or failure)
	TotalScans uint64

	// TotalBytesScanned is cumulative payload size across all scans
	TotalBytesScanned uint64

	// TotalMatches is cumulative rule matches across all scans
	TotalMatches uint64

	// TotalErrors is the number of Scan() calls that returned an error
	TotalErrors uint64

	// AvgScanDurationMs is the rolling average scan time in milliseconds
	AvgScanDurationMs float64
}
