package yara

import (
	"sync"
	"sync/atomic"
	"time"
)

// metrics holds Prometheus-compatible counters for scanner observability.
//
// All fields use atomic operations for lock-free increments.
// This struct is embedded in the Scanner to avoid allocation overhead.
type metrics struct {
	// Scan counters
	scansTotal       uint64 // Total Scan() calls
	scansBytesTotal  uint64 // Cumulative payload size
	scansMatchesTotal uint64 // Cumulative rule matches
	scansErrorsTotal uint64 // Total Scan() errors

	// Timing metrics (for rolling average calculation)
	scanDurationSum uint64 // Sum of all scan durations (nanoseconds)
	scanDurationCnt uint64 // Count of timed scans (for average)

	// Rule corpus metadata
	ruleCount  int    // Total compiled rules (immutable after init)
	bundleHash string // SHA-256 of rule corpus (immutable after init)

	// Lifecycle state
	closed atomic.Bool // Set to true after Close()
}

// newMetrics initializes a metrics instance.
func newMetrics(ruleCount int, bundleHash string) *metrics {
	return &metrics{
		ruleCount:  ruleCount,
		bundleHash: bundleHash,
	}
}

// recordScan increments counters after a scan completes.
func (m *metrics) recordScan(payloadSize int, matchCount int, duration time.Duration, err error) {
	atomic.AddUint64(&m.scansTotal, 1)
	atomic.AddUint64(&m.scansBytesTotal, uint64(payloadSize))
	atomic.AddUint64(&m.scansMatchesTotal, uint64(matchCount))

	if err != nil {
		atomic.AddUint64(&m.scansErrorsTotal, 1)
	}

	// Record timing for rolling average
	atomic.AddUint64(&m.scanDurationSum, uint64(duration.Nanoseconds()))
	atomic.AddUint64(&m.scanDurationCnt, 1)
}

// snapshot returns current statistics (implements ScanStats()).
func (m *metrics) snapshot() ScanStatistics {
	total := atomic.LoadUint64(&m.scansTotal)
	bytes := atomic.LoadUint64(&m.scansBytesTotal)
	matches := atomic.LoadUint64(&m.scansMatchesTotal)
	errors := atomic.LoadUint64(&m.scansErrorsTotal)

	// Calculate rolling average scan duration
	durationSum := atomic.LoadUint64(&m.scanDurationSum)
	durationCnt := atomic.LoadUint64(&m.scanDurationCnt)

	var avgMs float64
	if durationCnt > 0 {
		avgNs := float64(durationSum) / float64(durationCnt)
		avgMs = avgNs / 1_000_000 // nanoseconds → milliseconds
	}

	return ScanStatistics{
		TotalScans:        total,
		TotalBytesScanned: bytes,
		TotalMatches:      matches,
		TotalErrors:       errors,
		AvgScanDurationMs: avgMs,
	}
}

// isClosed returns true if Close() has been called.
func (m *metrics) isClosed() bool {
	return m.closed.Load()
}

// markClosed sets the closed flag (idempotent).
func (m *metrics) markClosed() {
	m.closed.Store(true)
}

// ─────────────────────────────────────────────────────────────────────────────
// Prometheus Export Helpers (optional: for integration with prometheus/client_go)
// ─────────────────────────────────────────────────────────────────────────────

// PrometheusLabels returns metric labels for Prometheus registration.
//
// Example usage with prometheus/client_go:
//
//	var (
//		scansTotal = prometheus.NewCounterVec(
//			prometheus.CounterOpts{
//				Name: "yara_scans_total",
//				Help: "Total number of YARA scans performed",
//			},
//			[]string{"result"}, // "match" or "clean"
//		)
//	)
//
//	// After each scan:
//	if len(matches) > 0 {
//		scansTotal.WithLabelValues("match").Inc()
//	} else {
//		scansTotal.WithLabelValues("clean").Inc()
//	}
type PrometheusLabels struct {
	RuleCount  int
	BundleHash string // Truncated to first 16 chars for cardinality control
}

// GetPrometheusLabels returns metadata for metric labels.
func (m *metrics) GetPrometheusLabels() PrometheusLabels {
	hash := m.bundleHash
	if len(hash) > 16 {
		hash = hash[:16]
	}
	return PrometheusLabels{
		RuleCount:  m.ruleCount,
		BundleHash: hash,
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// scanGuard provides wait-group tracking for graceful shutdown.
// ─────────────────────────────────────────────────────────────────────────────

// scanGuard tracks active scans to ensure Close() waits for them.
type scanGuard struct {
	wg sync.WaitGroup
}

// enter increments the active scan counter (call before Scan).
func (g *scanGuard) enter() {
	g.wg.Add(1)
}

// leave decrements the active scan counter (call after Scan via defer).
func (g *scanGuard) leave() {
	g.wg.Done()
}

// wait blocks until all active scans complete (called by Close).
func (g *scanGuard) wait() {
	g.wg.Wait()
}
