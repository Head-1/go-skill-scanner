// internal/yara/metrics.go
package yara

import (
    "sync"
    "sync/atomic"
    "time"
)

// metrics gerencia contadores thread-safe para observabilidade do scanner.
type metrics struct {
    scansTotal        uint64
    scansBytesTotal   uint64
    scansMatchesTotal uint64
    scansErrorsTotal  uint64

    scanDurationSum uint64
    scanDurationCnt uint64

    ruleCount  int
    bundleHash string

    closed     atomic.Bool
    lastScanAt int64
}

func newMetrics(ruleCount int, bundleHash string) *metrics {
    return &metrics{
        ruleCount:  ruleCount,
        bundleHash: bundleHash,
    }
}

func (m *metrics) recordScan(payloadSize int, matchCount int, duration time.Duration, err error) {
    atomic.AddUint64(&m.scansTotal, 1)
    atomic.AddUint64(&m.scansBytesTotal, uint64(payloadSize))
    atomic.AddUint64(&m.scansMatchesTotal, uint64(matchCount))
    atomic.StoreInt64(&m.lastScanAt, time.Now().Unix())

    if err != nil {
        atomic.AddUint64(&m.scansErrorsTotal, 1)
    }

    atomic.AddUint64(&m.scanDurationSum, uint64(duration.Nanoseconds()))
    atomic.AddUint64(&m.scanDurationCnt, 1)
}

func (m *metrics) snapshot() ScanStatistics {
    total := atomic.LoadUint64(&m.scansTotal)
    bytes := atomic.LoadUint64(&m.scansBytesTotal)
    matches := atomic.LoadUint64(&m.scansMatchesTotal)
    errors := atomic.LoadUint64(&m.scansErrorsTotal)

    durationSum := atomic.LoadUint64(&m.scanDurationSum)
    durationCnt := atomic.LoadUint64(&m.scanDurationCnt)

    var avgMs float64
    if durationCnt > 0 {
        avgNs := float64(durationSum) / float64(durationCnt)
        avgMs = avgNs / 1_000_000
    }

    return ScanStatistics{
        TotalScans:        int64(total),
        TotalBytesScanned: int64(bytes),
        TotalMatches:      int64(matches),
        TotalErrors:       int64(errors),
        AvgScanDurationMs: avgMs,
        TotalDuration:     time.Duration(durationSum),
        LastScanAt:        time.Unix(atomic.LoadInt64(&m.lastScanAt), 0),
    }
}

func (m *metrics) isClosed() bool {
    return m.closed.Load()
}

func (m *metrics) markClosed() {
    m.closed.Store(true)
}

// scanGuard para graceful shutdown
type scanGuard struct {
    wg sync.WaitGroup
}

func (g *scanGuard) enter() { g.wg.Add(1) }
func (g *scanGuard) leave() { g.wg.Done() }
func (g *scanGuard) wait()  { g.wg.Wait() }
