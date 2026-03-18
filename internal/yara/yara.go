// internal/yara/yara.go
package yara

import (
    "context"
    "time"

    "github.com/Head-1/go-skill-scanner/pkg/schema"
)

// Scanner é a interface que todas as implementações devem seguir
type Scanner interface {
    Scan(ctx context.Context, payload []byte) ([]schema.Finding, error)
    Close() error
    RuleCount() int
    BundleHash() string
    ScanStats() ScanStatistics
}

// ScanStatistics contém métricas do scanner
type ScanStatistics struct {
    TotalScans        int64
    TotalBytesScanned int64
    TotalMatches      int64
    TotalErrors       int64
    AvgScanDurationMs float64
    TotalDuration     time.Duration
    LastScanAt        time.Time
}
