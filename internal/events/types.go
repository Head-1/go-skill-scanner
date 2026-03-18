	package events

import (
    "time"

    "github.com/Head-1/go-skill-scanner/pkg/schema"
)

// ScanRequested representa um pedido de scan
type ScanRequested struct {
    Path      string
    Timestamp time.Time
    RequestID string
}

func (e ScanRequested) Type() EventType { return EventTypeScanRequested }

// ScanCompleted representa o resultado do scan
type ScanCompleted struct {
    Result    *schema.ScanResult
    Path      string
    Duration  time.Duration
    RequestID string
}

func (e ScanCompleted) Type() EventType { return EventTypeScanCompleted }
