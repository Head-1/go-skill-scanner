package events

import (
	"context" // Adicionado
	"time"
	"github.com/Head-1/go-skill-scanner/pkg/schema"
)

type EventType string

const (
	EventTypeScanRequested EventType = "scan.requested"
	EventTypeScanCompleted EventType = "scan.completed"
)

type Event interface {
	Type() EventType
}

type EventBus interface {
	Publish(ctx context.Context, event Event) error
	Subscribe(eventType EventType, handler Handler)
	Shutdown(ctx context.Context) error
}

type ScanRequested struct {
	ScanID    string    `json:"scan_id"`
	Path      string    `json:"path"`
	Timestamp time.Time `json:"timestamp"`
}

func (e ScanRequested) Type() EventType { return EventTypeScanRequested }

type ScanCompleted struct {
	ScanID   string             `json:"scan_id"`
	Path     string             `json:"path"`
	Result   *schema.ScanResult `json:"result"`
	Duration time.Duration      `json:"duration"`
}

func (e ScanCompleted) Type() EventType { return EventTypeScanCompleted }
