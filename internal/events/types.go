package events

import (
	"time"
	"github.com/Head-1/go-skill-scanner/pkg/schema"
)

type EventType string

const (
	ScanRequested EventType = "scan.requested"
	ScanCompleted EventType = "scan.completed"
)

type Event interface {
	Type() EventType
	Payload() interface{}
}

// ScanRequestedEvent - Struct do evento
type ScanRequestedEvent struct {
	ScanID    string    `json:"scan_id"`
	Path      string    `json:"path"`
	Timestamp time.Time `json:"timestamp"`
}

func (e ScanRequestedEvent) Type() EventType     { return ScanRequested }
func (e ScanRequestedEvent) Payload() interface{} { return e.Path }

// ScanCompletedEvent - Struct do evento
type ScanCompletedEvent struct {
	Result *schema.ScanResult
}

func (e ScanCompletedEvent) Type() EventType     { return ScanCompleted }
func (e ScanCompletedEvent) Payload() interface{} { return e.Result }

func NewScanCompletedEvent(res *schema.ScanResult) ScanCompletedEvent {
	return ScanCompletedEvent{Result: res}
}
