package engine

import (
    "context"
    "fmt"
    "os"
    "time"

    "github.com/google/uuid"
    "github.com/rs/zerolog"

    "github.com/Head-1/go-skill-scanner/internal/events"
    "github.com/Head-1/go-skill-scanner/internal/yara"
    "github.com/Head-1/go-skill-scanner/pkg/schema"
)

// Config holds engine configuration
type Config struct {
    Debug bool
}

// Engine orchestrates the scanning pipeline
type Engine struct {
    cfg      Config
    log      zerolog.Logger
    yara     yara.Scanner
    eventBus events.EventBus // Agora é a INTERFACE, não ponteiro para struct
}

// New creates a new Engine instance - recebe a INTERFACE EventBus
func New(cfg Config, log zerolog.Logger, yaraScanner yara.Scanner, eventBus events.EventBus) (*Engine, error) {
    return &Engine{
        cfg:      cfg,
        log:      log.With().Str("component", "engine").Logger(),
        yara:     yaraScanner,
        eventBus: eventBus,
    }, nil
}

// AsyncScan dispatches a scan task to the worker pool via event bus
func (e *Engine) AsyncScan(ctx context.Context, path string) (string, error) {
    scanID := uuid.New().String()

    // Verificação correta para interface
    if e.eventBus == nil {
        return "", fmt.Errorf("event bus not initialized")
    }

    event := events.ScanRequested{
        Path:      path,
        Timestamp: time.Now(),
        RequestID: scanID,
    }

    if err := e.eventBus.Publish(ctx, event); err != nil {
        e.log.Error().
            Err(err).
            Str("scan_id", scanID).
            Msg("failed to publish scan event")
        return "", fmt.Errorf("publish failed: %w", err)
    }

    e.log.Info().
        Str("scan_id", scanID).
        Str("path", path).
        Msg("scan dispatched to worker pool")
    
    return scanID, nil
}

// ScanFile performs the actual scan (called by workers)
func (e *Engine) ScanFile(ctx context.Context, path string) (*schema.ScanResult, error) {
    startTime := time.Now()
    scanID := uuid.New().String()

    // Read file
    payload, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("failed to read file: %w", err)
    }

    // Execute YARA scan
    yaraFindings, yaraErr := e.yara.Scan(ctx, payload)
    yaraDuration := time.Since(startTime)

    // Build trace
    trace := schema.LayerTrace{
        Status:     schema.LayerPass,
        DurationNs: yaraDuration.Nanoseconds(),
    }

    if yaraErr != nil {
        trace.Status = schema.LayerError
        trace.Error = yaraErr.Error()
    } else if len(yaraFindings) > 0 {
        trace.Status = schema.LayerFail
    }

    // Build result
    result := &schema.ScanResult{
        ScanID:    scanID,
        ScannedAt: startTime,
        Findings:  yaraFindings,
        Pipeline: schema.PipelineTrace{
            YARA: trace,
        },
    }

    e.log.Debug().
        Str("scan_id", scanID).
        Str("path", path).
        Dur("duration", yaraDuration).
        Int("findings", len(yaraFindings)).
        Msg("file scan completed")

    return result, nil
}

// Close releases engine resources
func (e *Engine) Close() error {
    e.log.Info().Msg("shutting down engine")
    if e.yara != nil {
        return e.yara.Close()
    }
    return nil
}
