package events

import (
    "context"
    "sync"
    "time"

    "github.com/Head-1/go-skill-scanner/pkg/schema"
    "github.com/rs/zerolog/log"
)

// ScanExecutor define o contrato que o WorkerPool precisa para rodar scans.
type ScanExecutor interface {
    ScanFile(ctx context.Context, path string) (*schema.ScanResult, error)
}

type WorkerPool struct {
    bus       EventBus
    executor  ScanExecutor
    workers   int
    wg        sync.WaitGroup
    shutdown  chan struct{}
    scanQueue chan ScanRequested
}

// NewWorkerPool recebe a INTERFACE EventBus
func NewWorkerPool(bus EventBus, executor ScanExecutor, workers int) *WorkerPool {
    return &WorkerPool{
        bus:       bus,
        executor:  executor,
        workers:   workers,
        shutdown:  make(chan struct{}),
        scanQueue: make(chan ScanRequested, 1000),
    }
}

// StartWithBus inicia o worker pool e se inscreve no barramento para receber eventos
func (wp *WorkerPool) StartWithBus(ctx context.Context) {
    // Inscrever para receber ScanRequested do barramento
    wp.bus.Subscribe(EventTypeScanRequested, func(ctx context.Context, event Event) error {
        if req, ok := event.(ScanRequested); ok {
            log.Debug().
                Str("request_id", req.RequestID).
                Str("path", req.Path).
                Msg("📨 Bus event received, forwarding to queue")
            wp.EnqueueScan(req)
        }
        return nil
    })
    
    // Iniciar os workers
    wp.Start(ctx)
}

// EnqueueScan permite que outros componentes coloquem tarefas na fila
func (wp *WorkerPool) EnqueueScan(req ScanRequested) {
    select {
    case wp.scanQueue <- req:
        log.Debug().
            Str("request_id", req.RequestID).
            Str("path", req.Path).
            Msg("📦 Scan enqueued")
    default:
        log.Warn().
            Str("path", req.Path).
            Msg("⚠️ Scan queue full, dropping request")
    }
}

func (wp *WorkerPool) Start(ctx context.Context) {
    for i := 0; i < wp.workers; i++ {
        wp.wg.Add(1)
        go wp.worker(ctx, i)
    }
    log.Info().
        Int("workers", wp.workers).
        Int("queue_capacity", cap(wp.scanQueue)).
        Msg("🚀 Worker pool started")
}

func (wp *WorkerPool) Stop() {
    log.Info().Msg("🛑 Stopping worker pool...")
    close(wp.shutdown)
    wp.wg.Wait()
    log.Info().Msg("✅ Worker pool stopped")
}

func (wp *WorkerPool) worker(ctx context.Context, id int) {
    defer wp.wg.Done()
    log.Debug().Int("worker_id", id).Msg("👷 Worker started")
    
    for {
        select {
        case <-ctx.Done():
            log.Debug().Int("worker_id", id).Msg("👋 Worker stopping (ctx done)")
            return
        case <-wp.shutdown:
            log.Debug().Int("worker_id", id).Msg("👋 Worker stopping (shutdown)")
            return
        case event := <-wp.scanQueue:
            log.Debug().
                Int("worker_id", id).
                Str("request_id", event.RequestID).
                Str("path", event.Path).
                Msg("📨 Worker received scan request from queue")
            wp.processScan(ctx, id, event)
        }
    }
}

func (wp *WorkerPool) processScan(ctx context.Context, workerID int, event ScanRequested) {
    log.Info().
        Int("worker_id", workerID).
        Str("request_id", event.RequestID).
        Str("path", event.Path).
        Msg("🔍 Starting scan")

    start := time.Now()
    result, err := wp.executor.ScanFile(ctx, event.Path)
    duration := time.Since(start)

    if err != nil {
        log.Error().
            Err(err).
            Int("worker_id", workerID).
            Str("request_id", event.RequestID).
            Str("path", event.Path).
            Msg("❌ Scan failed")
        return
    }

    log.Info().
        Int("worker_id", workerID).
        Str("request_id", event.RequestID).
        Str("path", event.Path).
        Dur("duration", duration).
        Int("findings", len(result.Findings)).
        Msg("✅ Scan completed, publishing result")

    // Publica resultado no barramento
    completedEvent := ScanCompleted{
        Result:    result,
        Path:      event.Path,
        Duration:  duration,
        RequestID: event.RequestID,
    }

    if err := wp.bus.Publish(ctx, completedEvent); err != nil {
        log.Error().
            Err(err).
            Str("request_id", event.RequestID).
            Str("path", event.Path).
            Msg("🔥 Failed to publish scan completed event")
    } else {
        log.Info().
            Str("request_id", event.RequestID).
            Msg("📤 Scan completed event published successfully")
    }
}
