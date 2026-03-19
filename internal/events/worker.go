package events

import (
	"context"
	"sync"
	// "time" removido pois não estava sendo usado nesta versão
	"github.com/Head-1/go-skill-scanner/pkg/schema"
	"github.com/rs/zerolog/log"
)

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

func NewWorkerPool(bus EventBus, executor ScanExecutor, workers int) *WorkerPool {
	return &WorkerPool{
		bus:       bus,
		executor:  executor,
		workers:   workers,
		shutdown:  make(chan struct{}),
		scanQueue: make(chan ScanRequested, 1000),
	}
}

func (wp *WorkerPool) StartWithBus(ctx context.Context) {
	wp.bus.Subscribe(EventTypeScanRequested, func(ctx context.Context, event Event) error {
		if req, ok := event.(ScanRequested); ok {
			wp.scanQueue <- req
			return nil
		}
		return nil
	})

	for i := 0; i < wp.workers; i++ {
		wp.wg.Add(1)
		go wp.worker(ctx, i)
	}
}

func (wp *WorkerPool) worker(ctx context.Context, id int) {
	defer wp.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-wp.shutdown:
			return
		case event := <-wp.scanQueue:
			wp.processScan(ctx, id, event)
		}
	}
}

func (wp *WorkerPool) processScan(ctx context.Context, workerID int, event ScanRequested) {
	log.Info().Int("worker", workerID).Str("scan_id", event.ScanID).Msg("🚀 Processando scan")

	result, err := wp.executor.ScanFile(ctx, event.Path)
	if err != nil {
		log.Error().Err(err).Str("scan_id", event.ScanID).Msg("❌ Erro no processamento")
		return
	}

	_ = wp.bus.Publish(ctx, ScanCompleted{
		ScanID: event.ScanID,
		Path:   event.Path,
		Result: result,
	})
}
