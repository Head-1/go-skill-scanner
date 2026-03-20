package audit

import (
	"context"
	"github.com/Head-1/go-skill-scanner/internal/events"
	"github.com/rs/zerolog"
)

type Worker struct {
	bus   *events.EventBus
	store AuditStore
	log   zerolog.Logger
}

func NewWorker(bus *events.EventBus, store AuditStore, log zerolog.Logger) *Worker {
	return &Worker{
		bus:   bus,
		store: store,
		log:   log.With().Str("component", "audit-worker").Logger(),
	}
}

func (w *Worker) Start(ctx context.Context) {
	w.log.Info().Msg("⚖️ Audit Worker: Iniciando custódia forense HCA...")

	// Inscrição no tópico de conclusão
	sub := w.bus.Subscribe(events.TopicScanCompleted)

	go func() {
		for {
			select {
			case <-ctx.Done():
				w.log.Warn().Msg("🛑 Audit Worker: Sinal de encerramento recebido. Drenando eventos...")
				return
			case event := <-sub:
				// Cast para o resultado e gravação
				if res, ok := event.Payload.(*schema.ScanResult); ok {
					if err := w.store.SaveResult(ctx, res); err != nil {
						w.log.Error().Err(err).Str("scan_id", res.ScanID).Msg("❌ FALHA NA CUSTÓDIA FORENSE")
					} else {
						w.log.Debug().Str("scan_id", res.ScanID).Msg("✅ Evidência imutável gravada")
					}
				}
			}
		}
	}()
}
