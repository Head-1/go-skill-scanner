package audit

import (
	"context"
	"reflect"

	"github.com/Head-1/go-skill-scanner/internal/events"
	"github.com/Head-1/go-skill-scanner/pkg/schema"
	"github.com/rs/zerolog"
)

type AuditStore interface {
	SaveResult(ctx context.Context, res *schema.ScanResult) error
	GetLastHash() (string, error)
}

type Worker struct {
	bus   events.EventBus
	store AuditStore
	log   zerolog.Logger
}

func NewWorker(bus events.EventBus, store AuditStore, log zerolog.Logger) *Worker {
	return &Worker{
		bus:   bus,
		store: store,
		log:   log.With().Str("component", "audit-worker").Logger(),
	}
}

func (w *Worker) Start(ctx context.Context) {
	w.log.Info().Msg("⚖️ Audit Worker: Operacional")

	// Agora implementamos a assinatura exata exigida pelo seu events.Handler
	h := func(handlerCtx context.Context, ev events.Event) error {
		// Como ev é uma interface genérica, usamos Reflection para procurar
		// o *schema.ScanResult independentemente de como a struct do evento se chama.
		v := reflect.ValueOf(ev)
		
		// Se for um ponteiro, pegamos o valor real
		if v.Kind() == reflect.Ptr {
			v = v.Elem()
		}

		if v.Kind() == reflect.Struct {
			// Varre os campos da struct do evento
			for i := 0; i < v.NumField(); i++ {
				field := v.Field(i)
				// Ignora campos privados e verifica se é o nosso ScanResult
				if field.CanInterface() {
					if res, ok := field.Interface().(*schema.ScanResult); ok {
						err := w.store.SaveResult(handlerCtx, res)
						if err != nil {
							w.log.Error().Err(err).Str("scan_id", res.ScanID).Msg("❌ FALHA NA CUSTÓDIA")
						} else {
							w.log.Debug().Str("scan_id", res.ScanID).Msg("✅ Evidência HCA gravada")
						}
						return err
					}
				}
			}
		}

		w.log.Trace().Msgf("Audit ignorou evento: não contém *schema.ScanResult (Tipo: %T)", ev)
		return nil
	}

	// Forçamos a conversão para events.Handler com a assinatura correta
	w.bus.Subscribe(events.EventType("scan.completed"), events.Handler(h))
}
