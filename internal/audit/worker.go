package audit

import (
    "context"

    "github.com/Head-1/go-skill-scanner/internal/events"
    "github.com/Head-1/go-skill-scanner/pkg/schema"
    "github.com/rs/zerolog"
)

// AuditStore define o contrato para persistência imutável (SQLite + HCA).
// Inclui tanto o armazenamento de resultados de scan (SaveResult) quanto
// o armazenamento de registros arbitrários (StoreRecord), que será usado
// pelo MCP server para gravar OS, traces e outros eventos.
type AuditStore interface {
    SaveResult(ctx context.Context, res *schema.ScanResult) error
    GetLastHash() (string, error)
    StoreRecord(ctx context.Context, recordType string, payload interface{}, scanID string) error
}

// Worker escuta o barramento de eventos e processa a custódia forense
// para eventos do tipo ScanCompleted. Ele usa apenas SaveResult.
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

// Start inicia a escuta de eventos de forma tipada e eficiente
func (w *Worker) Start(ctx context.Context) {
    w.log.Info().Msg("⚖️ Audit Worker: Operacional (Modo Direto)")

    handler := func(hCtx context.Context, ev events.Event) error {
        payload := ev.Payload()
        res, ok := payload.(*schema.ScanResult)
        if !ok {
            w.log.Trace().Msg("Audit ignorou evento: payload não é *schema.ScanResult")
            return nil
        }

        if err := w.store.SaveResult(hCtx, res); err != nil {
            w.log.Error().Err(err).
                Str("scan_id", res.ScanID).
                Msg("❌ FALHA NA CUSTÓDIA: Integridade em risco")
            return err
        }

        w.log.Debug().
            Str("scan_id", res.ScanID).
            Msg("✅ Evidência HCA selada no Mimir")
        return nil
    }

    w.bus.Subscribe(events.ScanCompleted, handler)
}
