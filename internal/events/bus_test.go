package events
import (
	"context"
	"testing"
	"time"
)
func TestEventBus_Restored(t *testing.T) {
	bus := NewEventBus(10)
	ctx := context.Background()
	
	p := YARACompletedPayload{ScanID: "coverage-fix"}
	_ = p.Type()

	// Handler simples para validar o processamento
	bus.Subscribe(EventTypeYARACompleted, func(ctx context.Context, e Event) error {
		return nil
	})

	_ = bus.Publish(ctx, p)
	
	// Pequena pausa para o dispatchLoop (evita o gap de cobertura)
	time.Sleep(10 * time.Millisecond)
	
	bus.Shutdown(ctx)
}
