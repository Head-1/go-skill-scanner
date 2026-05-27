package events

import (
	"context"
)

// Worker gerencia a execução de tarefas recebidas pelo barramento
type Worker struct {
	bus EventBus
}

func NewWorker(bus EventBus) *Worker {
	return &Worker{bus: bus}
}

func (w *Worker) Start(ctx context.Context) {
	// Inscreve-se usando a constante ScanRequested
	w.bus.Subscribe(ScanRequested, func(ctx context.Context, ev Event) error {
		// Type assertion para a struct ScanRequestedEvent
		if req, ok := ev.(ScanRequestedEvent); ok {
			// Lógica de processamento
			_ = req.Path 
		}
		return nil
	})
}
