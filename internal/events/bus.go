package events

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// EventBus define o contrato para o barramento de eventos.
type EventBus interface {
	Publish(ctx context.Context, event Event) error
	Subscribe(eventType EventType, handler Handler)
	Shutdown(ctx context.Context) error
}

type Handler func(ctx context.Context, event Event) error

type eventBusImpl struct {
	handlers     map[EventType][]Handler
	handlersLock sync.RWMutex
	eventChan    chan Event
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	mu           sync.Mutex
	closed       bool
}

func NewEventBus(bufferSize int) EventBus {
	// Tuning conforme check-list: Buffer mínimo de 2000 para evitar drops
	optimizedBuffer := bufferSize
	if optimizedBuffer < 2000 {
		optimizedBuffer = 2000
	}

	ctx, cancel := context.WithCancel(context.Background())
	eb := &eventBusImpl{
		handlers:  make(map[EventType][]Handler),
		eventChan: make(chan Event, optimizedBuffer),
		ctx:       ctx,
		cancel:    cancel,
	}

	eb.wg.Add(1)
	go eb.dispatchLoop()
	return eb
}

func (eb *eventBusImpl) Subscribe(eventType EventType, handler Handler) {
	eb.handlersLock.Lock()
	defer eb.handlersLock.Unlock()

	// Priorização: Mimir (Auditor) entra no início da fila para garantir custódia
	if eventType == ScanCompleted {
		eb.handlers[eventType] = append([]Handler{handler}, eb.handlers[eventType]...)
	} else {
		eb.handlers[eventType] = append(eb.handlers[eventType], handler)
	}
}

func (eb *eventBusImpl) Publish(ctx context.Context, event Event) error {
	eb.mu.Lock()
	if eb.closed {
		eb.mu.Unlock()
		return fmt.Errorf("event bus closed")
	}
	eb.mu.Unlock()

	select {
	case eb.eventChan <- event:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(250 * time.Millisecond):
		return fmt.Errorf("bus overloaded: critical backpressure on %s", event.Type())
	}
}

func (eb *eventBusImpl) dispatchLoop() {
	defer eb.wg.Done()
	for {
		select {
		case event, ok := <-eb.eventChan:
			if !ok {
				return
			}
			eb.handlersLock.RLock()
			handlers := eb.handlers[event.Type()]
			eb.handlersLock.RUnlock()

			for _, handler := range handlers {
				go func(h Handler, ev Event) {
					hCtx, cancel := context.WithTimeout(eb.ctx, 5*time.Second)
					defer cancel()
					_ = h(hCtx, ev)
				}(handler, event)
			}
		case <-eb.ctx.Done():
			return
		}
	}
}

func (eb *eventBusImpl) Shutdown(ctx context.Context) error {
	eb.mu.Lock()
	if eb.closed {
		eb.mu.Unlock()
		return nil
	}
	eb.closed = true
	eb.mu.Unlock()

	eb.cancel()
	close(eb.eventChan)

	done := make(chan struct{})
	go func() {
		eb.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
