package events

import (
    "context"
    "fmt"
    "sync"
    "time"
)

// =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// SCHEMAS E INTERFACES
// =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

type EventType string

const (
    EventTypeScanRequested        EventType = "scan.requested"
    EventTypeYARACompleted        EventType = "yara.completed"
    EventTypeASTAnalysisRequested EventType = "ast.analysis.requested"
    EventTypeSystemLog            EventType = "system.log"
    EventTypeScanCompleted        EventType = "scan.completed"
)

// Event é a interface que todas as mensagens do sistema devem implementar
type Event interface {
    Type() EventType
}

// EventBus define o contrato do barramento (INTERFACE)
type EventBus interface {
    Publish(ctx context.Context, event Event) error
    Subscribe(eventType EventType, handler Handler)
    Shutdown(ctx context.Context) error
}

// YARACompletedPayload - Disparado pelo Engine após o Tier 1
type YARACompletedPayload struct {
    ScanID         string
    TargetName     string
    TargetSHA256   string
    MatchedRules   []string
    FindingsCount  int
    RiskScore      float64
    DurationNs     int64
    RulesEvaluated int
    LayerStatus    string
    CompletedAt    time.Time
}

func (p YARACompletedPayload) Type() EventType { return EventTypeYARACompleted }

// ASTAnalysisRequestedPayload - O que o AST Analyzer vai "ouvir" para trabalhar
type ASTAnalysisRequestedPayload struct {
    ScanID     string
    FilePath   string
    FileSource []byte
    Language   string // ex: "python"
}

func (p *ASTAnalysisRequestedPayload) Type() EventType { return EventTypeASTAnalysisRequested }

// =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// CORE DO EVENT BUS (IMPLEMENTAÇÃO CONCRETA)
// =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

type Handler func(ctx context.Context, event Event) error

// eventBusImpl é a implementação concreta da interface EventBus
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

// NewEventBus cria uma nova instância do barramento (retorna a INTERFACE)
func NewEventBus(bufferSize int) EventBus {
    ctx, cancel := context.WithCancel(context.Background())
    eb := &eventBusImpl{
        handlers:  make(map[EventType][]Handler),
        eventChan: make(chan Event, bufferSize),
        ctx:       ctx,
        cancel:    cancel,
    }

    // Inicia o Dispatcher principal
    eb.wg.Add(1)
    go eb.dispatchLoop()

    return eb // Retorna a interface, não a struct
}

// Subscribe registra um interessado em um tipo de evento
func (eb *eventBusImpl) Subscribe(eventType EventType, handler Handler) {
    eb.handlersLock.Lock()
    defer eb.handlersLock.Unlock()
    eb.handlers[eventType] = append(eb.handlers[eventType], handler)
}

// Publish envia um evento para o barramento de forma não bloqueante (com timeout)
func (eb *eventBusImpl) Publish(ctx context.Context, event Event) error {
    eb.mu.Lock()
    if eb.closed {
        eb.mu.Unlock()
        return fmt.Errorf("event bus is closed")
    }
    eb.mu.Unlock()

    select {
    case eb.eventChan <- event:
        return nil
    case <-ctx.Done():
        return ctx.Err()
    case <-time.After(100 * time.Millisecond): // Backpressure safety
        return fmt.Errorf("event bus overloaded: dropping event %s", event.Type())
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
                    // Timeout interno por handler para não travar o bus
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

// Shutdown finaliza o barramento graciosamente
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
        return fmt.Errorf("shutdown timeout: events might be lost")
    }
}
