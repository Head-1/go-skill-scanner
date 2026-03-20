package llm

import (
	"context"
	"github.com/Head-1/go-skill-scanner/pkg/schema"
)

// Provider define a interface soberana para integração com LLMs
type Provider interface {
	// Name retorna o identificador do provedor (ex: "anthropic")
	Name() string
	
	// Analyze solicita um veredito final baseado no contexto técnico do scan
	Analyze(ctx context.Context, code []byte, findings []schema.Finding) (*schema.Verdict, error)
}
