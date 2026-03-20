package llm

import (
	"context"
	"fmt"
	"github.com/Head-1/go-skill-scanner/pkg/schema"
	"github.com/rs/zerolog"
)

type Service struct {
	log       zerolog.Logger
	providers map[string]Provider
	defaultPr string
}

func NewService(log zerolog.Logger, defaultProvider string) *Service {
	return &Service{
		log:       log.With().Str("component", "llm-service").Logger(),
		providers: make(map[string]Provider),
		defaultPr: defaultProvider,
	}
}

func (s *Service) RegisterProvider(p Provider) {
	s.providers[p.Name()] = p
	s.log.Info().Str("provider", p.Name()).Msg("Provedor LLM registrado")
}

func (s *Service) Analyze(ctx context.Context, code []byte, findings []schema.Finding) (*schema.Verdict, error) {
	p, ok := s.providers[s.defaultPr]
	if !ok {
		return nil, fmt.Errorf("provedor padrão '%s' não encontrado", s.defaultPr)
	}
	return p.Analyze(ctx, code, findings)
}
