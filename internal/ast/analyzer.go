package ast

import (
	"context"
	"github.com/Head-1/go-skill-scanner/pkg/schema"
	"github.com/rs/zerolog"
)

type Analyzer interface {
	Analyze(ctx context.Context, payload []byte, lang string) ([]schema.Finding, error)
}

type astAnalyzer struct {
	log zerolog.Logger
}

func NewAnalyzer(log zerolog.Logger) Analyzer {
	return &astAnalyzer{
		log: log.With().Str("component", "ast-analyzer").Logger(),
	}
}

func (a *astAnalyzer) Analyze(ctx context.Context, payload []byte, lang string) ([]schema.Finding, error) {
	if lang == "python" {
		return a.analyzePython(payload)
	}
	return nil, nil
}
