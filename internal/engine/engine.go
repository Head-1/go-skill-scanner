package engine

import (
	"context"
	"time"

	"github.com/Head-1/go-skill-scanner/internal/ast"
	"github.com/Head-1/go-skill-scanner/internal/yara"
	"github.com/Head-1/go-skill-scanner/pkg/schema"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

type Config struct {
	Debug bool
}

type ScanRequest struct {
	Name     string
	Payload  []byte
	CallerID string
}

type Engine struct {
	cfg  Config
	log  zerolog.Logger
	yara yara.Scanner
	ast  ast.Analyzer
}

func New(cfg Config, log zerolog.Logger, yaraScanner yara.Scanner, astAnalyzer ast.Analyzer) (*Engine, error) {
	return &Engine{
		cfg:  cfg,
		log:  log.With().Str("component", "engine").Logger(),
		yara: yaraScanner,
		ast:  astAnalyzer,
	}, nil
}

func (e *Engine) ScanFile(ctx context.Context, req ScanRequest) (*schema.ScanResult, error) {
	start := time.Now()
	var allFindings []schema.Finding

	// TIER 1: YARA Scan
	yaraFindings, err := e.yara.Scan(ctx, req.Payload)
	if err == nil {
		allFindings = append(allFindings, yaraFindings...)
	}

	// TIER 2: AST Scan (Focado em Python conforme internal/ast/python.go)
	astFindings, err := e.ast.Analyze(ctx, req.Payload, "python")
	if err == nil {
		allFindings = append(allFindings, astFindings...)
	}

	res := &schema.ScanResult{
		ScanID:    uuid.New().String(),
		ScannedAt: start,
		Target:    schema.TargetInfo{Name: req.Name},
		Verdict:   schema.Verdict{Status: schema.VerdictClean, Summary: "No threats detected"},
		Findings:  allFindings,
	}

	if len(allFindings) > 0 {
		res.Verdict.Status = schema.VerdictMalicious
		res.Verdict.Summary = "Malicious patterns or logic detected"
	}

	res.DurationNs = time.Since(start).Nanoseconds()
	return res, nil
}

func (e *Engine) Close() error {
	return e.yara.Close()
}
