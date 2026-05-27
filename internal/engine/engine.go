package engine

import (
	"context"
	"time"

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
}

func New(cfg Config, log zerolog.Logger, yaraScanner yara.Scanner) (*Engine, error) {
	return &Engine{
		cfg:  cfg,
		log:  log.With().Str("component", "engine").Logger(),
		yara: yaraScanner,
	}, nil
}

func (e *Engine) ScanFile(ctx context.Context, req ScanRequest) (*schema.ScanResult, error) {
	start := time.Now()

	// Executa o scan YARA
	findings, err := e.yara.Scan(ctx, req.Payload)
	if err != nil {
		return nil, err
	}

	// Tenta obter o hash das regras, se disponível
	ruleHash := "pending"
	if hasher, ok := e.yara.(interface{ BundleHash() string }); ok {
		ruleHash = hasher.BundleHash()
	}

	// Constrói o resultado
	res := &schema.ScanResult{
		ScanID:    uuid.New().String(),
		ScannedAt: start,
		Target: schema.TargetInfo{
			Name: req.Name,
		},
		Verdict: schema.Verdict{
			Status:     schema.VerdictClean,
			Summary:    "No threats detected",
			Confidence: 1.0,
		},
		Findings: findings,
		Audit: schema.AuditInfo{
			RuleBundleHash:  ruleHash,
			ResultSignature: "",
			EngineVersion:   "1.0.0",
		},
	}

	// Se houver findings, ajusta o veredito
	if len(findings) > 0 {
		res.Verdict.Status = schema.VerdictMalicious
		res.Verdict.Summary = "Malicious patterns detected in payload"
		res.RiskScore = 0.95
	}

	res.DurationNs = time.Since(start).Nanoseconds()
	return res, nil
}

func (e *Engine) Close() error {
	return e.yara.Close()
}
