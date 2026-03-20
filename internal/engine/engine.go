package engine

import (
	"context"
	"strings"
	"time"

	"github.com/Head-1/go-skill-scanner/internal/ast"
	"github.com/Head-1/go-skill-scanner/internal/audit"
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
	cfg   Config
	log   zerolog.Logger
	yara  yara.Scanner
	ast   ast.Analyzer
	audit *audit.QueueManager
}

func New(cfg Config, log zerolog.Logger, yaraScanner yara.Scanner, astAnalyzer ast.Analyzer, auditQueue *audit.QueueManager) (*Engine, error) {
	return &Engine{
		cfg:   cfg,
		log:   log.With().Str("component", "engine").Logger(),
		yara:  yaraScanner,
		ast:   astAnalyzer,
		audit: auditQueue,
	}, nil
}

// detectLanguage infere a linguagem pela extensão do arquivo.
func detectLanguage(filename string) string {
	switch {
	case strings.HasSuffix(filename, ".py"):
		return "python"
	case strings.HasSuffix(filename, ".js"):
		return "javascript"
	case strings.HasSuffix(filename, ".sh"):
		return "bash"
	case strings.HasSuffix(filename, ".go"):
		return "go"
	default:
		return "unknown"
	}
}

// ScanFile executa o pipeline completo e regista no audit.
func (e *Engine) ScanFile(ctx context.Context, req ScanRequest) (*schema.ScanResult, error) {
	start := time.Now()
	var allFindings []schema.Finding

	// TIER 1: YARA
	yaraFindings, err := e.yara.Scan(ctx, req.Payload)
	if err != nil {
		e.log.Error().Err(err).Msg("YARA scan failed")
	} else {
		allFindings = append(allFindings, yaraFindings...)
	}

	// TIER 2: AST (com detecção de linguagem)
	lang := detectLanguage(req.Name)
	astFindings, err := e.ast.Analyze(ctx, req.Payload, lang)
	if err != nil {
		e.log.Error().Err(err).Str("lang", lang).Msg("AST analysis failed")
	} else {
		allFindings = append(allFindings, astFindings...)
	}

	// Cria o resultado
	res := &schema.ScanResult{
		ScanID:    uuid.New().String(),
		ScannedAt: start,
		Target: schema.TargetInfo{
			Name:     req.Name,
			Language: lang,
		},
		Findings: allFindings,
		Pipeline: schema.PipelineTrace{
			YARA: schema.LayerTrace{
				Status:     "PASS", // string livre
				DurationNs: time.Since(start).Nanoseconds(),
			},
			AST: schema.LayerTrace{
				Status:     "PASS",
				DurationNs: time.Since(start).Nanoseconds(),
			},
		},
		Verdict: schema.Verdict{
			Status:     schema.VerdictClean,
			Summary:    "No threats detected",
			Confidence: 1.0,
		},
	}

	// Ajusta status das camadas e veredito com base nos findings
	if len(yaraFindings) > 0 {
		res.Pipeline.YARA.Status = "FAIL"
	}
	if len(astFindings) > 0 {
		res.Pipeline.AST.Status = "FAIL"
	}
	if len(allFindings) > 0 {
		res.Verdict.Status = schema.VerdictMalicious
		res.Verdict.Summary = "Malicious patterns or logic detected"
		res.Verdict.Confidence = 0.95
	}

	res.DurationNs = time.Since(start).Nanoseconds()

	// --- Persistência no audit ---
	if e.audit != nil {
		if err := e.audit.LogResult(res); err != nil {
			e.log.Error().Err(err).Str("scan_id", res.ScanID).Msg("failed to log result to audit")
		}
	}

	return res, nil
}

func (e *Engine) Close() error {
	return e.yara.Close()
}
