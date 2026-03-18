//go:build yara_static || yara_dynamic

package yara

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	goyara "github.com/hillu/go-yara/v4"
	"github.com/rs/zerolog"
	"github.com/Head-1/go-skill-scanner/pkg/schema"
)

//go:embed rules
var embeddedRules embed.FS

// ScanStatistics define a estrutura detalhada de métricas para o YARA.
type ScanStatistics struct {
	TotalScans         int64
	TotalBytesScanned  int64
	TotalMatches       int64
	TotalErrors        int64
	AvgScanDurationMs  float64
	TotalDuration      time.Duration
	LastScanAt         time.Time
}

type Scanner interface {
	Scan(ctx context.Context, payload []byte) ([]schema.Finding, error)
	GetRulesCount() int
	RuleCount() int
	BundleHash() string
	Close() error
	ScanStats() ScanStatistics
}

type scanner struct {
	rules   *goyara.Rules
	log     zerolog.Logger
	metrics *metrics
	guard   *scanGuard
	mu      sync.RWMutex
}

func New(log zerolog.Logger) (Scanner, error) {
	log = log.With().Str("component", "yara.Scanner").Logger()
	compiler, err := goyara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("yara: failed to create compiler: %w", err)
	}

	compiler.SetIncludeCallback(func(name, namespace, caller string) []byte {
		data, err := embeddedRules.ReadFile("rules/" + name)
		if err != nil { return nil }
		return data
	})

	// Busca arquivos .yar no embed
	var yarFiles []string
	err = walkEmbedFS(embeddedRules, "rules", &yarFiles)
	if err != nil { return nil, err }

	bundleHasher := sha256.New()
	for _, path := range yarFiles {
		data, err := embeddedRules.ReadFile(path)
		if err != nil { continue }
		if err := compiler.AddString(string(data), path); err != nil {
			log.Warn().Str("file", path).Err(err).Msg("YARA rule skipped")
			continue
		}
		bundleHasher.Write(data)
	}

	rules, err := compiler.GetRules()
	if err != nil { return nil, fmt.Errorf("yara: failed to get compiled rules: %w", err) }

	ruleCount := len(rules.GetRules())
	bundleHash := hex.EncodeToString(bundleHasher.Sum(nil))

	return &scanner{
		rules:   rules,
		log:     log,
		metrics: newMetrics(ruleCount, bundleHash),
		guard:   &scanGuard{},
	}, nil
}

func (s *scanner) Scan(ctx context.Context, payload []byte) ([]schema.Finding, error) {
	s.guard.enter()
	defer s.guard.leave()
	start := time.Now()

	var matches goyara.MatchRules
	if err := s.rules.ScanMem(payload, 0, 0, &matches); err != nil {
		s.metrics.recordScan(len(payload), 0, time.Since(start), err)
		return nil, err
	}

	findings := make([]schema.Finding, 0, len(matches))
	for _, m := range matches {
		findings = append(findings, schema.Finding{
			Source:      "yara",
			Category:    schema.CategoryMaliciousPattern,
			Severity:    schema.SeverityHigh,
			RuleID:      m.Rule,
			Description: fmt.Sprintf("YARA match: %s", m.Rule),
		})
	}

	s.metrics.recordScan(len(payload), len(findings), time.Since(start), nil)
	return findings, nil
}

func (s *scanner) GetRulesCount() int { return s.metrics.ruleCount }
func (s *scanner) RuleCount() int    { return s.metrics.ruleCount }
func (s *scanner) BundleHash() string { return s.metrics.bundleHash }
func (s *scanner) ScanStats() ScanStatistics { return s.metrics.snapshot() }

func (s *scanner) Close() error {
	s.guard.wait()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rules != nil {
		s.rules.Destroy()
		s.rules = nil
	}
	return nil
}

// walkEmbedFS navega recursivamente no embed.FS para encontrar as regras
func walkEmbedFS(fs embed.FS, dir string, paths *[]string) error {
	entries, err := fs.ReadDir(dir)
	if err != nil { return err }

	for _, entry := range entries {
		fullPath := dir + "/" + entry.Name()
		if entry.IsDir() {
			if err := walkEmbedFS(fs, fullPath, paths); err != nil {
				return err
			}
			continue
		}
		if len(entry.Name()) > 4 && entry.Name()[len(entry.Name())-4:] == ".yar" {
			*paths = append(*paths, fullPath)
		}
	}
	return nil
}
