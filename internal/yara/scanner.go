//go:build yara_static || yara_dynamic

package yara

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"

	goyara "github.com/hillu/go-yara/v4"
	"github.com/rs/zerolog"
)

import "embed"

//go:embed rules
var embeddedRules embed.FS

type scanner struct {
	rules *goyara.Rules
	log   zerolog.Logger

	metrics *metrics
	guard   *scanGuard

	mu sync.RWMutex
}

func New(log zerolog.Logger) (Scanner, error) {
	log = log.With().Str("component", "yara.Scanner").Logger()

	compiler, err := goyara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("yara: failed to create compiler: %w", err)
	}

	var compileErrors []string
	compiler.SetIncludeCallback(func(name, namespace, caller string) []byte {
		data, err := embeddedRules.ReadFile("rules/" + name)
		if err != nil {
			compileErrors = append(compileErrors, fmt.Sprintf("include %q: %v", name, err))
			return nil
		}
		return data
	})

	yarFiles, err := getAllYARFiles()
	if err != nil {
		return nil, fmt.Errorf("yara: failed to enumerate embedded rules: %w", err)
	}

	if len(yarFiles) == 0 {
		return nil, fmt.Errorf("yara: no .yar files found in embedded rules/ directory")
	}

	bundleHasher := sha256.New()
	loadedFiles := []string{}

	for _, path := range yarFiles {
		data, err := embeddedRules.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("yara: failed to read embedded rule %q: %w", path, err)
		}

		namespace := path
		if err := compiler.AddString(string(data), namespace); err != nil {
			log.Warn().Str("file", path).Err(err).Msg("YARA compilation warning — rule skipped")
			continue
		}

		bundleHasher.Write(data)
		loadedFiles = append(loadedFiles, path)
	}

	if len(compileErrors) > 0 {
		for _, e := range compileErrors {
			log.Error().Str("error", e).Msg("YARA include resolution failed")
		}
	}

	if len(loadedFiles) == 0 {
		return nil, fmt.Errorf("yara: all rule files failed compilation")
	}

	rules, err := compiler.GetRules()
	if err != nil {
		return nil, fmt.Errorf("yara: failed to get compiled rules: %w", err)
	}

	ruleCount := len(rules.GetRules())
	bundleHash := hex.EncodeToString(bundleHasher.Sum(nil))

	log.Info().
		Int("files_loaded", len(loadedFiles)).
		Int("rules_compiled", ruleCount).
		Str("bundle_hash", bundleHash[:16]+"...").
		Msg("YARA engine initialized")

	return &scanner{
		rules:   rules,
		log:     log,
		metrics: newMetrics(ruleCount, bundleHash),
		guard:   &scanGuard{},
	}, nil
}

func (s *scanner) Scan(ctx context.Context, payload []byte) ([]string, error) {
	if s.metrics.isClosed() {
		return nil, fmt.Errorf("yara: scanner is closed")
	}

	s.guard.enter()
	defer s.guard.leave()

	start := time.Now()
	var matchCount int
	var scanErr error
	defer func() {
		s.metrics.recordScan(len(payload), matchCount, time.Since(start), scanErr)
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	// CORREÇÃO: Usando a slice de MatchRule que é o padrão do go-yara v4
	var matches goyara.MatchRules

	// ScanMem preenche a slice 'matches' com as regras que dispararem
	if err := s.rules.ScanMem(payload, 0, 0, &matches); err != nil {
		scanErr = fmt.Errorf("yara: scan failed: %w", err)
		return nil, scanErr
	}

	matched := make([]string, 0, len(matches))
	for _, m := range matches {
		// No go-yara v4, acessamos o nome da regra diretamente pelo campo Rule
		matched = append(matched, m.Rule)

		s.log.Debug().
			Str("rule", m.Rule).
			Str("namespace", m.Namespace).
			Msg("YARA rule matched")
	}

	matchCount = len(matched)
	return matched, nil
}

func (s *scanner) RuleCount() int {
	return s.metrics.ruleCount
}

func (s *scanner) BundleHash() string {
	return s.metrics.bundleHash
}

func (s *scanner) ScanStats() ScanStatistics {
	return s.metrics.snapshot()
}

func (s *scanner) Close() error {
	if s.metrics.isClosed() {
		return nil
	}

	s.log.Info().Msg("YARA scanner shutting down...")
	s.guard.wait()
	s.metrics.markClosed()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.rules != nil {
		s.rules.Destroy()
		s.rules = nil
	}

	return nil
}

func getAllYARFiles() ([]string, error) {
	var paths []string
	if err := walkEmbedFS(embeddedRules, "rules", &paths); err != nil {
		return nil, err
	}
	sort.Strings(paths)
	return paths, nil
}

func walkEmbedFS(fs embed.FS, dir string, paths *[]string) error {
	entries, err := fs.ReadDir(dir)
	if err != nil {
		return err
	}

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
