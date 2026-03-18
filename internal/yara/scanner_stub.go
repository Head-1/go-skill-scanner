//go:build !yara_static && !yara_dynamic
// +build !yara_static,!yara_dynamic

package yara

import (
    "context"

    "github.com/Head-1/go-skill-scanner/pkg/schema"
)

type stubScanner struct{}

func NewScanner() (Scanner, error) {
    return &stubScanner{}, nil
}

func (s *stubScanner) Scan(ctx context.Context, payload []byte) ([]schema.Finding, error) {
    // Stub: retorna sempre vazio (simula YARA não disponível)
    return []schema.Finding{}, nil
}

func (s *stubScanner) Close() error {
    return nil
}

func (s *stubScanner) RuleCount() int {
    return 0
}

func (s *stubScanner) BundleHash() string {
    return "stub-no-rules"
}

func (s *stubScanner) ScanStats() ScanStatistics {
    return ScanStatistics{}
}
