package mcp

import (
	"github.com/Head-1/go-skill-scanner/pkg/schema"
)

// Tipos auxiliares para conversão e respostas da IA (AEGIS)
type AEGISScanResult struct {
	Verdict  string           `json:"verdict"`
	Score    float64          `json:"risk_score"`
	Findings []schema.Finding `json:"findings"`
}
