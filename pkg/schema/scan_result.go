// Package schema defines the canonical output contract for go-skill-scanner.
//
// THIS FILE IS THE SYSTEM'S NORTH STAR.
// Every component (engine, cache, MCP server, CLI) produces or consumes
// these types. 
package schema

import "time"

// ─────────────────────────────────────────────────────────────────────────────
// Top-level Result
// ─────────────────────────────────────────────────────────────────────────────

type ScanResult struct {
	SchemaVersion string          `json:"schema_version"`
	ScanID        string          `json:"scan_id"`
	ScannedAt     time.Time       `json:"scanned_at"`
	DurationNs    int64           `json:"duration_ns"`
	Target        TargetInfo      `json:"target"`
	Verdict       Verdict         `json:"verdict"`
	RiskScore     float64         `json:"risk_score"`
	Findings      []Finding       `json:"findings"`
	Pipeline      PipelineTrace   `json:"pipeline"`
	Manifest      *ManifestResult `json:"manifest,omitempty"`
	CacheInfo     CacheInfo       `json:"cache_info"`
	Audit         AuditInfo       `json:"audit"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Target Identity
// ─────────────────────────────────────────────────────────────────────────────

type TargetInfo struct {
	Name         string `json:"name"`
	SHA256       string `json:"sha256"`
	TLSHHash     string `json:"tlsh_hash"`
	SizeBytes    int64  `json:"size_bytes"`
	DetectedMIME string `json:"detected_mime"`
	Language     string `json:"language"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Verdict
// ─────────────────────────────────────────────────────────────────────────────

type VerdictStatus string

const (
	VerdictClean     VerdictStatus = "CLEAN"
	VerdictSuspect   VerdictStatus = "SUSPECT"
	VerdictMalicious VerdictStatus = "MALICIOUS"
	VerdictError     VerdictStatus = "ERROR"
)

type Verdict struct {
	Status     VerdictStatus `json:"status"`
	Summary    string        `json:"summary"`
	DecidedBy  string        `json:"decided_by"`
	Confidence float64       `json:"confidence"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Findings
// ─────────────────────────────────────────────────────────────────────────────

type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

type FindingCategory string

const (
	CategoryPromptInjection   FindingCategory = "PROMPT_INJECTION"
	CategoryCodeExecution     FindingCategory = "CODE_EXECUTION"
	CategoryDataExfiltration  FindingCategory = "DATA_EXFILTRATION"
	CategoryMaliciousPattern  FindingCategory = "MALICIOUS_PATTERN"
	CategoryCapabilityAbuse   FindingCategory = "CAPABILITY_ABUSE"
	CategoryPIILeak           FindingCategory = "PII_LEAK"
	CategoryAnomalousBehavior FindingCategory = "ANOMALOUS_BEHAVIOR"
	CategorySuspiciousImport  FindingCategory = "SUSPICIOUS_IMPORT"
)

type Finding struct {
	ID          string          `json:"id"`
	Source      string          `json:"source"`
	Category    FindingCategory `json:"category"`
	Severity    Severity        `json:"severity"`
	RuleID      string          `json:"rule_id"`
	Description string          `json:"description"`
	Location    *Location       `json:"location,omitempty"`
	Evidence    string          `json:"evidence"`
	Remediation string          `json:"remediation,omitempty"`
	Tags        []string        `json:"tags,omitempty"`
}

type Location struct {
	Line             int    `json:"line"`
	Column           int    `json:"column,omitempty"`
	ByteOffsetStart  int    `json:"byte_offset_start,omitempty"`
	ByteOffsetEnd    int    `json:"byte_offset_end,omitempty"`
	Context          string `json:"context,omitempty"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Pipeline Trace
// ─────────────────────────────────────────────────────────────────────────────

type PipelineTrace struct {
	YARA     LayerTrace  `json:"yara"`
	AST      LayerTrace  `json:"ast"`
	LLM      *LayerTrace `json:"llm,omitempty"`
	Wasm     *LayerTrace `json:"wasm,omitempty"`
	Manifest *LayerTrace `json:"manifest,omitempty"`
}

type LayerStatus string

const (
	LayerSkipped  LayerStatus = "SKIPPED"
	LayerPass     LayerStatus = "PASS"
	LayerFail     LayerStatus = "FAIL"
	LayerError    LayerStatus = "ERROR"
	LayerCacheHit LayerStatus = "CACHE_HIT"
)

type LayerTrace struct {
	Status         LayerStatus   `json:"status"`
	DurationNs     int64         `json:"duration_ns"`
	RulesEvaluated int           `json:"rules_evaluated"`
	FindingsCount  int           `json:"findings_count"`
	Error          string        `json:"error,omitempty"`
	LLMMetadata    *LLMLayerMeta `json:"llm_metadata,omitempty"`
}

type LLMLayerMeta struct {
	Provider         string `json:"provider"`
	ModelID          string `json:"model_id"`
	PromptTokens     int    `json:"prompt_tokens"`
	CompletionTokens int    `json:"completion_tokens"`
	PIIObfuscated    bool   `json:"pii_obfuscated"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Manifest Validation
// ─────────────────────────────────────────────────────────────────────────────

type ManifestResult struct {
	// Valid é o campo que o Engine Noop utiliza para reportar sucesso.
	Valid                  bool     `json:"valid"`
	Present                bool     `json:"present"`
	DeclaredCapabilities   []string `json:"declared_capabilities"`
	UndeclaredCapabilities []string `json:"undeclared_capabilities"`
	Compliant              bool     `json:"compliant"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Cache Info
// ─────────────────────────────────────────────────────────────────────────────

type CacheHitType string

const (
	CacheHitNone  CacheHitType = "NONE"
	CacheHitExact CacheHitType = "EXACT"
	CacheHitFuzzy CacheHitType = "FUZZY"
)

type CacheInfo struct {
	HitType              CacheHitType `json:"hit_type"`
	FuzzySimilarityScore int          `json:"fuzzy_similarity_score,omitempty"`
	CachedAt             *time.Time   `json:"cached_at,omitempty"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit & Compliance
// ─────────────────────────────────────────────────────────────────────────────

type AuditInfo struct {
	ScannerVersion  string          `json:"scanner_version"`
	RuleBundleHash  string          `json:"rule_bundle_hash"`
	ResultSignature string          `json:"result_signature"`
	CallerID        string          `json:"caller_id,omitempty"`
	SBOMComponents  []SBOMComponent `json:"sbom_components,omitempty"`
}

type SBOMComponent struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Version string   `json:"version,omitempty"`
	PURLs   []string `json:"purls,omitempty"`
}
