// Package schema defines the canonical output contract for go-skill-scanner.
//
// THIS FILE IS THE SYSTEM'S NORTH STAR.
// Every component (engine, cache, MCP server, CLI) produces or consumes
// these types. Do NOT change field names or types without a major version bump —
// consumers depend on this JSON layout being stable.
package schema

import "time"

// ─────────────────────────────────────────────────────────────────────────────
// Top-level Result
// ─────────────────────────────────────────────────────────────────────────────

// ScanResult is the root object returned by every scan operation.
// It is always serialized as JSON and is the contract between the engine
// and any consumer (MCP client, CLI, CI/CD pipeline, audit ledger).
type ScanResult struct {
	// Schema version — bump on breaking changes. Consumers MUST check this.
	SchemaVersion string `json:"schema_version"` // e.g. "1.0.0"

	// Unique identifier for this scan invocation (UUID v4).
	ScanID string `json:"scan_id"`

	// UTC timestamp of when the scan was initiated.
	ScannedAt time.Time `json:"scanned_at"`

	// Total wall-clock time for the full pipeline (nanoseconds precision).
	DurationNs int64 `json:"duration_ns"`

	// Identity of the artifact under inspection.
	Target TargetInfo `json:"target"`

	// The authoritative verdict. Consumers SHOULD gate on this field only.
	Verdict Verdict `json:"verdict"`

	// Aggregated risk score: 0.0 (clean) → 1.0 (critical threat).
	RiskScore float64 `json:"risk_score"`

	// Ordered list of findings from all analysis layers.
	// Empty slice (never null) when no issues are detected.
	Findings []Finding `json:"findings"`

	// Which analysis layers ran and their individual outcomes.
	Pipeline PipelineTrace `json:"pipeline"`

	// Manifest validation results (nil if no manifest was present).
	Manifest *ManifestResult `json:"manifest,omitempty"`

	// Cache hit metadata — explains why a full scan was (or wasn't) skipped.
	CacheInfo CacheInfo `json:"cache_info"`

	// Audit fields for compliance and forensic traceability.
	Audit AuditInfo `json:"audit"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Target Identity
// ─────────────────────────────────────────────────────────────────────────────

// TargetInfo identifies the artifact being scanned.
type TargetInfo struct {
	// Human-readable name provided by the caller.
	Name string `json:"name"`

	// SHA-256 of the raw input bytes. Canonical identity for caching.
	SHA256 string `json:"sha256"`

	// TLSH fuzzy hash — used for near-duplicate detection in cache lookups.
	TLSHHash string `json:"tlsh_hash"`

	// Byte size of the input.
	SizeBytes int64 `json:"size_bytes"`

	// MIME type detected from content (not from filename/extension).
	DetectedMIME string `json:"detected_mime"`

	// Language detected by AST parser (e.g. "python", "javascript", "unknown").
	Language string `json:"language"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Verdict
// ─────────────────────────────────────────────────────────────────────────────

// VerdictStatus is the set of possible authoritative outcomes.
type VerdictStatus string

const (
	VerdictClean     VerdictStatus = "CLEAN"     // No threats detected.
	VerdictSuspect   VerdictStatus = "SUSPECT"   // Anomalies found; human review recommended.
	VerdictMalicious VerdictStatus = "MALICIOUS" // Confirmed threat; block execution.
	VerdictError     VerdictStatus = "ERROR"     // Scanner internal error; treat as MALICIOUS by default.
)

// Verdict is the authoritative decision produced by the engine.
type Verdict struct {
	Status VerdictStatus `json:"status"`

	// Human-readable one-liner summarizing the verdict.
	// Example: "Blocked: prompt injection pattern detected on line 42"
	Summary string `json:"summary"`

	// Which pipeline layer produced the final verdict.
	// One of: "yara", "ast", "llm", "wasm", "manifest", "cache", "error"
	DecidedBy string `json:"decided_by"`

	// Confidence level of the deciding layer: 0.0 → 1.0.
	// YARA/AST matches are deterministic (1.0); LLM outputs are probabilistic.
	Confidence float64 `json:"confidence"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Findings
// ─────────────────────────────────────────────────────────────────────────────

// Severity maps to industry-standard CVSS qualitative ratings.
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// FindingCategory classifies the type of threat or anomaly.
type FindingCategory string

const (
	CategoryPromptInjection  FindingCategory = "PROMPT_INJECTION"
	CategoryCodeExecution    FindingCategory = "CODE_EXECUTION"
	CategoryDataExfiltration FindingCategory = "DATA_EXFILTRATION"
	CategoryMaliciousPattern FindingCategory = "MALICIOUS_PATTERN"
	CategoryCapabilityAbuse  FindingCategory = "CAPABILITY_ABUSE"
	CategoryPIILeak          FindingCategory = "PII_LEAK"
	CategoryAnomalousBehavior FindingCategory = "ANOMALOUS_BEHAVIOR"
	CategorySuspiciousImport FindingCategory = "SUSPICIOUS_IMPORT"
)

// Finding is a single, atomic piece of forensic evidence produced by any
// analysis layer. One scan can produce zero or more findings.
type Finding struct {
	// Unique ID within this scan result (e.g. "F-001", "F-002").
	ID string `json:"id"`

	// The analysis layer that generated this finding.
	// One of: "yara", "ast", "llm", "wasm", "manifest"
	Source string `json:"source"`

	Category FindingCategory `json:"category"`
	Severity Severity        `json:"severity"`

	// The specific rule, pattern, or model output that fired.
	// For YARA: rule name. For AST: pattern ID. For LLM: model reasoning tag.
	RuleID string `json:"rule_id"`

	// Human-readable description of the finding.
	Description string `json:"description"`

	// Precise location within the target artifact.
	Location *Location `json:"location,omitempty"`

	// The exact snippet of code/text that triggered the finding.
	// IMPORTANT: PII obfuscation must be applied before populating this field.
	Evidence string `json:"evidence"`

	// Remediation guidance for the developer.
	Remediation string `json:"remediation,omitempty"`

	// Tags for downstream filtering (e.g. ["owasp:llm01", "mitre:T1059"]).
	Tags []string `json:"tags,omitempty"`
}

// Location pinpoints where in the target artifact a finding occurred.
type Location struct {
	// 1-indexed line number. -1 if not applicable (e.g. binary content).
	Line int `json:"line"`

	// 1-indexed column of the finding's start.
	Column int `json:"column,omitempty"`

	// Byte offset range within the raw input.
	ByteOffsetStart int `json:"byte_offset_start,omitempty"`
	ByteOffsetEnd   int `json:"byte_offset_end,omitempty"`

	// Enclosing function or block name, when AST context is available.
	Context string `json:"context,omitempty"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Pipeline Trace
// ─────────────────────────────────────────────────────────────────────────────

// PipelineTrace records the execution status of each analysis layer.
// This is the "flight recorder" — critical for debugging false positives/negatives.
type PipelineTrace struct {
	YARA     LayerTrace  `json:"yara"`
	AST      LayerTrace  `json:"ast"`
	LLM      *LayerTrace `json:"llm,omitempty"`   // nil if LLM tier was not reached
	Wasm     *LayerTrace `json:"wasm,omitempty"`  // nil if Wasm sandbox was not engaged
	Manifest *LayerTrace `json:"manifest,omitempty"`
}

// LayerStatus represents the execution state of a single pipeline layer.
type LayerStatus string

const (
	LayerSkipped  LayerStatus = "SKIPPED"  // Not configured or not reached.
	LayerPass     LayerStatus = "PASS"     // Ran and found nothing.
	LayerFail     LayerStatus = "FAIL"     // Ran and found threats.
	LayerError    LayerStatus = "ERROR"    // Layer itself encountered an error.
	LayerCacheHit LayerStatus = "CACHE_HIT" // Result served from cache; layer not executed.
)

// LayerTrace captures the execution detail of a single analysis layer.
type LayerTrace struct {
	Status     LayerStatus `json:"status"`
	DurationNs int64       `json:"duration_ns"`

	// Number of rules/patterns evaluated (YARA rules, AST patterns, etc.).
	RulesEvaluated int `json:"rules_evaluated"`

	// Number of findings this layer contributed.
	FindingsCount int `json:"findings_count"`

	// Error message if Status == ERROR.
	Error string `json:"error,omitempty"`

	// LLM-specific metadata (only populated for the LLM layer).
	LLMMetadata *LLMLayerMeta `json:"llm_metadata,omitempty"`
}

// LLMLayerMeta holds model-specific telemetry for the LLM-as-a-Judge layer.
type LLMLayerMeta struct {
	// The LLM provider/backend that was used.
	// One of: "ollama", "anthropic", "openai", "vllm"
	Provider string `json:"provider"`

	// Model identifier as reported by the provider.
	ModelID string `json:"model_id"`

	// Tokens consumed (for cost tracking and quota management).
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`

	// Whether PII obfuscation was applied before sending to the LLM.
	PIIObfuscated bool `json:"pii_obfuscated"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Manifest Validation
// ─────────────────────────────────────────────────────────────────────────────

// ManifestResult captures the outcome of capability manifest validation.
type ManifestResult struct {
	// Whether a manifest.json was found and parseable.
	Present bool `json:"present"`

	// Capabilities declared in the manifest.
	DeclaredCapabilities []string `json:"declared_capabilities"`

	// Capabilities detected in the code but NOT declared in the manifest.
	// A non-empty slice here is always a HIGH severity finding.
	UndeclaredCapabilities []string `json:"undeclared_capabilities"`

	// Whether all detected capabilities are covered by the manifest.
	Compliant bool `json:"compliant"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Cache Info
// ─────────────────────────────────────────────────────────────────────────────

// CacheHitType describes the type of cache match that occurred.
type CacheHitType string

const (
	CacheHitNone  CacheHitType = "NONE"  // No match; full scan executed.
	CacheHitExact CacheHitType = "EXACT" // SHA-256 matched; result replayed from store.
	CacheHitFuzzy CacheHitType = "FUZZY" // TLSH near-match; fast path with fresh LLM confirm.
)

// CacheInfo documents how the cache influenced this scan.
type CacheInfo struct {
	HitType CacheHitType `json:"hit_type"`

	// TLSH similarity score if a fuzzy match was used (0–100, lower = more similar).
	FuzzySimilarityScore int `json:"fuzzy_similarity_score,omitempty"`

	// UTC timestamp of the original scan whose result was replayed.
	CachedAt *time.Time `json:"cached_at,omitempty"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit & Compliance
// ─────────────────────────────────────────────────────────────────────────────

// AuditInfo carries compliance and chain-of-custody metadata.
type AuditInfo struct {
	// Version of the go-skill-scanner binary that produced this result.
	ScannerVersion string `json:"scanner_version"`

	// SHA-256 of the YARA rule bundle used. Allows reproduction of results.
	RuleBundleHash string `json:"rule_bundle_hash"`

	// HMAC-SHA256 signature of the canonical JSON payload.
	// Consumers can verify this to detect tampering in the audit ledger.
	// Key is derived from the deployment secret; never included in output.
	ResultSignature string `json:"result_signature"`

	// Caller identity as provided by the MCP transport layer.
	// Empty string for direct CLI invocations.
	CallerID string `json:"caller_id,omitempty"`

	// SBOM fragment — direct dependencies detected in the scanned artifact.
	// Format follows CycloneDX 1.5 component schema (condensed).
	SBOMComponents []SBOMComponent `json:"sbom_components,omitempty"`
}

// SBOMComponent is a condensed CycloneDX component entry.
type SBOMComponent struct {
	Type    string `json:"type"`    // e.g. "library"
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURLs   []string `json:"purls,omitempty"` // Package URLs (pkg:npm/lodash@4.17.21)
}
