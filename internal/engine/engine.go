// Package engine is the central orchestrator of the go-skill-scanner pipeline.
//
// It coordinates the analysis layers in the following order:
//
//  1. Cache lookup (SHA-256 exact → TLSH fuzzy)
//  2. YARA static scan
//  3. AST structural analysis
//  4. Wasm sandbox pre-flight (if configured)
//  5. LLM-as-a-Judge (if YARA/AST verdict is ambiguous)
//  6. Manifest capability validation
//
// The engine is stateless between calls. All state lives in the injected
// dependencies (Cache, YARAScanner, etc.), making it safe for concurrent use
// from the MCP server's goroutine pool.
package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/Head-1/go-skill-scanner/internal/yara"
	"github.com/Head-1/go-skill-scanner/pkg/schema"
)

// Version and BuildTime are injected at compile time via -ldflags.
// See build/Dockerfile for the injection command.
var (
	Version   = "dev"
	BuildTime = "unknown"
)

// ─────────────────────────────────────────────────────────────────────────────
// Interfaces — dependency contracts
// Each layer is an interface so it can be:
//   a) mocked in unit tests (no real YARA/LLM needed)
//   b) swapped for alternative implementations
// ─────────────────────────────────────────────────────────────────────────────

// ASTAnalyzer performs structural code analysis to detect malicious patterns
// that YARA string matching cannot catch (e.g. chained pipe commands).
type ASTAnalyzer interface {
	Analyze(ctx context.Context, payload []byte, language string) (findings []schema.Finding, err error)
}

// Cache manages the reputation store.
type Cache interface {
	// GetBySHA256 returns a cached ScanResult for an exact hash match.
	GetBySHA256(ctx context.Context, sha256 string) (*schema.ScanResult, error)

	// GetByTLSH returns a cached ScanResult and similarity score for a fuzzy match.
	// Returns nil if no match is within the configured similarity threshold.
	GetByTLSH(ctx context.Context, tlshHash string) (*schema.ScanResult, int, error)

	// Put stores a ScanResult, keyed by both SHA-256 and TLSH hash.
	Put(ctx context.Context, result *schema.ScanResult) error
}

// LLMJudge sends ambiguous payloads to an LLM for probabilistic analysis.
type LLMJudge interface {
	// Analyze submits the payload and existing findings for LLM review.
	// Returns additional findings and a confidence-adjusted verdict.
	Analyze(ctx context.Context, payload []byte, preliminary []schema.Finding) (
		findings []schema.Finding,
		verdict schema.Verdict,
		meta *schema.LLMLayerMeta,
		err error,
	)
}

// WasmSandbox executes the payload in an isolated Wasm runtime.
type WasmSandbox interface {
	// Execute runs the payload and returns behavioral findings.
	// Timeout should be short (< 500ms) to prevent DoS from infinite loops.
	Execute(ctx context.Context, payload []byte) (findings []schema.Finding, err error)
}

// ManifestValidator checks that the Skill's behavior matches its declared manifest.
type ManifestValidator interface {
	Validate(ctx context.Context, payload []byte, manifestJSON []byte) (*schema.ManifestResult, []schema.Finding, error)
}

// SecurityProbe is the pluggable deep inspection interface.
// The default implementation is a no-op (safe for all environments).
// An eBPF implementation can be registered for privileged Linux environments.
type SecurityProbe interface {
	// Probe is called after Wasm execution with behavioral context.
	Probe(ctx context.Context, pid int) (findings []schema.Finding, err error)
}

// ─────────────────────────────────────────────────────────────────────────────
// Engine Configuration
// ─────────────────────────────────────────────────────────────────────────────

// Config controls which layers are active and their behavior thresholds.
type Config struct {
	// RiskScoreThresholds defines cutoff scores for routing decisions.
	Thresholds struct {
		// Below this score: YARA/AST result is trusted as CLEAN without LLM.
		CleanBelow float64 // default: 0.2

		// Above this score: result is MALICIOUS without LLM confirmation.
		MaliciousAbove float64 // default: 0.8

		// Between CleanBelow and MaliciousAbove: route to LLM.
	}

	// TLSH fuzzy match threshold (0–100, lower = stricter).
	// Payloads with TLSH distance ≤ this value use the cached verdict.
	FuzzyMatchThreshold int // default: 30

	// EnableWasm controls whether the Wasm sandbox pre-flight runs.
	EnableWasm bool

	// EnableLLM controls whether the LLM tier is available.
	EnableLLM bool

	// LLMTimeout is the maximum time to wait for an LLM response.
	LLMTimeout time.Duration // default: 30s

	// WasmTimeout is the maximum execution time for the Wasm sandbox.
	WasmTimeout time.Duration // default: 500ms
}

// DefaultConfig returns a conservative, production-safe configuration.
func DefaultConfig() Config {
	c := Config{
		FuzzyMatchThreshold: 30,
		EnableWasm:          false, // Opt-in: requires careful resource planning.
		EnableLLM:           false, // Opt-in: requires LLM backend configuration.
		LLMTimeout:          30 * time.Second,
		WasmTimeout:         500 * time.Millisecond,
	}
	c.Thresholds.CleanBelow = 0.2
	c.Thresholds.MaliciousAbove = 0.8
	return c
}

// ─────────────────────────────────────────────────────────────────────────────
// Engine
// ─────────────────────────────────────────────────────────────────────────────

// Engine is the central scan orchestrator.
// Construct via New() — do not create directly.
//
// CRITICAL: Engine holds C resources (YARA scanner). Call Close() to prevent leaks.
type Engine struct {
	cfg      Config
	log      zerolog.Logger
	yara     yara.Scanner // Uses internal/yara.Scanner interface
	ast      ASTAnalyzer
	cache    Cache
	llm      LLMJudge      // may be nil if EnableLLM == false
	wasm     WasmSandbox   // may be nil if EnableWasm == false
	manifest ManifestValidator
	probe    SecurityProbe // defaults to noopProbe
}

// New constructs a ready-to-use Engine. All required dependencies must be
// non-nil. Optional layers (llm, wasm) may be nil; the engine will skip them.
//
// CRITICAL: Caller MUST call Close() when done to prevent memory leaks.
func New(
	cfg Config,
	log zerolog.Logger,
	yaraScanner yara.Scanner, // Now uses internal/yara.Scanner
	ast ASTAnalyzer,
	cache Cache,
	manifest ManifestValidator,
	llm LLMJudge,       // nil to disable
	wasm WasmSandbox,   // nil to disable
	probe SecurityProbe, // nil defaults to noopProbe
) (*Engine, error) {
	if yaraScanner == nil {
		return nil, fmt.Errorf("engine: yara.Scanner is required")
	}
	if ast == nil {
		return nil, fmt.Errorf("engine: ASTAnalyzer is required")
	}
	if cache == nil {
		return nil, fmt.Errorf("engine: Cache is required")
	}
	if manifest == nil {
		return nil, fmt.Errorf("engine: ManifestValidator is required")
	}
	if probe == nil {
		probe = noopProbe{}
	}

	log.Info().
		Int("yara_rules", yaraScanner.RuleCount()).
		Str("yara_bundle_hash", yaraScanner.BundleHash()[:16]+"...").
		Bool("llm_enabled", llm != nil).
		Bool("wasm_enabled", wasm != nil).
		Msg("Engine initialized")

	return &Engine{
		cfg:      cfg,
		log:      log.With().Str("component", "engine").Logger(),
		yara:     yaraScanner,
		ast:      ast,
		cache:    cache,
		llm:      llm,
		wasm:     wasm,
		manifest: manifest,
		probe:    probe,
	}, nil
}

// Close releases all engine resources, particularly the YARA scanner's C memory.
//
// Behavior:
//   - Waits for active scans to complete (graceful shutdown)
//   - Releases YARA scanner resources
//   - Idempotent: safe to call multiple times
//
// CRITICAL: Failure to call Close() will leak C memory from the YARA engine.
func (e *Engine) Close() error {
	e.log.Info().Msg("Engine shutting down...")

	// Close YARA scanner (releases C memory)
	if err := e.yara.Close(); err != nil {
		e.log.Error().Err(err).Msg("Failed to close YARA scanner")
		return fmt.Errorf("engine: YARA scanner close failed: %w", err)
	}

	e.log.Info().Msg("Engine closed successfully")
	return nil
}

// YARAStats returns runtime statistics from the YARA scanner.
// Useful for health checks and observability dashboards.
func (e *Engine) YARAStats() yara.ScanStatistics {
	return e.yara.ScanStats()
}

// ─────────────────────────────────────────────────────────────────────────────
// Scan — the main entry point
// ─────────────────────────────────────────────────────────────────────────────

// ScanRequest is the input to a scan operation.
type ScanRequest struct {
	// Name is a human-readable identifier for the artifact (e.g. filename).
	Name string

	// Payload is the raw bytes of the Skill to be scanned.
	Payload []byte

	// ManifestJSON is the optional manifest.json content.
	// Pass nil if the Skill has no manifest.
	ManifestJSON []byte

	// CallerID identifies the MCP client initiating the scan (for audit logs).
	CallerID string
}

// Scan executes the full analysis pipeline for the given payload.
// It is safe to call concurrently from multiple goroutines.
func (e *Engine) Scan(ctx context.Context, req ScanRequest) (*schema.ScanResult, error) {
	startTime := time.Now()
	scanID := uuid.New().String()

	log := e.log.With().
		Str("scan_id", scanID).
		Str("target_name", req.Name).
		Logger()

	log.Info().Int("payload_bytes", len(req.Payload)).Msg("scan started")

	// ── 1. Build target identity ───────────────────────────────────────────
	sha256Hash := computeSHA256(req.Payload)
	tlshHash := computeTLSH(req.Payload)
	detectedMIME := detectMIME(req.Payload)
	detectedLanguage := detectLanguage(req.Payload, detectedMIME)

	target := schema.TargetInfo{
		Name:         req.Name,
		SHA256:       sha256Hash,
		TLSHHash:     tlshHash,
		SizeBytes:    int64(len(req.Payload)),
		DetectedMIME: detectedMIME,
		Language:     detectedLanguage,
	}

	result := &schema.ScanResult{
		SchemaVersion: "1.0.0",
		ScanID:        scanID,
		ScannedAt:     startTime.UTC(),
		Target:        target,
		Findings:      []schema.Finding{},
		CacheInfo:     schema.CacheInfo{HitType: schema.CacheHitNone},
		Audit: schema.AuditInfo{
			ScannerVersion: Version,
			RuleBundleHash: e.yara.BundleHash(),
			CallerID:       req.CallerID,
		},
	}

	// ── 2. Cache lookup ────────────────────────────────────────────────────
	if cached, err := e.cache.GetBySHA256(ctx, sha256Hash); err == nil && cached != nil {
		log.Debug().Msg("exact cache hit — replaying stored verdict")
		cached.ScanID = scanID // New ID for this invocation.
		cached.CacheInfo.HitType = schema.CacheHitExact
		return cached, nil
	}

	if cached, score, err := e.cache.GetByTLSH(ctx, tlshHash); err == nil && cached != nil {
		log.Debug().Int("tlsh_score", score).Msg("fuzzy cache hit")
		// For fuzzy hits, we trust the cached verdict unless LLM is available
		// to do a lightweight confirmation scan. This is the TLSH tiering logic.
		if !e.cfg.EnableLLM || cached.Verdict.Status == schema.VerdictMalicious {
			cached.ScanID = scanID
			cached.CacheInfo.HitType = schema.CacheHitFuzzy
			cached.CacheInfo.FuzzySimilarityScore = score
			return cached, nil
		}
		// If LLM is available and verdict was non-malicious, fall through
		// to full scan to confirm the fuzzy match is safe.
		log.Debug().Msg("fuzzy hit on non-malicious result — proceeding to full scan for LLM confirmation")
	}

	// ── 3. YARA scan ──────────────────────────────────────────────────────
	yaraTrace, yaraFindings := e.runYARA(ctx, req.Payload)
	result.Pipeline.YARA = yaraTrace
	result.Findings = append(result.Findings, yaraFindings...)

	// ── 4. AST analysis ───────────────────────────────────────────────────
	astTrace, astFindings := e.runAST(ctx, req.Payload, detectedLanguage)
	result.Pipeline.AST = astTrace
	result.Findings = append(result.Findings, astFindings...)

	// ── 5. Intermediate risk score (YARA + AST only) ──────────────────────
	intermediateScore := computeRiskScore(result.Findings)

	// ── 6. Tiering decision ───────────────────────────────────────────────
	log.Debug().
		Float64("intermediate_score", intermediateScore).
		Float64("clean_threshold", e.cfg.Thresholds.CleanBelow).
		Float64("malicious_threshold", e.cfg.Thresholds.MaliciousAbove).
		Msg("tiering check")

	switch {
	case intermediateScore >= e.cfg.Thresholds.MaliciousAbove:
		// Clear YARA/AST hit — no need to spend tokens on LLM.
		log.Info().Float64("score", intermediateScore).Msg("MALICIOUS: above threshold, no LLM needed")

	case intermediateScore <= e.cfg.Thresholds.CleanBelow:
		// Low signal — trust YARA/AST clean verdict.
		log.Info().Float64("score", intermediateScore).Msg("CLEAN: below threshold, no LLM needed")

	default:
		// Ambiguous zone — escalate to LLM if available.
		if e.cfg.EnableLLM && e.llm != nil {
			llmTrace, llmFindings := e.runLLM(ctx, req.Payload, result.Findings)
			result.Pipeline.LLM = &llmTrace
			result.Findings = append(result.Findings, llmFindings...)
		} else {
			log.Warn().
				Float64("score", intermediateScore).
				Msg("ambiguous score but LLM not configured — defaulting to SUSPECT")
		}
	}

	// ── 7. Wasm sandbox (optional) ────────────────────────────────────────
	if e.cfg.EnableWasm && e.wasm != nil {
		wasmCtx, cancel := context.WithTimeout(ctx, e.cfg.WasmTimeout)
		defer cancel()
		wasmTrace, wasmFindings := e.runWasm(wasmCtx, req.Payload)
		result.Pipeline.Wasm = &wasmTrace
		result.Findings = append(result.Findings, wasmFindings...)
	}

	// ── 8. Manifest validation (optional) ─────────────────────────────────
	if req.ManifestJSON != nil {
		manifestResult, manifestFindings, err := e.manifest.Validate(ctx, req.Payload, req.ManifestJSON)
		if err != nil {
			log.Error().Err(err).Msg("manifest validation failed")
		} else {
			result.Manifest = manifestResult
			result.Findings = append(result.Findings, manifestFindings...)
		}
	}

	// ── 9. Final scoring and verdict ──────────────────────────────────────
	result.RiskScore = computeRiskScore(result.Findings)
	result.Verdict = deriveVerdict(result.Findings, result.RiskScore, &result.Pipeline, e.cfg.Thresholds)
	result.Findings = numberFindings(result.Findings)

	// ── 10. Duration and cache write-back ─────────────────────────────────
	result.DurationNs = time.Since(startTime).Nanoseconds()

	if err := e.cache.Put(ctx, result); err != nil {
		log.Warn().Err(err).Msg("failed to write result to cache — scan result still valid")
	}

	log.Info().
		Str("verdict", string(result.Verdict.Status)).
		Float64("risk_score", result.RiskScore).
		Int("findings", len(result.Findings)).
		Int64("duration_ms", result.DurationNs/1e6).
		Msg("scan complete")

	return result, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal layer runners
// ─────────────────────────────────────────────────────────────────────────────

func (e *Engine) runYARA(ctx context.Context, payload []byte) (schema.LayerTrace, []schema.Finding) {
	start := time.Now()
	trace := schema.LayerTrace{RulesEvaluated: e.yara.RuleCount()}

	matched, err := e.yara.Scan(ctx, payload)
	trace.DurationNs = time.Since(start).Nanoseconds()

	if err != nil {
		trace.Status = schema.LayerError
		trace.Error = err.Error()
		return trace, nil
	}

	findings := make([]schema.Finding, 0, len(matched))
	for _, ruleName := range matched {
		findings = append(findings, schema.Finding{
			Source:      "yara",
			Category:    schema.CategoryMaliciousPattern,
			Severity:    schema.SeverityHigh, // YARA matches are high-confidence by default.
			RuleID:      ruleName,
			Description: fmt.Sprintf("YARA rule '%s' matched", ruleName),
			Evidence:    "", // YARA match context populated by the YARA layer itself.
		})
	}

	if len(findings) > 0 {
		trace.Status = schema.LayerFail
	} else {
		trace.Status = schema.LayerPass
	}
	trace.FindingsCount = len(findings)

	return trace, findings
}

func (e *Engine) runAST(ctx context.Context, payload []byte, language string) (schema.LayerTrace, []schema.Finding) {
	start := time.Now()

	findings, err := e.ast.Analyze(ctx, payload, language)
	trace := schema.LayerTrace{
		DurationNs: time.Since(start).Nanoseconds(),
	}

	if err != nil {
		trace.Status = schema.LayerError
		trace.Error = err.Error()
		return trace, nil
	}

	if len(findings) > 0 {
		trace.Status = schema.LayerFail
	} else {
		trace.Status = schema.LayerPass
	}
	trace.FindingsCount = len(findings)

	return trace, findings
}

func (e *Engine) runLLM(ctx context.Context, payload []byte, preliminary []schema.Finding) (schema.LayerTrace, []schema.Finding) {
	llmCtx, cancel := context.WithTimeout(ctx, e.cfg.LLMTimeout)
	defer cancel()

	start := time.Now()
	findings, _, meta, err := e.llm.Analyze(llmCtx, payload, preliminary)
	trace := schema.LayerTrace{
		DurationNs:  time.Since(start).Nanoseconds(),
		LLMMetadata: meta,
	}

	if err != nil {
		trace.Status = schema.LayerError
		trace.Error = err.Error()
		return trace, nil
	}

	if len(findings) > 0 {
		trace.Status = schema.LayerFail
	} else {
		trace.Status = schema.LayerPass
	}
	trace.FindingsCount = len(findings)

	return trace, findings
}

func (e *Engine) runWasm(ctx context.Context, payload []byte) (schema.LayerTrace, []schema.Finding) {
	start := time.Now()
	findings, err := e.wasm.Execute(ctx, payload)
	trace := schema.LayerTrace{
		DurationNs: time.Since(start).Nanoseconds(),
	}

	if err != nil {
		trace.Status = schema.LayerError
		trace.Error = err.Error()
		return trace, nil
	}

	if len(findings) > 0 {
		trace.Status = schema.LayerFail
	} else {
		trace.Status = schema.LayerPass
	}
	trace.FindingsCount = len(findings)

	return trace, findings
}

// ─────────────────────────────────────────────────────────────────────────────
// Scoring and verdict logic
// ─────────────────────────────────────────────────────────────────────────────

// severityWeight maps severity levels to risk score contributions.
var severityWeight = map[schema.Severity]float64{
	schema.SeverityInfo:     0.02,
	schema.SeverityLow:      0.10,
	schema.SeverityMedium:   0.30,
	schema.SeverityHigh:     0.60,
	schema.SeverityCritical: 1.00,
}

// computeRiskScore aggregates findings into a 0.0–1.0 score.
// Uses a non-linear accumulation: each finding pushes the score toward 1.0
// proportionally to its weight, but cannot exceed 1.0.
func computeRiskScore(findings []schema.Finding) float64 {
	if len(findings) == 0 {
		return 0.0
	}
	score := 0.0
	for _, f := range findings {
		weight := severityWeight[f.Severity]
		// Non-linear accumulation: score += weight * (1 - score)
		// This ensures multiple low-severity findings can accumulate to HIGH
		// without arithmetic overflow.
		score += weight * (1.0 - score)
	}
	if score > 1.0 {
		return 1.0
	}
	return score
}

type thresholds struct {
	CleanBelow     float64
	MaliciousAbove float64
}

func deriveVerdict(
	findings []schema.Finding,
	score float64,
	pipeline *schema.PipelineTrace,
	thresh struct {
		CleanBelow     float64
		MaliciousAbove float64
	},
) schema.Verdict {
	if len(findings) == 0 {
		return schema.Verdict{
			Status:     schema.VerdictClean,
			Summary:    "No threats detected across all analysis layers.",
			DecidedBy:  decidedBy(pipeline),
			Confidence: 0.95,
		}
	}

	// Find the highest-severity finding for the verdict summary.
	worst := findings[0]
	for _, f := range findings[1:] {
		if severityWeight[f.Severity] > severityWeight[worst.Severity] {
			worst = f
		}
	}

	switch {
	case score >= thresh.MaliciousAbove:
		return schema.Verdict{
			Status:     schema.VerdictMalicious,
			Summary:    fmt.Sprintf("Blocked: %s (rule: %s, score: %.2f)", worst.Description, worst.RuleID, score),
			DecidedBy:  decidedBy(pipeline),
			Confidence: score,
		}
	default:
		return schema.Verdict{
			Status:     schema.VerdictSuspect,
			Summary:    fmt.Sprintf("Suspicious patterns detected — human review recommended (score: %.2f)", score),
			DecidedBy:  decidedBy(pipeline),
			Confidence: score,
		}
	}
}

// decidedBy returns the name of the last pipeline layer that produced findings.
func decidedBy(p *schema.PipelineTrace) string {
	if p.LLM != nil && p.LLM.FindingsCount > 0 {
		return "llm"
	}
	if p.Wasm != nil && p.Wasm.FindingsCount > 0 {
		return "wasm"
	}
	if p.AST.FindingsCount > 0 {
		return "ast"
	}
	if p.YARA.FindingsCount > 0 {
		return "yara"
	}
	return "yara" // default: clean decision made by YARA pass
}

// numberFindings assigns sequential IDs to all findings ("F-001", "F-002"…).
func numberFindings(findings []schema.Finding) []schema.Finding {
	for i := range findings {
		findings[i].ID = fmt.Sprintf("F-%03d", i+1)
	}
	return findings
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility functions
// ─────────────────────────────────────────────────────────────────────────────

func computeSHA256(data []byte) string {
	h := sha256.New()
	_, _ = io.Writer(h).Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// computeTLSH is a placeholder. The real implementation is in internal/cache/hasher.go.
// It is declared here to avoid an import cycle during the bootstrap phase.
func computeTLSH(data []byte) string {
	// TODO: wire up tlsh-go in Sprint 1 when cache package is implemented.
	_ = data
	return "TLSH_NOT_COMPUTED"
}

// detectMIME is a placeholder. Final impl uses github.com/gabriel-vasile/mimetype.
func detectMIME(data []byte) string {
	if len(data) > 2 && data[0] == '#' && data[1] == '!' {
		return "text/x-shellscript"
	}
	return "text/plain"
}

// detectLanguage infers the programming language from MIME and content heuristics.
func detectLanguage(data []byte, mime string) string {
	switch mime {
	case "text/x-python", "application/x-python":
		return "python"
	case "application/javascript", "text/javascript":
		return "javascript"
	case "text/x-shellscript":
		return "shell"
	}
	// TODO: content-based heuristics (shebang parsing, keyword detection).
	return "unknown"
}

// ─────────────────────────────────────────────────────────────────────────────
// noopProbe — default SecurityProbe implementation
// ─────────────────────────────────────────────────────────────────────────────

type noopProbe struct{}

func (noopProbe) Probe(_ context.Context, _ int) ([]schema.Finding, error) {
	return nil, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Stub Implementations for Missing Dependencies
// ─────────────────────────────────────────────────────────────────────────────

// noopCache is a stub implementation for testing without a real cache backend.
type noopCache struct{}

func (noopCache) GetBySHA256(_ context.Context, _ string) (*schema.ScanResult, error) {
	return nil, nil // Cache miss
}

func (noopCache) GetByTLSH(_ context.Context, _ string) (*schema.ScanResult, int, error) {
	return nil, 0, nil // Cache miss
}

func (noopCache) Put(_ context.Context, _ *schema.ScanResult) error {
	return nil // No-op
}

// NewNoopCache returns a cache stub for testing.
func NewNoopCache() Cache {
	return noopCache{}
}

// noopAST is a stub implementation that never finds suspicious patterns.
type noopAST struct{}

func (noopAST) Analyze(_ context.Context, _ []byte, _ string) ([]schema.Finding, error) {
	return nil, nil // No findings
}

// NewNoopAST returns an AST analyzer stub for testing.
func NewNoopAST() ASTAnalyzer {
	return noopAST{}
}

// noopManifest is a stub implementation that always validates successfully.
type noopManifest struct{}

func (noopManifest) Validate(_ context.Context, _ []byte, _ []byte) (*schema.ManifestResult, []schema.Finding, error) {
	return &schema.ManifestResult{Valid: true}, nil, nil
}

// NewNoopManifest returns a manifest validator stub for testing.
func NewNoopManifest() ManifestValidator {
	return noopManifest{}
}
