package schema

import "time"

const (
	StatusPending   = "PENDING"
	StatusRunning   = "RUNNING"
	StatusCompleted = "COMPLETED"
	StatusFailed    = "FAILED"
)

type VerdictStatus string
const (
	VerdictClean     VerdictStatus = "CLEAN"
	VerdictSuspect   VerdictStatus = "SUSPECT"
	VerdictMalicious VerdictStatus = "MALICIOUS"
)

type FindingCategory string
const (
	CategoryMaliciousPattern FindingCategory = "MALICIOUS_PATTERN"
	CategoryCodeExecution   FindingCategory = "CODE_EXECUTION"
	CategoryDataExfiltration FindingCategory = "DATA_EXFILTRATION"
)

type Severity string
const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

type ScanResult struct {
	ScanID     string          `json:"scan_id"`
	ScannedAt  time.Time       `json:"scanned_at"`
	DurationNs int64           `json:"duration_ns"`
	Target     TargetInfo      `json:"target"`
	Verdict    Verdict         `json:"verdict"`
	RiskScore  float64         `json:"risk_score"`
	Findings   []Finding       `json:"findings"`
	Pipeline   PipelineTrace   `json:"pipeline"`
}

type TargetInfo struct {
	Name      string `json:"name"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	Language  string `json:"language"`
}

type Verdict struct {
	Status     VerdictStatus `json:"status"`
	Summary    string        `json:"summary"`
	Confidence float64       `json:"confidence"`
}

type Finding struct {
	ID          string          `json:"id"`
	Source      string          `json:"source"`
	Category    FindingCategory `json:"category"`
	Severity    Severity        `json:"severity"`
	RuleID      string          `json:"rule_id"`
	Description string          `json:"description"`
	Evidence    string          `json:"evidence"`
}

type PipelineTrace struct {
	YARA LayerTrace `json:"yara"`
	AST  LayerTrace `json:"ast"`
}

type LayerTrace struct {
	Status     string `json:"status"`
	DurationNs int64  `json:"duration_ns"`
	Error      string `json:"error,omitempty"`
}

type ManifestResult struct {
	Valid bool `json:"valid"`
}
