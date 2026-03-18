package mcp

import (
	"encoding/json"
	"time"
)

type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	ID      interface{}     `json:"id"`
}

type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
	ID      interface{} `json:"id"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Satisfaz a interface 'error' do Go
func (e *RPCError) Error() string {
	return e.Message
}

type CallToolRequest struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

type GSSScanRequest struct {
	Payload     string `json:"payload"`
	PayloadType string `json:"payload_type"`
	Options     struct {
		EnableAST bool `json:"enable_ast,omitempty"`
		TimeoutMs int  `json:"timeout_ms,omitempty"`
	} `json:"options,omitempty"`
}

type ToolResponse struct {
	Content []ContentItem `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

type ContentItem struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type AEGISScanResult struct {
	Verdict    string         `json:"verdict"`
	Confidence float64        `json:"confidence"`
	Findings   []AEGISFinding `json:"findings,omitempty"`
	ScanStats  ScanStats      `json:"scan_stats"`
	ScanID     string         `json:"scan_id"`
	Timestamp  time.Time      `json:"timestamp"`
}

type AEGISFinding struct {
	Rule       string  `json:"rule"`
	Severity   string  `json:"severity"`
	Line       int     `json:"line,omitempty"`
	Evidence   string  `json:"evidence,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
}

type ScanStats struct {
	DurationMs   int64 `json:"duration_ms"`
	YARAMatches  int   `json:"yara_matches"`
	ASTFindings  int   `json:"ast_findings"`
	BytesScanned int64 `json:"bytes_scanned"`
}

type Config struct {
	Addr string
}
