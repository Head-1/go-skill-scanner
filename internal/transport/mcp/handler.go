package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Head-1/go-skill-scanner/internal/engine"
	"github.com/Head-1/go-skill-scanner/internal/yara"
	"github.com/Head-1/go-skill-scanner/pkg/schema"
	"github.com/rs/zerolog"
)

type MCPHandler struct {
	scanner yara.Scanner
	engine  *engine.Engine
	logger  zerolog.Logger
}

func NewMCPHandler(scanner yara.Scanner, engine *engine.Engine, logger zerolog.Logger) *MCPHandler {
	return &MCPHandler{
		scanner: scanner,
		engine:  engine,
		logger:  logger.With().Str("component", "mcp-handler").Logger(),
	}
}

func (h *MCPHandler) HandleCallTool(ctx context.Context, rawParams json.RawMessage) (interface{}, error) {
	var req CallToolRequest
	if err := json.Unmarshal(rawParams, &req); err != nil {
		return nil, &RPCError{Code: -32602, Message: "Invalid params"}
	}

	if req.Name != "gss_scan" {
		return nil, &RPCError{Code: -32601, Message: "Method not found"}
	}

	argsBytes, _ := json.Marshal(req.Arguments)
	var scanReq GSSScanRequest
	if err := json.Unmarshal(argsBytes, &scanReq); err != nil {
		return nil, &RPCError{Code: -32602, Message: "Invalid arguments"}
	}

	result, err := h.executeScan(ctx, &scanReq)
	if err != nil {
		return &ToolResponse{
			Content: []ContentItem{{Type: "text", Text: fmt.Sprintf(`{"error": "%v"}`, err)}},
			IsError: true,
		}, nil
	}

	return &ToolResponse{
		Content: []ContentItem{{Type: "text", Text: result}},
		IsError: false,
	}, nil
}

func (h *MCPHandler) executeScan(ctx context.Context, req *GSSScanRequest) (string, error) {
	timeout := 30 * time.Second
	if req.Options.TimeoutMs > 0 {
		timeout = time.Duration(req.Options.TimeoutMs) * time.Millisecond
	}

	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var payload []byte
	var targetName string
	var err error

	if req.PayloadType == "file" {
		targetName = req.Payload
		payload, err = os.ReadFile(req.Payload)
		if err != nil {
			return "", err
		}
	} else {
		targetName = "mcp-payload"
		payload = []byte(req.Payload)
	}

	res, err := h.engine.Scan(scanCtx, engine.ScanRequest{
		Name:     targetName,
		Payload:  payload,
		CallerID: "aegis-mcp",
	})
	if err != nil {
		return "", err
	}

	aegisResult := h.convertToAEGISFormat(res, time.Since(res.ScannedAt))
	out, _ := json.Marshal(aegisResult)
	return string(out), nil
}

func (h *MCPHandler) convertToAEGISFormat(res *schema.ScanResult, dur time.Duration) AEGISScanResult {
	verdict := "CLEAN"
	if res.Pipeline.YARA.Status == schema.LayerFail {
		verdict = "SUSPECT"
	}

	aegisRes := AEGISScanResult{
		Verdict:    verdict,
		Confidence: 1.0,
		ScanID:     res.ScanID,
		Timestamp:  time.Now(),
		ScanStats: ScanStats{
			DurationMs:   dur.Milliseconds(),
			YARAMatches:  len(res.Findings),
			BytesScanned: int64(len(res.Findings)),
		},
	}

	for _, f := range res.Findings {
		aegisRes.Findings = append(aegisRes.Findings, AEGISFinding{
			Rule:     f.RuleID,
			Severity: string(f.Severity),
			Evidence: f.Evidence,
		})
	}
	return aegisRes
}

func (h *MCPHandler) HandleListTools() interface{} {
	return map[string]interface{}{"tools": []interface{}{
		map[string]interface{}{
			"name":        "gss_scan",
			"description": "Scan code/payload for malware",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"payload":      map[string]string{"type": "string"},
					"payload_type": map[string]string{"type": "string"},
				},
				"required": []string{"payload"},
			},
		},
	}}
}
