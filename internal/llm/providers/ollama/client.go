package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Head-1/go-skill-scanner/pkg/schema"
)

type Config struct {
	URL     string
	Model   string
	Timeout time.Duration
}

type Client struct {
	cfg  Config
	http *http.Client
}

func NewClient(cfg Config) *Client {
	if cfg.URL == "" {
		cfg.URL = "http://localhost:11434/api/generate"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 45 * time.Second // Análise profunda exige fôlego
	}
	return &Client{
		cfg: cfg,
		http: &http.Client{Timeout: cfg.Timeout},
	}
}

func (c *Client) Name() string { return "ollama" }

func (c *Client) Analyze(ctx context.Context, code []byte, findings []schema.Finding) (*schema.Verdict, error) {
	// Prompt de Sistema com restrição gramatical
	systemPrompt := `[Sovereign Security Engine]
Analise a intenção do código e os alertas dos Tiers 1/2.
Responda estritamente em JSON: {"status": "CLEAN|SUSPECT|MALICIOUS", "summary": "razão"}`

	prompt := fmt.Sprintf("%s\n\nCódigo:\n%s\n\nAlertas:\n%+v", systemPrompt, string(code), findings)

	reqBody, _ := json.Marshal(map[string]interface{}{
		"model":  c.cfg.Model,
		"prompt": prompt,
		"stream": false,
		"format": "json", // Força o Ollama a validar a saída JSON
		"options": map[string]interface{}{
			"temperature": 0.1,
			"num_ctx":     4096,
		},
	})

	req, err := http.NewRequestWithContext(ctx, "POST", c.cfg.URL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ollama unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ollama error status: %d", resp.StatusCode)
	}

	var res struct {
		Response string `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}

	var verdict schema.Verdict
	if err := json.Unmarshal([]byte(res.Response), &verdict); err != nil {
		return nil, fmt.Errorf("ia output corruption: %w", err)
	}

	return &verdict, nil
}
