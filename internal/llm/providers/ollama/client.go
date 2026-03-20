package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/Head-1/go-skill-scanner/pkg/schema"
)

type Config struct {
	URL   string
	Model string
}

type Client struct {
	cfg Config
}

func NewClient(cfg Config) *Client {
	if cfg.URL == "" {
		cfg.URL = "http://localhost:11434/api/generate"
	}
	return &Client{cfg: cfg}
}

func (c *Client) Name() string { return "ollama" }

func (c *Client) Analyze(ctx context.Context, code []byte, findings []schema.Finding) (*schema.Verdict, error) {
	// Prompt de Sistema focado em Segurança
	prompt := fmt.Sprintf(`Analise o seguinte código e os alertas detectados:
Código: %s
Alertas prévios: %+v
Responda APENAS em JSON no formato: {"status": "CLEAN|SUSPECT|MALICIOUS", "summary": "razão"}`, string(code), findings)

	reqBody, _ := json.Marshal(map[string]interface{}{
		"model":  c.cfg.Model,
		"prompt": prompt,
		"stream": false,
		"format": "json",
	})

	req, _ := http.NewRequestWithContext(ctx, "POST", c.cfg.URL, bytes.NewBuffer(reqBody))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var res struct {
		Response string `json:"response"`
	}
	json.NewDecoder(resp.Body).Decode(&res)

	var verdict schema.Verdict
	if err := json.Unmarshal([]byte(res.Response), &verdict); err != nil {
		return nil, err
	}

	return &verdict, nil
}
