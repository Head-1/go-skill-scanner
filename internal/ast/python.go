package ast

import (
	"context"
	"fmt"

	"github.com/Head-1/go-skill-scanner/pkg/schema"
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/python"
)

func (a *astAnalyzer) analyzePython(payload []byte) ([]schema.Finding, error) {
	parser := sitter.NewParser()
	parser.SetLanguage(python.GetLanguage())

	tree, err := parser.ParseCtx(context.Background(), nil, payload)
	if err != nil {
		return nil, err
	}

	// Query de precisão para chamadas perigosas
	queryString := `
		(call
			function: [
				(identifier) @func (#match? @func "^(eval|exec)$")
				(attribute
					object: (identifier) @obj (#match? @obj "^(os|subprocess)$")
					attribute: (identifier) @attr (#match? @attr "^(system|run|Popen)$")
				) @func
			]
		) @call_node
	`

	q, _ := sitter.NewQuery([]byte(queryString), python.GetLanguage())
	cursor := sitter.NewQueryCursor()
	cursor.Exec(q, tree.RootNode())

	var findings []schema.Finding
	for {
		m, ok := cursor.NextMatch()
		if !ok { break }

		for _, capture := range m.Captures {
			if q.CaptureNameForId(capture.Index) != "call_node" { continue }
			
			content := string(payload[capture.Node.StartByte():capture.Node.EndByte()])
			findings = append(findings, schema.Finding{
				RuleID:      "AST_PY_DANGEROUS_CODE",
				Severity:    schema.SeverityCritical,
				Category:    schema.CategoryCodeExecution,
				Description: fmt.Sprintf("Execução de código perigosa detectada: %s", content),
				Evidence:    content,
			})
		}
	}
	return findings, nil
}
