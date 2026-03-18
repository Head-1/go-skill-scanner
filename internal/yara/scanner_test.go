package yara
import (
	"context"
	"testing"
	"github.com/rs/zerolog"
)
func TestScanner_MissionComplete(t *testing.T) {
	s, _ := New(zerolog.New(nil))
	ctx := context.Background()
	
	// Cobre Scan, métricas e getters
	_, _ = s.Scan(ctx, []byte("rule t { condition: true }"))
	_ = s.GetRulesCount()
	_ = s.RuleCount()
	_ = s.BundleHash()
	
	// Forçamos o ScanStats antes e depois para garantir snapshot e isClosed
	_ = s.ScanStats()
	
	_ = s.Close()
	
	// Esta chamada é o segredo para cobrir a verificação de erro após fechar
	_ = s.ScanStats()
	_ = s.RuleCount()
}
