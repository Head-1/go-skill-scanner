package audit

import (
	"context"
	"database/sql"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/Head-1/go-skill-scanner/pkg/schema"
	_ "github.com/mattn/go-sqlite3" // Driver necessário
)

type SQLiteStore struct {
	db        *sql.DB
	lastHash  string
	mu        sync.Mutex
}

func NewSQLiteStore(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	// Criamos a tabela de Auditoria HCA
	// O campo 'prev_hash' é a âncora da nossa corrente forense
	query := `
	CREATE TABLE IF NOT EXISTS audit_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id TEXT,
		target_name TEXT,
		findings_count INTEGER,
		prev_hash TEXT,
		current_hash TEXT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	
	if _, err := db.Exec(query); err != nil {
		return nil, err
	}

	store := &SQLiteStore{db: db}
	// Recupera o último hash para continuar a corrente
	store.lastHash, _ = store.GetLastHash()
	
	return store, nil
}

func (s *SQLiteStore) SaveResult(ctx context.Context, res *schema.ScanResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. Gerar o Hash do registro atual vinculado ao anterior (HCA Chain)
	dataToHash := fmt.Sprintf("%s|%s|%d|%s", res.ScanID, res.Target.Name, len(res.Findings), s.lastHash)
	hash := sha256.Sum256([]byte(dataToHash))
	currentHash := hex.EncodeToString(hash[:])

	// 2. Persistir no Oráculo (Mimir)
	_, err := s.db.ExecContext(ctx, 
		"INSERT INTO audit_logs (scan_id, target_name, findings_count, prev_hash, current_hash) VALUES (?, ?, ?, ?, ?)",
		res.ScanID, res.Target.Name, len(res.Findings), s.lastHash, currentHash,
	)

	if err == nil {
		s.lastHash = currentHash
	}

	return err
}

func (s *SQLiteStore) GetLastHash() (string, error) {
	var hash string
	err := s.db.QueryRow("SELECT current_hash FROM audit_logs ORDER BY id DESC LIMIT 1").Scan(&hash)
	if err == sql.ErrNoRows {
		return "00000000000000000000000000000000", nil // Gênese da corrente
	}
	return hash, err
}
