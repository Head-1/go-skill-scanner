package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"sync"

	"github.com/Head-1/go-skill-scanner/pkg/schema"
	_ "github.com/mattn/go-sqlite3"
)

type SQLiteStore struct {
	db *sql.DB
	mu sync.Mutex // Garante linearidade no encadeamento de hashes
}

func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite3", dbPath+"?_journal=WAL&_sync=NORMAL")
	if err != nil {
		return nil, err
	}

	// Schema com suporte a HCA (audit_root_hash)
	schemaSQL := `
	CREATE TABLE IF NOT EXISTS audit_trail (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id TEXT UNIQUE,
		target_sha256 TEXT,
		verdict TEXT,
		previous_hash TEXT,
		audit_root_hash TEXT,
		payload_summary TEXT,
		created_at DATETIME
	);
	CREATE INDEX IF NOT EXISTS idx_scan_id ON audit_trail(scan_id);`

	if _, err := db.Exec(schemaSQL); err != nil {
		return nil, err
	}

	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) SaveResult(ctx context.Context, res *schema.ScanResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	lastHash, err := s.GetLastHash()
	if err != nil {
		return err
	}

	// Lógica HCA: Hash(ScanID + Verdict + PreviousHash)
	currentData := fmt.Sprintf("%s:%s:%s", res.ScanID, string(res.Verdict.Status), lastHash)
	newHash := fmt.Sprintf("%x", sha256.Sum256([]byte(currentData)))

	query := `INSERT INTO audit_trail 
		(scan_id, target_sha256, verdict, previous_hash, audit_root_hash, created_at) 
		VALUES (?, ?, ?, ?, ?, ?)`

	_, err = s.db.ExecContext(ctx, query, 
		res.ScanID, 
		res.Target.SHA256, 
		string(res.Verdict.Status), 
		lastHash, 
		newHash, 
		res.ScannedAt)

	return err
}

func (s *SQLiteStore) GetLastHash() (string, error) {
	var lastHash string
	err := s.db.QueryRow("SELECT audit_root_hash FROM audit_trail ORDER BY id DESC LIMIT 1").Scan(&lastHash)
	if err == sql.ErrNoRows {
		return "GENESIS_BLOCK", nil
	}
	return lastHash, err
}
