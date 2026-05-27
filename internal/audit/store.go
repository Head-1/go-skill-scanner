package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/Head-1/go-skill-scanner/pkg/schema"
	_ "github.com/mattn/go-sqlite3"
)

type SQLiteStore struct {
	db            *sql.DB
	lastHash      string // hash da última linha da tabela audit_logs
	lastEventHash string // hash da última linha da tabela events_log
	mu            sync.Mutex
}

func NewSQLiteStore(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	// Tabela para resultados de scan
	queryAudit := `
	CREATE TABLE IF NOT EXISTS audit_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id TEXT NOT NULL,
		target_name TEXT NOT NULL,
		verdict TEXT NOT NULL,
		findings_count INTEGER,
		rule_bundle_hash TEXT,
		prev_hash TEXT,
		current_hash TEXT NOT NULL,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	if _, err := db.Exec(queryAudit); err != nil {
		return nil, err
	}

	// Tabela para registros arbitrários (eventos)
	queryEvents := `
	CREATE TABLE IF NOT EXISTS events_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		record_type TEXT NOT NULL,
		payload TEXT NOT NULL,
		scan_id TEXT,
		prev_hash TEXT,
		current_hash TEXT NOT NULL,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	if _, err := db.Exec(queryEvents); err != nil {
		return nil, err
	}

	store := &SQLiteStore{db: db}

	// Recupera último hash da audit_logs
	hash, err := store.getLastHash("audit_logs")
	if err != nil {
		store.lastHash = "0000000000000000000000000000000000000000000000000000000000000000"
	} else {
		store.lastHash = hash
	}

	// Recupera último hash da events_log
	eventHash, err := store.getLastHash("events_log")
	if err != nil {
		store.lastEventHash = "0000000000000000000000000000000000000000000000000000000000000000"
	} else {
		store.lastEventHash = eventHash
	}

	return store, nil
}

func (s *SQLiteStore) getLastHash(table string) (string, error) {
	var hash string
	err := s.db.QueryRow(fmt.Sprintf("SELECT current_hash FROM %s ORDER BY id DESC LIMIT 1", table)).Scan(&hash)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return hash, err
}

func (s *SQLiteStore) SaveResult(ctx context.Context, res *schema.ScanResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	payload := fmt.Sprintf("%s|%s|%s|%s|%s",
		res.ScanID,
		res.Target.Name,
		res.Verdict.Status,
		res.Audit.RuleBundleHash,
		s.lastHash,
	)
	hash := sha256.Sum256([]byte(payload))
	currentHash := hex.EncodeToString(hash[:])

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_logs (scan_id, target_name, verdict, findings_count, rule_bundle_hash, prev_hash, current_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		res.ScanID, res.Target.Name, res.Verdict.Status, len(res.Findings),
		res.Audit.RuleBundleHash, s.lastHash, currentHash,
	)

	if err == nil {
		s.lastHash = currentHash
	}
	return err
}

func (s *SQLiteStore) StoreRecord(ctx context.Context, recordType string, payload interface{}, scanID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	data := fmt.Sprintf("%s|%s|%s|%s",
		recordType,
		string(payloadJSON),
		scanID,
		s.lastEventHash,
	)
	hash := sha256.Sum256([]byte(data))
	currentHash := hex.EncodeToString(hash[:])

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO events_log (record_type, payload, scan_id, prev_hash, current_hash)
		VALUES (?, ?, ?, ?, ?)`,
		recordType, string(payloadJSON), scanID, s.lastEventHash, currentHash,
	)

	if err == nil {
		s.lastEventHash = currentHash
	}
	return err
}

func (s *SQLiteStore) GetLastHash() (string, error) {
	var hash string
	err := s.db.QueryRow("SELECT current_hash FROM audit_logs ORDER BY id DESC LIMIT 1").Scan(&hash)
	if err == sql.ErrNoRows {
		return "0000000000000000000000000000000000000000000000000000000000000000", nil
	}
	return hash, err
}

func (s *SQLiteStore) GetLastEventHash() (string, error) {
	var hash string
	err := s.db.QueryRow("SELECT current_hash FROM events_log ORDER BY id DESC LIMIT 1").Scan(&hash)
	if err == sql.ErrNoRows {
		return "0000000000000000000000000000000000000000000000000000000000000000", nil
	}
	return hash, err
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}
