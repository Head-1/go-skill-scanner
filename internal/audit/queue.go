package audit

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"

	"github.com/Head-1/go-skill-scanner/pkg/schema"
)

type QueueManager struct {
	db *sql.DB
}

func NewQueueManager(dbPath string) (*QueueManager, error) {
	dsn := "file:" + dbPath + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit db: %w", err)
	}

	schema := `
	CREATE TABLE IF NOT EXISTS scan_queue (
		id TEXT PRIMARY KEY,
		payload BLOB,
		status TEXT,
		created_at DATETIME,
		updated_at DATETIME,
		retry_count INTEGER DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_queue_status ON scan_queue(status);
	
	CREATE TABLE IF NOT EXISTS audit_logs (
		scan_id TEXT PRIMARY KEY,
		verdict TEXT,
		duration_ns INTEGER,
		timestamp DATETIME
	);
	CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);`

	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	return &QueueManager{db: db}, nil
}

func (q *QueueManager) LogResult(res *schema.ScanResult) error {
	_, err := q.db.Exec(
		`INSERT INTO audit_logs (scan_id, verdict, duration_ns, timestamp) VALUES (?, ?, ?, ?)`,
		res.ScanID, string(res.Verdict.Status), res.DurationNs, res.ScannedAt,
	)
	return err
}

func (q *QueueManager) Close() error {
	return q.db.Close()
}
