package yara_test

import (
	"context"
	"testing"
	"time"

	"github.com/Head-1/go-skill-scanner/internal/yara"
	"github.com/rs/zerolog"
)

// ─────────────────────────────────────────────────────────────────────────────
// Interface Contract Tests
//
// These tests verify that both the full scanner and the stub satisfy
// the Scanner interface contract.
// ─────────────────────────────────────────────────────────────────────────────


func TestScanner_BasicLifecycle(t *testing.T) {
	log := zerolog.Nop()

	scanner, err := yara.New(log)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer scanner.Close()

	// Verify scanner is initialized
	if scanner.RuleCount() < 0 {
		t.Errorf("RuleCount() returned negative value: %d", scanner.RuleCount())
	}

	bundleHash := scanner.BundleHash()
	if bundleHash == "" {
		t.Error("BundleHash() returned empty string")
	}
}

func TestScanner_ScanEmptyPayload(t *testing.T) {
	log := zerolog.Nop()

	scanner, err := yara.New(log)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer scanner.Close()

	ctx := context.Background()
	matches, err := scanner.Scan(ctx, []byte{})
	if err != nil {
		t.Fatalf("Scan() failed on empty payload: %v", err)
	}

	// Empty payload should not match any rules
	if matches == nil {
		t.Error("Scan() returned nil matches (expected empty slice)")
	}
	if len(matches) != 0 {
		t.Errorf("Scan() returned %d matches on empty payload (expected 0)", len(matches))
	}
}

func TestScanner_ScanCleanPayload(t *testing.T) {
	log := zerolog.Nop()

	scanner, err := yara.New(log)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer scanner.Close()

	// Benign payload (unlikely to match malware rules)
	payload := []byte("Hello, World! This is a clean test payload.")

	ctx := context.Background()
	matches, err := scanner.Scan(ctx, payload)
	if err != nil {
		t.Fatalf("Scan() failed on clean payload: %v", err)
	}

	if matches == nil {
		t.Error("Scan() returned nil matches (expected empty slice)")
	}

	// We can't assert len(matches) == 0 because we don't control the rule corpus
	// (it's embedded and may contain overly broad rules).
	// Just verify matches is a valid slice.
	t.Logf("Clean payload scan result: %d matches", len(matches))
}

func TestScanner_ContextCancellation(t *testing.T) {
	log := zerolog.Nop()

	scanner, err := yara.New(log)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer scanner.Close()

	// Create a context that's already canceled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	payload := []byte("test payload")
	_, err = scanner.Scan(ctx, payload)

	if err == nil {
		t.Error("Scan() should fail with canceled context")
	}

	if err != context.Canceled {
		t.Errorf("Expected context.Canceled, got: %v", err)
	}
}

func TestScanner_ContextTimeout(t *testing.T) {
	log := zerolog.Nop()

	scanner, err := yara.New(log)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer scanner.Close()

	// Create a context with a very short timeout
	// NOTE: This test is best-effort because go-yara doesn't support
	// mid-scan cancellation. The timeout will only trigger if the scan
	// hasn't started yet.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	time.Sleep(10 * time.Millisecond) // Ensure timeout has fired

	payload := []byte("test payload")
	_, err = scanner.Scan(ctx, payload)

	// We expect either context.DeadlineExceeded or success
	// (depending on whether the scan started before timeout)
	if err != nil && err != context.DeadlineExceeded {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestScanner_ScanAfterClose(t *testing.T) {
	log := zerolog.Nop()

	scanner, err := yara.New(log)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Close the scanner
	if err := scanner.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}

	// Attempt to scan after close
	ctx := context.Background()
	_, err = scanner.Scan(ctx, []byte("test"))

	if err == nil {
		t.Error("Scan() should fail after Close()")
	}
}

func TestScanner_CloseIdempotent(t *testing.T) {
	log := zerolog.Nop()

	scanner, err := yara.New(log)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Close multiple times
	for i := 0; i < 3; i++ {
		if err := scanner.Close(); err != nil {
			t.Errorf("Close() call %d failed: %v", i+1, err)
		}
	}
}

func TestScanner_ScanStats(t *testing.T) {
	log := zerolog.Nop()

	scanner, err := yara.New(log)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer scanner.Close()

	// Initial stats should be zero
	stats := scanner.ScanStats()
	if stats.TotalScans != 0 {
		t.Errorf("TotalScans should be 0, got %d", stats.TotalScans)
	}

	// Perform a scan
	ctx := context.Background()
	payload := []byte("test payload")
	_, err = scanner.Scan(ctx, payload)
	if err != nil {
		t.Fatalf("Scan() failed: %v", err)
	}

	// Stats should be updated
	stats = scanner.ScanStats()
	if stats.TotalScans != 1 {
		t.Errorf("TotalScans should be 1, got %d", stats.TotalScans)
	}
	if stats.TotalBytesScanned != uint64(len(payload)) {
		t.Errorf("TotalBytesScanned should be %d, got %d", len(payload), stats.TotalBytesScanned)
	}
	if stats.AvgScanDurationMs < 0 {
		t.Errorf("AvgScanDurationMs should be non-negative, got %f", stats.AvgScanDurationMs)
	}
}

func TestScanner_ConcurrentScans(t *testing.T) {
	log := zerolog.Nop()

	scanner, err := yara.New(log)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer scanner.Close()

	// Run multiple scans concurrently
	const numScans = 10
	done := make(chan bool, numScans)

	for i := 0; i < numScans; i++ {
		go func(id int) {
			ctx := context.Background()
			payload := []byte("concurrent scan test")
			_, err := scanner.Scan(ctx, payload)
			if err != nil {
				t.Errorf("Concurrent scan %d failed: %v", id, err)
			}
			done <- true
		}(i)
	}

	// Wait for all scans to complete
	for i := 0; i < numScans; i++ {
		<-done
	}

	// Verify stats
	stats := scanner.ScanStats()
	if stats.TotalScans != numScans {
		t.Errorf("TotalScans should be %d, got %d", numScans, stats.TotalScans)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Benchmark Tests
// ─────────────────────────────────────────────────────────────────────────────

func BenchmarkScanner_SmallPayload(b *testing.B) {
	log := zerolog.Nop()
	scanner, err := yara.New(log)
	if err != nil {
		b.Fatalf("New() failed: %v", err)
	}
	defer scanner.Close()

	payload := []byte("small test payload")
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = scanner.Scan(ctx, payload)
	}
}

func BenchmarkScanner_LargePayload(b *testing.B) {
	log := zerolog.Nop()
	scanner, err := yara.New(log)
	if err != nil {
		b.Fatalf("New() failed: %v", err)
	}
	defer scanner.Close()

	// 1MB payload
	payload := make([]byte, 1024*1024)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = scanner.Scan(ctx, payload)
	}
}
