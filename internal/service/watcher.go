package service

import (
	"context"
	"os"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"
	"github.com/Head-1/go-skill-scanner/internal/engine"
)

type Watcher struct {
	log    zerolog.Logger
	engine *engine.Engine
}

func NewWatcher(log zerolog.Logger, eng *engine.Engine) *Watcher {
	return &Watcher{
		log:    log.With().Str("component", "watcher").Logger(),
		engine: eng,
	}
}

func (w *Watcher) Watch(ctx context.Context, path string) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()

	err = watcher.Add(path)
	if err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case event, ok := <-watcher.Events:
			if !ok { return nil }
			if event.Has(fsnotify.Write) {
				ext := filepath.Ext(event.Name)
				if ext == ".py" || ext == ".sh" {
					payload, _ := os.ReadFile(event.Name)
					res, _ := w.engine.ScanFile(ctx, engine.ScanRequest{
						Name:    event.Name,
						Payload: payload,
					})
					if res != nil && res.Verdict.Status == "MALICIOUS" {
						w.log.Warn().Str("file", event.Name).Msg("🚨 AMEAÇA DETECTADA NO MONITOR")
					}
				}
			}
		}
	}
}
