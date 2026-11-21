package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/plugins"
	"github.com/glimps-re/host-connector/pkg/quarantine"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

// sessionContext is the connector as the plugin sees it at Init.
type sessionContext struct {
	*scanner.Connector
	logger *slog.Logger
}

var _ plugins.HCContext = (*sessionContext)(nil)

func (s *sessionContext) GetLogger() *slog.Logger        { return s.logger }
func (s *sessionContext) GetConsoleLogger() *slog.Logger { return s.logger }

func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

func filesIn(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if !e.IsDir() && !strings.HasPrefix(e.Name(), quarantine.TempPrefix) {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out
}

func reportsIn(t *testing.T, dir string) int { return len(filesIn(t, dir)) }
