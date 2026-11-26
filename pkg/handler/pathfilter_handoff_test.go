package handler

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	gdetectMock "github.com/glimps-re/go-gdetect/pkg/gdetect/mock"
)

// lockedBuffer is the console of a connector that tests read after it is closed.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) Close() error { return nil }

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// The path rules of the configuration reach the connector that prepare and
// newConnector build: a forbidden file is refused with no analysis.
func TestPathFilter_reachesTheConnectorBuiltFromTheConfiguration(t *testing.T) {
	watched := t.TempDir()
	conf := validConf(t, watched)
	conf.Actions.Print = true
	conf.FilepathFilter.ForbiddenPaths = []string{`\.exe$`}
	h := new(Handler)
	h.submitter = &gdetectMock.MockGDetectSubmitter{ReconfigureMock: func(context.Context, gdetect.ClientConfig) error { return nil }}
	p, err := h.prepare(conf)
	if err != nil {
		t.Fatalf("prepare() error = %v", err)
	}
	console := &lockedBuffer{}
	c, err := h.newConnector(conf, p, console, nil, nil)
	if err != nil {
		t.Fatalf("newConnector() error = %v", err)
	}
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(watched, "a.exe")
	if err = os.WriteFile(file, []byte("X"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = c.ScanFile(t.Context(), file); err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}
	c.Close(t.Context())
	if got := console.String(); !strings.Contains(got, "reason: filtered-filepath") {
		t.Errorf("console = %q, want the file refused for its path", got)
	}
}
