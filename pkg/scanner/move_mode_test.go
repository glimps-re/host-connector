package scanner

import (
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/quarantine/mock"
)

// A move action that cannot be built must not vanish silently: the connector
// refuses to start.
func TestNewConnector_aBadMoveModeIsRefused(t *testing.T) {
	_, err := NewConnector(Config{
		Actions:  Actions{Move: true},
		MoveTo:   t.TempDir(),
		MoveFrom: t.TempDir(),
		MoveMode: "rnme",
		WorkDir:  t.TempDir(),
	}, &mock.QuarantineMock{}, nil)
	if err == nil || !strings.Contains(err.Error(), "move") {
		t.Fatalf("NewConnector() error = %v, want a refusal naming the move action", err)
	}
}
