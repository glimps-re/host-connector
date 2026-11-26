package scanner

import "testing"

func TestConnector_pendingFilesIsZeroWithoutMonitoring(t *testing.T) {
	c := &Connector{}
	if got := c.PendingFiles("/in/tom"); got != 0 {
		t.Errorf("PendingFiles() = %d, want 0 when nothing is monitored (scan mode)", got)
	}
	c.config.PendingFiles = func(dir string) int {
		if dir != "/in/tom" {
			t.Errorf("dir = %q", dir)
		}
		return 4
	}
	if got := c.PendingFiles("/in/tom"); got != 4 {
		t.Errorf("PendingFiles() = %d, want what the handler says", got)
	}
}
