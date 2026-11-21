//go:build linux && e2e

// The end-to-end suite runs the real binary against a fake GLIMPS Malware
// Detect and a fake console. It is not part of `go test ./...`:
//
//	go test -tags e2e ./test/...
//	golangci-lint run --build-tags e2e ./test/...
//
// It needs the Go toolchain (the binary and the plugins are built once). The
// scenarios that need Chrome or the embedded 7-Zip skip with a message when
// they are absent. Every scenario ends with the OUTPUT invariant, which also
// runs when the scenario fails early.

package test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	hcquarantine "github.com/glimps-re/host-connector/pkg/quarantine"
)

// Smoke test of the whole harness: a clean file is delivered, a malicious one
// is quarantined under its SHA256 and leaves INPUT, a detection report stands
// in OUTPUT, and the invariant holds.
func TestE2E_cleanDeliveredMaliciousQuarantined(t *testing.T) {
	gm := newGMalware(t, false)
	bad := []byte("this content is a malware for the fake service")
	gm.MarkMalicious(bad)
	in := startInstance(t, gm, options{})
	in.drop(t, "clean.txt", []byte("some harmless content"))
	badPath := in.drop(t, "bad.txt", bad)
	waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
	if !in.inOutput("clean.txt") {
		t.Errorf("clean.txt was not delivered; log:\n%s", in.stderr.String())
	}
	if in.inOutput("bad.txt") {
		t.Error("the malware reached OUTPUT")
	}
	if _, err := os.Stat(badPath); !os.IsNotExist(err) {
		t.Errorf("the malware is still in INPUT: %v", err)
	}
	lock := filepath.Join(in.quarantine, hcquarantine.ComputeCacheID(badPath, sha256Hex(bad))+".lock")
	if _, err := os.Stat(lock); err != nil {
		t.Errorf("the malware is not quarantined as %s: %v", filepath.Base(lock), err)
	}
	if m := globOne(t, filepath.Join(in.quarantine, "*")); len(m) != 1 {
		t.Errorf("quarantine = %v, want only the malware", m)
	}
	if m := globOne(t, filepath.Join(in.output, "tom", "bad.txt-lockreport*.json")); len(m) != 1 {
		t.Errorf("detection reports = %v, want one", m)
	}
}

// While the service is down nothing is delivered and nothing is lost: once it
// answers again the file is analyzed and delivered.
func TestE2E_gmalwareOutageThenRecovery(t *testing.T) {
	gm := newGMalware(t, false)
	gm.FailWith(503)
	in := startInstance(t, gm, options{config: map[string]any{"monitoring": map[string]any{"period": "2s"}}})
	path := in.drop(t, "a.txt", []byte("content waiting for the service"))
	waitFor(t, "the connector to meet the outage", func() bool { return gm.failed.Load() > 0 })
	waitFor(t, "the failure to be reported", func() bool { return in.logHas("could not analyze file") })
	if in.inOutput("a.txt") {
		t.Error("a file was delivered without analysis during the outage")
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the file left INPUT during the outage: %v", err)
	}
	gm.FailWith(0)
	waitFor(t, "the delivery after the recovery", func() bool { return in.inOutput("a.txt") })
	waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
}

// The console drives the agent: Stop and Start are executed and acknowledged
// without error, and files are analyzed again after Start.
func TestE2E_consoleStopThenStart(t *testing.T) {
	gm := newGMalware(t, false)
	in := startInstance(t, gm, options{agent: true})
	in.drop(t, "first.txt", []byte("first content"))
	waitFor(t, "the first delivery", func() bool { return in.inOutput("first.txt") })
	for _, action := range []string{"stop", "start"} {
		if msg := in.console.WaitAck(t, in.console.Push(t, action, nil)); msg != "" {
			t.Fatalf("%s acknowledged with the error %q", action, msg)
		}
	}
	in.drop(t, "second.txt", []byte("second content"))
	waitFor(t, "the delivery after the restart", func() bool { return in.inOutput("second.txt") })
	waitFor(t, "the session report", func() bool { return in.reportCount() > 0 })
}

// reportCount counts the session reports written to the exports.
func (in *instance) reportCount() int {
	m, err := filepath.Glob(filepath.Join(in.export, "*", datamodel.SessionReportPrefix+"*"))
	if err != nil {
		return 0
	}
	return len(m)
}
