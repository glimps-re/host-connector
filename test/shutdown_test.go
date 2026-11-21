//go:build linux

package test

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A SIGTERM while an archive is being analyzed (the service never answers): the
// process leaves within the shutdown time, with code 0, the work directory is
// gone, no 7-Zip is left, the archive stays in INPUT and the log says so.
func TestShutdown_sigtermDuringTheAnalysisOfAnArchive(t *testing.T) {
	g := newGMalware(t, true)
	in := startInstance(t, g, options{extract: true, timeout: "4s"})
	archive := filepath.Join(in.input, "tom", "a.zip")
	write(t, archive, zipOf(t, map[string]string{"m1.txt": strings.Repeat("member one ", 200), "m2.txt": strings.Repeat("member two ", 200)}))
	waitFor(t, "the analysis of a member to start", func() bool { return g.submitted.Load() > 0 })
	in.signal(t, syscall.SIGTERM)
	took, err := in.wait(t, 4*time.Second+2*time.Second)
	if err != nil {
		t.Errorf("exit = %v, want code 0; log:\n%s", err, in.stderr.String())
	}
	t.Logf("stopped in %s", took)
	if m := globOne(t, filepath.Join(in.work, "gmhost-*")); len(m) != 0 {
		t.Errorf("work directory left: %v", m)
	}
	if p := processesUnder(in.work); len(p) != 0 {
		t.Errorf("processes left under the work directory: %v", p)
	}
	if _, err := os.Stat(archive); err != nil {
		t.Errorf("the archive is not in INPUT any more: %v", err)
	}
	log := in.stderr.String()
	for _, want := range []string{"stop requested", "connector stopped", `"msg":"stop finished"`, `"work_dir_removed":true`} {
		if !strings.Contains(log, want) {
			t.Errorf("the log lacks %q:\n%s", want, log)
		}
	}
}

// A SIGTERM with a session that holds a processed file: its report is written
// by the same path as the order of the console.
func TestShutdown_sigtermWritesTheReportOfAnOpenSession(t *testing.T) {
	g := newGMalware(t, false)
	in := startInstance(t, g, options{})
	in.drop(t, "a.txt", []byte("some content to analyze"))
	waitFor(t, "the file to be delivered", func() bool { return in.inOutput("a.txt") })
	in.signal(t, syscall.SIGTERM)
	if _, err := in.wait(t, 6*time.Second); err != nil {
		t.Errorf("exit = %v, want code 0; log:\n%s", err, in.stderr.String())
	}
	reports := globOne(t, filepath.Join(in.export, "tom", "*"))
	if len(reports) != 1 {
		t.Fatalf("reports = %v, want one; log:\n%s", reports, in.stderr.String())
	}
	content, err := os.ReadFile(filepath.Clean(reports[0]))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "a.txt") {
		t.Errorf("the report does not mention the file:\n%s", content)
	}
}

// A second signal while the stop waits ends the process at once.
func TestShutdown_aSecondSignalStopsImmediately(t *testing.T) {
	g := newGMalware(t, true)
	in := startInstance(t, g, options{timeout: "30s"})
	in.drop(t, "a.txt", []byte("some content to analyze"))
	waitFor(t, "the analysis to start", func() bool { return g.submitted.Load() > 0 })
	in.signal(t, syscall.SIGTERM)
	waitFor(t, "the stop to be under way", func() bool { return in.logHas("stop requested") })
	in.signal(t, syscall.SIGTERM)
	took, err := in.wait(t, 3*time.Second)
	t.Logf("second signal handled in %s", took)
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("wait = %v, want the process killed by a signal", err)
	}
	if status, ok := exit.Sys().(syscall.WaitStatus); !ok || !status.Signaled() || status.Signal() != syscall.SIGTERM {
		t.Errorf("exit status = %v, want ended by SIGTERM (the default action, not the handler)", exit)
	}
}

func TestShutdown_aTooShortTimeoutRefusesToStart(t *testing.T) {
	g := newGMalware(t, false)
	in := startInstance(t, g, options{timeout: "1s"})
	_, err := in.wait(t, 10*time.Second)
	if err == nil || !strings.Contains(in.stderr.String()+fmt.Sprint(err), "shutdown_timeout") {
		t.Errorf("exit = %v, want a refusal naming shutdown_timeout; log:\n%s", err, in.stderr.String())
	}
}

// SIGINT (Ctrl+C) stops the connector the same way as SIGTERM.
func TestShutdown_sigintStopsLikeSigterm(t *testing.T) {
	g := newGMalware(t, true)
	in := startInstance(t, g, options{timeout: "4s"})
	in.drop(t, "a.txt", []byte("some content to analyze"))
	waitFor(t, "the analysis to start", func() bool { return g.submitted.Load() > 0 })
	in.signal(t, syscall.SIGINT)
	if _, err := in.wait(t, 6*time.Second); err != nil {
		t.Errorf("exit = %v, want code 0; log:\n%s", err, in.stderr.String())
	}
	if !strings.Contains(in.stderr.String(), `"signal":"interrupt"`) {
		t.Errorf("the log does not name the signal:\n%s", in.stderr.String())
	}
	if m := globOne(t, filepath.Join(in.work, "gmhost-*")); len(m) != 0 {
		t.Errorf("work directory left: %v", m)
	}
}

// The agent, driven by a connector manager, stops on a signal the same way.
func TestShutdown_sigtermStopsTheAgent(t *testing.T) {
	g := newGMalware(t, true)
	in := startInstance(t, g, options{timeout: "4s", agent: true})
	in.drop(t, "a.txt", []byte("some content to analyze"))
	waitFor(t, "the analysis to start", func() bool { return g.submitted.Load() > 0 })
	in.signal(t, syscall.SIGTERM)
	if _, err := in.wait(t, 6*time.Second); err != nil {
		t.Errorf("exit = %v, want code 0; log:\n%s", err, in.stderr.String())
	}
	if m := globOne(t, filepath.Join(in.work, "gmhost-*")); len(m) != 0 {
		t.Errorf("work directory left: %v", m)
	}
	if !strings.Contains(in.stderr.String(), `"msg":"stop finished"`) {
		t.Errorf("no summary in the log:\n%s", in.stderr.String())
	}
}
