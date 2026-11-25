//go:build linux && (e2e || e2e_core)

package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/test/internal/fakes/gmalware"
	"github.com/glimps-re/host-connector/test/internal/harness"
)

const (
	pressureEvent  = "host-monitor-pressure"
	tableFullEvent = "host-monitor-table-full"
	// quietMinute is the minute without a refusal the monitor waits for between
	// two reports when it has no rescan, with a margin.
	quietMinute = 62 * time.Second
)

// pressureMessages are the pressure reports in the console log, one per
// report: unlike the error events, the console does not merge two equal ones.
func pressureMessages(in *harness.Instance) (msgs []string) {
	for _, raw := range in.Console.EventsOfType("log") {
		var ev struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(raw, &ev) == nil && strings.HasPrefix(ev.Message, "monitoring table under pressure") {
			msgs = append(msgs, ev.Message)
		}
	}
	return msgs
}

func countOf(types []string, typ string) int {
	n := 0
	for _, got := range types {
		if got == typ {
			n++
		}
	}
	return n
}

// dropLongNamed drops n files with names of 180 characters below the owner
// folder: 3000 of them overflow a table of 1 MiB.
func dropLongNamed(t *testing.T, in *harness.Instance, n int) {
	t.Helper()
	long := strings.Repeat("n", 180)
	for i := range n {
		in.Drop(t, fmt.Sprintf("%s%05d.txt", long, i), []byte(fmt.Sprintf("file number %d", i)))
	}
}

// removeInput removes everything below the owner folder.
func removeInput(t *testing.T, in *harness.Instance) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(in.Input, "tom"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if err = os.RemoveAll(filepath.Join(in.Input, "tom", e.Name())); err != nil {
			t.Fatal(err)
		}
	}
}

// From TestMonitor_pressureEventInEventOnlyModeIsRateLimited: without a rescan,
// a table that overflows is reported at once, then at most once a minute
// whatever it refuses meanwhile. harness.Start: a scenario cannot wait a
// minute.
func TestE2E_withoutRescanThePressureIsReportedAtMostOnceAMinute(t *testing.T) {
	tests := []struct {
		name  string
		files int
	}{
		{name: "3000 files with long names, one more after a minute", files: 3000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gm := gmalware.New(t, false)
			in := harness.Start(t, gm, harness.Options{Agent: true, Config: map[string]any{
				"monitoring": map[string]any{"max_tracked_memory": "1MiB", "modification_delay": "1h"},
			}})
			in.WaitFor(t, "the monitoring to start", func() bool { return in.LogHas(harness.MonitoringStarted) })
			dropLongNamed(t, in, tt.files)
			in.WaitFor(t, "the first pressure report", func() bool { return len(pressureMessages(in)) > 0 })
			first := time.Now()
			time.Sleep(10 * time.Second)
			if msgs := pressureMessages(in); len(msgs) != 1 {
				t.Fatalf("%d pressure reports within the minute, want 1: %q", len(msgs), msgs)
			}
			time.Sleep(time.Until(first.Add(quietMinute)))
			in.Drop(t, "after-a-minute.txt", []byte("refused a minute after the first report"))
			in.WaitFor(t, "a second pressure report", func() bool { return len(pressureMessages(in)) >= 2 })
			if msgs := pressureMessages(in); len(msgs) != 2 {
				t.Errorf("%d pressure reports, want 2: %q", len(msgs), msgs)
			}
		})
	}
}

// From TestMonitor_pressureEndIsRaisedInEventOnlyMode: without a rescan, once
// the files are removed, the end of the pressure is told a minute after the
// last report, at the next file, and only once. The refusals of the overflow
// that came after the first report are reported first. harness.Start: a
// scenario cannot remove files nor wait a minute.
func TestE2E_withoutRescanTheEndOfThePressureIsToldOnceAfterAQuietMinute(t *testing.T) {
	tests := []struct {
		name  string
		files int
		delay time.Duration
	}{
		{name: "3000 files with long names removed before their 20 s delay", files: 3000, delay: 20 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gm := gmalware.New(t, false)
			in := harness.Start(t, gm, harness.Options{Agent: true, Config: map[string]any{
				"monitoring": map[string]any{"max_tracked_memory": "1MiB", "modification_delay": tt.delay.String()},
			}})
			in.WaitFor(t, "the monitoring to start", func() bool { return in.LogHas(harness.MonitoringStarted) })
			dropLongNamed(t, in, tt.files)
			in.WaitFor(t, "the first pressure report", func() bool { return len(pressureMessages(in)) > 0 })
			first := time.Now()
			removeInput(t, in)
			probe := func(name string) {
				t.Helper()
				in.Drop(t, name, []byte("probe "+name))
				in.WaitFor(t, "the delivery of "+name, func() bool { return in.InOutput(name) })
			}
			// The removed files leave the table once their delay is over: the
			// probe is admitted, within the minute.
			time.Sleep(tt.delay + 5*time.Second)
			probe("within-the-minute.txt")
			if got := countOf(in.Console.ResolvedTypes(), pressureEvent); got != 0 {
				t.Fatalf("%d resolutions within the minute, want none", got)
			}
			time.Sleep(time.Until(first.Add(quietMinute)))
			last := time.Now()
			probe("a-minute-later.txt")
			time.Sleep(time.Until(last.Add(quietMinute)))
			last = time.Now()
			probe("two-minutes-later.txt")
			in.WaitFor(t, "the end of the pressure", func() bool { return countOf(in.Console.ResolvedTypes(), pressureEvent) > 0 })
			time.Sleep(time.Until(last.Add(quietMinute)))
			probe("three-minutes-later.txt")
			if got := countOf(in.Console.ResolvedTypes(), pressureEvent); got != 1 {
				t.Errorf("%d resolutions, want 1", got)
			}
		})
	}
}

// From TestMonitor_pressureEventsAreRaisedThenResolved: with the move off, the
// files left in INPUT fill the table, new files are refused, and the console
// is told of the pressure and of the table full of files left in INPUT; once
// they are removed a rescan resolves both, once. harness.Start: a step cannot
// remove files.
func TestE2E_filesLeftInInputFillTheTableUntilTheyAreRemoved(t *testing.T) {
	tests := []struct {
		name   string
		files  int
		period time.Duration
	}{
		{name: "3000 files with long names, move off, 2 s rescan", files: 3000, period: 2 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gm := gmalware.New(t, false)
			in := harness.Start(t, gm, harness.Options{Agent: true, Config: map[string]any{
				"actions":    map[string]any{"move": false},
				"monitoring": map[string]any{"max_tracked_memory": "1MiB", "period": tt.period.String()},
			}})
			in.WaitFor(t, "the monitoring to start", func() bool { return in.LogHas(harness.MonitoringStarted) })
			dropLongNamed(t, in, tt.files)
			in.WaitFor(t, "the pressure and the table full", func() bool {
				errs := in.Console.ErrorTypes()
				return slices.Contains(errs, pressureEvent) && slices.Contains(errs, tableFullEvent)
			})
			removeInput(t, in)
			in.WaitFor(t, "both to be resolved", func() bool {
				res := in.Console.ResolvedTypes()
				return slices.Contains(res, pressureEvent) && slices.Contains(res, tableFullEvent)
			})
			time.Sleep(5 * tt.period)
			res := in.Console.ResolvedTypes()
			for _, typ := range []string{pressureEvent, tableFullEvent} {
				if got := countOf(res, typ); got != 1 {
					t.Errorf("%d resolutions of %s, want 1", got, typ)
				}
			}
		})
	}
}

// From TestFileTable_pressureReportNamesAtMost32Owners: when the table refuses
// or evicts the files of hundreds of owners, a pressure message names at most
// 32 of them, counts the others, and stays under 16 KiB. The owners are the
// folders beside tom.
func TestE2E_aPressureMessageNamesAtMost32Owners(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		owners, perUser int
		maxNamed        int
		maxBytes        int
	}{
		{name: "300 owner folders of 10 files", owners: 300, perUser: 10, maxNamed: 32, maxBytes: 16 << 10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			long := strings.Repeat("n", 180)
			s := harness.Scenario{
				Agent:             true,
				Config:            map[string]any{"monitoring": map[string]any{"max_tracked_memory": "1MiB", "period": "2s", "modification_delay": "1h"}},
				Want:              map[string]harness.Outcome{},
				WantConsoleErrors: []string{pressureEvent},
			}
			for o := range tt.owners {
				for i := range tt.perUser {
					f := harness.File{Path: fmt.Sprintf("../u%03d/%s%02d.txt", o, long, i), Content: []byte(fmt.Sprintf("file %d of owner %d", i, o))}
					s.Files = append(s.Files, f)
					s.Want[f.Path] = harness.Outcome{In: harness.Input, NoReport: true}
				}
			}
			in := harness.Run(t, s)
			in.WaitFor(t, "a pressure message that counts other owners", func() bool {
				return slices.ContainsFunc(pressureMessages(in), func(m string) bool { return strings.Contains(m, "more file(s) of other owners") })
			})
			for _, m := range pressureMessages(in) {
				if named := strings.Count(m, " holds "); named > tt.maxNamed {
					t.Errorf("a pressure message names %d owners, want at most %d", named, tt.maxNamed)
				}
				if len(m) >= tt.maxBytes {
					t.Errorf("a pressure message is %d bytes, want under %d", len(m), tt.maxBytes)
				}
			}
		})
	}
}
