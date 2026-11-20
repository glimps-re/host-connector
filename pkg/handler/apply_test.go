package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/connector-integration/sdk/events"
	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	gdetectMock "github.com/glimps-re/go-gdetect/pkg/gdetect/mock"
	"github.com/glimps-re/host-connector/pkg/config"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

type eventRecord struct {
	kind string
	key  events.ErrorEventType
	msg  string
}

type eventLog struct {
	events.NoopEventHandler
	mu      sync.Mutex
	records []eventRecord
}

func (e *eventLog) NotifyError(_ context.Context, key events.ErrorEventType, err error) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.records = append(e.records, eventRecord{"error", key, err.Error()})
	return nil
}

func (e *eventLog) NotifyResolution(_ context.Context, msg string, keys ...events.ErrorEventType) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, k := range keys {
		e.records = append(e.records, eventRecord{"resolution", k, msg})
	}
	return nil
}

func (e *eventLog) find(kind string, key events.ErrorEventType) []eventRecord {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []eventRecord
	for _, r := range e.records {
		if r.kind == kind && r.key == key {
			out = append(out, r)
		}
	}
	return out
}

func recordEvents(t *testing.T) *eventLog {
	t.Helper()
	rec := &eventLog{}
	prev := eventHandler
	eventHandler = rec
	t.Cleanup(func() { eventHandler = prev })
	return rec
}

func validConf(t *testing.T, watched string) *config.Config {
	t.Helper()
	conf := &config.Config{}
	conf.GMalwareAPIURL = "https://gmalware.example"
	conf.GMalwareAPIToken = "01234567-89abcdef-01234567-89abcdef-01234567"
	conf.Workers = 1
	conf.ExtractWorkers = 1
	conf.MaxFileSize = "10MiB"
	conf.Paths = []string{watched}
	conf.Actions.Log = true
	return conf
}

func rawConf(t *testing.T, conf *config.Config) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(conf)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func newRunningHandler(t *testing.T, conf *config.Config) *Handler {
	t.Helper()
	h := new(Handler)
	h.stopped = true
	h.submitter = &gdetectMock.MockGDetectSubmitter{
		ReconfigureMock: func(context.Context, gdetect.ClientConfig) error { return nil },
	}
	if err := h.setup(t.Context(), conf); err != nil {
		t.Fatalf("setup() error = %v", err)
	}
	if err := h.Start(t.Context()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() {
		h.stopRejectReminder()
		if err := h.Stop(context.Background()); err != nil {
			t.Errorf("Stop() error = %v", err)
		}
	})
	return h
}

func TestApply_firstStartInvalidThenStartDoesNotPanic(t *testing.T) {
	rec := recordEvents(t)
	h := new(Handler)
	h.stopped = true
	bad := validConf(t, t.TempDir())
	bad.Move.Mode = "copy"
	if err := h.setup(t.Context(), bad); err == nil {
		t.Fatal("setup() error = nil, want a refusal")
	}
	if got := h.Status(); got != sdk.Stopped {
		t.Errorf("Status() = %v, want Stopped", got)
	}
	if h.Conn != nil || h.monitor != nil {
		t.Error("nothing must be left built after a refused first start")
	}
	for range 2 {
		if err := h.Start(t.Context()); err == nil {
			t.Error("Start() error = nil, want the same refusal")
		}
	}
	if got := len(rec.find("error", HostConfigError)); got != 3 {
		t.Errorf("host-bad-config events = %d, want 3 (setup and two Start)", got)
	}
}

func TestApply_validationFailureTouchesNothing(t *testing.T) {
	rec := recordEvents(t)
	good := validConf(t, t.TempDir())
	h := newRunningHandler(t, good)
	conn, mon := h.Conn, h.monitor

	bad := validConf(t, t.TempDir())
	bad.Move.Mode = "copy"
	if err := h.Configure(t.Context(), rawConf(t, bad)); err == nil {
		t.Fatal("Configure() error = nil, want a refusal")
	}
	if h.Conn != conn || h.monitor != mon {
		t.Error("a refused configuration must leave the running connector in place")
	}
	if got := h.Status(); got != sdk.Started {
		t.Errorf("Status() = %v, want Started", got)
	}
	events := rec.find("error", HostConfigRejected)
	if len(events) != 1 {
		t.Fatalf("host-config-rejected events = %d, want 1", len(events))
	}
	for _, phrase := range []string{"previous configuration stays in service", "is NOT applied", "will not start"} {
		if !strings.Contains(events[0].msg, phrase) {
			t.Errorf("event %q misses %q", events[0].msg, phrase)
		}
	}
	if h.conf != good {
		t.Error("h.conf must stay the running configuration")
	}
}

func TestApply_installFailureRollsBack(t *testing.T) {
	rec := recordEvents(t)
	watched := t.TempDir()
	good := validConf(t, watched)
	good.Actions.Quarantine = true
	good.Quarantine.Location = filepath.Join(t.TempDir(), "quarantine")
	good.Quarantine.Password = "old"
	h := newRunningHandler(t, good)
	conn := h.Conn

	failing := validConf(t, filepath.Join(t.TempDir(), "missing"))
	failing.Actions.Quarantine = true
	newQuarantine := filepath.Join(t.TempDir(), "other-quarantine")
	failing.Quarantine.Location = newQuarantine
	failing.Quarantine.Password = "new"
	err := h.Configure(t.Context(), rawConf(t, failing))
	if err == nil {
		t.Fatal("Configure() error = nil, want a failure at step 2")
	}
	if got := h.Status(); got != sdk.Started {
		t.Errorf("Status() = %v, want Started after the rollback", got)
	}
	if h.Conn == nil || h.Conn == conn {
		t.Error("the rollback must rebuild a connector from the previous configuration")
	}
	if h.conf != good {
		t.Error("h.conf must be the previous configuration after the rollback")
	}
	if _, statErr := os.Stat(newQuarantine); !os.IsNotExist(statErr) {
		t.Errorf("the quarantine must not be touched when a watch fails (stat error = %v)", statErr)
	}
	if h.qConf.LockPassword != "old" || h.qConf.Location != good.Quarantine.Location {
		t.Errorf("quarantine config = %+v, want the previous one", h.qConf)
	}
	events := rec.find("error", HostConfigRejected)
	if len(events) != 1 || !strings.Contains(events[0].msg, "interrupted and resumed") {
		t.Errorf("host-config-rejected events = %v, want one saying the processing was resumed", events)
	}
}

func TestApply_rollbackFailureStopsEverything(t *testing.T) {
	recordEvents(t)
	watched := t.TempDir()
	good := validConf(t, watched)
	h := newRunningHandler(t, good)

	failing := validConf(t, filepath.Join(t.TempDir(), "missing"))
	if err := os.RemoveAll(watched); err != nil {
		t.Fatal(err)
	}
	if err := h.Configure(t.Context(), rawConf(t, failing)); err == nil {
		t.Fatal("Configure() error = nil, want a failure")
	}
	if got := h.Status(); got != sdk.Stopped {
		t.Errorf("Status() = %v, want Stopped when the rollback fails too", got)
	}
	if h.Conn != nil || h.monitor != nil {
		t.Error("nothing must be left built after a complete stop")
	}
	if err := h.Start(t.Context()); err == nil {
		t.Error("Start() error = nil, want the failure to persist without panic")
	}
}

func TestApply_undecodableJSONRaisesEvent(t *testing.T) {
	rec := recordEvents(t)
	h := newRunningHandler(t, validConf(t, t.TempDir()))
	conn := h.Conn
	if err := h.Configure(t.Context(), json.RawMessage(`{"workers":`)); err == nil {
		t.Fatal("Configure() error = nil, want a JSON error")
	}
	if got := len(rec.find("error", HostConfigRejected)); got != 1 {
		t.Errorf("host-config-rejected events = %d, want 1", got)
	}
	if h.Conn != conn || h.Status() != sdk.Started {
		t.Error("the running configuration must be left alone")
	}
}

func TestApply_rejectedEventSurvivesStopStartAndIsResolvedByConfigure(t *testing.T) {
	rec := recordEvents(t)
	good := validConf(t, t.TempDir())
	h := newRunningHandler(t, good)
	bad := validConf(t, t.TempDir())
	bad.Move.Mode = "copy"
	if err := h.Configure(t.Context(), rawConf(t, bad)); err == nil {
		t.Fatal("Configure() error = nil")
	}
	if err := h.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := h.Start(t.Context()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if got := len(rec.find("resolution", HostConfigRejected)); got != 0 {
		t.Errorf("Start must not resolve host-config-rejected (resolutions = %d)", got)
	}
	if err := h.Configure(t.Context(), rawConf(t, validConf(t, t.TempDir()))); err != nil {
		t.Fatalf("Configure() error = %v", err)
	}
	if got := len(rec.find("resolution", HostConfigRejected)); got != 1 {
		t.Errorf("resolutions after a successful Configure = %d, want 1", got)
	}
}

func TestApply_rejectionReminder(t *testing.T) {
	recordEvents(t)
	var logs syncBuffer
	prev := logger
	logger = slog.New(slog.NewTextHandler(&logs, nil))
	t.Cleanup(func() { logger = prev })
	prevEvery := rejectReminderEvery
	rejectReminderEvery = 10 * time.Millisecond
	t.Cleanup(func() { rejectReminderEvery = prevEvery })

	h := newRunningHandler(t, validConf(t, t.TempDir()))
	bad := validConf(t, t.TempDir())
	bad.Move.Mode = "copy"
	if err := h.Configure(t.Context(), rawConf(t, bad)); err == nil {
		t.Fatal("Configure() error = nil")
	}
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(logs.String(), "still pending") && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !strings.Contains(logs.String(), "still pending") {
		t.Fatal("no reminder logged while the rejection lasts")
	}
	if err := h.Configure(t.Context(), rawConf(t, validConf(t, t.TempDir()))); err != nil {
		t.Fatal(err)
	}
	h.remindMu.Lock()
	stopped := h.remindStop == nil
	h.remindMu.Unlock()
	if !stopped {
		t.Error("the reminder must stop once a Configure succeeded")
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestApply_unknownKeysFromConsole(t *testing.T) {
	rec := recordEvents(t)
	h := newRunningHandler(t, validConf(t, t.TempDir()))
	raw := rawConf(t, validConf(t, t.TempDir()))
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["future_key"] = true
	doc["monitoring"].(map[string]any)["future_monitoring_key"] = 1
	withUnknown, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Configure(t.Context(), withUnknown); err != nil {
		t.Fatalf("Configure() with unknown keys error = %v, want it applied", err)
	}
	events := rec.find("error", HostConfigUnknownKeys)
	if len(events) != 1 {
		t.Fatalf("host-config-unknown-keys events = %d, want 1", len(events))
	}
	for _, want := range []string{"future_key", "monitoring.future_monitoring_key", "NO effect", "update the connector"} {
		if !strings.Contains(events[0].msg, want) {
			t.Errorf("event %q misses %q", events[0].msg, want)
		}
	}
	if err := h.Configure(t.Context(), raw); err != nil {
		t.Fatal(err)
	}
	if got := len(rec.find("resolution", HostConfigUnknownKeys)); got != 1 {
		t.Errorf("unknown keys resolutions = %d, want 1", got)
	}
}

func TestApply_startTwiceIsHarmless(t *testing.T) {
	recordEvents(t)
	h := newRunningHandler(t, validConf(t, t.TempDir()))
	if err := h.Start(t.Context()); err != nil {
		t.Errorf("second Start() error = %v", err)
	}
	if h.Status() != sdk.Started {
		t.Error("Status() must stay Started")
	}
}

func TestUnknownKeys(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{"none", `{"workers":2,"monitoring":{"period":"1h"},"quarantine":{"format":"zip"}}`, nil},
		{"top level", `{"workers":2,"too_bg":"pass"}`, []string{"too_bg"}},
		{"nested", `{"unanalyzable_policy":{"too_bg":"pass"}}`, []string{"unanalyzable_policy.too_bg"}},
		{"console section", `{"console":{"url":"x","nope":1}}`, []string{"console.nope"}},
		{"not an object", `[1]`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := unknownKeys(json.RawMessage(tt.raw))
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Errorf("unknownKeys() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestApply_warningsOnEverySuccessfulApplication(t *testing.T) {
	recordEvents(t)
	var logs syncBuffer
	prev := logger
	logger = slog.New(slog.NewTextHandler(&logs, nil))
	t.Cleanup(func() { logger = prev })

	conf := validConf(t, t.TempDir())
	conf.Actions.Quarantine = true
	conf.Quarantine.Location = filepath.Join(t.TempDir(), "quarantine")
	conf.Quarantine.Format = "zip"
	h := newRunningHandler(t, conf)
	if err := h.Configure(t.Context(), rawConf(t, conf)); err != nil {
		t.Fatalf("Configure() error = %v", err)
	}
	if got := strings.Count(logs.String(), "must be considered public"); got != 2 {
		t.Errorf("zip warnings = %d, want 2 (start and an unchanged Configure)", got)
	}
}

// failStart makes the start of the workers fail for the next n calls (every
// call when n is 0) and restores it at the end of the test.
func failStart(t *testing.T, n int) {
	t.Helper()
	prev := startConnector
	calls := 0
	startConnector = func(c *scanner.Connector) error {
		calls++
		if n == 0 || calls <= n {
			return errors.New("injected failure at step 4")
		}
		return prev(c)
	}
	t.Cleanup(func() { startConnector = prev })
}

func failStartOnce(t *testing.T) { failStart(t, 1) }

func TestApply_step4FailureReplaysPreviousQuarantine(t *testing.T) {
	rec := recordEvents(t)
	watched := t.TempDir()
	good := validConf(t, watched)
	good.Actions.Quarantine = true
	good.Quarantine.Location = filepath.Join(t.TempDir(), "old")
	good.Quarantine.Password = "old"
	h := newRunningHandler(t, good)
	realQuarantiner := h.Quarantiner
	t.Cleanup(func() {
		if err := realQuarantiner.Close(); err != nil {
			t.Errorf("real quarantiner Close() error = %v", err)
		}
	})
	fake := &fakeQuarantiner{current: h.qConf}
	h.Quarantiner = fake

	next := validConf(t, watched)
	next.Actions.Quarantine = true
	next.Quarantine.Location = filepath.Join(t.TempDir(), "new")
	next.Quarantine.Password = "new"
	failStartOnce(t)
	if err := h.Configure(t.Context(), rawConf(t, next)); err == nil {
		t.Fatal("Configure() error = nil, want the step 4 failure")
	}
	fake.mu.Lock()
	calls := len(fake.calls)
	current := fake.current
	fake.mu.Unlock()
	if calls != 2 || current.Location != good.Quarantine.Location || current.LockPassword != "old" {
		t.Errorf("Reconfigure calls = %d, in service = %+v: want the new one then the previous one back", calls, current)
	}
	if h.Status() != sdk.Started || h.conf != good {
		t.Error("the previous configuration must be back in service")
	}
	if got := rec.find("error", HostConfigRejected); len(got) != 1 || !strings.Contains(got[0].msg, "interrupted and resumed") {
		t.Errorf("events = %v, want one saying the processing was resumed", got)
	}
}

func TestApply_failedRollbackEventSaysStoppedAndNotInService(t *testing.T) {
	rec := recordEvents(t)
	h := newRunningHandler(t, validConf(t, t.TempDir()))
	failStart(t, 0)
	if err := h.Configure(t.Context(), rawConf(t, validConf(t, t.TempDir()))); err == nil {
		t.Fatal("Configure() error = nil")
	}
	if h.Status() != sdk.Stopped {
		t.Fatalf("Status() = %v, want Stopped", h.Status())
	}
	events := rec.find("error", HostConfigRejected)
	if len(events) != 1 {
		t.Fatalf("events = %v", events)
	}
	if !strings.Contains(events[0].msg, rejectedStopped) || strings.Contains(events[0].msg, "stays in service") {
		t.Errorf("event %q must carry the stopped text and never say the previous configuration stays in service", events[0].msg)
	}
}

func TestApply_rejectionTextFollowsTheRealState(t *testing.T) {
	rec := recordEvents(t)
	good := validConf(t, t.TempDir())
	h := newRunningHandler(t, good)
	bad := validConf(t, t.TempDir())
	bad.Move.Mode = "copy"
	if err := h.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := h.Configure(t.Context(), rawConf(t, bad)); err == nil {
		t.Fatal("Configure() error = nil")
	}
	if err := h.Configure(t.Context(), json.RawMessage(`{"workers":`)); err == nil {
		t.Fatal("Configure() error = nil")
	}
	events := rec.find("error", HostConfigRejected)
	if len(events) != 2 {
		t.Fatalf("events = %v", events)
	}
	for _, e := range events {
		if !strings.Contains(e.msg, "the connector is stopped") || strings.Contains(e.msg, "stays in service") {
			t.Errorf("event %q must say the connector is stopped", e.msg)
		}
	}
}

func TestApply_reminderRepeatsTheLastMessage(t *testing.T) {
	recordEvents(t)
	var logs syncBuffer
	prev := logger
	logger = slog.New(slog.NewTextHandler(&logs, nil))
	t.Cleanup(func() { logger = prev })
	prevEvery := rejectReminderEvery
	rejectReminderEvery = 10 * time.Millisecond
	t.Cleanup(func() { rejectReminderEvery = prevEvery })
	h := newRunningHandler(t, validConf(t, t.TempDir()))
	failStart(t, 0)
	if err := h.Configure(t.Context(), rawConf(t, validConf(t, t.TempDir()))); err == nil {
		t.Fatal("Configure() error = nil")
	}
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(logs.String(), "still pending: configuration rejected") && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !strings.Contains(logs.String(), "still pending: configuration rejected") || !strings.Contains(logs.String(), "STOPPED") {
		t.Errorf("the reminder must repeat the last message: %s", logs.String())
	}
	h.Close()
	h.remindMu.Lock()
	stopped := h.remindStop == nil
	h.remindMu.Unlock()
	if !stopped {
		t.Error("Close must stop the reminder")
	}
}

func TestApply_stopAfterFailedSetupClosesQuarantine(t *testing.T) {
	recordEvents(t)
	good := validConf(t, t.TempDir())
	good.Actions.Quarantine = true
	good.Quarantine.Location = filepath.Join(t.TempDir(), "q")
	h := newRunningHandler(t, good)
	failStart(t, 0)
	if err := h.Configure(t.Context(), rawConf(t, validConf(t, t.TempDir()))); err == nil {
		t.Fatal("Configure() error = nil")
	}
	if h.Quarantiner == nil {
		t.Skip("quarantine already closed by the failed application")
	}
	if err := h.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	if h.Quarantiner != nil {
		t.Error("Stop after a failed setup must close the quarantine")
	}
}

func TestCheckReportLocation(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "report.log")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	notDir := filepath.Join(dir, "notdir")
	if err := os.WriteFile(notDir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"empty", "", false},
		{"existing file", file, false},
		{"new file in an existing directory", filepath.Join(dir, "new.log"), false},
		{"new file in a missing directory", filepath.Join(dir, "a", "b", "new.log"), false},
		{"a directory", dir, true},
		{"under a regular file", filepath.Join(notDir, "x.log"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := checkReportLocation(tt.path); (err != nil) != tt.wantErr {
				t.Errorf("checkReportLocation() error = %v, wantErr %t", err, tt.wantErr)
			}
		})
	}
	if _, err := os.Stat(filepath.Join(dir, "a")); err == nil {
		t.Error("the check must create nothing")
	}
}

func TestUnknownKeys_caseInsensitiveAndCapped(t *testing.T) {
	if got := unknownKeys(json.RawMessage(`{"Workers":2,"Monitoring":{"PreScan":true}}`)); len(got) != 0 {
		t.Errorf("unknownKeys() = %v, keys matched without regard to case are known", got)
	}
	doc := map[string]int{}
	for i := range 1000 {
		doc[strings.Repeat("k", 300)+strconv.Itoa(i)] = i
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	reported := capKeys(unknownKeys(raw))
	if len(reported) != maxReportedKeys+1 || !strings.Contains(reported[len(reported)-1], "950 more") {
		t.Errorf("reported %d entries, last %q", len(reported), reported[len(reported)-1])
	}
	for _, k := range reported[:maxReportedKeys] {
		if len(k) > maxReportedKeyLen+3 {
			t.Fatalf("key of %d bytes reported", len(k))
		}
	}
}
