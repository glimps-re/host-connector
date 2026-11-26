//go:build linux

package harness

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/test/internal/fakes/console"
	"github.com/glimps-re/host-connector/test/internal/fakes/gmalware"
)

// Instance is a run of the binary: clean files go from INPUT to OUTPUT,
// malware to the quarantine, session reports to the exports folder (the
// connector refuses one below the destination of the move).
type Instance struct {
	Cmd        *exec.Cmd
	Stderr     *syncBuffer
	exited     chan struct{}
	exitErr    error
	waited     bool
	Root       string
	Input      string
	Work       string
	Output     string
	Export     string
	Quarantine string
	gm         *gmalware.GMalware
	// conf is the connector configuration the run started with.
	conf map[string]any
	// bin and args are what launch ran, for a restart.
	bin      string
	args     []string
	killOnce sync.Once
	Console  *console.Console
	Expect   Expectations
}

// Options tune a run; every field is optional.
type Options struct {
	Timeout string
	// Agent runs the agent mode against a fake console instead of monitoring.
	Agent bool
	// Config is merged over the default configuration, key by key (a nested map
	// is merged, not replaced).
	Config map[string]any
	// Plugins turns plugins on, by name of their folder in cmd/plugins, with
	// their configuration. "extract" also turns the extraction on. "session" is
	// always on: its entry is merged over its default configuration.
	Plugins map[string]map[string]any
}

func MergeMaps(dst, src map[string]any) map[string]any {
	for k, v := range src {
		sub, isMap := v.(map[string]any)
		cur, curIsMap := dst[k].(map[string]any)
		if isMap && curIsMap {
			dst[k] = MergeMaps(cur, sub)
			continue
		}
		dst[k] = v
	}
	return dst
}

// cloneMap deep-copies a configuration.
func cloneMap(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var cp map[string]any
	if err = json.Unmarshal(raw, &cp); err != nil {
		t.Fatal(err)
	}
	return cp
}

// writeJSON writes v as JSON, which the YAML loaders of the connector read.
func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	Write(t, path, raw)
}

const testToken = "00000000-00000000-00000000-00000000-00000000"

func Start(t *testing.T, g *gmalware.GMalware, opt Options) *Instance {
	t.Helper()
	bin := buildAll(t)
	root := t.TempDir()
	in := &Instance{
		Root: root, Input: filepath.Join(root, "input"), Work: filepath.Join(root, "work"), Output: filepath.Join(root, "output"),
		Export: filepath.Join(root, "reports"), Quarantine: filepath.Join(root, "quarantine"), Stderr: &syncBuffer{}, gm: g,
	}
	for _, d := range []string{filepath.Join(in.Input, "tom"), in.Work, in.Output, in.Export} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	session := MergeMaps(map[string]any{"root_folder": in.Input, "exports": []string{in.Export}, "delay": "2s"}, opt.Plugins["session"])
	plugins := map[string]map[string]any{"session": {"file": filepath.Join(bin, "session.so"), "config": session}}
	_, extract := opt.Plugins["extract"]
	for name, cfg := range opt.Plugins {
		switch name {
		case "session":
		case "extract":
			plugins[name] = map[string]any{"file": filepath.Join(bin, "extract.so"), "config": cfg}
		default:
			plugins[name] = map[string]any{"file": buildPlugin(t, name), "config": cfg}
		}
	}
	pluginsFile := filepath.Join(root, "plugins.yml")
	conf := MergeMaps(map[string]any{
		"paths": []string{in.Input}, "plugins_config": pluginsFile, "work_dir": in.Work, "workers": 2,
		"extract": extract, "extract_min_size": "1KB", "max_file_size": "100MiB",
		"recursive_extract_max_size": "5GB", "recursive_extract_max_files": 10000, "recursive_extract_max_depth": 10,
		"gmalware_api_url": g.URL, "gmalware_api_token": testToken, "gmalware_timeout": "5m",
		"actions":    map[string]any{"log": true, "move": true, "quarantine": true},
		"move":       map[string]any{"source": in.Input, "destination": in.Output},
		"monitoring": map[string]any{"prescan": true, "modification_delay": "1s"},
		"quarantine": map[string]any{"password": "infected", "location": in.Quarantine},
	}, opt.Config)
	wd, _ := conf["work_dir"].(string)
	if rest, ok := strings.CutPrefix(wd, "INPUT/"); ok {
		conf["work_dir"] = filepath.Join(in.Input, rest)
	}
	in.conf = cloneMap(t, conf)
	maxSize, err := effectiveMaxFileSize(conf)
	if err != nil {
		t.Fatal(err)
	}
	in.Expect.maxFileSize = maxSize
	confFile := filepath.Join(root, "config.yml")
	writeJSON(t, pluginsFile, plugins)
	writeJSON(t, confFile, conf)
	timeout := opt.Timeout
	if timeout == "" {
		timeout = "4s"
	}
	args := []string{"--config", confFile, "--shutdown-timeout", timeout}
	if opt.Agent {
		in.Console = console.New(t, conf)
		args = append(args, "--console-url", in.Console.URL, "--console-api-key", console.APIKey, "agent")
	} else {
		args = append(args, "monitoring")
	}
	in.launch(t, bin, args)
	t.Cleanup(func() { in.finish(t) })
	return in
}

// launch starts the binary built in bin with args, in the root of the
// instance, and kills it, with everything it started, at the end of the test.
func (in *Instance) launch(t *testing.T, bin string, args []string) {
	t.Helper()
	in.bin, in.args = bin, args
	// Not tied to the context of the test, which ends before the cleanups: the
	// process is stopped by finish, then killed.
	cmd := exec.CommandContext(context.Background(), filepath.Join(bin, "GMHost"), args...) //nolint:gosec // G204: the binary the test built, with arguments of its own
	cmd.Stderr = in.Stderr
	cmd.Stdout = in.Stderr
	cmd.Dir = in.Root
	// Killed with the test process: a GMHost left behind by a killed go test
	// would go on writing into the folders of the test.
	// Pdeathsig follows the thread that started GMHost (Linux): the runtime only
	// ends threads locked by LockOSThread, so an early kill is accepted.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	in.Cmd = cmd
	in.waited = false
	exited := make(chan struct{})
	in.exited = exited
	go func() {
		in.exitErr = cmd.Wait()
		close(exited)
	}()
	// One cleanup for all the runs of the instance, registered by the first one:
	// a later registration (a restart) would run before finish, which must stop
	// the process gracefully first.
	in.killOnce.Do(func() {
		t.Cleanup(func() {
			if err := in.killGroup(); err != nil {
				t.Logf("kill: %v", err)
			}
			if t.Failed() {
				t.Logf("log of the process:\n%s", in.Stderr.String())
			}
		})
	})
}

func (in *Instance) killGroup() error {
	// A negative pid is the process group: the 7-Zip processes of the
	// connector must not outlive the test.
	if err := syscall.Kill(-in.Cmd.Process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}

// finish ends the process as an operator would, whatever the test did or
// failed to do, then holds what is left to the invariants: a failed test never
// hides a violation.
func (in *Instance) finish(t *testing.T) {
	t.Helper()
	select {
	case <-in.exited:
		if !in.waited {
			t.Errorf("the process exited on its own: %v", in.exitErr)
		}
	default:
		if err := in.Cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Logf("SIGTERM: %v", err)
		}
		select {
		case <-in.exited:
		case <-time.After(20 * time.Second):
			t.Errorf("the process did not stop on SIGTERM")
		}
	}
	for _, v := range outputViolations(in.checkSpec(), in.gm) {
		t.Errorf("OUTPUT invariant: %s", v)
	}
}

func (in *Instance) Signal(t *testing.T, sig syscall.Signal) {
	t.Helper()
	if err := in.Cmd.Process.Signal(sig); err != nil {
		t.Fatal(err)
	}
}

func (in *Instance) Wait(t *testing.T, limit time.Duration) (took time.Duration, err error) {
	t.Helper()
	at := time.Now()
	select {
	case <-in.exited:
		in.waited = true
		return time.Since(at), in.exitErr
	case <-time.After(limit):
		t.Fatalf("the process did not exit within %s; log:\n%s", limit, in.Stderr.String())
		return 0, nil
	}
}

// Stop stops the connector with SIGTERM; it must exit cleanly.
func (in *Instance) Stop(t *testing.T) {
	t.Helper()
	in.Signal(t, syscall.SIGTERM)
	if _, err := in.Wait(t, 20*time.Second); err != nil {
		t.Fatalf("the connector did not stop cleanly: %v", err)
	}
}

// Drop writes a file in INPUT, below the owner folder, and returns its path.
func (in *Instance) Drop(t *testing.T, rel string, content []byte) string {
	t.Helper()
	path := filepath.Join(in.Input, "tom", rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	Write(t, path, content)
	return path
}

// InOutput tells whether the file is in OUTPUT, below the owner folder.
func (in *Instance) InOutput(rel string) bool {
	_, err := os.Stat(filepath.Join(in.Output, "tom", rel))
	return err == nil
}

// LogHas tells whether the log of the process holds the text.
func (in *Instance) LogHas(text string) bool {
	return strings.Contains(in.Stderr.String(), text)
}

func (in *Instance) checkSpec() checkSpec {
	return checkSpec{input: in.Input, output: in.Output, reports: in.Export, quarantine: in.Quarantine, Expectations: in.Expect}
}

// maxLogSize bounds the log of a process the harness keeps; past it the
// oldest lines are dropped.
const maxLogSize = 8 << 20

// syncBuffer is the log of a process, read while the process still writes it.
type syncBuffer struct {
	mu        sync.Mutex
	buf       []byte
	truncated bool
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	if len(b.buf) > maxLogSize {
		b.buf = append([]byte(nil), b.buf[len(b.buf)-maxLogSize/2:]...)
		b.truncated = true
	}
	return len(p), nil
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.truncated {
		return "[the start of the log was dropped]\n" + string(b.buf)
	}
	return string(b.buf)
}
