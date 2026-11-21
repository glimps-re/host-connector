//go:build linux

// Package test holds the acceptance tests that run the real binary.
//
// A verdict counts as given by the fake GLIMPS Malware Detect only when its
// answer was written and flushed and the request was still alive: what the
// server cannot see is a connector that received the bytes and dropped them.
package test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/alecthomas/units"
)

// builds holds the binary and the plugins, built once with the same toolchain:
// a plugin only loads in the binary it was built with.
var builds struct {
	once sync.Once
	err  error
	dir  string
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func goBuild(root, out string, args ...string) error {
	cmd := exec.CommandContext(context.Background(), "go", append([]string{"build", "-o", out}, args...)...) //nolint:gosec // G204: the test builds the binary it then runs; every argument is its own
	cmd.Dir = root
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("go build %v: %w\n%s", args, err, b)
	}
	return nil
}

func buildAll(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds the binary and two plugins")
	}
	builds.once.Do(func() {
		root := repoRoot(t)
		dir := builds.dir
		builds.err = errors.Join(
			goBuild(root, filepath.Join(dir, "GMHost"), "."),
			goBuild(root, filepath.Join(dir, "session.so"), "-buildmode=plugin", "./cmd/plugins/session"),
			goBuild(root, filepath.Join(dir, "extract.so"), "-buildmode=plugin", "./cmd/plugins/extract"),
		)
	})
	if builds.err != nil {
		t.Fatal(builds.err)
	}
	return builds.dir
}

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "gmhost-accept-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	builds.dir = dir
	code := m.Run()
	if builds.dir != "" {
		if err := os.RemoveAll(builds.dir); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}
	os.Exit(code)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	poll(t, what, cond, nil, nil)
}

// poll waits for cond up to a minute. When exited is not nil and gets closed
// meanwhile, the process ended: a connector that refused its configuration
// would otherwise be waited for until the deadline.
func poll(t *testing.T, what string, cond func() bool, exited <-chan struct{}, exitErr func() error) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for !cond() {
		select {
		case <-exited:
			if cond() {
				return
			}
			t.Fatalf("the process ended (%v) while waiting for %s", exitErr(), what)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// waitFor waits for the condition like the package function, and fails at
// once if the process ended meanwhile: a connector that refused its
// configuration would otherwise be waited for until the deadline.
func (in *instance) waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	poll(t, what, cond, in.exited, func() error { return in.exitErr })
}

func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func zipOf(t *testing.T, members map[string]string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for name, content := range members {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = io.WriteString(w, content); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func globOne(t *testing.T, pattern string) []string {
	t.Helper()
	m, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// processesUnder lists the processes whose command line mentions dir.
func processesUnder(dir string) (found []string) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err == nil && strings.Contains(string(raw), dir) {
			found = append(found, e.Name()+" "+strings.ReplaceAll(string(raw), "\x00", " "))
		}
	}
	return found
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

// instance is a run of the binary: clean files go from INPUT to OUTPUT,
// malware to the quarantine, session reports to the exports folder (the
// connector refuses one below the destination of the move).
type instance struct {
	cmd        *exec.Cmd
	stderr     *syncBuffer
	exited     chan struct{}
	exitErr    error
	start      time.Time
	root       string
	input      string
	work       string
	output     string
	export     string
	quarantine string
	gm         *gmalware
	// conf is the connector configuration the run started with.
	conf map[string]any
	// bin, dir and args are what launch ran, for a restart.
	bin, dir string
	args     []string
	killOnce sync.Once
	// abortedUploads is how many uploads the scenario announced the connector
	// would cut short.
	abortedUploads int
	console        *fakeConsole
	expect         expectations
}

// options tune a run; every field is optional.
type options struct {
	extract bool
	timeout string
	// agent runs the agent mode against a fake console instead of monitoring.
	agent bool
	// config is merged over the default configuration, key by key (a nested map
	// is merged, not replaced).
	config map[string]any
	// session is merged over the configuration of the session plugin.
	session map[string]any
	// more adds plugins, by name of their folder in cmd/plugins, with their
	// configuration.
	more map[string]map[string]any
	// order lists the plugins that go first in the plugins file, in that order;
	// the others follow by name. The order of the plugins is the order of their
	// callbacks.
	order []string
	// plugins is merged over the configuration of the extract plugin.
	plugins map[string]any
}

func mergeMaps(dst, src map[string]any) map[string]any {
	for k, v := range src {
		sub, isMap := v.(map[string]any)
		cur, curIsMap := dst[k].(map[string]any)
		if isMap && curIsMap {
			dst[k] = mergeMaps(cur, sub)
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

// writePlugins writes the plugins file with the plugins of order first, in that
// order, then the others by name (a JSON object keeps the order it is written
// in).
func writePlugins(t *testing.T, path string, plugins map[string]map[string]any, order []string) {
	t.Helper()
	names := slices.Clone(order)
	if len(slices.Compact(slices.Sorted(slices.Values(order)))) != len(order) {
		t.Fatalf("a plugin is listed twice in the order %v", order)
	}
	rest := make([]string, 0, len(plugins))
	for name := range plugins {
		if !slices.Contains(order, name) {
			rest = append(rest, name)
		}
	}
	slices.Sort(rest)
	var buf bytes.Buffer
	buf.WriteString("{")
	for i, name := range append(names, rest...) {
		cfg, ok := plugins[name]
		if !ok {
			t.Fatalf("plugin %q is in the order but not in the plugins", name)
		}
		raw, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if i > 0 {
			buf.WriteString(",")
		}
		fmt.Fprintf(&buf, "%q:%s", name, raw)
	}
	buf.WriteString("}")
	write(t, path, buf.Bytes())
}

// pluginBuilds holds the plugins built on demand, besides the two of buildAll.
var pluginBuilds struct {
	mu   sync.Mutex
	errs map[string]error
}

// buildPlugin builds the plugin of cmd/plugins/<name> once, with the toolchain
// of the binary, and returns the path of its shared object.
func buildPlugin(t *testing.T, name string) string {
	t.Helper()
	bin := buildAll(t)
	out := filepath.Join(bin, name+".so")
	pluginBuilds.mu.Lock()
	defer pluginBuilds.mu.Unlock()
	if pluginBuilds.errs == nil {
		pluginBuilds.errs = map[string]error{}
	}
	err, built := pluginBuilds.errs[name]
	if !built {
		err = goBuild(repoRoot(t), out, "-buildmode=plugin", "./cmd/plugins/"+name)
		pluginBuilds.errs[name] = err
	}
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// writeJSON writes v as JSON, which the YAML loaders of the connector read.
func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	write(t, path, raw)
}

// defaultMaxFileSize mirrors maxFileSizeDetect of pkg/handler/apply.go: the
// most the connector analyzes without syndetect.
const defaultMaxFileSize = 100 << 20

// syndetectOn reads gmalware_syndetect as the configuration loader would: a
// bool, or a string that strconv.ParseBool reads. Anything else is refused,
// since it cannot be told off.
func syndetectOn(v any) (bool, error) {
	switch x := v.(type) {
	case nil:
		return false, nil
	case bool:
		return x, nil
	case string:
		on, err := strconv.ParseBool(x)
		if err != nil {
			return false, fmt.Errorf("gmalware_syndetect %q: %w", x, err)
		}
		return on, nil
	default:
		return false, fmt.Errorf("gmalware_syndetect of type %T is not understood by the harness", v)
	}
}

// effectiveMaxFileSize is the size above which the connector does not analyze a
// file, for the configuration given: the value of max_file_size read with the
// units of the product, brought to 100 MiB when it is above or not positive.
// The syndetect limit (2 GiB) is not modelled: a configuration that asks for
// syndetect is refused rather than judged with the wrong limit.
func effectiveMaxFileSize(conf map[string]any) (int64, error) {
	syn, err := syndetectOn(conf["gmalware_syndetect"])
	if err != nil {
		return 0, err
	}
	if syn {
		return 0, errors.New("gmalware_syndetect is not supported by the harness: its file size limit differs")
	}
	raw, ok := conf["max_file_size"].(string)
	if !ok {
		return 0, fmt.Errorf("max_file_size must be a string, not %T", conf["max_file_size"])
	}
	size, err := units.ParseStrictBytes(raw)
	if err != nil {
		return 0, fmt.Errorf("max_file_size %q: %w", raw, err)
	}
	if size <= 0 || size > defaultMaxFileSize {
		return defaultMaxFileSize, nil
	}
	return size, nil
}

const testToken = "00000000-00000000-00000000-00000000-00000000"

func startInstance(t *testing.T, g *gmalware, opt options) *instance {
	t.Helper()
	bin := buildAll(t)
	root := t.TempDir()
	in := &instance{
		root: root, input: filepath.Join(root, "input"), work: filepath.Join(root, "work"), output: filepath.Join(root, "output"),
		export: filepath.Join(root, "reports"), quarantine: filepath.Join(root, "quarantine"), stderr: &syncBuffer{}, gm: g,
	}
	for _, d := range []string{filepath.Join(in.input, "tom"), in.work, in.output, in.export} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	session := mergeMaps(map[string]any{"root_folder": in.input, "exports": []string{in.export}, "delay": "2s"}, opt.session)
	plugins := map[string]map[string]any{"session": {"file": filepath.Join(bin, "session.so"), "config": session}}
	if opt.extract {
		plugins["extract"] = map[string]any{"file": filepath.Join(bin, "extract.so"), "config": opt.plugins}
	}
	for name, cfg := range opt.more {
		plugins[name] = map[string]any{"file": buildPlugin(t, name), "config": cfg}
	}
	pluginsFile := filepath.Join(root, "plugins.yml")
	conf := mergeMaps(map[string]any{
		"paths": []string{in.input}, "plugins_config": pluginsFile, "work_dir": in.work, "workers": 2,
		"extract": opt.extract, "extract_min_size": "1KB", "max_file_size": "100MiB",
		"recursive_extract_max_size": "5GB", "recursive_extract_max_files": 10000, "recursive_extract_max_depth": 10,
		"gmalware_api_url": g.URL, "gmalware_api_token": testToken, "gmalware_timeout": "5m",
		"actions":    map[string]any{"log": true, "move": true, "quarantine": true},
		"move":       map[string]any{"source": in.input, "destination": in.output},
		"monitoring": map[string]any{"prescan": true, "modification_delay": "1s"},
		"quarantine": map[string]any{"password": "infected", "location": in.quarantine},
	}, opt.config)
	if wd, _ := conf["work_dir"].(string); strings.HasPrefix(wd, "INPUT/") {
		rest, _ := strings.CutPrefix(wd, "INPUT/")
		conf["work_dir"] = filepath.Join(in.input, rest)
	}
	in.conf = cloneMap(t, conf)
	maxSize, err := effectiveMaxFileSize(conf)
	if err != nil {
		t.Fatal(err)
	}
	in.expect.maxFileSize = maxSize
	confFile := filepath.Join(root, "config.yml")
	writePlugins(t, pluginsFile, plugins, opt.order)
	writeJSON(t, confFile, conf)
	timeout := opt.timeout
	if timeout == "" {
		timeout = "4s"
	}
	args := []string{"--config", confFile, "--shutdown-timeout", timeout, "monitoring"}
	if opt.agent {
		in.console = newFakeConsole(t, conf)
		args = []string{"--config", confFile, "--shutdown-timeout", timeout, "--console-url", in.console.URL, "--console-api-key", consoleAPIKey, "agent"}
	}
	in.launch(t, bin, root, args)
	t.Cleanup(func() { in.finish(t) })
	return in
}

// launch starts the binary built in bin with args, in dir, and kills it, with
// everything it started, at the end of the test.
func (in *instance) launch(t *testing.T, bin, dir string, args []string) {
	t.Helper()
	in.bin, in.dir, in.args = bin, dir, args
	// Not tied to the context of the test, which ends before the cleanups: the
	// process is stopped by finish, then killed.
	cmd := exec.CommandContext(context.Background(), filepath.Join(bin, "GMHost"), args...) //nolint:gosec // G204: the binary the test built, with arguments of its own
	cmd.Stderr = in.stderr
	cmd.Stdout = in.stderr
	cmd.Dir = dir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	in.start = time.Now()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	in.cmd = cmd
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
			// A negative pid is the process group: the 7-Zip processes of the
			// connector must not outlive the test.
			if err := syscall.Kill(-in.cmd.Process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
				t.Logf("kill: %v", err)
			}
			if t.Failed() {
				t.Logf("log of the process:\n%s", in.stderr.String())
			}
		})
	})
}

// finish ends the process as an operator would, whatever the test did or
// failed to do, then holds what is left to the invariants: a failed test never
// hides a violation.
func (in *instance) finish(t *testing.T) {
	t.Helper()
	select {
	case <-in.exited:
	default:
		if err := in.cmd.Process.Signal(syscall.SIGTERM); err != nil {
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
	for _, e := range in.gm.Errors() {
		t.Errorf("fake GMalware: %s", e)
	}
	if n := in.gm.AbortedUploads(); n != in.abortedUploads {
		t.Errorf("fake GMalware: %d aborted uploads, the scenario announced %d", n, in.abortedUploads)
	}
	if n := in.gm.Unconsumed(); n != 0 {
		t.Errorf("fake GMalware: %d announced aborted uploads never happened", n)
	}
	for _, n := range in.gm.Notes() {
		t.Logf("fake GMalware (expected): %s", n)
	}
	if in.console != nil {
		for _, e := range in.console.ProtocolErrors() {
			t.Errorf("console protocol: %s", e)
		}
	}
}

func (in *instance) signal(t *testing.T, sig syscall.Signal) {
	t.Helper()
	if err := in.cmd.Process.Signal(sig); err != nil {
		t.Fatal(err)
	}
}

func (in *instance) wait(t *testing.T, limit time.Duration) (took time.Duration, err error) {
	t.Helper()
	at := time.Now()
	select {
	case <-in.exited:
		return time.Since(at), in.exitErr
	case <-time.After(limit):
		t.Fatalf("the process did not exit within %s; log:\n%s", limit, in.stderr.String())
		return 0, nil
	}
}

// expectAbortedUploads announces that the connector is going to cut n uploads
// short; finish holds the run to exactly that.
func (in *instance) expectAbortedUploads(n int) {
	in.abortedUploads += n
	in.gm.ExpectAbortedUploads(n)
}

// drop writes a file in INPUT, below the owner folder, and returns its path.
func (in *instance) drop(t *testing.T, rel string, content []byte) string {
	t.Helper()
	path := filepath.Join(in.input, "tom", rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	write(t, path, content)
	return path
}

// inOutput tells whether the file is in OUTPUT, below the owner folder.
func (in *instance) inOutput(rel string) bool {
	_, err := os.Stat(filepath.Join(in.output, "tom", rel))
	return err == nil
}

// logHas tells whether the log of the process holds the text.
func (in *instance) logHas(text string) bool {
	return strings.Contains(in.stderr.String(), text)
}

func (in *instance) checkSpec() checkSpec {
	return checkSpec{output: in.output, reports: in.export, quarantine: in.quarantine, expectations: in.expect}
}
