//go:build linux

// Package test holds the acceptance tests that run the real binary.
package test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
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

// gmalware is a GLIMPS Malware Detect that either answers at once or never.
type gmalware struct {
	*httptest.Server
	hang      bool
	mu        sync.Mutex
	hashes    map[string]string
	submitted atomic.Int32
	answered  atomic.Int32
}

func newGMalware(t *testing.T, hang bool) *gmalware {
	t.Helper()
	g := &gmalware{hang: hang, hashes: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/versions", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"/api/lite/v2":"2.0"}`)
	})
	mux.HandleFunc("/api/lite/v2/submit", func(w http.ResponseWriter, r *http.Request) {
		g.submitted.Add(1)
		if g.hang {
			// The body is read first: the server notices a closed connection
			// only after that.
			_, _ = io.Copy(io.Discard, r.Body)
			<-r.Context().Done()
			return
		}
		mr, err := r.MultipartReader()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		part, err := mr.NextPart()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		h := sha256.New()
		if _, err = io.Copy(h, part); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		id := hex.EncodeToString(h.Sum(nil))
		uuid := id[0:8] + "-" + id[8:12] + "-" + id[12:16] + "-" + id[16:20] + "-" + id[20:32]
		g.mu.Lock()
		g.hashes[uuid] = id
		g.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"status": true, "uuid": uuid})
	})
	mux.HandleFunc("/api/lite/v2/results/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/lite/v2/results/")
		g.mu.Lock()
		sum := g.hashes[strings.TrimSuffix(id, "/full")]
		g.mu.Unlock()
		g.answered.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"uuid": id, "sha256": sum, "done": true, "is_malware": false, "score": 0, "size": 1})
	})
	mux.HandleFunc("/api/lite/v2/search/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"status":false,"error":"not found"}`, http.StatusNotFound)
	})
	g.Server = httptest.NewServer(mux)
	t.Cleanup(g.Close)
	return g
}

// instance is a run of the binary in monitoring mode.
type instance struct {
	cmd    *exec.Cmd
	stderr *bytes.Buffer
	done   chan error
	start  time.Time
	root   string
	input  string
	work   string
	export string
}

type options struct {
	extract bool
	timeout string
	agent   bool
}

// newConsole is a connector manager that registers the connector with the
// configuration it is given and has no task for it.
func newConsole(t *testing.T, managed map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "register"):
			_ = json.NewEncoder(w).Encode(map[string]any{"stopped": false, "config": managed, "unresolved_errors": map[string]string{}})
		case strings.HasSuffix(r.URL.Path, "tasks"):
			select {
			case <-time.After(300 * time.Millisecond):
			case <-r.Context().Done():
			}
			_, _ = io.WriteString(w, `{"tasks":[]}`)
		default:
			_, _ = io.WriteString(w, `{}`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func startInstance(t *testing.T, g *gmalware, opt options) *instance {
	t.Helper()
	bin := buildAll(t)
	root := t.TempDir()
	in := &instance{root: root, input: filepath.Join(root, "input"), work: filepath.Join(root, "work"), export: filepath.Join(root, "exports"), stderr: &bytes.Buffer{}}
	for _, d := range []string{in.input, filepath.Join(in.input, "tom"), in.work, in.export} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	plugins := fmt.Sprintf("session:\n  file: %s\n  config:\n    root_folder: %s\n    exports: [%s]\n", filepath.Join(bin, "session.so"), in.input, in.export)
	if opt.extract {
		plugins += fmt.Sprintf("extract:\n  file: %s\n", filepath.Join(bin, "extract.so"))
	}
	pluginsFile := filepath.Join(root, "plugins.yml")
	conf := fmt.Sprintf(`paths: [%s]
plugins_config: %s
work_dir: %s
workers: 2
extract: %t
extract_min_size: 1KB
gmalware_api_url: %s
gmalware_api_token: 00000000-00000000-00000000-00000000-00000000
gmalware_timeout: 5m
actions: {delete: false, quarantine: false, move: false, print: false, log: true}
monitoring: {prescan: true, modification_delay: 1s}
quarantine: {password: infected, location: %s}
`, in.input, pluginsFile, in.work, opt.extract, g.URL, filepath.Join(root, "quarantine"))
	confFile := filepath.Join(root, "config.yml")
	for name, content := range map[string]string{pluginsFile: plugins, confFile: conf} {
		if err := os.WriteFile(name, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	timeout := opt.timeout
	if timeout == "" {
		timeout = "4s"
	}
	args := []string{"--config", confFile, "--shutdown-timeout", timeout, "monitoring"}
	if opt.agent {
		console := newConsole(t, map[string]any{
			"paths": []string{in.input}, "plugins_config": pluginsFile, "work_dir": in.work, "workers": 2,
			"max_file_size": "100MiB", "extract_min_size": "1KB", "recursive_extract_max_size": "5GB", "recursive_extract_max_files": 10000,
			"recursive_extract_max_depth": 10, "gmalware_timeout": "5m", "gmalware_api_url": g.URL, "gmalware_api_token": "00000000-00000000-00000000-00000000-00000000",
			"actions": map[string]any{"log": true}, "monitoring": map[string]any{"prescan": true, "modification_delay": "1s"},
			"quarantine": map[string]any{"password": "infected", "location": filepath.Join(root, "quarantine")},
		})
		args = []string{"--config", confFile, "--shutdown-timeout", timeout, "--console-url", console.URL, "--console-api-key", "key", "agent"}
	}
	in.cmd = exec.CommandContext(t.Context(), filepath.Join(bin, "GMHost"), args...) //nolint:gosec // G204: the binary the test built, with arguments of its own
	in.cmd.Stderr = in.stderr
	in.cmd.Dir = root
	in.start = time.Now()
	if err := in.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	in.done = make(chan error, 1)
	go func() { in.done <- in.cmd.Wait() }()
	t.Cleanup(func() {
		if in.cmd.ProcessState == nil {
			if err := in.cmd.Process.Kill(); err != nil {
				t.Logf("kill: %v", err)
			}
		}
		if t.Failed() {
			t.Logf("log of the process:\n%s", in.stderr.String())
		}
	})
	return in
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
	case err = <-in.done:
		return time.Since(at), err
	case <-time.After(limit):
		t.Fatalf("the process did not exit within %s; log:\n%s", limit, in.stderr.String())
		return 0, nil
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
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
	write(t, filepath.Join(in.input, "tom", "a.txt"), []byte("some content to analyze"))
	waitFor(t, "the file to be analyzed", func() bool { return g.answered.Load() > 0 })
	time.Sleep(1500 * time.Millisecond)
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
	write(t, filepath.Join(in.input, "tom", "a.txt"), []byte("some content to analyze"))
	waitFor(t, "the analysis to start", func() bool { return g.submitted.Load() > 0 })
	in.signal(t, syscall.SIGTERM)
	time.Sleep(500 * time.Millisecond)
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
	write(t, filepath.Join(in.input, "tom", "a.txt"), []byte("some content to analyze"))
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
	write(t, filepath.Join(in.input, "tom", "a.txt"), []byte("some content to analyze"))
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
