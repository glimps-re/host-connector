//go:build linux

package test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Bounds on what the fakes read from the connector, as the product bounds what
// it reads from the network.
const (
	maxFakeSubmission = 1 << 32
	maxFakeEvent      = 1 << 20
)

// verdict is what the fake GLIMPS Malware Detect answers for a content.
type verdict struct {
	malware  bool
	malwares []string
}

// gmalware is a GLIMPS Malware Detect whose answers the test programs: a
// verdict per SHA256, a failure status for every request, a delay on the
// submissions, or no answer at all (hang). It remembers what it was asked.
type gmalware struct {
	*httptest.Server
	hang bool

	mu       sync.Mutex
	uuids    map[string]string
	verdicts map[string]verdict
	given    map[string]verdict
	failure  int
	delay    time.Duration

	submitted atomic.Int32
	answered  atomic.Int32
	failed    atomic.Int32
}

func newGMalware(t *testing.T, hang bool) *gmalware {
	t.Helper()
	g := &gmalware{hang: hang, uuids: map[string]string{}, verdicts: map[string]verdict{}, given: map[string]verdict{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/versions", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"/api/lite/v2":"2.0"}`)
	})
	// The client of go-gdetect v1.6.6 deadlocks in Reconfigure when the server
	// has no profile status (a 404 makes it ask the API version while it holds
	// its write lock): the fake serves it so that Stop then Start works.
	mux.HandleFunc("/api/lite/v2/status", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"cache":false,"malware_threshold":100}`)
	})
	mux.HandleFunc("/api/lite/v2/submit", g.submit)
	mux.HandleFunc("/api/lite/v2/results/", g.results)
	mux.HandleFunc("/api/lite/v2/search/", func(w http.ResponseWriter, r *http.Request) {
		if g.injected(w, r) {
			return
		}
		http.Error(w, `{"status":false,"error":"not found"}`, http.StatusNotFound)
	})
	g.Server = httptest.NewServer(mux)
	t.Cleanup(g.Close)
	return g
}

// injected answers with the programmed failure, if any.
func (g *gmalware) injected(w http.ResponseWriter, r *http.Request) bool {
	g.mu.Lock()
	status := g.failure
	g.mu.Unlock()
	if status == 0 {
		return false
	}
	g.failed.Add(1)
	_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, maxFakeSubmission))
	http.Error(w, `{"status":false,"error":"injected failure"}`, status)
	return true
}

func (g *gmalware) submit(w http.ResponseWriter, r *http.Request) {
	g.submitted.Add(1)
	if g.hang {
		// The body is read first: the server notices a closed connection only
		// after that.
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, maxFakeSubmission))
		<-r.Context().Done()
		return
	}
	g.mu.Lock()
	delay := g.delay
	g.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
	}
	if g.injected(w, r) {
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
	if _, err = io.Copy(h, io.LimitReader(part, maxFakeSubmission)); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sum := hex.EncodeToString(h.Sum(nil))
	uuid := sum[0:8] + "-" + sum[8:12] + "-" + sum[12:16] + "-" + sum[16:20] + "-" + sum[20:32]
	g.mu.Lock()
	g.uuids[uuid] = sum
	g.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]any{"status": true, "uuid": uuid})
}

func (g *gmalware) results(w http.ResponseWriter, r *http.Request) {
	if g.injected(w, r) {
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/lite/v2/results/"), "/full")
	g.mu.Lock()
	sum, known := g.uuids[id]
	v := g.verdicts[sum]
	if known {
		g.given[sum] = v
	}
	g.mu.Unlock()
	if !known {
		http.Error(w, `{"status":false,"error":"unknown analysis"}`, http.StatusNotFound)
		return
	}
	g.answered.Add(1)
	res := map[string]any{"uuid": id, "sha256": sum, "done": true, "is_malware": v.malware, "score": 0, "size": 1}
	if v.malware {
		res["score"] = 1000
		res["malwares"] = v.malwares
	}
	_ = json.NewEncoder(w).Encode(res)
}

func sha256Hex(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// MarkMalicious makes the content a malware for the service.
func (g *gmalware) MarkMalicious(content []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.verdicts[sha256Hex(content)] = verdict{malware: true, malwares: []string{"Test.Malware"}}
}

// FailWith makes every request fail with status (an outage), until
// FailWith(0).
func (g *gmalware) FailWith(status int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.failure = status
}

// DelaySubmissions makes every submission wait d before it is answered.
func (g *gmalware) DelaySubmissions(d time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.delay = d
}

// Given tells whether the service gave a result for the SHA256, and which.
func (g *gmalware) Given(sha string) (v verdict, ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	v, ok = g.given[sha]
	return v, ok
}

// Programmed tells whether the test made the SHA256 a malware, whether or not
// the connector ever submitted it.
func (g *gmalware) Programmed(sha string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.verdicts[sha].malware
}

// consoleEvent is an event the connector sent to the console.
type consoleEvent struct {
	Type  string          `json:"type"`
	Event json.RawMessage `json:"event"`
}

const consoleAPIKey = "key"

// fakeConsole plays the connector manager of the agent mode, with the protocol
// of the SDK (register, config, tasks, events, metrics). A request that
// strays from the protocol (method, API key, body) is answered 400 and
// recorded: ProtocolErrors says them.
type fakeConsole struct {
	*httptest.Server

	mu     sync.Mutex
	config map[string]any
	tasks  []map[string]any
	events []consoleEvent
	errs   []string
	nextID int
}

func newFakeConsole(t *testing.T, config map[string]any) *fakeConsole {
	t.Helper()
	c := &fakeConsole{config: config}
	c.Server = httptest.NewServer(http.HandlerFunc(c.serve))
	t.Cleanup(c.Close)
	return c
}

var consoleRoutes = map[string]string{
	"register": http.MethodPost, "config": http.MethodGet, "tasks": http.MethodGet,
	"events": http.MethodPost, "metrics": http.MethodPost,
}

func (c *fakeConsole) protocolError(w http.ResponseWriter, format string, args ...any) {
	c.mu.Lock()
	c.errs = append(c.errs, fmt.Sprintf(format, args...))
	c.mu.Unlock()
	http.Error(w, "protocol error", http.StatusBadRequest)
}

func (c *fakeConsole) serve(w http.ResponseWriter, r *http.Request) {
	route := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
	method, known := consoleRoutes[route]
	switch {
	case !known:
		c.protocolError(w, "unknown route %s", r.URL.Path)
		return
	case r.Method != method:
		c.protocolError(w, "%s with %s, want %s", route, r.Method, method)
		return
	case r.Header.Get("Authorization") != "ApiKey "+consoleAPIKey:
		c.protocolError(w, "%s with the authorization %q", route, r.Header.Get("Authorization"))
		return
	}
	switch route {
	case "register":
		_ = json.NewEncoder(w).Encode(map[string]any{"stopped": false, "config": c.currentConfig(), "unresolved_errors": map[string]string{}})
	case "config":
		_ = json.NewEncoder(w).Encode(map[string]any{"config": c.currentConfig()})
	case "tasks":
		select {
		case <-time.After(300 * time.Millisecond):
		case <-r.Context().Done():
			return
		}
		c.mu.Lock()
		pending := c.tasks
		c.tasks = nil
		c.mu.Unlock()
		if pending == nil {
			pending = []map[string]any{}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"tasks": pending})
	case "events":
		var ev consoleEvent
		if err := json.NewDecoder(io.LimitReader(r.Body, maxFakeEvent)).Decode(&ev); err != nil {
			c.protocolError(w, "undecodable event: %v", err)
			return
		}
		c.mu.Lock()
		c.events = append(c.events, ev)
		c.mu.Unlock()
		_, _ = io.WriteString(w, `{}`)
	default:
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, maxFakeEvent))
		_, _ = io.WriteString(w, `{}`)
	}
}

func (c *fakeConsole) currentConfig() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.config
}

// SetConfig replaces the configuration the console serves: the next
// update-config task makes the connector read it.
func (c *fakeConsole) SetConfig(config map[string]any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config = config
}

// Push queues a task for the connector and returns its ID. content may be
// nil.
func (c *fakeConsole) Push(t *testing.T, action string, content any) string {
	t.Helper()
	task := map[string]any{"connector_id": "e2e", "action": action, "created": time.Now().Unix()}
	if content != nil {
		raw, err := json.Marshal(content)
		if err != nil {
			t.Fatalf("task content: %v", err)
		}
		task["content"] = json.RawMessage(raw)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextID++
	id := "task-" + strconv.Itoa(c.nextID)
	task["id"] = id
	c.tasks = append(c.tasks, task)
	return id
}

// Events returns a copy of the events received so far, in order.
func (c *fakeConsole) Events() []consoleEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]consoleEvent(nil), c.events...)
}

// ProtocolErrors returns what the connector sent that strays from the
// protocol.
func (c *fakeConsole) ProtocolErrors() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.errs...)
}

// Ack returns the error text the connector gave for the task, and whether the
// task was acknowledged.
func (c *fakeConsole) Ack(taskID string) (errText string, acked bool) {
	for _, ev := range c.Events() {
		if ev.Type != "task" {
			continue
		}
		var te struct {
			TaskID string `json:"task_id"`
			Error  string `json:"error"`
		}
		if json.Unmarshal(ev.Event, &te) == nil && te.TaskID == taskID {
			return te.Error, true
		}
	}
	return "", false
}

// WaitAck waits for the acknowledgement of the task and returns its error text.
func (c *fakeConsole) WaitAck(t *testing.T, taskID string) string {
	t.Helper()
	var errText string
	waitFor(t, "the acknowledgement of "+taskID, func() bool {
		var acked bool
		errText, acked = c.Ack(taskID)
		return acked
	})
	return errText
}

// EventsOfType returns the events of one type (error, resolution, log, ...).
func (c *fakeConsole) EventsOfType(typ string) []json.RawMessage {
	var out []json.RawMessage
	for _, ev := range c.Events() {
		if ev.Type == typ {
			out = append(out, ev.Event)
		}
	}
	return out
}
