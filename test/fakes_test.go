//go:build linux

package test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Bounds on what the fakes read from the connector, as the product bounds what
// it reads from the network.
const (
	maxFakeSubmission = 1 << 32
	maxFakeEvent      = 1 << 20
)

// errLog records what a fake failed to read or write while answering. A
// connection that the connector closed or reset (it does at shutdown) is only a
// note; anything else is an error the run asserts at its end. A body cut short
// (io.ErrUnexpectedEOF) is a note only for the aborted uploads a scenario
// announced: a connector that cuts its uploads otherwise is an error.
type errLog struct {
	mu        sync.Mutex
	errs      []string
	notes     []string
	announced int
	aborted   int
}

// closedConnection tells the errors of a peer that went away.
func closedConnection(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled)
}

// record keeps the failure of an operation and tells whether it succeeded.
func (l *errLog) record(what string, err error) (ok bool) {
	if err == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	line := what + ": " + err.Error()
	if closedConnection(err) {
		l.notes = append(l.notes, line)
		return false
	}
	l.errs = append(l.errs, line)
	return false
}

// note keeps a failure that is expected, such as a client that went away.
func (l *errLog) note(what string, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.notes = append(l.notes, what+": "+err.Error())
}

// fail keeps a failure of the protocol, which is always an error.
func (l *errLog) fail(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.errs = append(l.errs, msg)
}

// ExpectAbortedUploads announces that n uploads are going to be cut short by
// the connector (a timeout, a stop): their truncated bodies are notes.
func (l *errLog) ExpectAbortedUploads(n int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.announced += n
}

// AbortedUploads counts the uploads whose body the connector cut short or
// whose connection it closed while it was read, for the scenarios to assert.
func (l *errLog) AbortedUploads() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.aborted
}

// Unconsumed counts the aborted uploads a scenario announced and that never
// happened.
func (l *errLog) Unconsumed() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.announced
}

// Errors returns the failures recorded so far.
func (l *errLog) Errors() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.errs...)
}

// Notes returns the expected failures recorded so far, for the log of a test.
func (l *errLog) Notes() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.notes...)
}

func endpoint(r *http.Request) string { return r.Method + " " + r.URL.Path }

// deliver writes an answer, flushes it, and tells whether it reached the
// client as far as the server can see: no write or flush error, and the request
// not cancelled once the answer is flushed. The writes of net/http go to a
// buffer and succeed even when the client has gone: only the context of the
// request tells. What the server cannot see is a client that receives the bytes
// and then drops them.
func (l *errLog) deliver(w http.ResponseWriter, r *http.Request, write func() error) bool {
	if !l.record("writing the answer to "+endpoint(r), write()) {
		return false
	}
	if !l.record("flushing the answer to "+endpoint(r), http.NewResponseController(w).Flush()) {
		return false
	}
	if err := r.Context().Err(); err != nil {
		l.note("the client of "+endpoint(r)+" gave up before the answer", err)
		return false
	}
	return true
}

// json answers with v as JSON and tells whether the answer was delivered.
func (l *errLog) json(w http.ResponseWriter, r *http.Request, v any) bool {
	return l.deliver(w, r, func() error { return json.NewEncoder(w).Encode(v) })
}

// text answers with s and tells whether the answer was delivered.
func (l *errLog) text(w http.ResponseWriter, r *http.Request, s string) bool {
	return l.deliver(w, r, func() error {
		_, err := io.WriteString(w, s)
		return err
	})
}

// drain reads and drops the body of the request, up to limit bytes. A body cut
// short is a note only for an upload the scenario announced.
func (l *errLog) drain(r *http.Request, limit int64) {
	_, err := io.Copy(io.Discard, io.LimitReader(r.Body, limit))
	what := "reading the body of " + endpoint(r)
	if err == nil {
		return
	}
	l.mu.Lock()
	switch {
	case errors.Is(err, io.ErrUnexpectedEOF) && l.announced > 0:
		l.announced--
		l.aborted++
		l.notes = append(l.notes, what+": "+err.Error())
		l.mu.Unlock()
		return
	case closedConnection(err):
		l.aborted++
	}
	l.mu.Unlock()
	l.record(what, err)
}

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
	errLog
	hang bool

	mu       sync.Mutex
	uuids    map[string]string
	verdicts map[string]verdict
	given    map[string]verdict
	failure  int
	delay    time.Duration
	// resultDelay is how long the results wait before they are answered.
	resultDelay time.Duration

	submitted atomic.Int32
	answered  atomic.Int32
	// handled counts the result requests whose handler has ended.
	handled atomic.Int32
	failed  atomic.Int32
}

func newGMalware(t *testing.T, hang bool) *gmalware {
	t.Helper()
	g := &gmalware{hang: hang, uuids: map[string]string{}, verdicts: map[string]verdict{}, given: map[string]verdict{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/versions", func(w http.ResponseWriter, r *http.Request) {
		g.text(w, r, `{"/api/lite/v2":"2.0"}`)
	})
	// The client of go-gdetect v1.6.6 deadlocks in Reconfigure when the server
	// has no profile status (a 404 makes it ask the API version while it holds
	// its write lock): the fake serves it so that Stop then Start works.
	mux.HandleFunc("/api/lite/v2/status", func(w http.ResponseWriter, r *http.Request) {
		g.text(w, r, `{"cache":false,"malware_threshold":100}`)
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
	g.drain(r, maxFakeSubmission)
	http.Error(w, `{"status":false,"error":"injected failure"}`, status)
	return true
}

func (g *gmalware) submit(w http.ResponseWriter, r *http.Request) {
	g.submitted.Add(1)
	if g.hang {
		// The body is read first: the server notices a closed connection only
		// after that.
		g.drain(r, maxFakeSubmission)
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
	g.json(w, r, map[string]any{"status": true, "uuid": uuid})
}

func (g *gmalware) results(w http.ResponseWriter, r *http.Request) {
	defer g.handled.Add(1)
	if g.injected(w, r) {
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/lite/v2/results/"), "/full")
	g.mu.Lock()
	sum, known := g.uuids[id]
	v := g.verdicts[sum]
	g.mu.Unlock()
	if !known {
		http.Error(w, `{"status":false,"error":"unknown analysis"}`, http.StatusNotFound)
		return
	}
	res := map[string]any{"uuid": id, "sha256": sum, "done": true, "is_malware": v.malware, "score": 0, "size": 1}
	if v.malware {
		res["score"] = 1000
		res["malwares"] = v.malwares
	}
	g.mu.Lock()
	delay := g.resultDelay
	g.mu.Unlock()
	// Not interrupted by the cancellation of the request: the handler goes on to
	// the answer, as a slow server does, and must see that nobody listens.
	time.Sleep(delay)
	// The verdict counts as given only once it was delivered: a connector that
	// never received it must not pass for one that analyzed the file. The lock is
	// taken to record only, never while a slow client is being written to.
	if !g.json(w, r, res) {
		return
	}
	g.mu.Lock()
	g.given[sum] = v
	g.mu.Unlock()
	g.answered.Add(1)
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

// DelayResults makes every result wait d before it is answered, whatever
// happens to the request meanwhile.
func (g *gmalware) DelayResults(d time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.resultDelay = d
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

// consolePollWait is how long a request for tasks waits before it is answered.
const consolePollWait = 300 * time.Millisecond

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
	errLog

	mu     sync.Mutex
	config map[string]any
	tasks  []map[string]any
	events []consoleEvent
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
	c.fail(fmt.Sprintf(format, args...))
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
		c.json(w, r, map[string]any{"stopped": false, "config": c.currentConfig(), "unresolved_errors": map[string]string{}})
	case "config":
		c.json(w, r, map[string]any{"config": c.currentConfig()})
	case "tasks":
		select {
		case <-time.After(consolePollWait):
		case <-r.Context().Done():
			return
		}
		// A task leaves the queue only once its answer was delivered: the request
		// of a connector that is gone (a process just restarted) wakes up after
		// its client died, and must not take the tasks of the next one.
		c.mu.Lock()
		pending := slices.Clone(c.tasks)
		c.mu.Unlock()
		if pending == nil {
			pending = []map[string]any{}
		}
		if !c.json(w, r, map[string]any{"tasks": pending}) {
			return
		}
		c.mu.Lock()
		c.tasks = slices.DeleteFunc(c.tasks, func(t map[string]any) bool {
			return slices.ContainsFunc(pending, func(p map[string]any) bool { return p["id"] == t["id"] })
		})
		c.mu.Unlock()
	case "events":
		var ev consoleEvent
		if err := json.NewDecoder(io.LimitReader(r.Body, maxFakeEvent)).Decode(&ev); err != nil {
			c.protocolError(w, "undecodable event: %v", err)
			return
		}
		c.mu.Lock()
		c.events = append(c.events, ev)
		c.mu.Unlock()
		c.text(w, r, `{}`)
	default:
		c.drain(r, maxFakeEvent)
		c.text(w, r, `{}`)
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
	return c.Errors()
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
