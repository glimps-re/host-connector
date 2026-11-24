//go:build linux

// Package console is a fake connector manager for the e2e suite.
package console

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/test/internal/fakes/errlog"
	"github.com/glimps-re/host-connector/test/internal/wait"
)

// maxFakeEvent bounds what the fake reads from the connector, as the product
// bounds what it reads from the network.
const maxFakeEvent = 1 << 20

// consolePollWait is how long a request for tasks waits before it is answered.
const consolePollWait = 300 * time.Millisecond

// Event is an event the connector sent to the console.
type Event struct {
	Type  string          `json:"type"`
	Event json.RawMessage `json:"event"`
}

const APIKey = "key"

// Console plays the connector manager of the agent mode, with the protocol
// of the SDK (register, config, tasks, events, metrics). A request that
// strays from the protocol (method, API key, body) is answered 400 and
// recorded: ProtocolErrors says them.
type Console struct {
	*httptest.Server
	errlog.Log

	// polls counts the requests for tasks being answered.
	polls atomic.Int32

	mu     sync.Mutex
	config map[string]any
	tasks  []map[string]any
	events []Event
	nextID int
}

func New(t *testing.T, config map[string]any) *Console {
	t.Helper()
	c := &Console{config: config}
	c.Server = httptest.NewServer(http.HandlerFunc(c.serve))
	t.Cleanup(c.Close)
	return c
}

var consoleRoutes = map[string]string{
	"register": http.MethodPost, "config": http.MethodGet, "tasks": http.MethodGet,
	"events": http.MethodPost, "metrics": http.MethodPost,
}

func (c *Console) protocolError(w http.ResponseWriter, format string, args ...any) {
	c.Fail(fmt.Sprintf(format, args...))
	http.Error(w, "protocol error", http.StatusBadRequest)
}

func (c *Console) serve(w http.ResponseWriter, r *http.Request) {
	route := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
	method, known := consoleRoutes[route]
	switch {
	case !known:
		c.protocolError(w, "unknown route %s", r.URL.Path)
		return
	case r.Method != method:
		c.protocolError(w, "%s with %s, want %s", route, r.Method, method)
		return
	case r.Header.Get("Authorization") != "ApiKey "+APIKey:
		c.protocolError(w, "%s with the authorization %q", route, r.Header.Get("Authorization"))
		return
	}
	switch route {
	case "register":
		c.JSON(w, r, map[string]any{"stopped": false, "config": c.currentConfig(), "unresolved_errors": map[string]string{}})
	case "config":
		c.JSON(w, r, map[string]any{"config": c.currentConfig()})
	case "tasks":
		c.polls.Add(1)
		defer c.polls.Add(-1)
		select {
		case <-time.After(consolePollWait):
		case <-r.Context().Done():
			return
		}
		// A task leaves the queue only once its answer was delivered: the request of
		// a connector that is gone (a process just restarted) wakes up after its
		// client died, and must not take the tasks of the next one. The real manager
		// is stricter about what it hands out; this fake re-delivers rather than
		// lose a task.
		c.mu.Lock()
		pending := slices.Clone(c.tasks)
		c.mu.Unlock()
		if pending == nil {
			pending = []map[string]any{}
		}
		if !c.JSON(w, r, map[string]any{"tasks": pending}) {
			return
		}
		c.mu.Lock()
		c.tasks = slices.DeleteFunc(c.tasks, func(t map[string]any) bool {
			return slices.ContainsFunc(pending, func(p map[string]any) bool { return p["id"] == t["id"] })
		})
		c.mu.Unlock()
	case "events":
		var ev Event
		if err := json.NewDecoder(io.LimitReader(r.Body, maxFakeEvent)).Decode(&ev); err != nil {
			c.protocolError(w, "undecodable event: %v", err)
			return
		}
		c.mu.Lock()
		c.events = append(c.events, ev)
		c.mu.Unlock()
		c.Text(w, r, `{}`)
	default:
		c.Drain(r, maxFakeEvent)
		c.Text(w, r, `{}`)
	}
}

func (c *Console) currentConfig() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.config
}

// SetConfig replaces the configuration the console serves: the next
// update-config task makes the connector read it.
func (c *Console) SetConfig(config map[string]any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.config = config
}

// Push queues a task for the connector and returns its ID. content may be
// nil.
func (c *Console) Push(t *testing.T, action string, content any) string {
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

// PollsInFlight counts the requests for tasks the console is still answering.
func (c *Console) PollsInFlight() int { return int(c.polls.Load()) }

// Events returns a copy of the events received so far, in order.
func (c *Console) Events() []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Event(nil), c.events...)
}

// ProtocolErrors returns what the connector sent that strays from the
// protocol.
func (c *Console) ProtocolErrors() []string {
	return c.Errors()
}

// Ack returns the error text the connector gave for the task, and whether the
// task was acknowledged.
func (c *Console) Ack(taskID string) (errText string, acked bool) {
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
func (c *Console) WaitAck(t *testing.T, taskID string) string {
	t.Helper()
	var errText string
	wait.WaitFor(t, "the acknowledgement of "+taskID, func() bool {
		var acked bool
		errText, acked = c.Ack(taskID)
		return acked
	})
	return errText
}

// EventsOfType returns the events of one type (error, resolution, log, ...).
func (c *Console) EventsOfType(typ string) []json.RawMessage {
	var out []json.RawMessage
	for _, ev := range c.Events() {
		if ev.Type == typ {
			out = append(out, ev.Event)
		}
	}
	return out
}

// ErrorTypes returns the types of the error events the console received.
func (c *Console) ErrorTypes() (types []string) {
	for _, raw := range c.EventsOfType("error") {
		var ev struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(raw, &ev) == nil {
			types = append(types, ev.Type)
		}
	}
	return types
}

// ResolvedTypes returns the error types the console received a resolution for.
func (c *Console) ResolvedTypes() (types []string) {
	for _, raw := range c.EventsOfType("resolution") {
		var ev struct {
			Types []string `json:"type"`
		}
		if json.Unmarshal(raw, &ev) == nil {
			types = append(types, ev.Types...)
		}
	}
	return types
}

// MitigationReasons returns the reasons of the mitigation events the console
// received.
func (c *Console) MitigationReasons() (reasons []string) {
	for _, raw := range c.EventsOfType("mitigation") {
		var ev struct {
			Reason string `json:"reason"`
		}
		if json.Unmarshal(raw, &ev) == nil {
			reasons = append(reasons, ev.Reason)
		}
	}
	return reasons
}
