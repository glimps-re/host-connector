//go:build linux

package console

import (
	"net/http"
	"strings"
	"testing"
)

// The fake console refuses what strays from the SDK protocol and says so.
func TestFakeConsole_protocol(t *testing.T) {
	c := New(t, map[string]any{})
	do := func(method, path, auth, body string) int {
		req, err := http.NewRequestWithContext(t.Context(), method, c.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}
	good := "ApiKey " + APIKey
	if got := do(http.MethodPost, "/api/v1/connectors/register", good, "{}"); got != http.StatusOK {
		t.Errorf("register = %d, want 200", got)
	}
	for name, got := range map[string]int{
		"wrong method":  do(http.MethodGet, "/api/v1/connectors/register", good, ""),
		"no key":        do(http.MethodPost, "/api/v1/connectors/register", "", "{}"),
		"unknown route": do(http.MethodPost, "/api/v1/connectors/elsewhere", good, "{}"),
		"bad event":     do(http.MethodPost, "/api/v1/connectors/events", good, "{not json"),
	} {
		if got != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", name, got)
		}
	}
	if n := len(c.ProtocolErrors()); n != 4 {
		t.Errorf("protocol errors = %d, want 4: %v", n, c.ProtocolErrors())
	}
	id := c.Push(t, "stop", nil)
	if _, acked := c.Ack(id); acked {
		t.Error("a task nobody acknowledged is reported acknowledged")
	}
}
