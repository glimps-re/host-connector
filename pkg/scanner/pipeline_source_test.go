package scanner

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/quarantine"
	quarantinemock "github.com/glimps-re/host-connector/pkg/quarantine/mock"
)

// Every path of the pipeline that runs actions gives them a Source with the root
// of the file, the identity and the SHA256 the pipeline computed: the actions
// that delete, move or quarantine refuse a source without them.
func TestPipeline_everyPathThatRunsActionsGivesAVerifiedSource(t *testing.T) {
	type scenario struct {
		name  string
		setup func(t *testing.T, dir string) (cfg Config, quarantiner quarantine.Quarantiner, setup func(c *Connector), file string)
	}
	plain := func(t *testing.T, dir string) string {
		t.Helper()
		p := filepath.Join(dir, "f.bin")
		if err := os.WriteFile(p, []byte("some content"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	scenarios := []scenario{
		{"simple file", func(t *testing.T, dir string) (Config, quarantine.Quarantiner, func(*Connector), string) {
			return Config{}, nil, nil, plain(t, dir)
		}},
		{"archive", func(t *testing.T, dir string) (Config, quarantine.Quarantiner, func(*Connector), string) {
			archive, _ := createArchive(t, []string{"member one", "member two"})
			b, err := os.ReadFile(filepath.Clean(archive))
			if err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if e := root.Close(); e != nil {
					t.Error(e)
				}
			}()
			if err := root.WriteFile("a.zip", b, 0o600); err != nil {
				t.Fatal(err)
			}
			dst := filepath.Join(dir, "a.zip")
			return Config{Extract: true, ExtractMinThreshold: 1, RecursiveExtractMaxDepth: 3}, nil, nil, dst
		}},
		{"restored file", func(t *testing.T, dir string) (Config, quarantine.Quarantiner, func(*Connector), string) {
			q := &quarantinemock.QuarantineMock{IsRestoredMock: func(context.Context, string, string) (bool, error) { return true, nil }}
			return Config{}, q, nil, plain(t, dir)
		}},
		{"file exempted by a plugin", func(t *testing.T, dir string) (Config, quarantine.Quarantiner, func(*Connector), string) {
			return Config{}, nil, func(c *Connector) {
				c.RegisterOnScanFile(func(name, location, sha256 string, _ bool) *datamodel.Result {
					return &datamodel.Result{Filename: name, Location: location, SHA256: "replaced-by-a-plugin"}
				})
			}, plain(t, dir)
		}},
		{"oversized file", func(t *testing.T, dir string) (Config, quarantine.Quarantiner, func(*Connector), string) {
			return Config{MaxFileSize: 4}, nil, nil, plain(t, dir)
		}},
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			noOpenInputs(t)
			dir := t.TempDir()
			cfg, q, setup, file := sc.setup(t, dir)
			cfg.Roots, cfg.WorkDir, cfg.Workers = []string{dir}, t.TempDir(), 2
			c, err := NewConnector(cfg, q, cleanSubmitter())
			if err != nil {
				t.Fatal(err)
			}
			if setup != nil {
				setup(c)
			}
			var mu sync.Mutex
			var seen []Source
			c.action = &MockAction{HandleMock: func(_ context.Context, src Source, _ datamodel.Result, _ *datamodel.Report) error {
				mu.Lock()
				defer mu.Unlock()
				seen = append(seen, src)
				return nil
			}}
			if err := c.Start(); err != nil {
				t.Fatal(err)
			}
			if err := c.ScanFile(t.Context(), file); err != nil {
				t.Fatal(err)
			}
			c.Close(t.Context())
			want, err := getFileSHA256(file)
			if err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			var top []Source
			for _, s := range seen {
				if s.Path == file {
					top = append(top, s)
				}
			}
			if len(top) != 1 {
				t.Fatalf("%d actions ran on %s, want exactly one (%d in all)", len(top), file, len(seen))
			}
			s := top[0]
			switch {
			case s.Root == "":
				t.Error("Source.Root is empty")
			case s.SHA256 != want:
				t.Errorf("Source.SHA256 = %q, want the hash the pipeline computed %q (not one a plugin put in the result)", s.SHA256, want)
			case s.Identity.zero():
				t.Error("Source.Identity is empty")
			}
		})
	}
}

func TestQuarantineAction_refusesASourceWithoutSHA256AndUsesTheOneOfTheSource(t *testing.T) {
	path, src := verifiedFile(t, "malware bytes")
	var gotSHA string
	a := NewQuarantineAction(&quarantinemock.QuarantineMock{QuarantineMock: func(_ context.Context, _ string, _ *os.File, sha string, _ []string) (string, string, error) {
		gotSHA = sha
		return "/q/lock", "id", nil
	}})
	noHash := src
	noHash.SHA256 = ""
	err := a.Handle(t.Context(), noHash, datamodel.Result{Malware: true, SHA256: "from-the-result"}, &datamodel.Report{})
	if !IsPermanentAction(err) || gotSHA != "" {
		t.Errorf("Handle() error = %v, Quarantine called with %q, want a permanent refusal and no quarantine", err, gotSHA)
	}
	if err := a.Handle(t.Context(), src, datamodel.Result{Malware: true, SHA256: "from-the-result"}, &datamodel.Report{SHA256: "from-the-report"}); err != nil {
		t.Fatal(err)
	}
	if gotSHA != src.SHA256 {
		t.Errorf("Quarantine got %q, want the hash of the source %q: not the one of the result or the report", gotSHA, src.SHA256)
	}
	_ = path
}
