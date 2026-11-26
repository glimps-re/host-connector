package scanner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp/syntax"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/glimps-re/connector-integration/sdk"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func mustPathFilter(t testing.TB, forbidden, skipped []string) *PathFilter {
	t.Helper()
	f, err := NewPathFilter(forbidden, skipped)
	if err != nil {
		t.Fatalf("NewPathFilter() error = %v", err)
	}
	return f
}

func TestPathFilter_Apply(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.txt")
	logFile := filepath.Join(tmpDir, "app.log")
	for _, p := range []string{tmpFile, logFile} {
		if err := os.WriteFile(p, []byte("test content"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	forbidden := func(name, location, sha string) *datamodel.Result {
		return &datamodel.Result{Filename: name, Location: location, Malware: true, SHA256: sha, Score: 1000, Malwares: []string{"forbidden_file_path"}, MalwareReason: datamodel.FilteredFilePath, FilteredVolume: 12, FileSize: 12}
	}
	tests := []struct {
		name               string
		forbidden, skipped []string
		file, location     string
		want               *datamodel.Result
	}{
		{name: "no rule", file: "x", location: tmpFile},
		{name: "a file that does not exist matches nothing", forbidden: []string{"^/nowhere/"}, skipped: []string{`\.txt$`}, file: "nonexistent.txt", location: "/nonexistent/path/file.txt"},
		{name: "forbidden", forbidden: []string{regexpQuote(tmpDir)}, file: tmpFile, location: tmpFile, want: forbidden(tmpFile, tmpFile, "sha")},
		{name: "skipped", skipped: []string{`\.log$`}, file: "app.log", location: logFile, want: &datamodel.Result{Filename: "app.log", Location: logFile, SHA256: "sha", Score: -500, NotAnalyzedReason: datamodel.NotAnalyzedSkippedPath, FilteredVolume: 12, FileSize: 12}},
		{name: "no pattern matches", forbidden: []string{"^/forbidden/"}, skipped: []string{`\.bak$`}, file: "test.txt", location: tmpFile},
		{name: "a forbidden path beats a skipped one", forbidden: []string{regexpQuote(tmpDir)}, skipped: []string{`\.log$`}, file: logFile, location: logFile, want: forbidden(logFile, logFile, "sha")},
		{name: "a location not cleaned (dot-dot)", forbidden: []string{regexpQuote(tmpDir)}, file: tmpFile, location: tmpDir + "/../" + filepath.Base(tmpDir) + "/test.txt", want: forbidden(tmpFile, tmpFile, "sha")},
		{name: "a location not cleaned (double slash)", forbidden: []string{regexpQuote(tmpDir)}, file: tmpFile, location: tmpDir + "//test.txt", want: forbidden(tmpFile, tmpFile, "sha")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mustPathFilter(t, tt.forbidden, tt.skipped).Apply(tt.file, "", tt.location, "sha")
			if diff := cmp.Diff(tt.want, got, cmpopts.IgnoreFields(datamodel.Result{}, "MaliciousSubfiles")); diff != "" {
				t.Errorf("Apply() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func regexpQuote(s string) string {
	return strings.NewReplacer(`\`, `\\`, `.`, `\.`, `+`, `\+`, `*`, `\*`, `?`, `\?`, `(`, `\(`, `)`, `\)`, `[`, `\[`, `]`, `\]`, `{`, `\{`, `}`, `\}`, `^`, `\^`, `$`, `\$`, `|`, `\|`).Replace(s)
}

// The rules are matched on the logical path of the file, never on the temporary
// folder the member was extracted to.
func TestPathFilter_Apply_logicalPath(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "extract-1234")
	if err := os.MkdirAll(tmp, 0o750); err != nil {
		t.Fatal(err)
	}
	member := filepath.Join(tmp, "y.exe")
	if err := os.WriteFile(member, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := mustPathFilter(t, []string{`^/in/alice/.*\.exe$`}, []string{"^" + regexpQuote(tmp)})
	if res := f.Apply("/in/alice/a.zip/x/y.exe", "", member, "sha"); res == nil || !res.Malware {
		t.Errorf("a member of an archive of alice must match on its logical path, got %+v", res)
	}
	if res := f.Apply("/in/bob/a.zip/x/y.exe", "", member, "sha"); res != nil {
		t.Errorf("the temporary folder must never be matched, got %+v", res)
	}
	tests := []struct {
		name, file string
		want       bool
	}{
		{"nested archive", "/in/alice/a.zip/b.zip/y.exe", true},
		{"name of 4096 bytes", "/in/alice/" + strings.Repeat("a", 4096-len("/in/alice/.exe")) + ".exe", true},
		{"neutralized control character", "/in/alice/a.zip/a_b.exe", true},
		{"dot-dot with a nul at the end", "/in/alice/a.zip/../../etc/y.exe\x00", true},
		{"nul at the end is folded away", "/in/alice/a.zip/y.exe\x00", true},
		{"empty name", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := f.Apply(tt.file, "", member, "sha")
			if got := res != nil && res.Malware; got != tt.want {
				t.Errorf("Apply(%q) malware = %t, want %t (%+v)", tt.file, got, tt.want, res)
			}
		})
	}
	t.Run("a forbidden path applies even when the file cannot be examined", func(t *testing.T) {
		res := f.Apply("/in/alice/a.zip/x/y.exe", "", filepath.Join(tmp, "gone.exe"), "sha")
		if res == nil || !res.Malware || res.FileSize != 0 {
			t.Errorf("Apply() = %+v, want malware with an unknown size", res)
		}
	})
	t.Run("a skipped path is not waived when the file cannot be read", func(t *testing.T) {
		if res := f.Apply(member, "", filepath.Join(tmp, "gone.exe"), "sha"); res != nil {
			t.Errorf("Apply() = %+v, want no waiver for a file that cannot be read", res)
		}
	})
}

func TestPathFilter_nilAndEmptyApplyNothing(t *testing.T) {
	var nilFilter *PathFilter
	for name, f := range map[string]*PathFilter{"nil": nilFilter, "empty": mustPathFilter(t, nil, nil)} {
		if !f.empty() || f.Apply("/in/x.exe", "", "/in/x.exe", "sha") != nil {
			t.Errorf("%s filter must apply no rule", name)
		}
	}
}

func TestNewPathFilter_refusals(t *testing.T) {
	distinct := func(n, size int, letter string) []string {
		out := make([]string, n)
		for i := range out {
			tail := fmt.Sprintf("%06d", i)
			pad := size - len(letter) - len(tail)
			if pad < 0 {
				out[i] = strings.Repeat(letter, size-len(tail)) + tail
				continue
			}
			out[i] = letter + strings.Repeat("(?s)", pad/4) + strings.Repeat(letter, pad%4) + tail
		}
		return out
	}
	tests := []struct {
		name               string
		forbidden, skipped []string
		want               string // "" accepted
	}{
		{name: "valid rules", forbidden: []string{`\.exe$`}, skipped: []string{`^/srv/in/trusted/`}},
		{name: "no rule"},
		{name: "two spaces match only a path with two spaces", skipped: []string{"  "}},
		{name: "an empty forbidden pattern", forbidden: []string{"a", ""}, want: "forbidden_paths[1]: an empty pattern"},
		{name: "an empty skipped pattern", skipped: []string{""}, want: "skipped_paths[0]: an empty pattern"},
		{name: "an unbalanced group", skipped: []string{"ok", "("}, want: "skipped_paths[1]"},
		{name: "a bracket never closed", forbidden: []string{"(["}, want: "forbidden_paths[0]"},
		{name: "a pattern that matches the empty string", forbidden: []string{"a*"}, want: "matches the empty string"},
		{name: "an alternative that matches the empty string", skipped: []string{"x|"}, want: "matches the empty string"},
		{name: "an empty group matches the empty string", skipped: []string{"()"}, want: "matches the empty string"},
		{name: "a pattern too large to compile", forbidden: []string{`((a{1000}){1000}){1000}`}, want: "forbidden_paths[0]"},
		{name: "1024 ASCII bytes", skipped: distinct(1, 1024, "a")},
		{name: "1025 ASCII bytes", forbidden: distinct(1, 1025, "a"), want: "1025 bytes, at most 1024"},
		{name: "1024 bytes of two-byte runes and flags", skipped: []string{strings.Repeat("(?s)", 200) + strings.Repeat("é", 112)}},
		{name: "513 two-byte runes are 1026 bytes", skipped: []string{strings.Repeat("é", 513)}, want: "1026 bytes"},
		{name: "a pattern in both lists", forbidden: []string{"x", "same"}, skipped: []string{"y", "same"}, want: "skipped_paths[1]: the pattern \"same\" is also in forbidden_paths"},
		{name: "256 patterns", forbidden: distinct(256, 6, "a")},
		{name: "257 patterns", skipped: distinct(257, 6, "a"), want: "257 patterns, at most 256"},
		{name: "20000 patterns", forbidden: distinct(20_000, 6, "a"), want: "20000 patterns, at most 256"},
		{name: "32 KiB in all", forbidden: distinct(16, 1024, "a"), skipped: distinct(16, 1024, "b")},
		{name: "32 KiB and one byte", forbidden: distinct(16, 1024, "a"), skipped: append(distinct(15, 1024, "b"), distinct(1, 1024, "c")[0], "d"), want: "32768 in all"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewPathFilter(tt.forbidden, tt.skipped)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("NewPathFilter() error = %v, want it accepted", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidPathFilter) || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("NewPathFilter() error = %v, want %q", err, tt.want)
			}
		})
	}
}

// The checks come in a fixed order, and what is refused early is never compiled.
func TestNewPathFilter_checksInOrder(t *testing.T) {
	tests := []struct {
		name               string
		forbidden, skipped []string
		want               string
	}{
		{"count before size", func() []string { l := make([]string, 257); return l }(), []string{""}, "257 patterns"},
		{"size before content", append(slices.Repeat([]string{strings.Repeat("a", 1024)}, 32), ""), []string{"("}, "in all"},
		{"an empty pattern before a bad syntax", []string{"(", ""}, nil, "forbidden_paths[1]"},
		{"overlap before a bad syntax", []string{"x", "("}, []string{"x"}, "also in forbidden_paths"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewPathFilter(tt.forbidden, tt.skipped)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("NewPathFilter() error = %v, want %q first", err, tt.want)
			}
		})
	}
}

func TestNewPathFilter_errorsEchoLittleOfThePattern(t *testing.T) {
	_, err := NewPathFilter([]string{"(" + strings.Repeat("é", 400)}, nil)
	if err == nil {
		t.Fatal("an invalid pattern was accepted")
	}
	if strings.Count(err.Error(), "é") > 32 {
		t.Errorf("the error echoes %d characters of the pattern, want at most 64 bytes", strings.Count(err.Error(), "é"))
	}
}

func TestPathFilter_isSafeForConcurrentUse(t *testing.T) {
	f := mustPathFilter(t, []string{`\.exe$`}, []string{`\.log$`})
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			for range 200 {
				f.Apply(fmt.Sprintf("/in/%d/x.exe", i), "", "/nonexistent", "sha")
			}
		})
	}
	wg.Wait()
}

func BenchmarkPathFilter_Apply(b *testing.B) {
	forbidden := make([]string, 64)
	skipped := make([]string, 64)
	for i := range forbidden {
		forbidden[i] = fmt.Sprintf(`^/in/f%03d/.*\.exe$`, i)
		skipped[i] = fmt.Sprintf(`^/in/s%03d/`, i)
	}
	f := mustPathFilter(b, forbidden, skipped)
	paths := make([]string, 100_000)
	for i := range paths {
		paths[i] = fmt.Sprintf("/srv/in/user%d/batch%d/file%d.bin", i%97, i%13, i)
	}
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		if f.Apply(paths[i%len(paths)], "", "/nonexistent", "sha") != nil {
			b.Fatal("a path matched")
		}
	}
}

// The rules of the configuration come before the plugins: a refusal of theirs
// stops the chain, a waiver of theirs is kept and the plugins still run, so that
// a refusal of a plugin (a forbidden type) beats a skipped path.
func TestConnector_onScanFile_pathRulesAndPlugins(t *testing.T) {
	file := filepath.Join(t.TempDir(), "x.bin")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	pluginRefusal := &datamodel.Result{Malware: true, Malwares: []string{"plugin"}, MalwareReason: datamodel.FilteredFileType}
	tests := []struct {
		name         string
		forbidden    []string
		skipped      []string
		plugin       *datamodel.Result
		wantPlugin   bool // the plugin is called
		wantMalware  bool
		wantWaiver   bool
		wantMalwares []string
	}{
		{name: "no rule matches: the plugin decides", skipped: []string{"^/nowhere"}, plugin: pluginRefusal, wantPlugin: true, wantMalware: true, wantMalwares: []string{"plugin"}},
		{name: "a forbidden path stops the chain", forbidden: []string{`x\.bin$`}, plugin: &datamodel.Result{}, wantMalware: true, wantMalwares: []string{"forbidden_file_path"}},
		{name: "a skipped path is kept and the plugin runs", skipped: []string{`x\.bin$`}, wantPlugin: true, wantWaiver: true},
		{name: "a refusal of a plugin beats a skipped path", skipped: []string{`x\.bin$`}, plugin: pluginRefusal, wantPlugin: true, wantMalware: true, wantMalwares: []string{"plugin"}},
		{name: "a waiver of a plugin changes nothing to a skipped path", skipped: []string{`x\.bin$`}, plugin: &datamodel.Result{Score: 7}, wantPlugin: true, wantWaiver: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Connector{config: Config{PathFilter: mustPathFilter(t, tt.forbidden, tt.skipped)}}
			called := false
			c.onScanFileCbs = append(c.onScanFileCbs, func(string, string, string, bool) *datamodel.Result {
				called = true
				return tt.plugin
			})
			got := c.onScanFile("/in/x.bin", file, "sha", false)
			if called != tt.wantPlugin {
				t.Errorf("plugin called = %t, want %t", called, tt.wantPlugin)
			}
			if got == nil {
				t.Fatal("onScanFile() = nil, want a result")
			}
			if got.Malware != tt.wantMalware || (tt.wantWaiver && !isWaiver(got)) {
				t.Errorf("onScanFile() = %+v, want malware %t, waiver %t", got, tt.wantMalware, tt.wantWaiver)
			}
			if tt.wantMalwares != nil && !slices.Equal(got.Malwares, tt.wantMalwares) {
				t.Errorf("malwares = %v, want %v", got.Malwares, tt.wantMalwares)
			}
			if tt.wantWaiver && got.Score != -500 {
				t.Errorf("score = %d, want the skipped path's waiver to be the one kept", got.Score)
			}
		})
	}
}

func TestNewPathFilter_costBounds(t *testing.T) {
	heavy := func(letter byte, n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("(?:%c{50}){5}", letter+byte(i))
		}
		return out
	}
	realistic := func(format string, n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf(format, i)
		}
		return out
	}
	tests := []struct {
		name               string
		forbidden, skipped []string
		want               string // "" accepted
	}{
		{name: "a repeat of 100", forbidden: []string{`a{100}b`}},
		{name: "a repeat of 100 to 100", forbidden: []string{`a{100,100}b`}},
		{name: "a repeat of 101", forbidden: []string{`a{101}b`}, want: "forbidden_paths[0]: the pattern \"a{101}b\" repeats 101 times, at most 100"},
		{name: "a range that ends at 101", skipped: []string{`a{1,101}b`}, want: "skipped_paths[0]: the pattern \"a{1,101}b\" repeats 101 times"},
		{name: "a repeat of 101 nested in a group", skipped: []string{`(?:x(?:a{101})y)+z`}, want: "repeats 101 times"},
		{name: "an estimate under 512 instructions", forbidden: []string{`(?:a{50}){5}`}},
		{name: "an estimate over 512 instructions", forbidden: []string{`(?:a{50}){10}`}, want: "estimated at 526 instructions, at most 512"},
		{name: "written-out optional characters", forbidden: []string{strings.Repeat("a?", 500) + "b"}, want: "instructions, at most 512"},
		{name: "repeats side by side", skipped: []string{`(?:a{100}){3}(?:b{100}){3}`}, want: "instructions, at most 512"},
		{name: "nested counted repeats that parse refuses", skipped: []string{`((a{100}){100}){100}`}, want: "not a valid regular expression (invalid repeat count)"},
		{name: "15 patterns of 266", forbidden: heavy('a', 8), skipped: heavy('i', 7)},
		{name: "16 patterns of 266", forbidden: heavy('a', 8), skipped: heavy('i', 8), want: "more than 4096 instructions in all"},
		{name: "120 realistic patterns", forbidden: realistic(`^/in/u%03d/.*\.(exe|dll)$`, 60), skipped: realistic(`^/in/t%03d/[^/]+\.pdf$`, 60)},
		{name: "classes of Unicode letters", forbidden: []string{`\pL`, `\pL`, `\pL`, `\pL`, `\pL`, `\pL`, `\pL`}, want: "more than 4096 ranges in all"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewPathFilter(tt.forbidden, tt.skipped)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("NewPathFilter() error = %v, want it accepted", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidPathFilter) || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("NewPathFilter() error = %v, want %q", err, tt.want)
			}
		})
	}
}

// The size is estimated from the parse tree: what is refused is refused before any
// compilation, whose cost in memory is the reason of the bound.
func TestNewPathFilter_refusesBeforeCompiling(t *testing.T) {
	patterns := make([]string, 30)
	for i := range patterns {
		patterns[i] = fmt.Sprintf(`(?i:\pL)x%d`, i)
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := NewPathFilter(patterns, nil)
	runtime.ReadMemStats(&after)
	if err == nil || !strings.Contains(err.Error(), "ranges in all") {
		t.Fatalf("NewPathFilter() error = %v, want the ranges bound", err)
	}
	if grown := after.TotalAlloc - before.TotalAlloc; grown > 10<<20 {
		t.Errorf("%d MiB allocated to refuse the patterns, want under 10", grown>>20)
	}
}

// The estimate never falls under what compiling gives, and is not far above it for
// ordinary patterns.
func TestEstimateProgram_isAnUpperBoundOfTheCompiledProgram(t *testing.T) {
	patterns := []string{
		`\.exe$`, `^/in/[^/]+/trusted/`, `(?i)\.(lnk|hta|wsf)$`, `a{100}b`, `(?:a{50}){5}`, `(a|b|c)+d*e?`, `x{3,7}y`, `x{3,}y`,
		`.*\.zip/.*\.exe$`, `(?s).+a`, `[a-z0-9_]{1,20}@x`, `(?:foo|bar|baz){2,4}`, `\b\w+\b`, `^$|a`, `(?m)^a$`,
		`\p{Han}+`, `(a?){30}b`, `((ab){3}c){4}`,
	}
	for _, p := range patterns {
		tree, err := syntax.Parse(p, syntax.Perl)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		est, _ := estimatePattern(tree)
		prog, err := syntax.Compile(tree.Simplify())
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if got := len(prog.Inst); est < got {
			t.Errorf("%s: estimated %d instructions, the program has %d", p, est, got)
		}
	}
}

func TestPathFilter_Apply_pathLength(t *testing.T) {
	long := func(n int) string { return "/in/" + strings.Repeat("a", n-len("/in/.exe")) + ".exe" }
	tests := []struct {
		name               string
		forbidden, skipped []string
		path, raw          string
		want               string // "malware", "error", "skipped" or "" for no result
	}{
		{"forbidden, a path of 4096 bytes", []string{`\.exe$`}, nil, long(4096), "", "malware"},
		{"forbidden, a path of 4097 bytes is an error, not malware", []string{`\.exe$`}, nil, long(4097), "", "error"},
		{"forbidden, even a path that no rule matches", []string{`\.dll$`}, nil, long(4097), "", "error"},
		{"forbidden and skipped, a long path is an error", []string{`\.dll$`}, []string{`^/in/`}, long(4097), "", "error"},
		{"only skipped, a long path is never skipped", nil, []string{`^/in/`}, long(4097), "", ""},
		{"only skipped, a path of 4096 bytes is skipped", nil, []string{`^/in/`}, long(4096), "", "skipped"},
		{"a raw form over the bound counts as well", []string{`\.dll$`}, nil, "/in/a.exe", long(4097), "error"},
		{"a raw form that is the only one to be forbidden", []string{`\.exe\n$`}, nil, "/in/a.exe_", "/in/a.exe\n", "malware"},
		{"skipped by the logical form only is not skipped", nil, []string{`a_b\.txt$`}, "/in/a_b.txt", "/in/a\x01b.txt", ""},
		{"skipped by both forms", nil, []string{`/in/a.`, `b\.txt$`}, "/in/a_b.txt", "/in/a\x01b.txt", "skipped"},
		{"forbidden by the logical form only", []string{`a_b\.txt$`}, nil, "/in/a_b.txt", "/in/a\x01b.txt", "malware"},
		{"a raw form equal to the logical one is matched once", nil, []string{`^/in/`}, "/in/x", "/in/x", "skipped"},
	}
	loc := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(loc, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := mustPathFilter(t, tt.forbidden, tt.skipped).Apply(tt.path, tt.raw, loc, "sha")
			got := ""
			switch {
			case res == nil:
			case res.Error != nil:
				got = "error"
				if !errors.Is(res.Error, errPathTooLong) || res.Malware {
					t.Errorf("result = %+v, want errPathTooLong and no detection", res)
				}
			case res.Malware:
				got = "malware"
			case isWaiver(res):
				got = "skipped"
			}
			if got != tt.want {
				t.Errorf("Apply() = %q, want %q (%+v)", got, tt.want, res)
			}
		})
	}
}

func TestPathFilter_withTheSkippedPathsIgnored(t *testing.T) {
	f := mustPathFilter(t, []string{`\.exe$`}, []string{`^/in/`})
	tests := []struct {
		name        string
		file        string
		skip        bool
		wantMalware bool
		wantResult  bool
	}{
		{"forbidden, skip allowed", "/in/a.exe", true, true, true},
		{"forbidden, skip ignored", "/in/a.exe", false, true, true},
		{"skipped, skip allowed", "/in/a.txt", true, false, false},
		{"skipped, skip ignored: no result", "/in/a.txt", false, false, false},
	}
	loc := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(loc, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := f.apply(tt.file, "", loc, "sha", tt.skip)
			if got := r != nil && r.Malware; got != tt.wantMalware {
				t.Errorf("apply() = %+v, want malware %t", r, tt.wantMalware)
			}
			if tt.skip && !tt.wantMalware && (r == nil || !isWaiver(r)) {
				t.Errorf("apply() = %+v, want the waiver", r)
			}
			if !tt.skip && !tt.wantMalware && r != nil {
				t.Errorf("apply() = %+v, want nil", r)
			}
		})
	}
}

func TestPathFilter_hasForbidden(t *testing.T) {
	tests := []struct {
		name string
		f    *PathFilter
		want bool
	}{
		{"both lists", mustPathFilter(t, []string{`a`}, []string{`b`}), true},
		{"skipped only", mustPathFilter(t, nil, []string{`^/in/`}), false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		if got := tt.f.hasForbidden(); got != tt.want {
			t.Errorf("%s: hasForbidden() = %t, want %t", tt.name, got, tt.want)
		}
	}
}

func TestPathFilter_regexpDoesNotTellInvalidUTF8FromItsReplacement(t *testing.T) {
	forbidden := mustPathFilter(t, []string{`a\x{FFFD}b$`}, nil)
	if d, _ := forbidden.decide("/in/a\uFFFDb", "/in/a\xffb", true); d != pathForbidden {
		t.Errorf("decide() = %d, want forbidden: RE2 reads an invalid byte as U+FFFD", d)
	}
	skipped := mustPathFilter(t, nil, []string{`a\x{FFFD}b$`})
	if skipped.skipsPath("/in/a\uFFFDb", "/in/a\xffb") {
		t.Error("skipsPath() = true, want false: the folded form without the invalid byte does not match")
	}
}

func BenchmarkPathFilter_realisticRules(b *testing.B) {
	forbidden := []string{`\.(exe|dll|scr|bat|cmd|js|vbs|ps1|jar|msi)$`, `(?i)\.(lnk|hta|wsf)$`, `/\.git/`, `/node_modules/`}
	skipped := make([]string, 0, 46)
	for i := range 23 {
		skipped = append(skipped, fmt.Sprintf(`^/srv/in/trusted%02d/`, i), fmt.Sprintf(`^/srv/in/user%02d/(docs|images)/[^/]+\.(txt|png|jpg)$`, i))
	}
	f := mustPathFilter(b, forbidden, skipped)
	path := "/srv/in/other/" + strings.Repeat("segment/", 500)[:4000] + "file.bin"
	raw := strings.Replace(path, "file", "fi\x01e", 1)
	b.ReportAllocs()
	for b.Loop() {
		f.decide(path, raw, true)
	}
}

func heaviestAccepted(tb testing.TB) (forbidden, skipped []string) {
	tb.Helper()
	heavy := func(first byte, n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("(?:[%c/]{50}){5}z", first+byte(i))
		}
		return out
	}
	forbidden, skipped = heavy('a', 8), heavy('i', 7)
	mustPathFilter(tb, forbidden, skipped)
	return forbidden, skipped
}

// BenchmarkPathFilter_heaviestAcceptedRules is the worst case the bounds let in,
// matched on a path of 4 KiB with the two forms of it.
func BenchmarkPathFilter_heaviestAcceptedRules(b *testing.B) {
	forbidden, skipped := heaviestAccepted(b)
	f := mustPathFilter(b, forbidden, skipped)
	path := "/" + strings.Repeat("a/", 2047) + "x"
	raw := strings.Replace(path, "x", "\x01", 1)
	b.ReportAllocs()
	for b.Loop() {
		f.decide(path, raw, true)
	}
}

func BenchmarkNewPathFilter_heaviestAcceptedRules(b *testing.B) {
	forbidden, skipped := heaviestAccepted(b)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := NewPathFilter(forbidden, skipped); err != nil {
			b.Fatal(err)
		}
	}
}

// The SDK validation of the configuration and NewPathFilter hold the same bounds,
// each with its own copy of the estimate: they must give the same verdict.
func TestNewPathFilter_agreesWithTheSDKValidation(t *testing.T) {
	v, err := sdk.DefaultValidator()
	if err != nil {
		t.Fatal(err)
	}
	unicode := slices.Repeat([]string{`\pL`}, 7)
	lists := [][]string{
		{`\.exe$`},
		{`a{100}b`},
		{`a{101}b`},
		{`(?:a{50}){5}`},
		{`(?:a{50}){10}`},
		{strings.Repeat("a?", 500) + "b"},
		{`((a{100}){100}){100}`},
		unicode,
		{`(?i)\.(exe|dll|scr|bat|cmd|js|vbs|ps1|jar|msi)$`},
		{`(`},
		{`(?:a{100}){3}(?:b{100}){3}`},
		{`x{3,}y`},
		{`\p{Han}+`},
		{`(a?){30}b`},
	}
	for _, patterns := range lists {
		name := patterns[0]
		if len(name) > 30 {
			name = name[:30]
		}
		t.Run(name, func(t *testing.T) {
			_, coreErr := NewPathFilter(patterns, nil)
			sdkErr := v.Validate(sdk.HostFilepathFilter{ForbiddenPaths: patterns})
			if (coreErr == nil) != (sdkErr == nil) {
				t.Errorf("NewPathFilter() error = %v, the validation of the SDK says %v", coreErr, sdkErr)
			}
		})
	}
}

func TestPathFilter_decideFoldedForm(t *testing.T) {
	tests := []struct {
		name      string
		forbidden []string
		skipped   []string
		path      string
		want      pathDecision
	}{
		{"forbidden, zero width space after the extension", []string{`\.exe$`}, nil, "a.exe\u200B", pathForbidden},
		{"forbidden, soft hyphen in the extension", []string{`\.exe$`}, nil, "a.ex\u00ADe", pathForbidden},
		{"forbidden, newline after the extension", []string{`\.exe$`}, nil, "a.exe\n", pathForbidden},
		{"forbidden, override before the extension", []string{`\.exe$`}, nil, "a\u202Eexe.exe", pathForbidden},
		{"forbidden, tag character", []string{`\.exe$`}, nil, "a.exe\U000E0041", pathForbidden},
		{"forbidden, combining grapheme joiner", []string{`\.exe$`}, nil, "a.exe\u034F", pathForbidden},
		{"forbidden, variation selector 16", []string{`\.exe$`}, nil, "a.exe\uFE0F", pathForbidden},
		{"forbidden, variation selector supplement", []string{`\.exe$`}, nil, "a.exe\U000E0100", pathForbidden},
		{"forbidden, mongolian variation selector", []string{`\.exe$`}, nil, "a.exe\u180B", pathForbidden},
		{"forbidden, khmer inherent vowel", []string{`\.exe$`}, nil, "a.exe\u17B4", pathForbidden},
		{"forbidden, unassigned default ignorable 2065", []string{`\.exe$`}, nil, "a.exe\u2065", pathForbidden},
		{"forbidden, unassigned default ignorable FFF0", []string{`\.exe$`}, nil, "a.exe\uFFF0", pathForbidden},
		{"forbidden, unassigned default ignorable E0000", []string{`\.exe$`}, nil, "a.exe\U000E0000", pathForbidden},
		{"forbidden, unassigned default ignorable E0080", []string{`\.exe$`}, nil, "a.exe\U000E0080", pathForbidden},
		{"forbidden, braille blank", []string{`\.exe$`}, nil, "a.exe\u2800", pathForbidden},
		{"forbidden, invalid UTF-8 byte", []string{`\.exe$`}, nil, "a.exe\xff", pathForbidden},
		{"forbidden, a rule on the hidden rune still matches the raw form", []string{`\x{200b}`}, nil, "a\u200Bb", pathForbidden},
		{"forbidden, folded form joins two halves", []string{`^ab$`}, nil, "a\u200Bb", pathForbidden},
		{"forbidden, trailing spaces are still not caught", []string{`\.exe$`}, nil, "a.exe ", pathUnruled},
		{"forbidden, a plain name is unchanged", []string{`\.exe$`}, nil, "a.txt", pathUnruled},
		{"skipped by every form", nil, []string{`\.log$`}, "a\u200B.log", pathSkipped},
		{"not skipped when the raw form fails", nil, []string{`^a\.log$`}, "a\u200B.log", pathUnruled},
		{"not skipped when only the folded form matches", nil, []string{`^ab$`}, "a\u200Bb", pathUnruled},
		{"not widened by a control character and a hidden rune", nil, []string{`^/in/a\.log$`}, "/in/a\x01\u200B.log", pathUnruled},
		{"forbidden wins over skipped", []string{`\.exe$`}, []string{`\.log$`}, "a.exe\u200B", pathForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := mustPathFilter(t, tt.forbidden, tt.skipped)
			for _, name := range []string{tt.path, sanitizeControl(tt.path)} {
				got, _ := f.decide(name, tt.path, true)
				if got != tt.want {
					t.Errorf("decide(%q, %q) = %d, want %d", name, tt.path, got, tt.want)
				}
			}
			if got, _ := f.decide(tt.path, "", true); got != tt.want {
				t.Errorf("decide(%q, \"\") = %d, want %d", tt.path, got, tt.want)
			}
		})
	}
}

func TestPathFilter_decideFoldedFormIsBounded(t *testing.T) {
	long := strings.Repeat("a", maxMatchedPath) + "\u200B"
	tests := []struct {
		name      string
		forbidden []string
		want      pathDecision
	}{
		{"checked with forbidden paths: too long", []string{`\.exe$`}, pathTooLong},
		{"no forbidden paths: unruled", nil, pathUnruled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := mustPathFilter(t, tt.forbidden, []string{`a$`})
			if got, _ := f.decide(long, long, true); got != tt.want {
				t.Errorf("decide() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestFoldHidden(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"plain", "plain.txt", "plain.txt"},
		{"hidden runes and controls", "a\u200Bb\u202Ec\nd\x00e", "abcde"},
		{"only hidden runes", "\u200B\u202E", ""},
		{"nbsp and ideographic space kept", "a\u00A0b\u3000", "a\u00A0b\u3000"},
		{"invalid UTF-8 dropped", "a\xffb", "ab"},
		{"truncated sequence dropped", "a\xe2\x82", "a"},
		{"literal replacement character kept", "a\uFFFDb\xff", "a\uFFFDb"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := foldHidden(tt.in); got != tt.want {
				t.Errorf("foldHidden(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// A name without hidden rune must cost no more than before the folded form: no
// third form, no allocation, on the path of every file.
func TestPathFilter_plainNameHasNoExtraForm(t *testing.T) {
	f := mustPathFilter(t, nil, []string{`\.log$`})
	allocs := testing.AllocsPerRun(100, func() {
		f.decide("/in/a.log", "/in/a.log", true)
	})
	if allocs != 0 {
		t.Errorf("a plain name allocates %v times, want 0", allocs)
	}
}

func BenchmarkPathFilter_plainName(b *testing.B) {
	f := mustPathFilter(b, []string{`\.(exe|dll)$`}, []string{`^/in/trusted/`})
	b.ReportAllocs()
	for b.Loop() {
		f.decide("/in/other/a.txt", "/in/other/a.txt", true)
	}
}

func BenchmarkFoldHidden(b *testing.B) {
	plain := "/srv/in/" + strings.Repeat("segment/", 500)[:4000] + "file.bin"
	hidden := plain + "\u202E"
	b.Run("plain 4 KiB", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			foldHidden(plain)
		}
	})
	b.Run("hidden 4 KiB", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			foldHidden(hidden)
		}
	})
}
