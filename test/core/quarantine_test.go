//go:build linux && (e2e || e2e_core)

package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	hcquarantine "github.com/glimps-re/host-connector/pkg/quarantine"
	"github.com/glimps-re/host-connector/test/internal/fakes/gmalware"
	"github.com/glimps-re/host-connector/test/internal/harness"
)

// quarantineConfig is the configuration of a run whose quarantine writes the
// format given ("" for the default).
func quarantineConfig(format string) map[string]any {
	if format == "" {
		return nil
	}
	return map[string]any{"quarantine": map[string]any{"format": format}}
}

// From TestQuarantineRestore_WrittenFormat: the container is written in the
// configured format (tar by default) and gives the file back whole on restore,
// leaving no temporary file and no container behind.
func TestE2E_aContainerIsWrittenInItsFormatAndRestoredWhole(t *testing.T) {
	t.Parallel()
	longName := strings.Repeat("a", 251) + ".exe"
	tests := []struct {
		name       string
		format     string
		file       harness.File
		config     map[string]any
		malware    datamodel.MalwareReason
		container  harness.Format
		mitigation string
	}{
		{name: "zip", format: "zip", file: harness.File{Path: "sample.bin", Content: []byte("zip payload"), Verdict: harness.Malicious}, malware: datamodel.MalwareDetected, container: harness.Zip, mitigation: "malware"},
		{name: "tar explicit", format: "tar", file: harness.File{Path: "sample.bin", Content: []byte("tar payload"), Verdict: harness.Malicious}, malware: datamodel.MalwareDetected, container: harness.Tar, mitigation: "malware"},
		{name: "default is tar", file: harness.File{Path: "sample.bin", Content: []byte("default payload"), Verdict: harness.Malicious}, malware: datamodel.MalwareDetected, container: harness.Tar, mitigation: "malware"},
		{name: "zip empty file", format: "zip", file: harness.File{Path: "empty.bin"}, config: map[string]any{"unanalyzable_policy": map[string]any{"empty": "mitigate"}}, malware: datamodel.Empty, container: harness.Zip, mitigation: "invalid"},
		{name: "zip 255 byte file name", format: "zip", file: harness.File{Path: longName, Content: []byte("long"), Verdict: harness.Malicious}, malware: datamodel.MalwareDetected, container: harness.Zip, mitigation: "malware"},
		{name: "tar 255 byte file name", format: "tar", file: harness.File{Path: longName, Content: []byte("long"), Verdict: harness.Malicious}, malware: datamodel.MalwareDetected, container: harness.Tar, mitigation: "malware"},
		{name: "zip binary content", format: "zip", file: harness.File{Path: "b.bin", Content: bytes.Repeat([]byte{0, 0xff, 'P', 'K', 3, 4}, 5000), Verdict: harness.Malicious}, malware: datamodel.MalwareDetected, container: harness.Zip, mitigation: "malware"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, harness.Scenario{
				Agent:  true,
				Config: harness.MergeMaps(harness.MergeMaps(map[string]any{}, quarantineConfig(tt.format)), tt.config),
				Files:  []harness.File{tt.file},
				Steps: []harness.Step{
					harness.Await(tt.file.Path, harness.Outcome{In: harness.Quarantine, Malware: tt.malware, Container: tt.container}),
					harness.Restore(tt.file.Path, ""),
				},
				Want: map[string]harness.Outcome{
					tt.file.Path: {In: harness.Output, Restored: true},
				},
				WantMitigations: []string{tt.mitigation},
			})
		})
	}
}

// From TestReconfigure_FormatChangeKeepsOldLocksRestorable: after the console
// changes the format, new containers are written in the new one and the old
// containers stay restorable.
func TestE2E_aFormatChangeKeepsTheOldContainersRestorable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		from, to string
	}{
		{name: "tar to zip", from: "tar", to: "zip"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, harness.Scenario{
				Agent:  true,
				Config: quarantineConfig(tt.from),
				Files:  []harness.File{{Path: "old.bin", Content: []byte("old " + tt.from + " content"), Verdict: harness.Malicious}},
				Steps: []harness.Step{
					harness.Await("old.bin", harness.Outcome{In: harness.Quarantine, Malware: datamodel.MalwareDetected}),
					harness.UpdateConfig(quarantineConfig(tt.to), ""),
					harness.AddFileToInput(harness.File{Path: "new.bin", Content: []byte("new " + tt.to + " content"), Verdict: harness.Malicious}),
					harness.Await("new.bin", harness.Outcome{In: harness.Quarantine, Malware: datamodel.MalwareDetected, Container: harness.Format(tt.to)}),
					harness.Restore("old.bin", ""),
					harness.Restore("new.bin", ""),
				},
				Want: map[string]harness.Outcome{
					"old.bin": {In: harness.Output, Restored: true},
					"new.bin": {In: harness.Output, Restored: true},
				},
				WantMitigations: []string{"malware", "malware"},
			})
		})
	}
}

// From TestNewQuarantineHandler_UnknownFormat and
// TestReconfigure_UnknownFormatKeepsState: an unknown format is refused at
// start, and on update-config, where the old format stays in force. The update
// comes once a first file is delivered, so it replaces an applied configuration.
func TestE2E_anUnknownQuarantineFormatIsRefused(t *testing.T) {
	t.Parallel()
	const refused = "invalid configuration: quarantine: Key: 'HostQuarantineConfig.format'"
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name:     "at start",
			scenario: harness.Scenario{Config: quarantineConfig("rar"), WantRefused: refused},
		},
		{
			name: "on update-config",
			scenario: harness.Scenario{
				Agent:  true,
				Config: quarantineConfig("tar"),
				Files:  []harness.File{{Path: "first.txt", Content: []byte("first")}},
				Steps: []harness.Step{
					harness.Await("first.txt", harness.Outcome{In: harness.Output}),
					harness.UpdateConfig(quarantineConfig("rar"), refused),
					harness.AddFileToInput(harness.File{Path: "s.bin", Content: []byte("still tar"), Verdict: harness.Malicious}),
				},
				Want: map[string]harness.Outcome{
					"first.txt": {In: harness.Output},
					"s.bin":     {In: harness.Quarantine, Malware: datamodel.MalwareDetected, Container: harness.Tar},
				},
				WantMitigations: []string{"malware"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, tt.scenario)
		})
	}
}

// From TestRestore_hostileIDs: a restore whose ID is not a container ID is
// refused, whatever it holds.
func TestE2E_aHostileRestoreIDIsRefused(t *testing.T) {
	t.Parallel()
	valid := strings.Repeat("a", 64)
	tests := []struct {
		name string
		id   string
	}{
		{name: "63 hex", id: valid[:63]},
		{name: "65 hex", id: valid + "a"},
		{name: "traversal prefix", id: "../" + valid[:61]},
		{name: "traversal inside", id: valid[:30] + "/../" + valid[:30]},
		{name: "slash", id: valid[:63] + "/"},
		{name: "nul", id: valid[:63] + "\x00"},
		{name: "non hex", id: valid[:63] + "g"},
		{name: "absolute", id: "/etc/passwd"},
		{name: "newline", id: valid + "\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, harness.Scenario{
				Agent: true,
				Steps: []harness.Step{harness.RestoreID(tt.id, "invalid quarantine id")},
			})
		})
	}
}

// largeTestsEnv opts in to the scenarios that write gigabytes.
const largeTestsEnv = "GMHOST_LARGE_TESTS"

// From TestRestore_SparseFileOver5GiB: a sparse file over 5 GiB, quarantined
// under the too_big policy, is restored whole in either format.
func TestE2E_aSparseFileOver5GiBIsRestored(t *testing.T) {
	if os.Getenv(largeTestsEnv) != "1" {
		t.Skipf("set %s=1 to run", largeTestsEnv)
	}
	const size = int64(5<<30) + 4096
	tests := []struct {
		name   string
		format string
	}{
		{name: "tar", format: "tar"},
		{name: "zip", format: "zip"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gm := gmalware.New(t, false)
			in := harness.Start(t, gm, harness.Options{Agent: true, Config: harness.MergeMaps(quarantineConfig(tt.format), map[string]any{
				"unanalyzable_policy": map[string]any{"too_big": "mitigate"},
			})})
			src := in.Create(t, "big.bin", 0)
			f, err := os.OpenFile(filepath.Clean(src), os.O_WRONLY, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteAt([]byte("tail"), size-4); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			h := sha256.New()
			r, err := os.Open(filepath.Clean(src))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.Copy(h, r); err != nil {
				t.Fatal(err)
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			sum := hex.EncodeToString(h.Sum(nil))
			in.Expect.FlagSHA256(sum)
			in.Expect.ReleaseSHA256(sum)
			id := hcquarantine.ComputeCacheID(src, sum)
			lock := filepath.Join(in.Quarantine, id+".lock")
			in.WaitFor(t, "the quarantine of the big file", func() bool { return !in.Gone(lock) && in.Gone(src) })
			if msg := in.WaitAck(t, in.Console.Push(t, "restore", map[string]string{"id": id})); msg != "" {
				t.Fatalf("restore of a %d byte file refused: %s", size, msg)
			}
			in.WaitFor(t, "the restored file to be delivered", func() bool { return in.InOutput("big.bin") })
			delivered := filepath.Join(in.Output, "tom", "big.bin")
			info, err := os.Stat(delivered)
			if err != nil || info.Size() != size {
				t.Fatalf("restored size = %v (err %v), want %d", info, err, size)
			}
			out, err := os.Open(filepath.Clean(delivered))
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := out.Close(); err != nil {
					t.Error(err)
				}
			}()
			tail := make([]byte, 4)
			if _, err := out.ReadAt(tail, size-4); err != nil && err != io.EOF {
				t.Fatal(err)
			}
			if !bytes.Equal(tail, []byte("tail")) {
				t.Errorf("tail = %q, want tail", tail)
			}
		})
	}
}
