package quarantine

import (
	"bytes"
	"crypto/rand"
	mrand "math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeFileInfo is a deterministic os.FileInfo stand-in used only to
// generate/verify the legacy golden fixture: a real file's mtime/uid/gid
// are not reproducible across machines, but the wire format must be.
type fakeFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func (f *fakeFileInfo) Name() string       { return f.name }
func (f *fakeFileInfo) Size() int64        { return f.size }
func (f *fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f *fakeFileInfo) ModTime() time.Time { return f.modTime }
func (f *fakeFileInfo) IsDir() bool        { return false }
func (f *fakeFileInfo) Sys() any           { return nil }

// legacyFixtureSeed pins math/rand.Reader so cipherFile's salt/IV are
// reproducible; legacyFixtureTime pins the tar header timestamps.
const legacyFixtureSeed = 20260101

var legacyFixtureTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func buildLegacyFixture(t *testing.T) []byte {
	t.Helper()
	origRand := rand.Reader
	origNow := now
	t.Cleanup(func() {
		rand.Reader = origRand
		now = origNow
	})
	rand.Reader = mrand.New(mrand.NewSource(legacyFixtureSeed)) //nolint:gosec // deterministic salt and IV for the golden fixture, never used outside tests
	now = func() time.Time { return legacyFixtureTime }

	info := &fakeFileInfo{
		name:    filepath.Base(legacyFixtureFilepath),
		size:    int64(len(legacyFixtureContent)),
		mode:    0o644,
		modTime: legacyFixtureTime,
	}

	locker := tarLocker{Password: legacyFixturePassword}
	var buf bytes.Buffer
	if err := locker.LockFile(legacyFixtureFilepath, bytes.NewReader([]byte(legacyFixtureContent)), info, legacyFixtureReason, &buf); err != nil {
		t.Fatalf("buildLegacyFixture: LockFile failed: %s", err)
	}
	return buf.Bytes()
}

// TestLegacyFixtureGoldenBytes pins the tar `.lock` wire format: it
// regenerates the fixture deterministically (fixed rand + fixed timestamps)
// and asserts the result is byte-identical to the checked-in
// testdata/legacy_v1.5.3.lock, so any accidental change to the tar layout,
// header fields or cipher framing is caught.
func TestLegacyFixtureGoldenBytes(t *testing.T) {
	got := buildLegacyFixture(t)

	want, err := os.ReadFile(filepath.Join("testdata", "legacy_v1.5.3.lock"))
	if err != nil {
		t.Fatalf("could not read golden fixture: %s", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("legacy fixture bytes changed: tar wire format is no longer byte-identical to the pinned golden file")
	}
}
