package quarantine

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestRegistry(t *testing.T) {
	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "test in memory",
			test: func(t *testing.T) {
				registry, err := newSQLiteRegistry(t.Context(), "")
				if err != nil {
					t.Errorf("NewSQLiteRegistry() error = %v", err)
					return
				}
				entry1 := Entry{
					ID:              "abcdef",
					SHA256:          "abcdef",
					InitialLocation: "/test/abc",
				}
				err = registry.Set(t.Context(), &entry1)
				if err != nil {
					t.Errorf("registry.Set(entry1) error = %v", err)
					return
				}
				entry2, err := registry.Get(t.Context(), entry1.ID)
				if err != nil {
					t.Errorf("registry.Get(entry1.ID) error = %v", err)
					return
				}
				if entry1.InitialLocation != entry2.InitialLocation {
					t.Errorf("registry.Get(entry1.ID) != entry1, want = %v, got = %v", entry1, entry2)
					return
				}

				entry2.InitialLocation = "/tmp/def"
				err = registry.Set(t.Context(), entry2)
				if err != nil {
					t.Errorf("registry.Set(entry2) error = %v", err)
					return
				}
				entry3, err := registry.Get(t.Context(), entry2.ID)
				if err != nil {
					t.Errorf("registry.Get(entry2.ID) error = %v", err)
					return
				}
				if entry2.InitialLocation != entry3.InitialLocation {
					t.Errorf("registry.Get(entry2.ID) != entry2, want = %v, got = %v", entry2, entry3)
					return
				}
			},
		},
		{
			name: "test file",
			test: func(t *testing.T) {
				tfile, err := os.CreateTemp(os.TempDir(), "test_db_*.db")
				if err != nil {
					t.Errorf("NewCache() test error = %v", err)
					return
				}
				if err := tfile.Close(); err != nil {
					t.Errorf("Close test file error = %v", err)
				}
				defer func() {
					err := os.Remove(tfile.Name())
					if err != nil {
						t.Errorf("Remove test file error = %v", err)
					}
				}()
				registry, err := newSQLiteRegistry(t.Context(), tfile.Name())
				if err != nil {
					t.Errorf("NewCache() error = %v", err)
					return
				}
				entry1 := Entry{
					ID:              "abcdef",
					SHA256:          "abcdef",
					InitialLocation: "/test/abc",
				}
				err = registry.Set(t.Context(), &entry1)
				if err != nil {
					t.Errorf("registry.Set(entry1) error = %v", err)
					return
				}
				entry2, err := registry.Get(t.Context(), entry1.ID)
				if err != nil {
					t.Errorf("registry.Get(entry1.ID) error = %v", err)
					return
				}
				if entry1.InitialLocation != entry2.InitialLocation {
					t.Errorf("registry.Get(entry1.ID) != entry1, want = %v, got = %v", entry1, entry2)
					return
				}

				err = registry.Close()
				if err != nil {
					t.Errorf("test cannot close cache: %s", err)
				}
				cache2, err := newSQLiteRegistry(t.Context(), tfile.Name())
				if err != nil {
					t.Errorf("NewCache() error = %v", err)
					return
				}
				defer func() {
					err := cache2.Close()
					if err != nil {
						t.Errorf("cache2.Close() test error = %v", err)
					}
				}()
				entry, err := cache2.Get(t.Context(), entry2.ID)
				if err != nil {
					t.Errorf("registry.Get(entry2.ID) error = %v", err)
					return
				}
				if entry.InitialLocation != entry2.InitialLocation {
					t.Errorf("registry.Get(entry1.ID) != entry1, want = %v, got = %v", entry1, entry2)
					return
				}
			},
		},
		{
			name: "entry not found",
			test: func(t *testing.T) {
				registry, err := newSQLiteRegistry(t.Context(), "")
				if err != nil {
					t.Errorf("NewCache() error = %v", err)
					return
				}
				_, err = registry.Get(t.Context(), "test")
				if !errors.Is(err, errEntryNotFound) {
					t.Errorf("registry.Get(unknown) error = %v, want = %v", err, errEntryNotFound)
				}
			},
		},
		{
			name: "goroutines",
			test: func(t *testing.T) {
				// prepare goroutine
				wg := sync.WaitGroup{}
				workers := 50
				wg.Add(workers)
				start := make(chan struct{})
				registry, err := newSQLiteRegistry(t.Context(), "")
				if err != nil {
					t.Errorf("NewCache() error = %v", err)
					return
				}
				worker := func(i int) {
					defer wg.Done()
					_, err := registry.Get(t.Context(), "test")
					if !errors.Is(err, errEntryNotFound) {
						t.Errorf("[%d]registry.Get(unknown) error = %v, want = %v", i, err, errEntryNotFound)
					}
				}
				for i := range workers {
					go worker(i)
				}
				close(start)
				wg.Wait()
			},
		},
		{
			name: "goroutines set",
			test: func(t *testing.T) {
				// prepare goroutine
				wg := sync.WaitGroup{}
				workers := 50
				wg.Add(workers)
				start := make(chan struct{})
				registry, err := newSQLiteRegistry(t.Context(), "")
				if err != nil {
					t.Errorf("NewCache() error = %v", err)
					return
				}
				worker := func(i int) {
					defer wg.Done()
					err := registry.Set(t.Context(), &Entry{SHA256: "test"})
					if !errors.Is(err, nil) {
						t.Errorf("[%d]registry.Set(unknown) error = %v", i, err)
					}
				}
				for i := range workers {
					go worker(i)
				}
				close(start)
				wg.Wait()
			},
		},
		{
			name: "goroutines getSha",
			test: func(t *testing.T) {
				// prepare goroutine
				wg := sync.WaitGroup{}
				workers := 50
				wg.Add(workers)
				start := make(chan struct{})
				registry, err := newSQLiteRegistry(t.Context(), "")
				if err != nil {
					t.Errorf("NewCache() error = %v", err)
					return
				}
				worker := func(i int) {
					defer wg.Done()
					_, err := registry.Get(t.Context(), "test")
					if !errors.Is(err, errEntryNotFound) {
						t.Errorf("[%d]registry.Get(unknown) error = %v, want = %v", i, err, errEntryNotFound)
					}
				}
				for i := range workers {
					go worker(i)
				}
				close(start)
				wg.Wait()
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, tt.test)
	}
}

func TestClone(t *testing.T) {
	entry := &Entry{ID: "abc123", SHA256: "sha256abc", InitialLocation: "/test/path", QuarantineLocation: "/q/abc123.lock"}
	t.Run("file to memory keeps the original untouched", func(t *testing.T) {
		original, err := newSQLiteRegistry(t.Context(), filepath.Join(t.TempDir(), "a.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = original.Close() })
		if err = original.Set(t.Context(), entry); err != nil {
			t.Fatal(err)
		}
		clone, err := original.Clone(t.Context(), "", false)
		if err != nil {
			t.Fatalf("Clone() error = %v", err)
		}
		t.Cleanup(func() { _ = clone.Discard() })
		if clone.GetLocation() != "file::memory:" {
			t.Errorf("clone location = %q, want in memory", clone.GetLocation())
		}
		got, err := clone.Get(t.Context(), "abc123")
		if err != nil || got.InitialLocation != entry.InitialLocation || got.QuarantineLocation != entry.QuarantineLocation {
			t.Errorf("clone entry = %+v (err %v), want %+v", got, err, entry)
		}
		changed := *got
		changed.QuarantineLocation = "/elsewhere"
		if err = clone.Set(t.Context(), &changed); err != nil {
			t.Fatal(err)
		}
		orig, err := original.Get(t.Context(), "abc123")
		if err != nil || orig.QuarantineLocation != entry.QuarantineLocation {
			t.Errorf("original entry = %+v (err %v), a change in the clone must not reach it", orig, err)
		}
	})
	t.Run("memory to file, discard removes the created file only", func(t *testing.T) {
		original, err := newSQLiteRegistry(t.Context(), "")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = original.Close() })
		if err = original.Set(t.Context(), entry); err != nil {
			t.Fatal(err)
		}
		dbPath := filepath.Join(t.TempDir(), "cloned.db")
		clone, err := original.Clone(t.Context(), dbPath, false)
		if err != nil {
			t.Fatalf("Clone() error = %v", err)
		}
		if _, err = os.Stat(dbPath); err != nil {
			t.Fatalf("the clone file must exist: %v", err)
		}
		if err = clone.Discard(); err != nil {
			t.Fatalf("Discard() error = %v", err)
		}
		if _, err = os.Stat(dbPath); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("a discarded clone must remove its file (stat error = %v)", err)
		}

		existing := filepath.Join(t.TempDir(), "existing.db")
		pre, err := newSQLiteRegistry(t.Context(), existing)
		if err != nil {
			t.Fatal(err)
		}
		if err = pre.Close(); err != nil {
			t.Fatal(err)
		}
		clone, err = original.Clone(t.Context(), existing, false)
		if err != nil {
			t.Fatal(err)
		}
		if err = clone.Discard(); err != nil {
			t.Fatal(err)
		}
		if _, err = os.Stat(existing); err != nil {
			t.Errorf("a pre-existing registry file must survive Discard: %v", err)
		}
	})
	t.Run("relative location is refused", func(t *testing.T) {
		original, err := newSQLiteRegistry(t.Context(), "")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = original.Close() })
		if _, err = original.Clone(t.Context(), "relative.db", false); err == nil {
			t.Error("Clone() with a relative location must fail")
		}
	})
}

func TestComputeCacheID(t *testing.T) {
	type args struct {
		path   string
		sha256 string
	}
	tests := []struct {
		name   string
		args   args
		wantID string
	}{
		{
			name: "test",
			args: args{
				path:   "test_path",
				sha256: "8e2787502f1eef4fcbc40e9a5be298520f177146db1a04dae4bf9680db31f5f1",
			},
			wantID: "371c77f9f238c014471862add559e3c37840968c835e7c7bd50b6071ad56b06d",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotID := ComputeCacheID(tt.args.path, tt.args.sha256); gotID != tt.wantID {
				t.Errorf("ComputeCacheID() = %v, want %v", gotID, tt.wantID)
			}
		})
	}
}

func TestClone_refusesANonEmptyRegistry(t *testing.T) {
	original, err := newSQLiteRegistry(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = original.Close() })
	existing := filepath.Join(t.TempDir(), "existing.db")
	pre, err := newSQLiteRegistry(t.Context(), existing)
	if err != nil {
		t.Fatal(err)
	}
	if err = pre.Set(t.Context(), &Entry{ID: "x", SHA256: "s", InitialLocation: "/a"}); err != nil {
		t.Fatal(err)
	}
	if err = pre.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = original.Clone(t.Context(), existing, false); err == nil {
		t.Fatal("Clone() into a registry that already holds entries: error = nil")
	}
	if _, err = os.Stat(existing); err != nil {
		t.Errorf("the pre-existing registry must be left alone: %v", err)
	}
}

func TestDiscard_removesSQLiteSideFiles(t *testing.T) {
	original, err := newSQLiteRegistry(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = original.Close() })
	path := filepath.Join(t.TempDir(), "clone.db")
	clone, err := original.Clone(t.Context(), path, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if err = os.WriteFile(path+suffix, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err = clone.Discard(); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		if _, err = os.Stat(path + suffix); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s must be removed (stat error = %v)", path+suffix, err)
		}
	}
}
