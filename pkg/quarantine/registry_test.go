package quarantine

import (
	"errors"
	"os"
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
				entrySha, err := registry.GetBySHA256(t.Context(), entry1.SHA256)
				if err != nil {
					t.Errorf("registry.Get(entry1.ID) error = %v", err)
					return
				}
				if entry1.InitialLocation != entrySha.InitialLocation {
					t.Errorf("registry.Get(entry1.ID) != entry1, want = %v, got = %v", entry1, entrySha)
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
				entrySha, err := registry.GetBySHA256(t.Context(), entry1.SHA256)
				if err != nil {
					t.Errorf("registry.Get(entry1.ID) error = %v", err)
					return
				}
				if entry1.InitialLocation != entrySha.InitialLocation {
					t.Errorf("registry.Get(entry1.ID) != entry1, want = %v, got = %v", entry1, entrySha)
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
				if !errors.Is(err, ErrEntryNotFound) {
					t.Errorf("registry.Get(unknown) error = %v, want = %v", err, ErrEntryNotFound)
				}
				_, err = registry.GetBySHA256(t.Context(), "test")
				if !errors.Is(err, ErrEntryNotFound) {
					t.Errorf("registry.Get(unknown) error = %v, want = %v", err, ErrEntryNotFound)
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
					if !errors.Is(err, ErrEntryNotFound) {
						t.Errorf("[%d]registry.Get(unknown) error = %v, want = %v", i, err, ErrEntryNotFound)
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
					_, err := registry.GetBySHA256(t.Context(), "test")
					if !errors.Is(err, ErrEntryNotFound) {
						t.Errorf("[%d]registry.Get(unknown) error = %v, want = %v", i, err, ErrEntryNotFound)
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
