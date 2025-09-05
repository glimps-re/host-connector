package cache

import (
	"errors"
	"os"
	"sync"
	"testing"
)

func TestCache(t *testing.T) {
	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "test in memory",
			test: func(t *testing.T) {
				cache, err := NewCache(t.Context(), "")
				if err != nil {
					t.Errorf("NewCache() error = %v", err)
					return
				}
				entry1 := Entry{
					ID:              "abcdef",
					Sha256:          "abcdef",
					InitialLocation: "/test/abc",
				}
				err = cache.Set(t.Context(), &entry1)
				if err != nil {
					t.Errorf("cache.Set(entry1) error = %v", err)
					return
				}
				entry2, err := cache.Get(t.Context(), entry1.ID)
				if err != nil {
					t.Errorf("cache.Get(entry1.ID) error = %v", err)
					return
				}
				if entry1.InitialLocation != entry2.InitialLocation {
					t.Errorf("cache.Get(entry1.ID) != entry1, want = %v, got = %v", entry1, entry2)
					return
				}
				entrySha, err := cache.GetBySha256(t.Context(), entry1.Sha256)
				if err != nil {
					t.Errorf("cache.Get(entry1.ID) error = %v", err)
					return
				}
				if entry1.InitialLocation != entrySha.InitialLocation {
					t.Errorf("cache.Get(entry1.ID) != entry1, want = %v, got = %v", entry1, entrySha)
					return
				}

				entry2.InitialLocation = "/tmp/def"
				err = cache.Set(t.Context(), entry2)
				if err != nil {
					t.Errorf("cache.Set(entry2) error = %v", err)
					return
				}
				entry3, err := cache.Get(t.Context(), entry2.ID)
				if err != nil {
					t.Errorf("cache.Get(entry2.ID) error = %v", err)
					return
				}
				if entry2.InitialLocation != entry3.InitialLocation {
					t.Errorf("cache.Get(entry2.ID) != entry2, want = %v, got = %v", entry2, entry3)
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
				cache, err := NewCache(t.Context(), tfile.Name())
				if err != nil {
					t.Errorf("NewCache() error = %v", err)
					return
				}
				entry1 := Entry{
					ID:              "abcdef",
					Sha256:          "abcdef",
					InitialLocation: "/test/abc",
				}
				err = cache.Set(t.Context(), &entry1)
				if err != nil {
					t.Errorf("cache.Set(entry1) error = %v", err)
					return
				}
				entry2, err := cache.Get(t.Context(), entry1.ID)
				if err != nil {
					t.Errorf("cache.Get(entry1.ID) error = %v", err)
					return
				}
				if entry1.InitialLocation != entry2.InitialLocation {
					t.Errorf("cache.Get(entry1.ID) != entry1, want = %v, got = %v", entry1, entry2)
					return
				}
				entrySha, err := cache.GetBySha256(t.Context(), entry1.Sha256)
				if err != nil {
					t.Errorf("cache.Get(entry1.ID) error = %v", err)
					return
				}
				if entry1.InitialLocation != entrySha.InitialLocation {
					t.Errorf("cache.Get(entry1.ID) != entry1, want = %v, got = %v", entry1, entrySha)
					return
				}

				err = cache.Close()
				if err != nil {
					t.Errorf("test cannot close cache: %s", err)
				}
				cache2, err := NewCache(t.Context(), tfile.Name())
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
					t.Errorf("cache.Get(entry2.ID) error = %v", err)
					return
				}
				if entry.InitialLocation != entry2.InitialLocation {
					t.Errorf("cache.Get(entry1.ID) != entry1, want = %v, got = %v", entry1, entry2)
					return
				}
			},
		},
		{
			name: "entry not found",
			test: func(t *testing.T) {
				cache, err := NewCache(t.Context(), "")
				if err != nil {
					t.Errorf("NewCache() error = %v", err)
					return
				}
				_, err = cache.Get(t.Context(), "test")
				if !errors.Is(err, ErrEntryNotFound) {
					t.Errorf("cache.Get(unknown) error = %v, want = %v", err, ErrEntryNotFound)
				}
				_, err = cache.GetBySha256(t.Context(), "test")
				if !errors.Is(err, ErrEntryNotFound) {
					t.Errorf("cache.Get(unknown) error = %v, want = %v", err, ErrEntryNotFound)
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
				cache, err := NewCache(t.Context(), "")
				if err != nil {
					t.Errorf("NewCache() error = %v", err)
					return
				}
				worker := func(i int) {
					defer wg.Done()
					_, err := cache.Get(t.Context(), "test")
					if !errors.Is(err, ErrEntryNotFound) {
						t.Errorf("[%d]cache.Get(unknown) error = %v, want = %v", i, err, ErrEntryNotFound)
					}
				}
				for i := 0; i < workers; i++ {
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
				cache, err := NewCache(t.Context(), "")
				if err != nil {
					t.Errorf("NewCache() error = %v", err)
					return
				}
				worker := func(i int) {
					defer wg.Done()
					err := cache.Set(t.Context(), &Entry{Sha256: "test"})
					if !errors.Is(err, nil) {
						t.Errorf("[%d]cache.Set(unknown) error = %v", i, err)
					}
				}
				for i := 0; i < workers; i++ {
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
				cache, err := NewCache(t.Context(), "")
				if err != nil {
					t.Errorf("NewCache() error = %v", err)
					return
				}
				worker := func(i int) {
					defer wg.Done()
					_, err := cache.GetBySha256(t.Context(), "test")
					if !errors.Is(err, ErrEntryNotFound) {
						t.Errorf("[%d]cache.Get(unknown) error = %v, want = %v", i, err, ErrEntryNotFound)
					}
				}
				for i := 0; i < workers; i++ {
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
		path string
	}
	tests := []struct {
		name   string
		args   args
		wantID string
	}{
		{
			name:   "test",
			args:   args{path: "test_path"},
			wantID: "8e2787502f1eef4fcbc40e9a5be298520f177146db1a04dae4bf9680db31f5f1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotID := ComputeCacheID(tt.args.path); gotID != tt.wantID {
				t.Errorf("ComputeCacheID() = %v, want %v", gotID, tt.wantID)
			}
		})
	}
}
