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
				cache, err := NewCache("")
				if err != nil {
					t.Errorf("NewCache() error = %v", err)
					return
				}
				entry1 := Entry{
					Sha256:          "abcdef",
					InitialLocation: "/test/abc",
				}
				err = cache.Set(&entry1)
				if err != nil {
					t.Errorf("cache.Set(entry1) error = %v", err)
					return
				}
				entry2, err := cache.Get(entry1.Sha256)
				if err != nil {
					t.Errorf("cache.Get(entry1.Sha256) error = %v", err)
					return
				}
				if entry1.InitialLocation != entry2.InitialLocation {
					t.Errorf("cache.Get(entry1.Sha256) != entry1, want = %v, got = %v", entry1, entry2)
					return
				}

				entry2.InitialLocation = "/tmp/def"
				err = cache.Set(entry2)
				if err != nil {
					t.Errorf("cache.Set(entry2) error = %v", err)
					return
				}
				entry3, err := cache.Get(entry2.Sha256)
				if err != nil {
					t.Errorf("cache.Get(entry2.Sha256) error = %v", err)
					return
				}
				if entry2.InitialLocation != entry3.InitialLocation {
					t.Errorf("cache.Get(entry2.Sha256) != entry2, want = %v, got = %v", entry2, entry3)
					return
				}
			},
		},
		{
			name: "test file",
			test: func(t *testing.T) {
				tfile, err := os.CreateTemp(os.TempDir(), "test_db_*.db")
				if err != nil {
					t.Errorf("NewCache() error = %v", err)
					return
				}
				tfile.Close()
				defer os.Remove(tfile.Name())
				cache, err := NewCache(tfile.Name())
				if err != nil {
					t.Errorf("NewCache() error = %v", err)
					return
				}
				entry1 := Entry{
					Sha256:          "abcdef",
					InitialLocation: "/test/abc",
				}
				err = cache.Set(&entry1)
				if err != nil {
					t.Errorf("cache.Set(entry1) error = %v", err)
					return
				}
				entry2, err := cache.Get(entry1.Sha256)
				if err != nil {
					t.Errorf("cache.Get(entry1.Sha256) error = %v", err)
					return
				}
				if entry1.InitialLocation != entry2.InitialLocation {
					t.Errorf("cache.Get(entry1.Sha256) != entry1, want = %v, got = %v", entry1, entry2)
					return
				}

				cache.Close()
				cache2, err := NewCache(tfile.Name())
				if err != nil {
					t.Errorf("NewCache() error = %v", err)
					return
				}
				defer cache2.Close()
				entry, err := cache2.Get(entry2.Sha256)
				if err != nil {
					t.Errorf("cache.Get(entry2.Sha256) error = %v", err)
					return
				}
				if entry.InitialLocation != entry2.InitialLocation {
					t.Errorf("cache.Get(entry1.Sha256) != entry1, want = %v, got = %v", entry1, entry2)
					return
				}
			},
		},
		{
			name: "entry not found",
			test: func(t *testing.T) {
				cache, err := NewCache("")
				if err != nil {
					t.Errorf("NewCache() error = %v", err)
					return
				}
				_, err = cache.Get("test")
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
				cache, err := NewCache("")
				if err != nil {
					t.Errorf("NewCache() error = %v", err)
					return
				}
				worker := func(i int) {
					defer wg.Done()
					_, err := cache.Get("test")
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
				cache, err := NewCache("")
				if err != nil {
					t.Errorf("NewCache() error = %v", err)
					return
				}
				worker := func(i int) {
					defer wg.Done()
					err := cache.Set(&Entry{Sha256: "test"})
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
	}
	for _, tt := range tests {
		t.Run(tt.name, tt.test)
	}
}
