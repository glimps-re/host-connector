package cache

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"modernc.org/sqlite"
)

var Logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{}))

type Entry struct {
	ID        string    `gorm:"primarykey" field:"id"`
	Sha256    string    `field:"sha256"`
	CreatedAt time.Time `field:"created_at"`
	UpdatedAt time.Time `field:"updated_at"`
	// DeletedAt          gorm.DeletedAt `gorm:"index"`
	InitialLocation    string    `field:"location"`
	QuarantineLocation string    `field:"quarantine"`
	RestoredAt         time.Time `field:"restored_at"`
}

type Cacher interface {
	// Set adds or updates a cache entry
	Set(ctx context.Context, entry *Entry) error

	// Get fetch a cache entry
	Get(ctx context.Context, id string) (entry *Entry, err error)
	GetBySha256(ctx context.Context, sha256 string) (entry *Entry, err error)

	Close() error
}

var ErrEntryNotFound = errors.New("entry not found")

type Cache struct {
	db *sql.DB
	sync.Mutex
}

var _ Cacher = &Cache{}

var CreateTable = `CREATE TABLE IF NOT EXISTS entries (
	id TEXT PRIMARY KEY,
	sha256 TEXT,
	created_at int NOT NULL,
	updated_at int NOT NULL,
	quarantine TEXT,
	location TEXT,
	restored_at int);`

func NewCache(ctx context.Context, location string) (c *Cache, err error) {
	if location == "" {
		location = "file::memory:"
	} else {
		_, err = os.Stat(location)
		if errors.Is(err, os.ErrNotExist) {
			dir, _ := filepath.Split(location)
			err = os.MkdirAll(dir, 0o750)
			if err != nil {
				return
			}
			_, err = os.Create(filepath.Clean(location))
			if err != nil {
				return
			}
		}
	}
	db, err := sql.Open("sqlite", location)
	if err != nil {
		return
	}

	result, err := db.ExecContext(ctx, CreateTable)
	if err != nil {
		return
	}
	Logger.Info("create new db", slog.Any("result", result))
	c = &Cache{db: db}
	return
}

func (c *Cache) Close() error {
	return c.db.Close()
}

func (c *Cache) Get(ctx context.Context, id string) (entry *Entry, err error) {
	c.Lock()
	defer c.Unlock()
	entry = &Entry{}
	var createdAt, updatedAt, restoredAt int64
	err = c.db.QueryRowContext(ctx, "SELECT * FROM entries where id = ?", id).Scan(
		&entry.ID,
		&entry.Sha256,
		&createdAt,
		&updatedAt,
		&entry.QuarantineLocation,
		&entry.InitialLocation,
		&restoredAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrEntryNotFound
		}
		return
	}
	entry.CreatedAt = time.UnixMilli(createdAt)
	entry.UpdatedAt = time.UnixMilli(updatedAt)
	entry.RestoredAt = time.UnixMilli(restoredAt)
	return
}

func (c *Cache) GetBySha256(ctx context.Context, sha256 string) (entry *Entry, err error) {
	c.Lock()
	defer c.Unlock()
	entry = &Entry{}
	var createdAt, updatedAt, restoredAt int64
	err = c.db.QueryRowContext(ctx, "SELECT * FROM entries where sha256 = ?", sha256).Scan(
		&entry.ID,
		&entry.Sha256,
		&createdAt,
		&updatedAt,
		&entry.QuarantineLocation,
		&entry.InitialLocation,
		&restoredAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrEntryNotFound
		}
		return
	}
	entry.CreatedAt = time.UnixMilli(createdAt)
	entry.UpdatedAt = time.UnixMilli(updatedAt)
	entry.RestoredAt = time.UnixMilli(restoredAt)
	return
}

var Now = time.Now

func (c *Cache) Set(ctx context.Context, entry *Entry) (err error) {
	c.Lock()
	defer c.Unlock()
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer func() {
		err := tx.Commit()
		if err != nil {
			Logger.Error("cannot commit cache set transaction", "error", err)
		}
	}()
	sqlStatement := `
INSERT INTO entries (id, sha256, created_at, updated_at, quarantine, location, restored_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)`
	if entry.CreatedAt.UnixMilli() <= 0 {
		entry.CreatedAt = Now()
	}
	if entry.UpdatedAt.UnixMilli() <= 0 {
		entry.UpdatedAt = Now()
	}
	_, err = tx.ExecContext(ctx, sqlStatement,
		entry.ID,
		entry.Sha256,
		entry.CreatedAt.UnixMilli(),
		entry.UpdatedAt.UnixMilli(),
		entry.QuarantineLocation,
		entry.InitialLocation,
		entry.RestoredAt.UnixMilli(),
	)
	if err == nil {
		return
	}
	// check for update
	sqliteErr := new(sqlite.Error)
	if errors.As(err, &sqliteErr) && sqliteErr.Code() == 1555 {
		sqlStatement := `
		UPDATE entries SET sha256=$2, created_at=$3, updated_at=$4, quarantine=$5, location=$6, restored_at=$7
		WHERE id = $1`
		_, err = tx.ExecContext(ctx, sqlStatement,
			entry.ID,
			entry.Sha256,
			entry.CreatedAt.UnixMilli(),
			entry.UpdatedAt.UnixMilli(),
			entry.QuarantineLocation,
			entry.InitialLocation,
			entry.RestoredAt.UnixMilli(),
		)
		return err
	}
	return
}

func ComputeCacheID(path string) (id string) {
	hash := sha256.New()
	hash.Write([]byte(path))
	id = hex.EncodeToString(hash.Sum(nil))
	return
}
