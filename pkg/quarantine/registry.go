package quarantine

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

var LogLevel = &slog.LevelVar{}

var logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
	Level: LogLevel,
}))

type Entry struct {
	ID                 string    `gorm:"primarykey" field:"id"`
	SHA256             string    `field:"sha256"`
	CreatedAt          time.Time `field:"created_at"`
	UpdatedAt          time.Time `field:"updated_at"`
	InitialLocation    string    `field:"location"`
	QuarantineLocation string    `field:"quarantine"`
	RestoredAt         time.Time `field:"restored_at"`
}

type quarantineRegistry interface {
	GetLocation() (location string)

	// Set adds or updates an entry
	Set(ctx context.Context, entry *Entry) error

	// Get fetch an entry
	Get(ctx context.Context, id string) (entry *Entry, err error)
	GetBySHA256(ctx context.Context, sha256 string) (entry *Entry, err error)

	// Migrate migrates all entries to a new location, closing the old database and updating internal state
	Migrate(ctx context.Context, newLocation string) error

	Close() error
}

var errEntryNotFound = errors.New("entry not found")

type sqliteRegistry struct {
	db       *sql.DB
	location string
	sync.RWMutex
}

var _ quarantineRegistry = &sqliteRegistry{}

func ensureDBFile(location string) error {
	_, err := os.Stat(location)
	if err == nil {
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to stat quarantine registry db: %w", err)
	}

	dir := filepath.Dir(location)
	if err = os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("failed to create quarantine registry db location: %w", err)
	}

	f, err := os.OpenFile(filepath.Clean(location), os.O_RDONLY|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create quarantine registry db file: %w", err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("failed to close quarantine registry db file after creation: %w", err)
	}
	return nil
}

const createTable = `CREATE TABLE IF NOT EXISTS entries (
	id TEXT PRIMARY KEY,
	sha256 TEXT,
	created_at int NOT NULL,
	updated_at int NOT NULL,
	quarantine TEXT,
	location TEXT,
	restored_at int);`

func newSQLiteRegistry(ctx context.Context, location string) (c *sqliteRegistry, err error) {
	finalLocation := "file::memory:"
	if location != "" {
		if !filepath.IsAbs(location) {
			err = fmt.Errorf("registry location must be an absolute path, got %q", location)
			return
		}
		if err = ensureDBFile(location); err != nil {
			return
		}
		finalLocation = location
	}

	db, err := sql.Open("sqlite", finalLocation)
	if err != nil {
		err = fmt.Errorf("failed to open quarantine db: %w", err)
		return
	}
	// SQLite does not support concurrent connections to in-memory databases;
	// each connection gets its own empty database. Limit to 1 connection
	// so all queries share the same in-memory state.
	if location == "" {
		db.SetMaxOpenConns(1)
	}

	result, err := db.ExecContext(ctx, createTable)
	if err != nil {
		err = fmt.Errorf("failed to create quarantine db: %w", err)
		return
	}

	logger.Info("create new db", slog.Any("result", result))
	c = &sqliteRegistry{db: db, location: finalLocation}
	return
}

func (c *sqliteRegistry) GetLocation() (location string) {
	return c.location
}

func (c *sqliteRegistry) Close() error {
	return c.db.Close()
}

func (c *sqliteRegistry) Migrate(ctx context.Context, newLocation string) (err error) {
	// Check if migration is actually needed
	currentLocation := c.location
	if newLocation == "" {
		newLocation = "file::memory:"
	}
	if currentLocation == newLocation {
		return
	}

	newReg, err := newSQLiteRegistry(ctx, newLocation)
	if err != nil {
		return
	}

	c.Lock()
	defer c.Unlock()

	rows, err := c.db.QueryContext(ctx, "SELECT id, sha256, created_at, updated_at, quarantine, location, restored_at FROM entries")
	if err != nil {
		return
	}
	defer func() {
		if e := rows.Close(); e != nil {
			logger.Error("cannot close rows", slog.String("error", e.Error()))
		}
	}()

	for rows.Next() {
		entry := &Entry{}
		var createdAt, updatedAt, restoredAt int64
		if err = rows.Scan(&entry.ID, &entry.SHA256, &createdAt, &updatedAt, &entry.QuarantineLocation, &entry.InitialLocation, &restoredAt); err != nil {
			return
		}
		entry.CreatedAt = time.UnixMilli(createdAt)
		entry.UpdatedAt = time.UnixMilli(updatedAt)
		entry.RestoredAt = time.UnixMilli(restoredAt)

		if err = newReg.Set(ctx, entry); err != nil {
			return
		}
	}

	if err = rows.Err(); err != nil {
		return
	}

	oldDB := c.db
	c.db = newReg.db
	c.location = newReg.location

	if closeErr := oldDB.Close(); closeErr != nil {
		logger.Error("failed to close old registry database", slog.String("error", closeErr.Error()))
	}
	return
}

func (c *sqliteRegistry) Get(ctx context.Context, id string) (entry *Entry, err error) {
	c.RLock()
	defer c.RUnlock()
	entry = &Entry{}
	var createdAt, updatedAt, restoredAt int64
	err = c.db.QueryRowContext(ctx, "SELECT * FROM entries where id = ?", id).Scan(
		&entry.ID,
		&entry.SHA256,
		&createdAt,
		&updatedAt,
		&entry.QuarantineLocation,
		&entry.InitialLocation,
		&restoredAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errEntryNotFound
		}
		return
	}
	entry.CreatedAt = time.UnixMilli(createdAt)
	entry.UpdatedAt = time.UnixMilli(updatedAt)
	entry.RestoredAt = time.UnixMilli(restoredAt)
	return
}

func (c *sqliteRegistry) GetBySHA256(ctx context.Context, sha256 string) (entry *Entry, err error) {
	c.RLock()
	defer c.RUnlock()
	entry = &Entry{}
	var createdAt, updatedAt, restoredAt int64
	err = c.db.QueryRowContext(ctx, "SELECT * FROM entries where sha256 = ?", sha256).Scan(
		&entry.ID,
		&entry.SHA256,
		&createdAt,
		&updatedAt,
		&entry.QuarantineLocation,
		&entry.InitialLocation,
		&restoredAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errEntryNotFound
		}
		return
	}
	entry.CreatedAt = time.UnixMilli(createdAt)
	entry.UpdatedAt = time.UnixMilli(updatedAt)
	entry.RestoredAt = time.UnixMilli(restoredAt)
	return
}

var now = time.Now

func (c *sqliteRegistry) Set(ctx context.Context, entry *Entry) (err error) {
	c.Lock()
	defer c.Unlock()
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer func() {
		if err == nil {
			commitErr := tx.Commit()
			if commitErr != nil {
				err = fmt.Errorf("cannot commit cache set transaction, error: %w", commitErr)
			}
		} else {
			if rbErr := tx.Rollback(); rbErr != nil {
				logger.Error("cannot rollback transaction", slog.String("error", rbErr.Error()))
			}
		}
	}()
	if entry.CreatedAt.UnixMilli() <= 0 {
		entry.CreatedAt = now()
	}
	if entry.UpdatedAt.UnixMilli() <= 0 {
		entry.UpdatedAt = now()
	}
	sqlStatement := `INSERT INTO entries (id, sha256, created_at, updated_at, quarantine, location, restored_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT(id) DO UPDATE SET
	sha256=$2,
	created_at=$3,
	updated_at=$4,
	quarantine=$5,
	location=$6,
	restored_at=$7`
	_, err = tx.ExecContext(ctx, sqlStatement,
		entry.ID,
		entry.SHA256,
		entry.CreatedAt.UnixMilli(),
		entry.UpdatedAt.UnixMilli(),
		entry.QuarantineLocation,
		entry.InitialLocation,
		entry.RestoredAt.UnixMilli(),
	)
	return
}

func ComputeCacheID(path string, contentSHA256 string) (id string) {
	hash := sha256.New()
	hash.Write([]byte(path))
	hash.Write([]byte(contentSHA256))
	id = hex.EncodeToString(hash.Sum(nil))
	return
}
