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

	"modernc.org/sqlite"
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

var ErrEntryNotFound = errors.New("entry not found")

type sqliteRegistry struct {
	db       *sql.DB
	location string
	sync.Mutex
}

var _ quarantineRegistry = &sqliteRegistry{}

const CreateTable = `CREATE TABLE IF NOT EXISTS entries (
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
		_, err = os.Stat(location)
		switch {
		case err == nil:
		case errors.Is(err, os.ErrNotExist):
			dir, _ := filepath.Split(location)
			err = os.MkdirAll(dir, 0o750)
			if err != nil {
				err = fmt.Errorf("failed to create quarantine registry db location: %w", err)
				return
			}
			_, err = os.Create(filepath.Clean(location))
			if err != nil {
				err = fmt.Errorf("failed to create quarantine registry db file: %w", err)
				return
			}
		default:
			return
		}
		finalLocation = location
	}

	db, err := sql.Open("sqlite", finalLocation)
	if err != nil {
		err = fmt.Errorf("failed to open quarantine db: %w", err)
		return
	}

	result, err := db.ExecContext(ctx, CreateTable)
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
	if err = oldDB.Close(); err != nil {
		if closeErr := newReg.Close(); closeErr != nil {
			logger.Error("failed to close new registry after old database close error", slog.String("error", closeErr.Error()))
		}
		return
	}

	c.db = newReg.db
	c.location = newReg.location
	return
}

func (c *sqliteRegistry) Get(ctx context.Context, id string) (entry *Entry, err error) {
	c.Lock()
	defer c.Unlock()
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
			return nil, ErrEntryNotFound
		}
		return
	}
	entry.CreatedAt = time.UnixMilli(createdAt)
	entry.UpdatedAt = time.UnixMilli(updatedAt)
	entry.RestoredAt = time.UnixMilli(restoredAt)
	return
}

func (c *sqliteRegistry) GetBySHA256(ctx context.Context, sha256 string) (entry *Entry, err error) {
	c.Lock()
	defer c.Unlock()
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
		}
	}()
	sqlStatement := `INSERT INTO entries (id, sha256, created_at, updated_at, quarantine, location, restored_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)`
	if entry.CreatedAt.UnixMilli() <= 0 {
		entry.CreatedAt = Now()
	}
	if entry.UpdatedAt.UnixMilli() <= 0 {
		entry.UpdatedAt = Now()
	}
	_, err = tx.ExecContext(ctx, sqlStatement,
		entry.ID,
		entry.SHA256,
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
		sqlStatement := `UPDATE entries SET sha256=$2, created_at=$3, updated_at=$4, quarantine=$5, location=$6, restored_at=$7
		WHERE id = $1`
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
	return
}

func ComputeCacheID(path string, contentSHA256 string) (id string) {
	hash := sha256.New()
	hash.Write([]byte(path))
	hash.Write([]byte(contentSHA256))
	id = hex.EncodeToString(hash.Sum(nil))
	return
}
