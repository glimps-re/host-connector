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

// Restored reports whether the entry was restored.
func (e *Entry) Restored() bool { return e.RestoredAt.UnixMilli() > 0 }

type quarantineRegistry interface {
	GetLocation() (location string)

	// Set adds or updates an entry
	Set(ctx context.Context, entry *Entry) error

	// Get fetch an entry
	Get(ctx context.Context, id string) (entry *Entry, err error)

	// Clone returns a new registry at newLocation (in memory when empty) holding
	// a copy of every entry. The receiver is left untouched, so a caller can
	// switch to the clone at the end of a multi-step change, or Discard it.
	//
	// An existing registry at newLocation must be empty, unless mergeExisting:
	// that is for a rollback to the registry just left, whose entries are
	// refreshed from the receiver.
	Clone(ctx context.Context, newLocation string, mergeExisting bool) (quarantineRegistry, error)

	// Discard closes the registry and removes its database file when this
	// registry created it: an abandoned clone leaves nothing behind.
	Discard() error

	Close() error
}

var errEntryNotFound = errors.New("entry not found")

// errRegistryNotWritten is wrapped in the error of any call of the registry that
// gave up waiting for its lock before it reached the database (Get, Set, Clone
// and the others take it the same way): nothing was read, written or
// created, so a restoration whose marking fails with it has nothing to undo.
var errRegistryNotWritten = errors.New("the registry was not reached")

type sqliteRegistry struct {
	db          *sql.DB
	location    string
	createdFile bool
	// gate is the lock of the registry: one slot, taken with the context of the
	// call, so that a caller that gives up does not wait behind a call that is
	// stuck. A call that never returns (a hung disk or file system) still holds it:
	// the callers that wait are freed by their own deadline, the call is not. The
	// gate is in-process only and no busy_timeout is set: a second process that
	// holds the database lock makes a call fail with SQLITE_BUSY at once instead of
	// waiting.
	gate chan struct{}
}

// wait takes the lock of the registry, however long it takes, for the calls that
// end the registry.
func (c *sqliteRegistry) wait() (unlock func()) {
	c.gate <- struct{}{}
	return func() { <-c.gate }
}

// lock takes the lock of the registry, or fails when ctx ends first.
func (c *sqliteRegistry) lock(ctx context.Context) (unlock func(), err error) {
	if err = ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", errRegistryNotWritten, err)
	}
	select {
	case c.gate <- struct{}{}:
		return func() { <-c.gate }, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: %w", errRegistryNotWritten, ctx.Err())
	}
}

var _ quarantineRegistry = &sqliteRegistry{}

// ensureDBFile creates the database file when absent and reports whether it
// did.
func ensureDBFile(location string) (created bool, err error) {
	_, err = os.Stat(location)
	if err == nil {
		return false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("failed to stat quarantine registry db: %w", err)
	}

	dir := filepath.Dir(location)
	if err = os.MkdirAll(dir, 0o750); err != nil {
		return false, fmt.Errorf("failed to create quarantine registry db location: %w", err)
	}

	f, err := os.OpenFile(filepath.Clean(location), os.O_RDONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return false, fmt.Errorf("failed to create quarantine registry db file: %w", err)
	}
	if err = f.Close(); err != nil {
		return true, fmt.Errorf("failed to close quarantine registry db file after creation: %w", err)
	}
	return true, nil
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
	createdFile := false
	if location != "" {
		if !filepath.IsAbs(location) {
			err = fmt.Errorf("registry location must be an absolute path, got %q", location)
			return
		}
		if createdFile, err = ensureDBFile(location); err != nil {
			return
		}
		finalLocation = location
	}

	db, err := sql.Open("sqlite", finalLocation)
	if err != nil {
		err = fmt.Errorf("failed to open quarantine db: %w", err)
		removeCreated(location, createdFile)
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
		if e := db.Close(); e != nil {
			logger.Error("cannot close quarantine db", slog.String("error", e.Error()))
		}
		removeCreated(location, createdFile)
		return
	}

	logger.Info("create new db", slog.Any("result", result))
	c = &sqliteRegistry{db: db, location: finalLocation, createdFile: createdFile, gate: make(chan struct{}, 1)}
	return
}

func removeCreated(location string, created bool) {
	if !created {
		return
	}
	if err := os.Remove(location); err != nil && !errors.Is(err, os.ErrNotExist) {
		logger.Error("cannot remove abandoned quarantine registry", slog.String("file", location), slog.String("error", err.Error()))
	}
}

func (c *sqliteRegistry) GetLocation() (location string) {
	return c.location
}

// Close waits, without bound, for the call in progress.
func (c *sqliteRegistry) Close() error {
	defer c.wait()()
	return c.db.Close()
}

func (c *sqliteRegistry) Clone(ctx context.Context, newLocation string, mergeExisting bool) (quarantineRegistry, error) {
	clone, err := newSQLiteRegistry(ctx, newLocation)
	if err != nil {
		return nil, err
	}
	// A registry that already exists must be empty: copying into it would mix
	// two histories, and discarding the clone would leave the copies behind.
	var existing int
	if err = clone.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM entries").Scan(&existing); err != nil {
		return nil, errors.Join(err, clone.Discard())
	}
	if existing > 0 && !mergeExisting {
		return nil, errors.Join(fmt.Errorf("the registry %s already holds %d entries", newLocation, existing), clone.Discard())
	}

	unlock, err := c.lock(ctx)
	if err != nil {
		return nil, errors.Join(err, clone.Discard())
	}
	defer unlock()
	rows, err := c.db.QueryContext(ctx, "SELECT id, sha256, created_at, updated_at, quarantine, location, restored_at FROM entries")
	if err != nil {
		return nil, errors.Join(err, clone.Discard())
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
			return nil, errors.Join(err, clone.Discard())
		}
		entry.CreatedAt = time.UnixMilli(createdAt)
		entry.UpdatedAt = time.UnixMilli(updatedAt)
		entry.RestoredAt = time.UnixMilli(restoredAt)
		if err = clone.Set(ctx, entry); err != nil {
			return nil, errors.Join(err, clone.Discard())
		}
	}
	if err = rows.Err(); err != nil {
		return nil, errors.Join(err, clone.Discard())
	}
	return clone, nil
}

// Discard waits, without bound, for the call in progress.
func (c *sqliteRegistry) Discard() error {
	defer c.wait()()
	err := c.db.Close()
	removeCreated(c.location, c.createdFile)
	if c.createdFile {
		// SQLite side files of a database we created.
		for _, suffix := range []string{"-wal", "-shm", "-journal"} {
			removeCreated(c.location+suffix, true)
		}
	}
	return err
}

func (c *sqliteRegistry) Get(ctx context.Context, id string) (entry *Entry, err error) {
	unlock, err := c.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
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

var now = time.Now

func (c *sqliteRegistry) Set(ctx context.Context, entry *Entry) (err error) {
	unlock, lockErr := c.lock(ctx)
	if lockErr != nil {
		return lockErr
	}
	defer unlock()
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

// ComputeCacheID returns the registry id of the file at path holding the content
// of this SHA256, taken as given: the package derives it from a clean path and a
// lower-case SHA256.
func ComputeCacheID(path string, contentSHA256 string) (id string) {
	hash := sha256.New()
	hash.Write([]byte(path))
	hash.Write([]byte(contentSHA256))
	id = hex.EncodeToString(hash.Sum(nil))
	return
}
