package cache

import (
	"database/sql"
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
	Sha256    string    `gorm:"primarykey" field:"sha256"`
	CreatedAt time.Time `field:"created_at"`
	UpdatedAt time.Time `field:"updated_at"`
	// DeletedAt          gorm.DeletedAt `gorm:"index"`
	InitialLocation    string    `field:"location"`
	QuarantineLocation string    `field:"quarantine"`
	RestoredAt         time.Time `field:"restore_at"`
}

type Cacher interface {
	// Set adds or updates a cache entry
	Set(entry *Entry) error

	// Get fetch a cache entry
	Get(id string) (entry *Entry, err error)

	Close() error
}

var ErrEntryNotFound = errors.New("entry not found")

type Cache struct {
	db *sql.DB
	sync.Mutex
}

var CreateTable = `CREATE TABLE IF NOT EXISTS entries (
	sha256 TEXT PRIMARY KEY, 
	created_at int NOT NULL, 
	updated_at int NOT NULL, 
	quarantine TEXT, 
	location TEXT, 
	restored_at int );`

func NewCache(location string) (c *Cache, err error) {
	if location == "" {
		location = "file::memory:"
	} else {
		_, err = os.Stat(location)
		if errors.Is(err, os.ErrNotExist) {
			dir, _ := filepath.Split(location)
			err = os.MkdirAll(dir, 0o755)
			if err != nil {
				return
			}
			_, err = os.Create(location)
			if err != nil {
				return
			}
		}
	}
	db, err := sql.Open("sqlite", location)
	if err != nil {
		return
	}

	result, err := db.Exec(CreateTable)
	Logger.Info("create new db", "result", result)

	c = &Cache{db: db}
	return
}

func (c *Cache) Close() error {
	return c.db.Close()
}

func (c *Cache) Get(id string) (entry *Entry, err error) {
	c.Lock()
	defer c.Unlock()
	entry = &Entry{}
	var createAt, updatedAt, restoredAt int64
	err = c.db.QueryRow("SELECT * FROM entries where sha256 = ?", id).Scan(
		&entry.Sha256,
		&createAt,
		&updatedAt,
		&entry.QuarantineLocation,
		&entry.InitialLocation,
		&restoredAt,
	)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return nil, ErrEntryNotFound
		}
		return
	}
	entry.CreatedAt = time.UnixMilli(createAt)
	entry.UpdatedAt = time.UnixMilli(updatedAt)
	entry.RestoredAt = time.UnixMilli(restoredAt)
	return
}

var Now = time.Now

func (c *Cache) Set(entry *Entry) (err error) {
	c.Lock()
	defer c.Unlock()
	tx, err := c.db.Begin()
	if err != nil {
		return
	}
	defer tx.Commit()
	sqlStatement := `
INSERT INTO entries (sha256, created_at, updated_at, quarantine, location, restored_at)
VALUES ($1, $2, $3, $4, $5, $6)`
	if entry.CreatedAt.UnixMilli() <= 0 {
		entry.CreatedAt = Now()
	}
	if entry.UpdatedAt.UnixMilli() <= 0 {
		entry.UpdatedAt = Now()
	}
	_, err = tx.Exec(sqlStatement,
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
	if e, ok := err.(*sqlite.Error); ok && e.Code() == 1555 {
		sqlStatement := `
		UPDATE entries SET created_at=$2, updated_at=$3, quarantine=$4, location=$5, restored_at=$6
		WHERE sha256 = $1`
		_, err = tx.Exec(sqlStatement,
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
