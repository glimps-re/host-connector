//go:build !linux

package main

import (
	"context"
	"errors"
	"time"
)

// cleanupSupported tells whether removeEmptyDirs works on this system.
const cleanupSupported = false

func removeEmptyDirs(context.Context, string, string, time.Duration, string) (cleanupStats, error) {
	return cleanupStats{}, errors.New("removing empty folders is not supported on this system")
}
