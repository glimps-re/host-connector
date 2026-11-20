package config

import (
	"fmt"
	"time"
)

const (
	// DefaultShutdownTimeout is the time a stop on a signal may take when
	// shutdown_timeout is not set: under the 10 s of `docker stop`.
	DefaultShutdownTimeout = 8 * time.Second
	// MinShutdownTimeout is the shortest accepted shutdown_timeout.
	MinShutdownTimeout = 2 * time.Second
	// maxShutdownReserve is the most of the timeout kept for closing.
	maxShutdownReserve = 30 * time.Second
)

// ShutdownDurations returns the time a stop may take and the part of it files
// being processed may use to finish: the rest is kept for closing (sessions,
// plugins, work directory), which may use the whole time if the files finish
// early. An unset timeout is DefaultShutdownTimeout; one under
// MinShutdownTimeout is refused.
func (c *Config) ShutdownDurations() (total, drain time.Duration, err error) {
	total = time.Duration(c.ShutdownTimeout)
	if total == 0 {
		total = DefaultShutdownTimeout
	}
	if total < MinShutdownTimeout {
		return 0, 0, fmt.Errorf("shutdown_timeout %s is too short: at least %s", total, MinShutdownTimeout)
	}
	return total, total - min(total/2, maxShutdownReserve), nil
}
