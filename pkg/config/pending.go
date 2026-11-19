package config

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
)

// ErrNotImplemented is returned, wrapped, when a configuration key is
// recognized but not yet supported by this version.
var ErrNotImplemented = errors.New("configuration key recognized but not supported yet by this version; remove the key")

type pendingKey struct {
	key string
	get func(c *Config) string
	// accepted lists the values this version supports for the key; the
	// empty value (SDK zero) is always accepted.
	accepted []string
}

// Each task implementing a key removes its entry from this list.
var pendingKeys = []pendingKey{
	{"monitoring.max_tracked_memory", func(c *Config) string { return c.Monitoring.MaxTrackedMemory }, nil},
	{"monitoring.max_tracked_dir_percent", func(c *Config) string { return strconv.Itoa(c.Monitoring.MaxTrackedDirPercent) }, []string{"0"}},
	{"move.mode", func(c *Config) string { return c.Move.Mode }, []string{"rename"}},
	{"move.min_throughput", func(c *Config) string { return c.Move.MinThroughput }, nil},
	{"unanalyzable_policy.too_big", func(c *Config) string { return c.UnanalyzablePolicy.TooBig }, []string{"error"}},
	{"unanalyzable_policy.empty", func(c *Config) string { return c.UnanalyzablePolicy.Empty }, []string{"skip"}},
	{"unanalyzable_policy.encrypted", func(c *Config) string { return c.UnanalyzablePolicy.Encrypted }, nil},
	{"unanalyzable_policy.extract_error", func(c *Config) string { return c.UnanalyzablePolicy.ExtractError }, nil},
}

// CheckImplemented fails when conf sets a key this version does not support yet.
func CheckImplemented(conf *Config) error {
	var errs []error
	for _, k := range pendingKeys {
		if v := k.get(conf); v != "" && !slices.Contains(k.accepted, v) {
			errs = append(errs, fmt.Errorf("%s=%q: %w", k.key, v, ErrNotImplemented))
		}
	}
	return errors.Join(errs...)
}
