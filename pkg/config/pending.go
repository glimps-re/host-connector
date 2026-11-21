package config

import (
	"errors"
	"fmt"
	"slices"
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

// Each task implementing a key removes its entry from this list; the last one
// deletes this file, CheckImplemented and its call.
var pendingKeys = []pendingKey{
	{"filepath_filter", func(c *Config) string {
		if n := len(c.FilepathFilter.ForbiddenPaths) + len(c.FilepathFilter.SkippedPaths); n > 0 {
			return fmt.Sprintf("%d pattern(s)", n)
		}
		return ""
	}, nil},
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
