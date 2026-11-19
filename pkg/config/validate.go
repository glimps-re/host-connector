package config

import (
	"errors"
	"fmt"

	"github.com/glimps-re/connector-integration/sdk"
)

// Validate applies the SDK validation tags to the enumerations and bounds of
// conf. Fields required only by some commands (paths, gmalware_api_url) are
// not validated here: `quarantine` sub-commands run without them.
func Validate(conf *Config) error {
	v, err := sdk.DefaultValidator()
	if err != nil {
		return fmt.Errorf("init validator: %w", err)
	}
	sections := []struct {
		name  string
		value any
	}{
		{"unanalyzable_policy", conf.UnanalyzablePolicy},
		{"move", conf.Move},
		{"monitoring", conf.Monitoring},
		{"quarantine", conf.Quarantine},
	}
	var errs []error
	for _, s := range sections {
		if err := v.Validate(s.value); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.name, err))
		}
	}
	return errors.Join(errs...)
}
