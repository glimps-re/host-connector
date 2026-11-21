package config

import (
	"errors"
	"fmt"

	"github.com/glimps-re/connector-integration/sdk"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
)

// ErrWatcherNeedsPeriod is returned by Validate when filesystem events are
// disabled without a periodic rescan: no file would ever be discovered.
var ErrWatcherNeedsPeriod = errors.New("monitoring.disable_fs_watcher requires monitoring.period: files would never be discovered")

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
		{"filepath_filter", conf.FilepathFilter},
		{"move", conf.Move},
		{"monitoring", conf.Monitoring},
		{"quarantine", conf.Quarantine},
	}
	var errs []error
	for _, s := range sections {
		if err := v.Validate(s.value); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.name, withReasons(err, v.Trans)))
		}
	}
	if conf.Monitoring.DisableFSWatcher && conf.Monitoring.Period == 0 {
		errs = append(errs, ErrWatcherNeedsPeriod)
	}
	return errors.Join(errs...)
}

// withReasons adds to a validation error the message of each refused pattern of
// filepath_filter (which list, which index, why): the raw error only names the
// tag.
func withReasons(err error, trans ut.Translator) error {
	verrs, ok := errors.AsType[validator.ValidationErrors](err)
	if !ok {
		return err
	}
	reasons := []error{err}
	for _, fe := range verrs {
		if fe.Tag() == "filepath_pattern" {
			reasons = append(reasons, errors.New(fe.Translate(trans)))
		}
	}
	return errors.Join(reasons...)
}
