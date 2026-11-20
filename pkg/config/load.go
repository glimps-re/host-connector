package config

import (
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/glimps-re/connector-integration/sdk"
	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

// LoadFile reads the YAML configuration file at path into conf. A missing file
// is accepted unless mustExist is set (an explicit --config): conf keeps its
// values. A file that cannot be read or parsed, holds a mistyped value or a key
// conf does not declare fails: starting with defaults instead would run the
// connector with a configuration nobody wrote, and a misspelled key
// (`too_bg: pass`) would silently have no effect. Values are typed strictly,
// like the JSON the console sends, and durations need a unit. Errors name the
// file and the keys, never a value: it may be a secret.
func LoadFile(path string, conf *Config, mustExist bool) error {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	if err := v.ReadInConfig(); err != nil {
		if errors.Is(err, fs.ErrNotExist) && !mustExist {
			return nil
		}
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("configuration file %s does not exist", path)
		}
		return fmt.Errorf("configuration file %s: %s", path, yamlProblem(err))
	}
	err := v.Unmarshal(conf,
		viper.DecodeHook(mapstructure.ComposeDecodeHookFunc(notNull, wholeNumber, strictDuration, sdk.DurationMapstructureHook())),
		func(dc *mapstructure.DecoderConfig) {
			dc.ErrorUnused = true
			dc.WeaklyTypedInput = false
		},
	)
	if err != nil {
		return fmt.Errorf("configuration file %s: %s", path, decodeProblem(err))
	}
	return nil
}

var yamlLine = regexp.MustCompile(`line (\d+)`)

// yamlProblem hides the text of a YAML error, which can quote a value.
func yamlProblem(err error) string {
	if m := yamlLine.FindStringSubmatch(err.Error()); m != nil {
		return "cannot be read: YAML syntax error (line " + m[1] + ")"
	}
	return "cannot be read"
}

// decodeProblem names the keys at fault, never their values.
func decodeProblem(err error) string {
	var invalid, unknown []string
	var walk func(error)
	walk = func(e error) {
		var de *mapstructure.DecodeError
		if errors.As(e, &de) {
			// An unused key is reported as "'section' has invalid keys: a, b".
			if _, after, ok := strings.Cut(de.Error(), "has invalid keys:"); ok {
				prefix := de.Name()
				for _, k := range strings.Split(strings.TrimSpace(strings.SplitN(after, "\n", 2)[0]), ",") {
					k = strings.TrimSpace(k)
					if prefix != "" && !strings.Contains(prefix, "config.Config") {
						k = prefix + "." + k
					}
					unknown = append(unknown, k)
				}
				return
			}
			invalid = append(invalid, de.Name())
			return
		}
		if multi, ok := e.(interface{ Unwrap() []error }); ok {
			for _, sub := range multi.Unwrap() {
				walk(sub)
			}
		}
	}
	walk(err)
	var parts []string
	if len(unknown) > 0 {
		parts = append(parts, "unknown key(s) "+strings.Join(unknown, ", "))
	}
	if len(invalid) > 0 {
		parts = append(parts, "invalid value for key(s) "+strings.Join(invalid, ", "))
	}
	if len(parts) == 0 {
		return "invalid configuration"
	}
	return strings.Join(parts, "; ")
}

// strictDuration refuses what would silently be wrong for a sdk.Duration: a
// number without unit (a bare 5 is 5 ns: a rescan loop, or analyses expiring at
// once) and a negative value. A bare 0 stays valid (disabled).
func strictDuration(_, to reflect.Type, data any) (any, error) {
	if to != reflect.TypeFor[sdk.Duration]() {
		return data, nil
	}
	noUnit := errors.New("duration needs a unit (e.g. 30s)")
	switch value := data.(type) {
	case int:
		if value != 0 {
			return nil, noUnit
		}
	case int64:
		if value != 0 {
			return nil, noUnit
		}
	case uint64:
		if value != 0 {
			return nil, noUnit
		}
	case float64:
		if value != 0 {
			return nil, noUnit
		}
	case string:
		if _, err := strconv.ParseFloat(value, 64); err == nil && value != "0" {
			return nil, noUnit
		}
		if d, err := time.ParseDuration(value); err == nil && d < 0 {
			return nil, errors.New("duration must not be negative")
		}
	}
	return data, nil
}

// notNull refuses an explicit null for a field that is not optional: it would
// silently reset the value to zero.
func notNull(_, to reflect.Type, data any) (any, error) {
	if data == nil {
		switch to.Kind() {
		case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice:
		default:
			return nil, errors.New("null is not a valid value")
		}
	}
	return data, nil
}

// wholeNumber refuses a fractional number for an integer field: mapstructure
// would truncate it.
func wholeNumber(_, to reflect.Type, data any) (any, error) {
	switch to.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if f, ok := data.(float64); ok && f != float64(int64(f)) {
			return nil, errors.New("not a whole number")
		}
	}
	return data, nil
}
