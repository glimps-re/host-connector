package plugins

import (
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
)

// ErrInvalidConfig is wrapped by every error DecodeConfig returns.
var ErrInvalidConfig = errors.New("invalid plugin configuration")

// removedConfigKeys maps a plugin name to its removed configuration keys and
// the message explaining the replacement. It is consulted before the strict
// decoding, so the operator reads the replacement rather than a generic
// "unknown key".
var removedConfigKeys = map[string]map[string]string{
	"extract": {
		"max_file_size":            "the extraction limits are the global ones now: use max_file_size of the main configuration (per extracted file); remove the key, and adjust the global limit if the old value must be kept",
		"max_extracted_files":      "the extraction limits are the global ones now: use recursive_extract_max_files of the main configuration (it counts all levels of one scan, not one archive); remove the key, and adjust the global limit if the old value must be kept",
		"max_total_extracted_size": "the extraction limits are the global ones now: use recursive_extract_max_size of the main configuration (it counts all levels of one scan, not one archive); remove the key, and adjust the global limit if the old value must be kept",
	},
}

// DecodeConfig decodes the raw configuration section of plugin pluginName
// into dst (the value returned by Plugin.GetDefaultConfig). It first refuses
// removed keys with a dedicated message, then decodes strictly: an unknown key
// is an error, a typo would otherwise leave a filter silently inactive. Time
// durations are accepted as strings ("30s"). Errors name keys, never values,
// which may be secrets (e.g. passwords).
func DecodeConfig(pluginName string, raw map[string]any, dst any) error {
	if err := checkRemovedKeys(pluginName, raw); err != nil {
		return err
	}
	var md mapstructure.Metadata
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: decodeDuration,
		Result:     dst,
		Metadata:   &md,
	})
	if err != nil {
		return fmt.Errorf("plugin %q: %w: create decoder", pluginName, ErrInvalidConfig)
	}
	if err = decoder.Decode(raw); err != nil {
		return fmt.Errorf("plugin %q: %w: invalid value for key(s) %s", pluginName, ErrInvalidConfig, quotedKeys(decodeErrKeys(err)))
	}
	if len(md.Unused) > 0 {
		unused := slices.Sorted(slices.Values(md.Unused))
		return fmt.Errorf("plugin %q: %w: unknown config key(s) %s", pluginName, ErrInvalidConfig, quotedKeys(unused))
	}
	return nil
}

// What an error says of the keys of a configuration, which someone else writes:
// each is quoted (a control or invisible character is escaped), cut, and only the
// first few are listed.
const (
	maxQuotedKeys   = 20
	maxQuotedKeyLen = 100
)

func quotedKeys(keys []string) string {
	shown := keys[:min(len(keys), maxQuotedKeys)]
	quoted := make([]string, len(shown))
	for i, k := range shown {
		if len(k) > maxQuotedKeyLen {
			k = k[:maxQuotedKeyLen] + "..."
		}
		quoted[i] = strconv.Quote(k)
	}
	list := strings.Join(quoted, ", ")
	if len(keys) > len(shown) {
		list += fmt.Sprintf(", ... and %d more", len(keys)-len(shown))
	}
	return list
}

func checkRemovedKeys(pluginName string, config map[string]any) error {
	removed := removedConfigKeys[pluginName]
	if len(removed) == 0 {
		return nil
	}
	var errs []error
	for _, key := range slices.Sorted(maps.Keys(config)) {
		if msg, ok := removed[key]; ok {
			errs = append(errs, fmt.Errorf("plugin %q: %w: key %q removed: %s", pluginName, ErrInvalidConfig, key, msg))
		}
	}
	return errors.Join(errs...)
}

func decodeDuration(fromType reflect.Type, toType reflect.Type, from any) (any, error) {
	if toType != reflect.TypeFor[time.Duration]() || fromType.Kind() != reflect.String {
		return from, nil
	}
	str, ok := from.(string)
	if !ok {
		return from, nil
	}
	duration, err := time.ParseDuration(str)
	if err != nil {
		return nil, errors.New("invalid duration")
	}
	return duration, nil
}

func decodeErrKeys(err error) []string {
	var keys []string
	var walk func(error)
	walk = func(e error) {
		if de, ok := errors.AsType[*mapstructure.DecodeError](e); ok {
			keys = append(keys, de.Name())
			return
		}
		if multi, ok := e.(interface{ Unwrap() []error }); ok {
			for _, sub := range multi.Unwrap() {
				walk(sub)
			}
		}
	}
	walk(err)
	if len(keys) == 0 {
		return []string{"?"}
	}
	return keys
}
