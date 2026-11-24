//go:build linux

package harness

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/alecthomas/units"
)

// defaultMaxFileSize mirrors maxFileSizeDetect of pkg/handler/apply.go: the
// most the connector analyzes without syndetect.
const defaultMaxFileSize = 100 << 20

// syndetectOn reads gmalware_syndetect as the configuration loader would: a
// bool, or a string that strconv.ParseBool reads. Anything else is refused,
// since it cannot be told off.
func syndetectOn(v any) (bool, error) {
	switch x := v.(type) {
	case nil:
		return false, nil
	case bool:
		return x, nil
	case string:
		on, err := strconv.ParseBool(x)
		if err != nil {
			return false, fmt.Errorf("gmalware_syndetect %q: %w", x, err)
		}
		return on, nil
	default:
		return false, fmt.Errorf("gmalware_syndetect of type %T is not understood by the harness", v)
	}
}

// effectiveMaxFileSize is the size above which the connector does not analyze a
// file, for the configuration given: the value of max_file_size read with the
// units of the product, brought to 100 MiB when it is above or not positive.
// The syndetect limit (2 GiB) is not modelled: a configuration that asks for
// syndetect is refused rather than judged with the wrong limit.
func effectiveMaxFileSize(conf map[string]any) (int64, error) {
	syn, err := syndetectOn(conf["gmalware_syndetect"])
	if err != nil {
		return 0, err
	}
	if syn {
		return 0, errors.New("gmalware_syndetect is not supported by the harness: its file size limit differs")
	}
	raw, ok := conf["max_file_size"].(string)
	if !ok {
		return 0, fmt.Errorf("max_file_size must be a string, not %T", conf["max_file_size"])
	}
	size, err := units.ParseStrictBytes(raw)
	if err != nil {
		return 0, fmt.Errorf("max_file_size %q: %w", raw, err)
	}
	if size <= 0 || size > defaultMaxFileSize {
		return defaultMaxFileSize, nil
	}
	return size, nil
}
