//go:build linux

package harness

import (
	"errors"
	"fmt"

	"github.com/alecthomas/units"
)

// defaultMaxFileSize mirrors maxFileSizeDetect of pkg/handler/apply.go: the
// most the connector analyzes without syndetect.
const defaultMaxFileSize = 100 << 20

// effectiveMaxFileSize is the size above which the connector does not analyze a
// file, for the configuration given: the value of max_file_size read with the
// units of the product, brought to 100 MiB when it is above or not positive.
// The syndetect limit (2 GiB) is not modelled: a configuration that sets
// gmalware_syndetect is refused rather than judged with the wrong limit.
func effectiveMaxFileSize(conf map[string]any) (int64, error) {
	if _, set := conf["gmalware_syndetect"]; set {
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
