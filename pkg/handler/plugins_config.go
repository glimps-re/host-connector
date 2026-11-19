package handler

import (
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/glimps-re/host-connector/pkg/scanner"
	"go.yaml.in/yaml/v3"
)

// maxPluginsConfigSize bounds the plugins file read: it is parsed in memory.
const maxPluginsConfigSize = 1 << 20

var (
	errPluginsConfigFormat = errors.New("invalid plugins config")
	errPluginsConfigTooBig = fmt.Errorf("%w: file larger than %d bytes", errPluginsConfigFormat, maxPluginsConfigSize)
)

// limitedReader fails past the limit instead of returning io.EOF like
// io.LimitReader: a truncated file would otherwise be read as a valid shorter
// one, silently dropping plugins.
type limitedReader struct {
	r        io.Reader
	n        int64
	exceeded bool
	readErr  error
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		l.exceeded = true
		return 0, errPluginsConfigTooBig
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	if err != nil && !errors.Is(err, io.EOF) {
		l.readErr = err
	}
	return n, err
}

// decodePluginsConfig reads the plugins file as an ordered list: a YAML map
// would lose the key order, which decides the plugins callback order. An empty
// file is an error: loading no plugin would silently drop every filter.
// Anchors, aliases and merge keys (at any level), duplicate keys, unknown
// entry keys and extra documents are refused: they could load one plugin file
// under two names or hide an entry. Errors never quote a value, which may be a
// secret.
func decodePluginsConfig(r io.Reader) ([]scanner.PluginConfig, error) {
	lr := &limitedReader{r: r, n: maxPluginsConfigSize + 1}
	dec := yaml.NewDecoder(lr)
	var root yaml.Node
	if err := dec.Decode(&root); err != nil {
		if lr.exceeded {
			return nil, errPluginsConfigTooBig
		}
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%w: empty plugins file", errPluginsConfigFormat)
		}
		if lr.readErr != nil {
			return nil, fmt.Errorf("%w: read plugins file: %w", errPluginsConfigFormat, lr.readErr)
		}
		return nil, syntaxError(err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, fmt.Errorf("%w: only one YAML document is allowed", errPluginsConfigFormat)
	} else if !errors.Is(err, io.EOF) {
		if lr.exceeded {
			return nil, errPluginsConfigTooBig
		}
		if lr.readErr != nil {
			return nil, fmt.Errorf("%w: read plugins file: %w", errPluginsConfigFormat, lr.readErr)
		}
		return nil, syntaxError(err)
	}
	if err := refuseReuse(&root); err != nil {
		return nil, err
	}
	doc := &root
	if doc.Kind == yaml.DocumentNode && len(doc.Content) == 1 {
		doc = doc.Content[0]
	}
	if doc.Kind != yaml.MappingNode || len(doc.Content) == 0 {
		return nil, fmt.Errorf("%w: top level must be a non-empty mapping of plugin name to settings", errPluginsConfigFormat)
	}
	configs := make([]scanner.PluginConfig, 0, len(doc.Content)/2)
	seen := make(map[string]struct{}, len(doc.Content)/2)
	for i := 0; i+1 < len(doc.Content); i += 2 {
		key, value := doc.Content[i], doc.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Value == "" || key.Tag == "!!merge" {
			return nil, fmt.Errorf("%w: plugin names must be plain non-empty strings", errPluginsConfigFormat)
		}
		if err := checkEntryKeys(key.Value, value); err != nil {
			return nil, err
		}
		if _, dup := seen[key.Value]; dup {
			return nil, fmt.Errorf("%w: duplicate plugin %q", errPluginsConfigFormat, key.Value)
		}
		seen[key.Value] = struct{}{}
		var pc scanner.PluginConfig
		if err := value.Decode(&pc); err != nil {
			return nil, fmt.Errorf("%w: plugin %q: invalid settings (line %d)", errPluginsConfigFormat, key.Value, value.Line)
		}
		pc.Name = key.Value
		configs = append(configs, pc)
	}
	return configs, nil
}

var yamlErrLine = regexp.MustCompile(`line (\d+)`)

// syntaxError hides the text of a YAML error, which can quote a value.
func syntaxError(err error) error {
	if m := yamlErrLine.FindStringSubmatch(err.Error()); m != nil {
		return fmt.Errorf("%w: YAML syntax error (line %s)", errPluginsConfigFormat, m[1])
	}
	return fmt.Errorf("%w: YAML syntax error", errPluginsConfigFormat)
}

func refuseReuse(n *yaml.Node) error {
	if n.Kind == yaml.AliasNode || n.Anchor != "" || n.Tag == "!!merge" {
		return fmt.Errorf("%w: anchors, aliases and merge keys are not allowed (line %d)", errPluginsConfigFormat, n.Line)
	}
	for _, child := range n.Content {
		if err := refuseReuse(child); err != nil {
			return err
		}
	}
	return nil
}

// checkEntryKeys accepts only the "file" and "config" keys: a misspelled
// "config" would otherwise leave the plugin on its defaults without notice.
func checkEntryKeys(plugin string, entry *yaml.Node) error {
	if entry.Kind != yaml.MappingNode {
		return fmt.Errorf("%w: plugin %q: settings must be a mapping with %q and %q", errPluginsConfigFormat, plugin, "file", "config")
	}
	for i := 0; i+1 < len(entry.Content); i += 2 {
		k := entry.Content[i]
		if k.Kind != yaml.ScalarNode {
			return fmt.Errorf("%w: plugin %q: keys must be plain strings (line %d)", errPluginsConfigFormat, plugin, k.Line)
		}
		if k.Value != "file" && k.Value != "config" {
			return fmt.Errorf("%w: plugin %q: unknown key %q (line %d), only %q and %q are allowed", errPluginsConfigFormat, plugin, k.Value, k.Line, "file", "config")
		}
	}
	return nil
}
