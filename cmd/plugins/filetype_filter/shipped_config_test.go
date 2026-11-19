package main

import (
	"os"
	"regexp"
	"testing"

	"github.com/glimps-re/host-connector/pkg/plugins"
	"go.yaml.in/yaml/v3"
)

const shippedPluginName = "filetype_filter"

func newShippedPlugin() interface{ GetDefaultConfig() any } { return new(FTFilterPlugin) }

func TestShippedConfigsDecodeStrictly(t *testing.T) {
	rscRaw, err := os.ReadFile("../../../rsc/plugin_config.yml")
	if err != nil {
		t.Fatal(err)
	}
	readme, err := os.ReadFile("../../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	sources := map[string][]string{"rsc/plugin_config.yml": {string(rscRaw)}}
	for _, m := range regexp.MustCompile("(?s)```yaml\n(.*?)```").FindAllStringSubmatch(string(readme), -1) {
		sources["README.md"] = append(sources["README.md"], m[1])
	}
	for src, docs := range sources {
		found := false
		for _, doc := range docs {
			var top map[string]map[string]any
			if err := yaml.Unmarshal([]byte(doc), &top); err != nil {
				continue
			}
			section, ok := top[shippedPluginName]
			if !ok {
				continue
			}
			found = true
			raw, _ := section["config"].(map[string]any)
			result := newShippedPlugin().GetDefaultConfig()
			if err := plugins.DecodeConfig(shippedPluginName, raw, result); err != nil {
				t.Errorf("%s: %v", src, err)
			}
		}
		if !found {
			t.Errorf("%s: no %q section found", src, shippedPluginName)
		}
	}
}
