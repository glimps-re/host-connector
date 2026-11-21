package config

import (
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/glimps-re/connector-integration/sdk"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestShippedYAMLUnchanged(t *testing.T) {
	b, err := os.ReadFile("../../rsc/config.yml")
	if err != nil {
		t.Fatal(err)
	}
	got := loadViperYAML(t, string(b))
	if err := Validate(got); err != nil {
		t.Fatalf("rsc/config.yml refused: %v", err)
	}
	// Effective values with SDK v0.8.4; v0.10.0 only adds zero-valued fields.
	want := &Config{HostConfig: sdk.HostConfig{
		CommonConnectorConfig: sdk.CommonConnectorConfig{
			GMalwareAPIURL:   "https://gmalware.ggp.glimps.re",
			GMalwareAPIToken: "00000000-00000000-00000000-00000000-00000000",
			GMalwareTimeout:  sdk.Duration(5 * time.Minute),
			GMalwareUserTags: []string{"Server1"},
		},
		Paths:      []string{},
		Actions:    sdk.HostActionsConfig{Delete: true, Quarantine: true},
		Monitoring: sdk.HostMonitoringConfig{PreScan: true, Period: sdk.Duration(time.Hour), ModificationDelay: sdk.Duration(30 * time.Second)},
		Quarantine: sdk.HostQuarantineConfig{Password: "infected"},
	}}
	if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("rsc/config.yml effective configuration changed (-want +got):\n%s", diff)
	}
}

func TestREADMEExamplesAccepted(t *testing.T) {
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	coreKey := regexp.MustCompile(`(?m)^(workers|paths|actions|monitoring|quarantine|move|gmalware_api_url):`)
	blocks := regexp.MustCompile("(?s)```yaml\n(.*?)```").FindAllStringSubmatch(string(b), -1)
	checked := 0
	for i, m := range blocks {
		if !coreKey.MatchString(m[1]) {
			continue
		}
		checked++
		if err := Validate(loadViperYAML(t, m[1])); err != nil {
			t.Errorf("README example %d refused: %v", i, err)
		}
	}
	if checked == 0 {
		t.Error("no core configuration example found in README.md")
	}
}

func TestValidate_QuarantineFormats(t *testing.T) {
	for _, format := range []string{"", "tar", "zip"} {
		conf := &Config{}
		conf.Quarantine.Format = format
		if err := Validate(conf); err != nil {
			t.Errorf("Validate(format=%q) error = %v", format, err)
		}
	}
}
