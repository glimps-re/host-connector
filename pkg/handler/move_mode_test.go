package handler

import (
	"testing"

	"github.com/glimps-re/host-connector/pkg/config"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

func TestPrepare_moveThroughput(t *testing.T) {
	tests := []struct {
		name, value string
		want        int64
	}{
		{"default", "", scanner.DefaultMoveMinThroughput},
		{"explicit", "1MiB", 1 << 20},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf := validConf(t, t.TempDir())
			conf.Move.MinThroughput = tt.value
			p, err := new(Handler).prepare(conf)
			if err != nil {
				t.Fatal(err)
			}
			if p.moveMinThroughput != tt.want {
				t.Errorf("moveMinThroughput = %d, want %d", p.moveMinThroughput, tt.want)
			}
		})
	}
}

func TestReportMoveMode(t *testing.T) {
	tests := []struct {
		name      string
		move      bool
		mode      string
		wantError bool
	}{
		{"rename with move", true, "rename", true},
		{"copy with move", true, "copy", false},
		{"default with move", true, "", false},
		{"rename without move", false, "rename", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := recordEvents(t)
			conf := &config.Config{}
			conf.Actions.Move, conf.Move.Mode = tt.move, tt.mode
			h := new(Handler)
			h.reportMoveMode(t.Context(), conf)
			h.reportMoveMode(t.Context(), conf)
			errs, resolved := rec.find("error", HostMoveRename), rec.find("resolution", HostMoveRename)
			if tt.wantError && (len(errs) != 2 || len(resolved) != 0) {
				t.Errorf("errors %d, resolutions %d, want the event raised at each application", len(errs), len(resolved))
			}
			if !tt.wantError && (len(errs) != 0 || len(resolved) != 2) {
				t.Errorf("errors %d, resolutions %d, want the event resolved", len(errs), len(resolved))
			}
		})
	}
}
