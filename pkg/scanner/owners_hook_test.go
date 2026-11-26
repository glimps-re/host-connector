package scanner

import (
	"errors"
	"testing"
)

func TestConnector_SetTrackingOwners(t *testing.T) {
	c := &Connector{}
	if err := c.SetTrackingOwners("/in", 2); err != nil {
		t.Fatalf("SetTrackingOwners() error = %v", err)
	}
	if err := c.SetTrackingOwners("/other", 1); err != nil {
		t.Fatalf("a disjoint root must be accepted: %v", err)
	}
	for name, tt := range map[string]struct {
		root  string
		depth int
	}{
		"same root":      {"/in", 1},
		"inside a root":  {"/in/sub", 1},
		"contains":       {"/", 1},
		"relative":       {"in", 1},
		"depth zero":     {"/third", 0},
		"negative depth": {"/third", -2},
	} {
		if err := c.SetTrackingOwners(tt.root, tt.depth); !errors.Is(err, ErrInvalidOwnerRule) {
			t.Errorf("%s: error = %v, want ErrInvalidOwnerRule", name, err)
		}
	}
	rules := c.TrackingOwners()
	if len(rules) != 2 || rules[0].Root != "/in" || rules[0].Depth != 2 {
		t.Errorf("TrackingOwners() = %v", rules)
	}
	rules[0].Root = "/tampered"
	if c.TrackingOwners()[0].Root != "/in" {
		t.Error("TrackingOwners() must return a copy")
	}
}

func TestConnector_SetTrackingOwnersOnlyDuringInit(t *testing.T) {
	c := &Connector{}
	c.setSealed(true)
	if err := c.SetTrackingOwners("/in", 1); !errors.Is(err, errOwnersAfterInit) {
		t.Errorf("error = %v, want errOwnersAfterInit once the plugins are loaded", err)
	}
}
