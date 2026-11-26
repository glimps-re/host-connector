package scanner

import (
	"errors"
	"slices"
)

var errOwnersAfterInit = errors.New("tracking owners can only be declared during Init")

// SetTrackingOwners declares how the files below root are grouped into owners
// (see DeclareOwners). It is part of plugins.HCContext and is valid during
// Init only.
func (c *Connector) SetTrackingOwners(root string, depth int) error {
	c.pluginsMu.Lock()
	defer c.pluginsMu.Unlock()
	if c.pluginsSealed {
		return errOwnersAfterInit
	}
	rules, err := DeclareOwners(c.owners, root, depth)
	if err != nil {
		return err
	}
	c.owners = rules
	return nil
}

// TrackingOwners returns the declarations made by the plugins.
func (c *Connector) TrackingOwners() []OwnerRule {
	c.pluginsMu.Lock()
	defer c.pluginsMu.Unlock()
	return slices.Clone(c.owners)
}

// PendingFiles returns how many files the monitoring has detected under the
// owner whose folder is dir and has not finished processing. It is 0 when
// nothing is monitored.
func (c *Connector) PendingFiles(dir string) int {
	if c.config.PendingFiles == nil {
		return 0
	}
	return c.config.PendingFiles(dir)
}
