package scanner

import "github.com/glimps-re/host-connector/pkg/datamodel"

// onScanFile is onScanFileRules for a file whose raw path is its logical one,
// with the skipped paths allowed.
func (c *Connector) onScanFile(filename, filepath, sha256 string, isArchive bool) *datamodel.Result {
	return c.onScanFileRules(filename, "", filepath, sha256, isArchive, true)
}
