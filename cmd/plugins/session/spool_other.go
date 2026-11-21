//go:build !unix

package main

// openNoFollow is unavailable on this system: the spool folder is private to
// the connector, and the file is created exclusively.
const openNoFollow = 0
