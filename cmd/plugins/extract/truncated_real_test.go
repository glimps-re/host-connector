//go:build linux

package main

import (
	"testing"
)

// notDelivered fails when the file reached OUTPUT or left INPUT.
func notDelivered(t *testing.T, r *pipelineRun, name string) {
	t.Helper()
	if r.exists(r.out, name) {
		t.Errorf("%s was delivered to OUTPUT", name)
	}
	if !r.exists(r.in, name) {
		t.Errorf("%s left INPUT", name)
	}
}
