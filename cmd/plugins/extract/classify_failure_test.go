//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/glimps-re/host-connector/pkg/plugins"
)

func TestClassifyFailure(t *testing.T) {
	tests := []struct {
		name          string
		err           error
		wantAnomaly   bool
		wantEncrypted bool
	}{
		{"recoverable 7z error", errors.Join(errSevenZipRecoverable, errors.New("Data Error")), true, false},
		{"listing that does not match", fmt.Errorf("%w: 3 members, 2 announced", errBadListing), true, false},
		{"member failure an encryption can explain", &encryptionHintError{members: 1, quoted: "x"}, true, false},
		{"output flood", fmt.Errorf("%w: lines", errSevenZipOutputTooLarge), true, false},
		{"already an anomaly", fmt.Errorf("x: %w", plugins.ErrArchiveAnomaly), true, false},
		{"password nobody knows", fmt.Errorf("%w: x", ErrInvalidPassword), false, true},
		{"7z timeout", errSevenZipTimeout, false, false},
		{"extractor unavailable", fmt.Errorf("%w: exec", plugins.ErrExtractorUnavailable), false, false},
		{"failure of the output folder", fmt.Errorf("%w: unreadable", errOutputFolder), false, false},
		{"unknown 7z error", errors.New("exit status 2: something else"), false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyFailure(tt.err)
			if anomaly := errors.Is(got, plugins.ErrArchiveAnomaly); anomaly != tt.wantAnomaly {
				t.Errorf("anomaly = %t, want %t (error: %v)", anomaly, tt.wantAnomaly, got)
			}
			if possible := errors.Is(got, plugins.ErrEncryptionPossible); possible != tt.wantAnomaly {
				t.Errorf("encryption possible = %t, want %t: an anomaly of a failed run proves nothing (error: %v)", possible, tt.wantAnomaly, got)
			}
			if encrypted := errors.Is(got, plugins.ErrEncrypted); encrypted != tt.wantEncrypted {
				t.Errorf("encrypted = %t, want %t (error: %v)", encrypted, tt.wantEncrypted, got)
			}
			if !errors.Is(got, tt.err) {
				t.Errorf("the cause is lost: %v", got)
			}
		})
	}
}

func TestClassifyFailure_aTimeoutIsADeadlineAndStaysVisibleBesideAnAnomaly(t *testing.T) {
	if !errors.Is(errSevenZipTimeout, context.DeadlineExceeded) {
		t.Error("the 7z timeout must wrap context.DeadlineExceeded: the scanner recognizes a transient failure by it")
	}
	got := classifyFailure(errors.Join(errSevenZipRecoverable, errSevenZipTimeout))
	if !errors.Is(got, context.DeadlineExceeded) {
		t.Errorf("the timeout is hidden by the anomaly: %v", got)
	}
}
