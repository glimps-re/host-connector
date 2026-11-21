package main

import (
	"errors"
	"log/slog"
	"os/exec"
	"testing"
)

func failed(t *testing.T, err error) error {
	t.Helper()
	if err == nil {
		t.Fatal("the command did not fail")
	}
	return err
}

func TestHandleSevenZipError_silentExitCodes(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		wantRecovery bool
	}{
		{"fatal error without a word: the archive is damaged", failed(t, exec.CommandContext(t.Context(), "sh", "-c", "exit 2").Run()), true},
		{"not enough memory", failed(t, exec.CommandContext(t.Context(), "sh", "-c", "exit 8").Run()), false},
		{"warning", failed(t, exec.CommandContext(t.Context(), "sh", "-c", "exit 1").Run()), false},
		{"not an exit status", errors.New("pipe closed"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := handleSevenZipError(tt.err, "", slog.New(slog.DiscardHandler), "/a")
			if got := errors.Is(err, errSevenZipRecoverable); got != tt.wantRecovery {
				t.Errorf("recoverable = %t, want %t (error: %v)", got, tt.wantRecovery, err)
			}
			if !errors.Is(err, tt.err) {
				t.Errorf("error %v lost its cause %v", err, tt.err)
			}
		})
	}
}
