package cli

import (
	"context"
	"errors"
	"testing"

	"github.com/glimps-re/host-connector/pkg/config"
	"github.com/glimps-re/host-connector/pkg/handler"
	"github.com/glimps-re/host-connector/pkg/quarantine"
	quarantineMock "github.com/glimps-re/host-connector/pkg/quarantine/mock"
	"github.com/spf13/cobra"
)

const (
	firstID  = "0000000000000000000000000000000000000000000000000000000000000001"
	secondID = "0000000000000000000000000000000000000000000000000000000000000002"
)

// A file restored whose container could not be removed is a success: the command
// goes on with the next ids and ends without an error.
func TestQuarantineRestore_aContainerLeftBehindDoesNotStopTheNextIds(t *testing.T) {
	var restored []string
	prevHandler, prevConfig := hostHandler, hostConfig
	hostConfig = &config.Config{}
	hostHandler = &handler.Handler{Quarantiner: &quarantineMock.QuarantineMock{
		RestoreMock: func(_ context.Context, id string) error {
			restored = append(restored, id)
			if id == firstID {
				return errors.Join(quarantine.ErrRestoredLockKept, errors.New("permission denied"))
			}
			return nil
		},
	}}
	t.Cleanup(func() { hostHandler, hostConfig = prevHandler, prevConfig })

	cmd := &cobra.Command{}
	cmd.SetContext(t.Context())
	if err := quarantineRestoreCmd.RunE(cmd, []string{firstID + ".lock", secondID}); err != nil {
		t.Fatalf("RunE() = %v, want no error: the file was restored", err)
	}
	if len(restored) != 2 || restored[0] != firstID || restored[1] != secondID {
		t.Errorf("restored %v, want both ids in order", restored)
	}
}

// A failure that is one stops the command.
func TestQuarantineRestore_aFailureStopsTheCommand(t *testing.T) {
	var restored []string
	prevHandler, prevConfig := hostHandler, hostConfig
	hostConfig = &config.Config{}
	hostHandler = &handler.Handler{Quarantiner: &quarantineMock.QuarantineMock{
		RestoreMock: func(_ context.Context, id string) error {
			restored = append(restored, id)
			return quarantine.ErrDestinationExists
		},
	}}
	t.Cleanup(func() { hostHandler, hostConfig = prevHandler, prevConfig })

	cmd := &cobra.Command{}
	cmd.SetContext(t.Context())
	if err := quarantineRestoreCmd.RunE(cmd, []string{firstID, secondID}); !errors.Is(err, quarantine.ErrDestinationExists) {
		t.Fatalf("RunE() = %v, want the failure", err)
	}
	if len(restored) != 1 {
		t.Errorf("restored %v, want the command stopped at the first id", restored)
	}
}
