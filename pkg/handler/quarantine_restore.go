package handler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/glimps-re/connector-integration/sdk/events"
	"github.com/glimps-re/host-connector/pkg/quarantine"
)

// HostQuarantineRestoreUnregistered is the console event raised, as a warning and
// never resolved, by the restoration of a quarantined file that had no registry
// entry (decision Q30): the content is now allowed without the registry having
// said so beforehand.
const HostQuarantineRestoreUnregistered events.ErrorEventType = "quarantine-restore-unregistered"

// notifyUnregisteredRestore tells the console, within notifyTimeout, of a
// restoration without registry entry.
func notifyUnregisteredRestore(ctx context.Context, id, dest, sha256 string) {
	msg := fmt.Sprintf("the quarantined file %s was restored to %s without a registry entry (sha256 %s): the registry did not know it", id, dest, sha256)
	consoleLogger.Warn(msg)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), notifyTimeout)
	defer cancel()
	if e := eventHandler.NotifyError(ctx, HostQuarantineRestoreUnregistered, errors.New(msg)); e != nil {
		logger.Warn("could not push console error", slog.String("error", e.Error()))
	}
}

// Console events of a restoration, never resolved: they tell of a registry that
// disagrees with the files.
const (
	// HostQuarantineRestoreUnmarkFailed is raised when a restoration failed and the
	// registry could not be put back as it was: the content is allowed by its
	// SHA256 although nothing was published.
	HostQuarantineRestoreUnmarkFailed events.ErrorEventType = "quarantine-restore-unmark-failed"
	// HostQuarantineRestoreNotRegistered is raised when a container without
	// registry entry was restored but the registry could not be told: the content
	// is detected and quarantined again at the next pass.
	HostQuarantineRestoreNotRegistered events.ErrorEventType = "quarantine-restore-not-registered"
)

// notifyRestoreRegistry raises the event that matches how a restoration left the
// registry, within notifyTimeout; nothing for any other outcome.
func notifyRestoreRegistry(ctx context.Context, id string, err error) {
	var key events.ErrorEventType
	var what string
	switch {
	case errors.Is(err, quarantine.ErrRestoreRollbackFailed):
		key, what = HostQuarantineRestoreUnmarkFailed, "the restoration failed and its registry entry could not be put back: the content is allowed although nothing was restored"
	case errors.Is(err, quarantine.ErrRestoredNotRegistered):
		key, what = HostQuarantineRestoreNotRegistered, "the file was restored but the registry does not know it: its content will be detected and quarantined again at the next pass"
	default:
		return
	}
	msg := fmt.Sprintf("quarantined file %s: %s: %v", id, what, err)
	consoleLogger.Error(msg)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), notifyTimeout)
	defer cancel()
	if e := eventHandler.NotifyError(ctx, key, errors.New(msg)); e != nil {
		logger.Warn("could not push console error", slog.String("error", e.Error()))
	}
}

// restoreBindings is what the quarantine of the connector takes from the running
// instance: they are not configuration, so they are set after every application
// and never travel in quarantine.Config.
type restoreBindings interface {
	SetWorkDir(dir string)
	SetUnregisteredRestoreHook(f func(ctx context.Context, id, dest, sha256 string))
}

// bindQuarantine gives the quarantine the private work directory of the
// connector, which exists only once the connector is made (the quarantine is set
// up before it), and the notification of the restorations without registry
// entry. It runs as soon as the connector is made, whatever follows: the setters
// survive a Reconfigure, and a restoration is then never served without them, even
// when the application fails later. A quarantine that does not take them (a mock)
// is left as it is.
func (h *Handler) bindQuarantine(workDir string) {
	if b, ok := h.Quarantiner.(restoreBindings); ok {
		b.SetWorkDir(workDir)
		b.SetUnregisteredRestoreHook(notifyUnregisteredRestore)
	}
}
