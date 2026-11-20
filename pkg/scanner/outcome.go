package scanner

import (
	"context"
	"errors"
	"sync"
	"syscall"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

// OutcomeKind says what the end of a file's processing means for what follows.
type OutcomeKind uint8

const (
	// OutcomeRetry is a transient failure: it is retried after a backoff, at
	// most a few times. It is the zero value, on purpose: a path that forgets to
	// say anything falls back on the capped case, never on "final".
	OutcomeRetry OutcomeKind = iota
	// OutcomeResource is a failure of the machine, not of the file (a slow or
	// full storage, an extractor that is down): retried with the same backoff,
	// without a cap.
	OutcomeResource
	// OutcomeFinal means the file is not processed again until it changes.
	OutcomeFinal
)

// FileOutcome reports the end of the processing of one accepted file.
type FileOutcome struct {
	// Location is the path the file was submitted with.
	Location string
	// Identity is the identity the file was submitted with.
	Identity FileIdentity
	// Kind says whether the file is to be processed again.
	Kind OutcomeKind
}

// ongoing is what the connector remembers of a file between its acceptance and
// its end. The outcome is a retry unless the processing says otherwise.
type ongoing struct {
	want FileIdentity

	mu      sync.Mutex
	input   *inputFD
	kind    OutcomeKind
	started bool   // onStartScanFile was called for this file
	scanned bool   // onFileScanned was called for it
	sha     string // given to onStartScanFile
}

func (o *ongoing) setInput(in *inputFD) {
	o.mu.Lock()
	o.input = in
	o.mu.Unlock()
}

// closeInput releases the descriptor, if any. Closing is idempotent.
func (o *ongoing) closeInput() {
	o.mu.Lock()
	in := o.input
	o.mu.Unlock()
	closeInput(in)
}

func (o *ongoing) outcome(location string) FileOutcome {
	o.mu.Lock()
	defer o.mu.Unlock()
	return FileOutcome{Location: location, Identity: o.want, Kind: o.kind}
}

// entry returns what is remembered of the ongoing file at location.
func (c *Connector) entry(location string) *ongoing {
	v, ok := c.ongoingAnalysis.Load(location)
	if !ok {
		return nil
	}
	o, _ := v.(*ongoing)
	return o
}

// runOf is the run an operation belongs to: the one it carries, which is the
// generation that was accepted, never whatever is now registered under the same
// path (the monitor may have submitted the file again meanwhile). Only code
// that has no run (tests) falls back on the path.
func (c *Connector) runOf(location string, run *ongoing) *ongoing {
	if run != nil {
		return run
	}
	return c.entry(location)
}

// setFinal marks the outcome of the run as final: it is never retried.
func (c *Connector) setFinal(location string, run *ongoing) {
	if o := c.runOf(location, run); o != nil {
		o.mu.Lock()
		o.kind = OutcomeFinal
		o.mu.Unlock()
	}
}

// setResource marks the outcome of the run as the failure of a resource.
func (c *Connector) setResource(location string, run *ongoing) {
	if o := c.runOf(location, run); o != nil {
		o.mu.Lock()
		if o.kind != OutcomeFinal {
			o.kind = OutcomeResource
		}
		o.mu.Unlock()
	}
}

// concludeOutcome decides, once the action ran, whether the file is done for
// good or worth another attempt. When in doubt it is retried (the monitor caps
// the attempts).
func (c *Connector) concludeOutcome(location string, run *ongoing, result resultView, actionErr error) {
	switch {
	case actionErr != nil:
		switch {
		case IsPermanentAction(actionErr):
			c.setFinal(location, run)
		case isResourceAction(actionErr):
			c.setResource(location, run)
		}
	case result.analysisError != "":
		c.setFinal(location, run)
	case result.err == nil:
		c.setFinal(location, run)
	case errors.Is(result.err, errFileTooBig), errors.Is(result.err, errInconsistentPluginResult), errors.Is(result.err, errInnerPermanent):
		c.setFinal(location, run)
	case errors.Is(result.err, plugins.ErrExtractorUnavailable):
		c.setResource(location, run)
	}
}

// resultView is what concludeOutcome needs from a result.
type resultView struct {
	err           error
	analysisError string
}

// isResourceAction reports a failure of the machine, not of the file, in an
// action: it timed out or the disk is full. A timeout of the analysis is not
// one: a huge file would be retried for ever.
func isResourceAction(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, syscall.ENOSPC)
}

// errAbandoned is the Error given to the plugins of a file that was started and
// never reached the end of its processing.
var errAbandoned = errors.New("processing abandoned before its end")

// startScan tells the plugins that the file at location starts being processed,
// and remembers it: every start is followed by exactly one onFileScanned.
func (c *Connector) startScan(location string, run *ongoing, sha256 string) {
	if o := c.runOf(location, run); o != nil {
		o.mu.Lock()
		o.started, o.sha = true, sha256
		o.mu.Unlock()
	}
	c.onStartScanFile(location, sha256)
}

// fileScanned tells the plugins that the file at location is done, and
// remembers it so that finishAnalysis does not do it again.
func (c *Connector) fileScanned(location string, run *ongoing, sha256 string, result datamodel.Result) *datamodel.Result {
	if o := c.runOf(location, run); o != nil {
		o.mu.Lock()
		if o.started && o.scanned {
			// Already told, by the end of the run or by an earlier call: the
			// plugins get one onFileScanned per onStartScanFile.
			o.mu.Unlock()
			return nil
		}
		o.scanned = true
		o.mu.Unlock()
	}
	return c.onFileScanned(location, sha256, result)
}

// unpaired reports, once, that the file was started and never scanned.
func (o *ongoing) unpaired() (sha256 string, ok bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.started || o.scanned {
		return "", false
	}
	o.scanned = true
	return o.sha, true
}

// noteOwnTrace is called when an action failed after it may have touched the
// source (a link then an unlink moves the change time). If only the change time
// differs from the identity the file was submitted with, that is the state the
// connector itself left the file in: the outcome applies to it, and the monitor
// will not take it for a change made by someone else.
func (c *Connector) noteOwnTrace(location string, run *ongoing, submitted FileIdentity) {
	o := c.runOf(location, run)
	if o == nil {
		return
	}
	info, err := c.statInput(location)
	if err != nil {
		return
	}
	cur := IdentityOf(info)
	if cur.Equal(submitted) || cur.Dev != submitted.Dev || cur.Ino != submitted.Ino || cur.Size != submitted.Size || !cur.ModTime.Equal(submitted.ModTime) {
		return
	}
	o.mu.Lock()
	o.want = cur
	o.mu.Unlock()
}
