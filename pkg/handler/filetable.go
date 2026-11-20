package handler

import (
	"container/heap"
	"path/filepath"
	"sync"
	"time"

	"github.com/glimps-re/host-connector/pkg/scanner"
)

// Fixed costs added to the length of a path or of an owner name: what an entry
// or an owner takes in memory besides its string.
const (
	fileOverhead  = 320
	ownerOverhead = 256
)

type filePhase uint8

const (
	phaseWaiting   filePhase = iota // seen, waiting for its stability delay
	phaseSubmitted                  // handed to the pipeline
	phaseDone                       // processed; kept to not process it again
)

// trackedFile is one tracked file. It sits in at most one list of its owner and,
// while waiting, in the deadline heap.
type trackedFile struct {
	path       string
	owner      *ownerState
	phase      filePhase
	seen       time.Time
	deadline   time.Time // phaseWaiting
	retryAt    time.Time // phaseDone: zero means a final outcome
	attempts   uint8     // failures counted against the cap
	resource   uint8     // failures of a resource, not counted: they only lengthen the backoff
	reopens    uint8     // consecutive outcomes that found the file changed by someone else
	modified   bool      // an event showed a different identity while it was submitted
	stamp      scanner.FileIdentity
	missed     uint8 // consecutive rescans that could not read its folder
	prev, next *trackedFile
	list       *fileList
	rPrev      *trackedFile // global "seen" / "not seen yet" lists
	rNext      *trackedFile
	rSide      uint8 // which of the two rescan lists holds the file
	heapIdx    int   // position in the deadline heap, -1 if absent
}

func fileCost(path string) int64 { return int64(len(path)) + fileOverhead }

func ownerCost(name string) int64 { return int64(len(name)) + ownerOverhead }

func (f *trackedFile) cost() int64 { return fileCost(f.path) }

// fileList is a doubly linked list: removal anywhere is O(1).
type fileList struct {
	head, tail *trackedFile
	n          int
}

func (l *fileList) pushBack(f *trackedFile) {
	f.prev, f.next, f.list = l.tail, nil, l
	if l.tail != nil {
		l.tail.next = f
	} else {
		l.head = f
	}
	l.tail = f
	l.n++
}

func (l *fileList) remove(f *trackedFile) {
	if f.prev != nil {
		f.prev.next = f.next
	} else {
		l.head = f.next
	}
	if f.next != nil {
		f.next.prev = f.prev
	} else {
		l.tail = f.prev
	}
	f.prev, f.next, f.list = nil, nil, nil
	l.n--
}

// rescanList is a doubly linked list over the rPrev / rNext links. The table
// owns two of them; which one holds the files "seen" by the current rescan is
// told by fileTable.seenSide, so that starting a rescan swaps their roles in
// O(1).
type rescanList struct {
	head, tail *trackedFile
}

func (l *rescanList) pushBack(f *trackedFile, side uint8) {
	f.rPrev, f.rNext, f.rSide = l.tail, nil, side
	if l.tail != nil {
		l.tail.rNext = f
	} else {
		l.head = f
	}
	l.tail = f
}

func (l *rescanList) remove(f *trackedFile) {
	if f.rPrev != nil {
		f.rPrev.rNext = f.rNext
	} else {
		l.head = f.rNext
	}
	if f.rNext != nil {
		f.rNext.rPrev = f.rPrev
	} else {
		l.tail = f.rPrev
	}
	f.rPrev, f.rNext = nil, nil
}

// moveAll moves every file of l to the end of dst (O(n), used only when a
// rescan did not end or when the purge is skipped).
func (l *rescanList) moveAll(dst *rescanList, side uint8) {
	for l.head != nil {
		f := l.head
		l.remove(f)
		dst.pushBack(f, side)
	}
}

// ownerState groups the files that share the table fairly.
type ownerState struct {
	name      string
	bytes     int64 // cost of its entries
	doneBytes int64 // cost of its phaseDone entries
	submitted int   // entries handed to the pipeline: they keep the owner alive
	waiting   fileList
	doneRetry fileList
	doneFinal fileList
	heapIdx   int
}

func (o *ownerState) cost() int64 { return ownerCost(o.name) }

func (o *ownerState) entries() int {
	return o.waiting.n + o.doneRetry.n + o.doneFinal.n + o.submitted
}

// kind is what an owner holds that can be evicted.
type kind uint8

const (
	kindW kind = iota // at least one waiting entry
	kindR             // no waiting entry, at least one done entry to retry
	kindF             // neither, at least one final done entry
	kind0             // nothing evictable
)

func (o *ownerState) kind() kind {
	switch {
	case o.waiting.n > 0:
		return kindW
	case o.doneRetry.n > 0:
		return kindR
	case o.doneFinal.n > 0:
		return kindF
	default:
		return kind0
	}
}

// ownerHeap keeps the largest owner on top: O(1) read, O(log P) update.
type ownerHeap []*ownerState

func (h ownerHeap) Len() int           { return len(h) }
func (h ownerHeap) Less(i, j int) bool { return h[i].bytes > h[j].bytes }
func (h ownerHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].heapIdx, h[j].heapIdx = i, j
}

func (h *ownerHeap) Push(x any) {
	o, _ := x.(*ownerState)
	o.heapIdx = len(*h)
	*h = append(*h, o)
}

func (h *ownerHeap) Pop() any {
	old := *h
	n := len(old)
	o := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	o.heapIdx = -1
	return o
}

// deadlineHeap orders the waiting entries by deadline.
type deadlineHeap []*trackedFile

func (h deadlineHeap) Len() int           { return len(h) }
func (h deadlineHeap) Less(i, j int) bool { return h[i].deadline.Before(h[j].deadline) }
func (h deadlineHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].heapIdx, h[j].heapIdx = i, j
}

func (h *deadlineHeap) Push(x any) {
	f, _ := x.(*trackedFile)
	f.heapIdx = len(*h)
	*h = append(*h, f)
}

func (h *deadlineHeap) Pop() any {
	old := *h
	n := len(old)
	f := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	f.heapIdx = -1
	return f
}

// position is where the incoming owner stands against the largest one.
type position uint8

const (
	posIsLargest position = iota
	posSameSize
	posAboveQuota // smaller than the largest, above its quota
	posUnderQuota // smaller than the largest, under its quota
)

// action is what decide asks the table to do to make room.
type action uint8

const (
	actRefuse         action = iota
	actEvictLargestW         // newest waiting entry of the largest owner
	actEvictLargestR         // done entry to retry of the largest owner
	actEvictLargestF         // final done entry of the largest owner
	actEvictIncomingR        // done entry to retry of the incoming owner
	actEvictIncomingF        // final done entry of the incoming owner
)

// decide is the decision table of the monitoring table under pressure. e is
// the state of the incoming owner, g the state of the largest one.
//
// Two rules produce it: an owner yields in its own entries (R before F) only
// when it has no waiting entry; making the largest owner yield follows the
// order waiting, retry, final, and is impossible when it holds nothing
// evictable.
func decide(pos position, e, g kind) action {
	yieldLargest := func() action {
		switch g {
		case kindW:
			return actEvictLargestW
		case kindR:
			return actEvictLargestR
		case kindF:
			return actEvictLargestF
		default:
			return actRefuse
		}
	}
	yieldSelf := func() action {
		switch e {
		case kindR:
			return actEvictIncomingR
		case kindF:
			return actEvictIncomingF
		default:
			return actRefuse
		}
	}
	switch pos {
	case posIsLargest:
		return yieldSelf()
	case posSameSize:
		if e == kind0 {
			return yieldLargest()
		}
		return yieldSelf()
	case posAboveQuota:
		if e == kindR || e == kindF {
			return yieldSelf()
		}
		return yieldLargest()
	case posUnderQuota:
		if (e == kindR || e == kindF) && g == kind0 {
			return yieldSelf()
		}
		return yieldLargest()
	}
	return actRefuse
}

// ownerPressure counts what a rescan took from one owner.
type ownerPressure struct {
	Owner             string
	Share             int64 // bytes held when it was visited
	Waiting, Retry    int
	Final             int
	RefusedFiles      int
	DoneBytesOverHalf bool
}

// pressureReport is what a rescan reports about the table: nil owners and no
// refusal means no pressure.
type pressureReport struct {
	Refused int
	Owners  map[string]*ownerPressure
	// Others counts the files refused or evicted for owners beyond
	// maxPressureOwners: the report must not grow with the number of owners.
	Others int
}

// maxPressureOwners bounds the owners a pressure report names.
const maxPressureOwners = 32

// fileTable tracks the files of the monitored paths within a byte budget, shared
// fairly between owners under pressure. Every operation is O(1) or O(log n)
// under one short mutex, which is never held while calling out.
type fileTable struct {
	mu       sync.Mutex
	maxBytes int64
	quotaPct int
	rules    []scanner.OwnerRule
	watched  []string
	files    map[string]*trackedFile
	owners   map[string]*ownerState
	ownerH   ownerHeap
	deadH    deadlineHeap
	used     int64
	rescan   [2]rescanList
	seenSide uint8
	pressure pressureReport
}

func (t *fileTable) seenList() *rescanList   { return &t.rescan[t.seenSide] }
func (t *fileTable) unseenList() *rescanList { return &t.rescan[1-t.seenSide] }

// markSeen puts f in the "seen" list.
func (t *fileTable) markSeen(f *trackedFile) {
	f.missed = 0
	if f.rSide == t.seenSide {
		return
	}
	t.rescan[f.rSide].remove(f)
	t.seenList().pushBack(f, t.seenSide)
}

func newFileTable(maxBytes int64, quotaPercent int, rules []scanner.OwnerRule, watched []string) *fileTable {
	return &fileTable{
		maxBytes: maxBytes,
		quotaPct: quotaPercent,
		rules:    rules,
		watched:  cleanAll(watched),
		files:    make(map[string]*trackedFile),
		owners:   make(map[string]*ownerState),
		pressure: pressureReport{Owners: make(map[string]*ownerPressure)},
	}
}

// Used returns the counted memory.
func (t *fileTable) Used() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.used
}

// Len returns the number of tracked files.
func (t *fileTable) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.files)
}

// Owners returns the number of owners with at least one entry.
func (t *fileTable) Owners() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.owners)
}

// Get returns a copy of the state of path.
func (t *fileTable) Get(path string) (trackedFile, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	f, ok := t.files[path]
	if !ok {
		return trackedFile{}, false
	}
	c := *f
	c.owner, c.prev, c.next, c.list = nil, nil, nil, nil
	return c, true
}

// Track admits path, waiting for deadline. It returns false when the table has
// no room for it, after evicting what the decision table allows, and true when
// path is tracked after the call. A path that is already tracked is marked as
// seen; when its stamp changed and it still
// waits, its deadline is pushed back to the given one, which also moves it to
// the end of its owner's waiting list: the list stays in deadline order.
func (t *fileTable) Track(path string, stamp scanner.FileIdentity, seen, deadline time.Time) (admitted bool) {
	ownerName := scanner.OwnerOf(path, t.rules, t.watched)
	t.mu.Lock()
	defer t.mu.Unlock()
	if f, ok := t.files[path]; ok {
		t.markSeen(f)
		switch {
		case f.phase == phaseWaiting && !f.stamp.Equal(stamp):
			f.stamp, f.seen, f.deadline = stamp, seen, deadline
			f.list.remove(f)
			f.owner.waiting.pushBack(f)
			heap.Fix(&t.deadH, f.heapIdx)
		case f.phase == phaseSubmitted && !f.stamp.Equal(stamp):
			// A change received while it is processed: whatever the outcome
			// is, the entry is reopened when it comes.
			f.stamp, f.modified = stamp, true
		case f.phase == phaseDone && !f.stamp.Equal(stamp):
			t.reopen(f, stamp, seen, deadline, true)
		case f.phase == phaseDone && !f.retryAt.IsZero() && !seen.Before(f.retryAt):
			// Without a rescan, an event on a file is what brings back a failure
			// whose delay is over.
			t.reopen(f, f.stamp, seen, deadline, false)
		}
		return true
	}
	incomingCost := fileCost(path)
	for {
		owner := t.owners[ownerName]
		need := incomingCost
		if owner == nil {
			need += ownerCost(ownerName)
		}
		if t.used+need <= t.maxBytes {
			break
		}
		if need > t.maxBytes {
			t.refuse(ownerName)
			return false
		}
		if !t.makeRoom(owner, ownerName) {
			t.refuse(ownerName)
			return false
		}
	}
	owner := t.owners[ownerName]
	if owner == nil {
		owner = &ownerState{name: ownerName}
		t.owners[ownerName] = owner
		heap.Push(&t.ownerH, owner)
		t.used += owner.cost()
	}
	f := &trackedFile{path: path, owner: owner, phase: phaseWaiting, stamp: stamp, seen: seen, deadline: deadline, heapIdx: -1}
	t.files[path] = f
	owner.waiting.pushBack(f)
	owner.bytes += f.cost()
	t.used += f.cost()
	heap.Fix(&t.ownerH, owner.heapIdx)
	heap.Push(&t.deadH, f)
	t.seenList().pushBack(f, t.seenSide)
	return true
}

// touchResult tells what a rescan finding a path must do with it.
type touchResult uint8

const (
	// touchUnknown: the path is not tracked.
	touchUnknown touchResult = iota
	// touchSeen: tracked and waiting or submitted, nothing to do.
	touchSeen
	// touchDone: tracked and processed; its metadata must be compared to find
	// a change (a stat, never a read of the content).
	touchDone
	// touchReopened: a retry came due, the entry waits again.
	touchReopened
)

// Touch marks path as seen by the rescan. A processed file whose retry came due
// is reopened, keeping its count of attempts.
func (t *fileTable) Touch(path string, now time.Time) touchResult {
	t.mu.Lock()
	defer t.mu.Unlock()
	f, ok := t.files[path]
	if !ok {
		return touchUnknown
	}
	t.markSeen(f)
	if f.phase != phaseDone {
		return touchSeen
	}
	if !f.retryAt.IsZero() && !now.Before(f.retryAt) {
		t.reopen(f, f.stamp, now, now, false)
		return touchReopened
	}
	return touchDone
}

// reopen makes a submitted or processed entry wait again for deadline. A change
// of the file (resetCounters) also forgets its failures.
func (t *fileTable) reopen(f *trackedFile, stamp scanner.FileIdentity, seen, deadline time.Time, resetCounters bool) {
	switch f.phase {
	case phaseDone:
		f.owner.doneBytes -= f.cost()
		f.list.remove(f)
	case phaseSubmitted:
		f.owner.submitted--
	case phaseWaiting:
		return
	}
	f.phase = phaseWaiting
	f.stamp, f.seen, f.deadline, f.retryAt = stamp, seen, deadline, time.Time{}
	if resetCounters {
		f.attempts, f.resource = 0, 0
	}
	f.owner.waiting.pushBack(f)
	heap.Push(&t.deadH, f)
}

// Retry limits (documented in the README): the delay before the next attempt
// doubles with every failure, from the rescan period, up to retryCeiling, and
// the file is given up after maxAttempts failures.
const (
	maxAttempts  = 8
	retryCeiling = time.Hour
	maxBackoff   = 6 // the delay stops doubling after 2^6 periods
	// retryFloor is the delay of the first retry when there is no rescan period.
	retryFloor = time.Minute
)

// finishArgs is what the end of the processing of a submitted file says.
type finishArgs struct {
	// Retry and Resource: the outcome is a failure worth another attempt; a
	// resource failure is not counted against maxAttempts.
	Retry, Resource bool
	Now             time.Time
	Base            time.Duration // delay of the first retry, before doubling
	Jitter          float64       // a fraction, ±0.2
	Submitted       scanner.FileIdentity
	Current         scanner.FileIdentity // seen by a stat when the outcome came
	Deadline        time.Time            // stability deadline if the file changed
}

// Finish records the end of the processing of a submitted file. A final outcome
// is remembered until the file changes. A failure is retried after base × 2^n
// (n failures so far, at most maxBackoff, never more than retryCeiling),
// shifted by the jitter, unless it is the maxAttempts-th: then it becomes final
// and gaveUp is true.
//
// A file that changed under its processing, by someone else (the stat taken
// when the outcome came differs from the identity the outcome applies to, or an
// event showed a change meanwhile), waits for its stability again whatever the
// outcome says, the old failures forgotten: the outcome was about the old
// content. The first two such reopenings in a row are immediate; the next ones
// are pushed back by base × 2^(n-2), at most retryCeiling, so that a user who
// rewrites a file during every analysis is processed at most once an hour, and
// never abandoned. Finish with an outcome the monitor can trust (the pipeline
// reports its own trace on the file in Submitted) resets that count.
func (t *fileTable) Finish(path string, a finishArgs) (gaveUp, reopened bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	f, ok := t.files[path]
	if !ok || f.phase != phaseSubmitted {
		return false, false
	}
	if !a.Current.Equal(a.Submitted) || f.modified {
		stamp := f.stamp
		if !a.Current.Equal(a.Submitted) {
			stamp = a.Current
		}
		if f.reopens < 255 {
			f.reopens++
		}
		deadline := a.Deadline
		if f.reopens > 2 {
			base := min(a.Base, retryCeiling)
			later := a.Now.Add(min(base<<min(int(f.reopens)-2, 20), retryCeiling))
			if later.After(deadline) {
				deadline = later
			}
		}
		reopens := f.reopens
		t.reopen(f, stamp, a.Now, deadline, true)
		f.reopens, f.modified = reopens, false
		return false, true
	}
	f.reopens = 0
	if a.Current != (scanner.FileIdentity{}) {
		// The state the connector itself left the file in (its action touched
		// the change time) is the one a rescan must find unchanged.
		f.stamp = a.Current
	}
	if !a.Retry {
		t.complete(f, time.Time{})
		return false, false
	}
	if a.Resource {
		if f.resource < 255 {
			f.resource++
		}
	} else if f.attempts < 255 {
		f.attempts++
	}
	if f.attempts >= maxAttempts {
		t.complete(f, time.Time{})
		return true, false
	}
	base := min(a.Base, retryCeiling)
	delay := min(base<<min(int(f.attempts)+int(f.resource), maxBackoff), retryCeiling)
	t.complete(f, a.Now.Add(time.Duration(float64(delay)*(1+a.Jitter))))
	return false, false
}

// makeRoom applies one step of the decision table; it returns false for a
// refusal.
func (t *fileTable) makeRoom(incoming *ownerState, incomingName string) bool {
	if len(t.ownerH) == 0 {
		return false
	}
	g := t.ownerH[0]
	eKind, pos := kind0, posUnderQuota
	switch {
	case incoming == g:
		eKind, pos = incoming.kind(), posIsLargest
	case incoming != nil && incoming.bytes == g.bytes:
		eKind, pos = incoming.kind(), posSameSize
	case incoming != nil:
		eKind = incoming.kind()
		if incoming.bytes*100 > int64(t.quotaPct)*t.maxBytes {
			pos = posAboveQuota
		}
	}
	switch decide(pos, eKind, g.kind()) {
	case actEvictLargestW:
		return t.evict(g.waiting.tail, incomingName, g)
	case actEvictLargestR:
		return t.evict(g.doneRetry.head, incomingName, g)
	case actEvictLargestF:
		return t.evict(g.doneFinal.head, incomingName, g)
	case actEvictIncomingR:
		return t.evict(incoming.doneRetry.head, incomingName, incoming)
	case actEvictIncomingF:
		return t.evict(incoming.doneFinal.head, incomingName, incoming)
	default:
		return false
	}
}

// pressureOf returns the entry of the owner in the report, nil when the report
// already names maxPressureOwners other owners.
func (t *fileTable) pressureOf(name string) *ownerPressure {
	p := t.pressure.Owners[name]
	if p == nil {
		if len(t.pressure.Owners) >= maxPressureOwners {
			return nil
		}
		p = &ownerPressure{Owner: name}
		t.pressure.Owners[name] = p
	}
	return p
}

func (t *fileTable) refuse(ownerName string) {
	t.pressure.Refused++
	p := t.pressureOf(ownerName)
	if p == nil {
		t.pressure.Others++
		return
	}
	p.RefusedFiles++
}

// evict removes f for the sake of the owner named for, recording it when the
// victim is another owner. It returns false when there was nothing to evict,
// which a consistent table never does: the caller then refuses instead of
// looping.
func (t *fileTable) evict(f *trackedFile, forOwner string, victim *ownerState) bool {
	if f == nil {
		return false
	}
	if victim.name != forOwner {
		if p := t.pressureOf(victim.name); p == nil {
			t.pressure.Others++
		} else {
			p.Share = victim.bytes
			switch {
			case f.phase == phaseWaiting:
				p.Waiting++
			case !f.retryAt.IsZero():
				p.Retry++
			default:
				p.Final++
			}
		}
	}
	t.remove(f)
	return true
}

// remove forgets f and, when it was the last of its owner, the owner.
func (t *fileTable) remove(f *trackedFile) {
	if f.heapIdx >= 0 {
		heap.Remove(&t.deadH, f.heapIdx)
	}
	if f.list != nil {
		f.list.remove(f)
	}
	t.rescan[f.rSide].remove(f)
	delete(t.files, f.path)
	o := f.owner
	o.bytes -= f.cost()
	t.used -= f.cost()
	switch f.phase {
	case phaseSubmitted:
		o.submitted--
	case phaseDone:
		o.doneBytes -= f.cost()
	case phaseWaiting:
	}
	if o.entries() == 0 {
		heap.Remove(&t.ownerH, o.heapIdx)
		delete(t.owners, o.name)
		t.used -= o.cost()
		return
	}
	heap.Fix(&t.ownerH, o.heapIdx)
}

// Forget drops path, whatever its phase.
func (t *fileTable) Forget(path string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if f, ok := t.files[path]; ok {
		t.remove(f)
	}
}

// NextDeadline returns the earliest deadline of the waiting entries.
func (t *fileTable) NextDeadline() (time.Time, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.deadH) == 0 {
		return time.Time{}, false
	}
	return t.deadH[0].deadline, true
}

// PopDue marks as submitted the waiting entry whose deadline is the earliest
// and has passed, and returns its path and stamp.
func (t *fileTable) PopDue(now time.Time) (path string, stamp scanner.FileIdentity, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.deadH) == 0 || t.deadH[0].deadline.After(now) {
		return "", scanner.FileIdentity{}, false
	}
	f, _ := heap.Pop(&t.deadH).(*trackedFile)
	f.owner.waiting.remove(f)
	f.phase = phaseSubmitted
	f.owner.submitted++
	return f.path, f.stamp, true
}

// Done records the outcome of a submitted file: retryAt zero is a final
// outcome, otherwise the file is retried at retryAt. A path no longer tracked
// (evicted or purged meanwhile) is ignored.
func (t *fileTable) Done(path string, retryAt time.Time, attempts uint8) {
	t.mu.Lock()
	defer t.mu.Unlock()
	f, ok := t.files[path]
	if !ok || f.phase != phaseSubmitted {
		return
	}
	f.attempts = attempts
	t.complete(f, retryAt)
}

// complete records the outcome of a submitted entry: retryAt zero is final.
func (t *fileTable) complete(f *trackedFile, retryAt time.Time) {
	f.phase, f.retryAt = phaseDone, retryAt
	f.owner.submitted--
	f.owner.doneBytes += f.cost()
	if retryAt.IsZero() {
		f.owner.doneFinal.pushBack(f)
	} else {
		f.owner.doneRetry.pushBack(f)
	}
}

// BeginRescan opens a rescan: the files seen by the previous one become "not
// seen yet", in O(1) (the two lists swap roles). A rescan that never ended
// leaves files in the old "not seen" list: they join the new one.
func (t *fileTable) BeginRescan() {
	t.mu.Lock()
	defer t.mu.Unlock()
	leftover := t.unseenList()
	t.seenSide = 1 - t.seenSide
	if leftover.head != nil {
		leftover.moveAll(t.unseenList(), 1-t.seenSide)
	}
}

// Limits of the purge of a rescan that could not read some folders.
const (
	maxUnreadableDirs = 1024
	maxProtectedScans = 10
	purgeBatch        = 256
)

// EndRescan purges the files the rescan did not see: they are gone. It works
// on the "not seen yet" list only, 256 files at a time with the lock released
// between batches, so that Done, Track and Forget never wait long. Submitted
// entries are never purged. A file below a folder that could not be read is
// kept for at most maxProtectedScans consecutive rescans. When overflow is
// true the walk found more than maxUnreadableDirs such folders and could not
// list them all: every file is then protected, with the same limit of rescans.
func (t *fileTable) EndRescan(unreadable []string, overflow bool) {
	dirs := make(map[string]struct{}, len(unreadable))
	for _, d := range unreadable {
		dirs[filepath.Clean(d)] = struct{}{}
	}
	for t.purgeBatch(dirs, overflow) {
	}
}

// purgeBatch handles up to purgeBatch files; it reports whether some remain.
func (t *fileTable) purgeBatch(dirs map[string]struct{}, protectAll bool) (more bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	unseen := t.unseenList()
	for range purgeBatch {
		f := unseen.head
		if f == nil {
			return false
		}
		switch {
		case f.phase == phaseSubmitted:
			t.markSeen(f)
		case f.missed < maxProtectedScans && (protectAll || underAnyDir(dirs, f.path)):
			missed := f.missed + 1
			t.markSeen(f)
			f.missed = missed
		default:
			t.remove(f)
		}
	}
	return unseen.head != nil
}

// underAnyDir reports whether path lies below a folder of dirs, walking up its
// parents: O(depth), whatever the number of folders.
func underAnyDir(dirs map[string]struct{}, path string) bool {
	if len(dirs) == 0 {
		return false
	}
	for dir := filepath.Dir(path); ; {
		if _, ok := dirs[dir]; ok {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}

// HasPressure tells whether a refusal or an eviction is waiting to be reported.
func (t *fileTable) HasPressure() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.pressure.Refused > 0 || len(t.pressure.Owners) > 0 || t.pressure.Others > 0
}

// TakePressure returns and resets what the table took from the owners.
func (t *fileTable) TakePressure() pressureReport {
	t.mu.Lock()
	defer t.mu.Unlock()
	r := t.pressure
	for _, p := range r.Owners {
		if o := t.owners[p.Owner]; o != nil {
			p.Share = o.bytes
			p.DoneBytesOverHalf = p.RefusedFiles > 0 && o.doneBytes*2 > t.maxBytes
		}
	}
	t.pressure = pressureReport{Owners: make(map[string]*ownerPressure)}
	return r
}

func cleanAll(paths []string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = filepath.Clean(p)
	}
	return out
}
