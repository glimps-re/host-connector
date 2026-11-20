package handler

import (
	"fmt"
	"math"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/scanner"
)

// The decision table of the plan, one row per (position, incoming state).
// Columns: the state of the largest owner W, R, F, 0.
func TestDecide(t *testing.T) {
	const (
		R  = actRefuse
		GW = actEvictLargestW
		GR = actEvictLargestR
		GF = actEvictLargestF
		ER = actEvictIncomingR
		EF = actEvictIncomingF
		na = actRefuse // impossible cell: never reached, refusing is the safe answer
	)
	type row struct {
		pos  position
		e    kind
		want [4]action // largest = W, R, F, 0
	}
	rows := []row{
		{posIsLargest, kindW, [4]action{R, na, na, na}},
		{posIsLargest, kindR, [4]action{na, ER, na, na}},
		{posIsLargest, kindF, [4]action{na, na, EF, na}},
		{posIsLargest, kind0, [4]action{na, na, na, R}},

		{posSameSize, kindW, [4]action{R, R, R, R}},
		{posSameSize, kindR, [4]action{ER, ER, ER, ER}},
		{posSameSize, kindF, [4]action{EF, EF, EF, EF}},
		{posSameSize, kind0, [4]action{GW, GR, GF, R}},

		{posAboveQuota, kindW, [4]action{GW, GR, GF, R}},
		{posAboveQuota, kindR, [4]action{ER, ER, ER, ER}},
		{posAboveQuota, kindF, [4]action{EF, EF, EF, EF}},
		{posAboveQuota, kind0, [4]action{GW, GR, GF, R}},

		{posUnderQuota, kindW, [4]action{GW, GR, GF, R}},
		{posUnderQuota, kindR, [4]action{GW, GR, GF, ER}},
		{posUnderQuota, kindF, [4]action{GW, GR, GF, EF}},
		{posUnderQuota, kind0, [4]action{GW, GR, GF, R}},
	}
	gKinds := [4]kind{kindW, kindR, kindF, kind0}
	cells := 0
	for _, r := range rows {
		for i, g := range gKinds {
			if r.pos == posIsLargest && kind(i) != r.e {
				continue // the incoming owner is the largest: one state
			}
			cells++
			if got := decide(r.pos, r.e, g); got != r.want[i] {
				t.Errorf("decide(pos %d, e %d, g %d) = %d, want %d", r.pos, r.e, g, got, r.want[i])
			}
		}
	}
	if cells != 52 {
		t.Errorf("checked %d cells, want 52", cells)
	}
}

func newTestTable(limit int64, quota int) *fileTable {
	return newFileTable(limit, quota, nil, []string{"/in"})
}

func tp(owner string, n int) string { return fmt.Sprintf("/in/%s/f%04d", owner, n) }

func TestFileTable_adminAndCounting(t *testing.T) {
	now := time.Unix(1000, 0)
	tab := newTestTable(1<<20, 25)
	if !tab.Track(tp("a", 1), scanner.FileIdentity{}, now, now.Add(time.Second)) || !tab.Track(tp("b", 1), scanner.FileIdentity{}, now, now.Add(2*time.Second)) {
		t.Fatal("room available: must be admitted")
	}
	if tab.Len() != 2 || tab.Owners() != 2 {
		t.Errorf("len = %d, owners = %d", tab.Len(), tab.Owners())
	}
	want := int64(len(tp("a", 1))+len(tp("b", 1))) + 2*fileOverhead + int64(len("/in/a")+len("/in/b")) + 2*ownerOverhead
	if tab.Used() != want {
		t.Errorf("used = %d, want %d", tab.Used(), want)
	}
	if d, ok := tab.NextDeadline(); !ok || !d.Equal(now.Add(time.Second)) {
		t.Errorf("NextDeadline() = %v, %t", d, ok)
	}
	if _, _, ok := tab.PopDue(now); ok {
		t.Error("nothing is due yet")
	}
	path, _, ok := tab.PopDue(now.Add(time.Second))
	if !ok || path != tp("a", 1) {
		t.Fatalf("PopDue() = %q, %t", path, ok)
	}
	tab.Done(path, time.Time{}, 1)
	tab.Forget(tp("a", 1))
	if tab.Owners() != 1 {
		t.Errorf("an owner without entry must disappear: owners = %d", tab.Owners())
	}
	tab.Forget(tp("b", 1))
	if tab.Used() != 0 || tab.Len() != 0 || tab.Owners() != 0 {
		t.Errorf("table not empty: used %d len %d owners %d", tab.Used(), tab.Len(), tab.Owners())
	}
}

func TestFileTable_singleOwnerFillsTheTableWithoutRefusal(t *testing.T) {
	now := time.Unix(1000, 0)
	entry := int64(len(tp("solo", 0))) + fileOverhead
	limit := int64(len("/in/solo")) + ownerOverhead + 50*entry
	tab := newTestTable(limit, 25)
	for i := range 50 {
		if !tab.Track(tp("solo", i), scanner.FileIdentity{}, now, now.Add(time.Second)) {
			t.Fatalf("file %d refused while the table has room: the quota applies under pressure only", i)
		}
	}
	if tab.Used() > limit {
		t.Fatalf("used %d > %d", tab.Used(), limit)
	}
	if tab.Track(tp("solo", 50), scanner.FileIdentity{}, now, now.Add(time.Second)) {
		t.Error("a single owner holding only waiting entries is refused when the table is full")
	}
	if tab.Used() > limit {
		t.Errorf("used %d > %d", tab.Used(), limit)
	}
}

func TestFileTable_fairSharingUnderPressure(t *testing.T) {
	now := time.Unix(1000, 0)
	entry := int64(len(tp("aaa", 0))) + fileOverhead
	own := int64(len("/in/aaa")) + ownerOverhead
	limit := 2*own + 40*entry
	tab := newTestTable(limit, 25)
	for i := 0; tab.Track(tp("aaa", i), scanner.FileIdentity{}, now, now.Add(time.Hour)); i++ {
		if i > 1000 {
			t.Fatal("the table never fills")
		}
	}
	// aaa filled the table; a new owner is admitted by evicting aaa's newest waiting entry.
	if !tab.Track(tp("bob", 1), scanner.FileIdentity{}, now, now.Add(time.Hour)) {
		t.Fatal("bob must be admitted: aaa yields")
	}
	if tab.Owners() != 2 {
		t.Errorf("owners = %d, want 2", tab.Owners())
	}
	// aaa's own new files are refused.
	if tab.Track(tp("aaa", 5000), scanner.FileIdentity{}, now, now.Add(time.Hour)) {
		t.Error("aaa must be refused: it is the largest and has waiting entries")
	}
	rep := tab.TakePressure()
	p := rep.Owners["/in/aaa"]
	if p == nil || p.Waiting == 0 || rep.Refused == 0 {
		t.Errorf("pressure = %+v (refused %d), want aaa named with evicted waiting entries", p, rep.Refused)
	}
	if again := tab.TakePressure(); again.Refused != 0 || len(again.Owners) != 0 {
		t.Errorf("pressure must reset: %+v", again)
	}
}

func TestFileTable_neverEvictsSubmitted(t *testing.T) {
	now := time.Unix(1000, 0)
	entry := int64(len(tp("aaa", 0))) + fileOverhead
	own := int64(len("/in/aaa")) + ownerOverhead
	tab := newTestTable(2*own+10*entry, 25)
	for i := 0; tab.Track(tp("aaa", i), scanner.FileIdentity{}, now, now); i++ {
		if i > 1000 {
			t.Fatal("never full")
		}
	}
	for {
		p, _, ok := tab.PopDue(now)
		if !ok {
			break
		}
		_ = p
	}
	if tab.Track(tp("bob", 1), scanner.FileIdentity{}, now, now) {
		t.Error("the largest owner holds only submitted entries: the incoming file is refused")
	}
	if tab.Len() == 0 {
		t.Error("submitted entries were evicted")
	}
}

func TestFileTable_evictedWaitingEntryLeavesTheDeadlineHeap(t *testing.T) {
	now := time.Unix(1000, 0)
	entry := int64(len(tp("aaa", 0))) + fileOverhead
	own := int64(len("/in/aaa")) + ownerOverhead
	tab := newTestTable(2*own+10*entry, 25)
	for i := 0; tab.Track(tp("aaa", i), scanner.FileIdentity{}, now, now.Add(time.Duration(i)*time.Second)); i++ {
		if i > 1000 {
			t.Fatal("never full")
		}
	}
	count := tab.Len()
	newest := tp("aaa", count-1)
	if !tab.Track(tp("bob", 1), scanner.FileIdentity{}, now, now.Add(time.Hour)) {
		t.Fatal("bob must be admitted")
	}
	if _, ok := tab.Get(newest); ok {
		t.Fatalf("the newest waiting entry of aaa must be the one evicted")
	}
	for {
		p, _, ok := tab.PopDue(now.Add(24 * time.Hour))
		if !ok {
			break
		}
		if p == newest {
			t.Fatal("a submission would leave for an evicted entry")
		}
	}
}

func TestFileTable_doneEntriesGoBeforeNothingElseAndRetryBeforeFinal(t *testing.T) {
	now := time.Unix(1000, 0)
	entry := int64(len(tp("aaa", 0))) + fileOverhead
	own := int64(len("/in/aaa")) + ownerOverhead
	tab := newTestTable(2*own+8*entry, 25)
	for i := 0; tab.Track(tp("aaa", i), scanner.FileIdentity{}, now, now); i++ {
		if i > 1000 {
			t.Fatal("never full")
		}
	}
	n := 0
	for {
		p, _, ok := tab.PopDue(now)
		if !ok {
			break
		}
		if n%2 == 0 {
			tab.Done(p, time.Time{}, 1) // final
		} else {
			tab.Done(p, now.Add(time.Hour), 1) // retry
		}
		n++
	}
	if !tab.Track(tp("bob", 1), scanner.FileIdentity{}, now, now) {
		t.Fatal("bob must be admitted: aaa holds only done entries")
	}
	rep := tab.TakePressure()
	p := rep.Owners["/in/aaa"]
	if p == nil || p.Retry == 0 || p.Final != 0 {
		t.Errorf("pressure on aaa = %+v, want a retry entry evicted before any final one", p)
	}
}

func TestFileTable_rescanPurge(t *testing.T) {
	now := time.Unix(1000, 0)
	tab := newTestTable(1<<20, 25)
	tab.BeginRescan()
	tab.Track("/in/a/seen", scanner.FileIdentity{}, now, now)
	tab.Track("/in/a/gone", scanner.FileIdentity{}, now, now)
	tab.Track("/in/b/unreadable/x", scanner.FileIdentity{}, now, now)
	tab.Track("/in/c/submitted", scanner.FileIdentity{}, now, now)
	tab.PopDue(now) // submits the earliest due entry, whichever
	tab.EndRescan(nil, false)

	tab.BeginRescan()
	tab.Track("/in/a/seen", scanner.FileIdentity{}, now, now.Add(time.Hour))
	tab.EndRescan([]string{"/in/b/unreadable"}, false)
	if _, ok := tab.Get("/in/a/gone"); ok {
		t.Error("a file that is gone must be purged")
	}
	if _, ok := tab.Get("/in/b/unreadable/x"); !ok {
		t.Error("an entry under an unreadable folder must be kept")
	}
	// Protected for 10 consecutive rescans, then purged.
	for range maxProtectedScans + 1 {
		tab.BeginRescan()
		tab.Track("/in/a/seen", scanner.FileIdentity{}, now, now.Add(time.Hour))
		tab.EndRescan([]string{"/in/b/unreadable"}, false)
	}
	if _, ok := tab.Get("/in/b/unreadable/x"); ok {
		t.Error("an entry under a permanently unreadable folder must be purged after 10 rescans")
	}
}

func TestFileTable_tooManyUnreadableDirsProtectEverythingForAWhile(t *testing.T) {
	now := time.Unix(1000, 0)
	tab := newTestTable(1<<20, 25)
	tab.BeginRescan()
	tab.Track("/in/a/f", scanner.FileIdentity{}, now, now.Add(time.Hour))
	tab.EndRescan(nil, false)
	for i := range maxProtectedScans {
		tab.BeginRescan()
		tab.EndRescan(nil, true)
		if _, ok := tab.Get("/in/a/f"); !ok {
			t.Fatalf("rescan %d: every entry must be kept when too many folders failed", i+1)
		}
	}
	tab.BeginRescan()
	tab.EndRescan(nil, true)
	if _, ok := tab.Get("/in/a/f"); ok {
		t.Error("the protection of an overflowing rescan must stop after maxProtectedScans rescans")
	}
}

// TestFileTableProperties drives random sequences and checks the invariants of
// the decision table after every step.
func TestFileTableProperties(t *testing.T) {
	seed := uint64(time.Now().UnixNano())
	if testing.Short() {
		seed = 1
	}
	t.Logf("seed %d", seed)
	rng := &prng{state: seed}
	for round := range 40 {
		runPropertyRound(t, rng)
		if t.Failed() {
			t.Fatalf("failed in round %d (seed %d)", round, seed)
		}
	}
}

func runPropertyRound(t *testing.T, rng *prng) {
	t.Helper()
	nOwners := 2 + rng.IntN(49)
	now := time.Unix(1000, 0)
	maxBytes := int64(4000 + rng.IntN(60000))
	tab := newTestTable(maxBytes, 1+rng.IntN(60))
	var live []string
	for step := range 400 {
		switch op := rng.IntN(10); {
		case op < 6:
			owner := fmt.Sprintf("o%02d", rng.IntN(nOwners))
			path := "/in/" + owner + "/" + strings.Repeat("x", 10+rng.IntN(300)) + strconv.Itoa(step)
			before := snapshot(tab)
			var added int64
			if tab.Track(path, scanner.FileIdentity{}, now, now.Add(time.Duration(rng.IntN(100))*time.Second)) {
				added = fileCost(path)
			}
			checkEvictions(t, before, tab, "/in/"+owner, added)
			live = append(live, path)
		case op < 8:
			if p, _, ok := tab.PopDue(now.Add(time.Duration(rng.IntN(120)) * time.Second)); ok {
				if rng.IntN(2) == 0 {
					tab.Done(p, time.Time{}, 1)
				} else {
					tab.Done(p, now.Add(time.Hour), 1)
				}
			}
		case op < 9 && len(live) > 0:
			tab.Forget(live[rng.IntN(len(live))])
		default:
			tab.BeginRescan()
			tab.EndRescan(nil, false)
		}
		if used := tab.Used(); used > maxBytes {
			t.Fatalf("used %d exceeds the bound %d", used, maxBytes)
		}
		checkConsistency(t, tab)
	}
}

type ownerSnap struct {
	bytes        int64
	waiting      map[string]bool
	done         int
	newestWaiter string
}

func snapshot(t *fileTable) map[string]ownerSnap {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := map[string]ownerSnap{}
	for name, o := range t.owners {
		s := ownerSnap{bytes: o.bytes, waiting: map[string]bool{}, done: o.doneRetry.n + o.doneFinal.n}
		for f := o.waiting.head; f != nil; f = f.next {
			s.waiting[f.path] = true
			s.newestWaiter = f.path
		}
		out[name] = s
	}
	return out
}

func checkEvictions(t *testing.T, before map[string]ownerSnap, tab *fileTable, incoming string, added int64) {
	t.Helper()
	after := snapshot(tab)
	// The incoming owner only shrinks while it makes room, then grows by the
	// entry it adds: what it holds at the end without that entry is a lower
	// bound of what it held whenever it took from another owner.
	var incomingBytes int64
	if _, ok := before[incoming]; ok {
		incomingBytes = after[incoming].bytes - added
	}
	for name, b := range before {
		a, still := after[name]
		evictedWaiting := 0
		for p := range b.waiting {
			if !a.waiting[p] {
				evictedWaiting++
			}
		}
		doneLost := b.done - a.done
		if !still {
			doneLost = b.done
		}
		if (evictedWaiting > 0 || doneLost > 0) && name != incoming && b.bytes < incomingBytes {
			t.Fatalf("owner %s (%d bytes) lost entries for a larger incoming owner (%d bytes)", name, b.bytes, incomingBytes)
		}
		if doneLost > 0 && len(b.waiting) > 0 && evictedWaiting == 0 {
			t.Fatalf("a done entry of %s was evicted while it had waiting entries", name)
		}
		if evictedWaiting > 1 {
			continue
		}
		if evictedWaiting == 1 && name != incoming && b.newestWaiter != "" {
			if a.waiting[b.newestWaiter] {
				t.Fatalf("owner %s lost a waiting entry that was not its newest", name)
			}
		}
	}
}

func checkConsistency(t *testing.T, tab *fileTable) {
	t.Helper()
	tab.mu.Lock()
	defer tab.mu.Unlock()
	var used int64
	n := 0
	for _, o := range tab.owners {
		var b int64
		for _, l := range []*fileList{&o.waiting, &o.doneRetry, &o.doneFinal} {
			c := 0
			for f := l.head; f != nil; f = f.next {
				b += f.cost()
				c++
				if f.owner != o {
					t.Fatalf("entry %s in the wrong owner", f.path)
				}
			}
			if c != l.n {
				t.Fatalf("list count %d != %d", c, l.n)
			}
			n += c
		}
		if o.entries() == 0 {
			t.Fatalf("owner %s without entry is still counted", o.name)
		}
		submittedBytes := int64(0)
		for _, f := range tab.files {
			if f.owner == o && f.phase == phaseSubmitted {
				submittedBytes += f.cost()
			}
		}
		if b+submittedBytes != o.bytes {
			t.Fatalf("owner bytes %d != listed %d + submitted %d", o.bytes, b, submittedBytes)
		}
		used += o.cost() + o.bytes
	}
	// submitted entries are in no list but count in the map.
	submitted := 0
	for _, f := range tab.files {
		if f.phase == phaseSubmitted {
			submitted++
		}
	}
	if len(tab.files) != n+submitted {
		t.Fatalf("files %d != listed %d + submitted %d", len(tab.files), n, submitted)
	}
	if used != tab.used {
		t.Fatalf("counted %d != used %d", used, tab.used)
	}
	listed := 0
	for side := range tab.rescan {
		for f := tab.rescan[side].head; f != nil; f = f.rNext {
			listed++
			if f.rSide != uint8(side) {
				t.Fatalf("entry %s says side %d but sits in list %d", f.path, f.rSide, side)
			}
		}
	}
	if listed != len(tab.files) {
		t.Fatalf("rescan lists hold %d entries for %d files", listed, len(tab.files))
	}
	for _, o := range tab.owners {
		sub, done := 0, int64(0)
		for _, f := range tab.files {
			switch {
			case f.owner == o && f.phase == phaseSubmitted:
				sub++
			case f.owner == o && f.phase == phaseDone:
				done += f.cost()
			}
		}
		if sub != o.submitted || done != o.doneBytes {
			t.Fatalf("owner %s: submitted %d/%d, done bytes %d/%d", o.name, o.submitted, sub, o.doneBytes, done)
		}
	}
	if len(tab.ownerH) != len(tab.owners) {
		t.Fatalf("owner heap %d != owners %d", len(tab.ownerH), len(tab.owners))
	}
	if len(tab.ownerH) > 0 {
		for _, o := range tab.owners {
			if o.bytes > tab.ownerH[0].bytes {
				t.Fatalf("heap top %d is not the largest (%d)", tab.ownerH[0].bytes, o.bytes)
			}
		}
	}
}

func TestOwnerOf(t *testing.T) {
	rules := []scanner.OwnerRule{{Root: "/in", Depth: 2}}
	watched := []string{"/in", "/data/other"}
	tests := []struct{ path, want string }{
		{"/in/eq1/alice/f", "/in/eq1/alice"},
		{"/in/eq1/alice/deep/f", "/in/eq1/alice"},
		{"/in/eq1/f", "/in/eq1"},
		{"/in/f", "/in"},
		{"/data/other/u/f", "/data/other/u"},
		{"/data/other/f", "/data/other"},
	}
	for _, tt := range tests {
		if got := scanner.OwnerOf(tt.path, rules, watched); got != tt.want {
			t.Errorf("OwnerOf(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
	if got := scanner.OwnerOf("/in/alice/f", nil, []string{"/in"}); got != "/in/alice" {
		t.Errorf("without declaration: %q", got)
	}
	if got := scanner.OwnerOf(filepath.Join("/in-other", "f"), []scanner.OwnerRule{{Root: "/in", Depth: 1}}, []string{"/in"}); got == "/in" {
		t.Errorf("/in-other must not be taken for a path under /in: %q", got)
	}
}

func TestDeclareOwners(t *testing.T) {
	rules, err := scanner.DeclareOwners(nil, "/in", 2)
	if err != nil || len(rules) != 1 {
		t.Fatalf("first declaration: %v, %v", rules, err)
	}
	for name, tt := range map[string]struct {
		root  string
		depth int
	}{
		"same root":           {"/in", 1},
		"root inside a root":  {"/in/sub", 1},
		"root contains root":  {"/", 1},
		"relative root":       {"in", 1},
		"depth zero":          {"/other", 0},
		"negative depth":      {"/other", -1},
		"cleaned equal root":  {"/in/", 3},
		"dot segment overlap": {"/in/./sub", 1},
	} {
		if _, err := scanner.DeclareOwners(rules, tt.root, tt.depth); err == nil {
			t.Errorf("%s: declaration accepted", name)
		}
	}
	if _, err := scanner.DeclareOwners(rules, "/other", 1); err != nil {
		t.Errorf("a disjoint root must be accepted: %v", err)
	}
}

// prng is a splitmix64 generator: reproducible from the logged seed.
type prng struct{ state uint64 }

func (r *prng) next() uint64 {
	r.state += 0x9e3779b97f4a7c15
	z := r.state
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

func (r *prng) IntN(n int) int {
	if n <= 0 {
		return 0
	}
	v := r.next() % uint64(n)
	if v > math.MaxInt32 {
		return 0
	}
	return int(v)
}

// The owner of an entry in the pipeline stays alive: removing the other entries
// must not detach it (it made Done panic).
func TestFileTable_ownerSurvivesWhileSubmittedEntriesRemain(t *testing.T) {
	now := time.Unix(1000, 0)
	tab := newTestTable(1<<20, 25)
	tab.Track(tp("u", 1), scanner.FileIdentity{}, now, now)
	tab.Track(tp("u", 2), scanner.FileIdentity{}, now, now.Add(time.Hour))
	first, _, ok := tab.PopDue(now)
	if !ok {
		t.Fatal("nothing due")
	}
	tab.Forget(tp("u", 2))
	if tab.Owners() != 1 {
		t.Fatalf("owners = %d, want the owner kept for its submitted entry", tab.Owners())
	}
	tab.Done(first, time.Time{}, 1)
	tab.Forget(first)
	if tab.Owners() != 0 || tab.Used() != 0 {
		t.Errorf("owners = %d, used = %d, want an empty table", tab.Owners(), tab.Used())
	}
	checkConsistency(t, tab)
}

func TestFileTable_changedStampPushesTheDeadlineBackInOrder(t *testing.T) {
	now := time.Unix(1000, 0)
	tab := newTestTable(1<<20, 25)
	a, b := tp("u", 1), tp("u", 2)
	tab.Track(a, scanner.FileIdentity{Size: 1}, now, now.Add(time.Second))
	tab.Track(b, scanner.FileIdentity{Size: 1}, now, now.Add(2*time.Second))
	tab.Track(a, scanner.FileIdentity{Size: 2}, now, now.Add(10*time.Second)) // a changed
	if p, _, ok := tab.PopDue(now.Add(3 * time.Second)); !ok || p != b {
		t.Errorf("PopDue() = %q, %t; want b first: a was pushed back", p, ok)
	}
	if _, _, ok := tab.PopDue(now.Add(3 * time.Second)); ok {
		t.Error("a must not be due yet")
	}
	if d, _ := tab.NextDeadline(); !d.Equal(now.Add(10 * time.Second)) {
		t.Errorf("NextDeadline() = %v, want a's pushed back deadline", d)
	}
	checkConsistency(t, tab)
}

func TestFileTable_doneBytesOverHalfIsReported(t *testing.T) {
	now := time.Unix(1000, 0)
	entry := int64(len(tp("solo", 0))) + fileOverhead
	own := int64(len("/in/solo")) + ownerOverhead
	tab := newTestTable(own+20*entry, 25)
	for i := 0; tab.Track(tp("solo", i), scanner.FileIdentity{}, now, now); i++ {
		if i > 100 {
			t.Fatal("never full")
		}
	}
	for {
		p, _, ok := tab.PopDue(now)
		if !ok {
			break
		}
		tab.Done(p, time.Time{}, 1)
	}
	tab.TakePressure()
	if tab.Track(tp("solo", 500), scanner.FileIdentity{}, now, now) && tab.Track(tp("solo", 501), scanner.FileIdentity{}, now, now) && tab.Track(tp("solo", 502), scanner.FileIdentity{}, now, now) {
		t.Fatal("a table full of final entries admits one file per eviction, not many")
	}
	rep := tab.TakePressure()
	p := rep.Owners["/in/solo"]
	if p == nil || !p.DoneBytesOverHalf || p.RefusedFiles == 0 {
		t.Errorf("pressure = %+v, want refusals and DoneBytesOverHalf", p)
	}
}

func TestOwnerOf_shortestWatchedPath(t *testing.T) {
	if got := scanner.OwnerOf("/in/alice/sub/f", nil, []string{"/in/alice", "/in"}); got != "/in/alice" {
		t.Errorf("OwnerOf() = %q, want /in/alice: the first level under the shortest watched path", got)
	}
}

// The purge of a rescan works in batches, releasing the lock between two of
// them: no call may handle more than purgeBatch entries, however large the table.
func TestFileTable_purgeWorksInBoundedBatches(t *testing.T) {
	now := time.Unix(1000, 0)
	tab := newFileTable(1<<40, 25, nil, []string{"/in"})
	const n = 20 * purgeBatch
	for i := range n {
		tab.Track(fmt.Sprintf("/in/u%d/f%d", i%100, i), scanner.FileIdentity{}, now, now.Add(time.Hour))
	}
	tab.BeginRescan()
	batches := 0
	for left := n; ; batches++ {
		more := tab.purgeBatch(nil, false)
		now := tab.Len()
		if left-now > purgeBatch {
			t.Fatalf("a batch purged %d entries, want at most %d", left-now, purgeBatch)
		}
		left = now
		if !more {
			break
		}
	}
	if tab.Len() != 0 || batches+1 < 20 {
		t.Errorf("left %d entries after %d batches, want 0 after at least 20", tab.Len(), batches+1)
	}
}

func TestFileTable_submittedEntriesAreNeverPurged(t *testing.T) {
	now := time.Unix(1000, 0)
	tab := newTestTable(1<<20, 25)
	const sub = "/in/c/submitted"
	tab.Track(sub, scanner.FileIdentity{}, now, now)
	tab.Track("/in/a/gone", scanner.FileIdentity{}, now, now.Add(time.Hour))
	if p, _, ok := tab.PopDue(now); !ok || p != sub {
		t.Fatalf("PopDue() = %q, %t; want the submitted entry", p, ok)
	}
	for range maxProtectedScans + 2 {
		tab.BeginRescan()
		tab.EndRescan(nil, false)
	}
	if _, ok := tab.Get(sub); !ok {
		t.Error("a submitted entry is being handled: the purge must keep it")
	}
	if _, ok := tab.Get("/in/a/gone"); ok {
		t.Error("an unseen waiting entry must be purged")
	}
}

func FuzzFileTable(f *testing.F) {
	f.Add(uint64(1))
	f.Add(uint64(7))
	f.Fuzz(func(t *testing.T, seed uint64) {
		runPropertyRound(t, &prng{state: seed})
	})
}

func fillOwner(tab *fileTable, owner string, now time.Time, deadline time.Time) int {
	n := 0
	for tab.Track(tp(owner, n), scanner.FileIdentity{}, now, deadline) {
		n++
		if n > 100000 {
			break
		}
	}
	return n
}

func TestFileTable_depthTwoSharing(t *testing.T) {
	now := time.Unix(1000, 0)
	rules := []scanner.OwnerRule{{Root: "/in", Depth: 2}}
	entry := int64(len("/in/eq1/alice/f0000")) + fileOverhead
	own := int64(len("/in/eq1/alice")) + ownerOverhead
	tab := newFileTable(3*own+30*entry, 25, rules, []string{"/in"})
	for i := 0; tab.Track(fmt.Sprintf("/in/eq1/alice/f%04d", i), scanner.FileIdentity{}, now, now.Add(time.Hour)); i++ {
		if i > 10000 {
			t.Fatal("never full")
		}
	}
	if !tab.Track("/in/eq1/bob/f0", scanner.FileIdentity{}, now, now.Add(time.Hour)) {
		t.Error("bob (same team) must be admitted: alice yields")
	}
	if !tab.Track("/in/eq2/carol/f0", scanner.FileIdentity{}, now, now.Add(time.Hour)) {
		t.Error("carol (other team) must be admitted: alice yields")
	}
	if !tab.Track("/in/eq1/loose", scanner.FileIdentity{}, now, now.Add(time.Hour)) {
		t.Error("a file at the team level is admitted too")
	}
	tab.mu.Lock()
	_, teamOwner := tab.owners["/in/eq1"]
	tab.mu.Unlock()
	if !teamOwner {
		t.Error("a file posed in /in/eq1 has /in/eq1 as owner")
	}
}

// V3: an owner that floods never costs a smaller owner an entry, over 20 rescans.
func TestFileTable_smallerOwnerIsNeverEvicted(t *testing.T) {
	now := time.Unix(1000, 0)
	entry := int64(len(tp("aaa", 0))) + fileOverhead
	own := int64(len("/in/aaa")) + ownerOverhead
	tab := newTestTable(2*own+60*entry, 25)
	fillOwner(tab, "aaa", now, now.Add(time.Hour))
	for i := range 5 {
		tab.Track(tp("bob", i), scanner.FileIdentity{}, now, now.Add(time.Hour))
	}
	bobBefore := bobEntries(tab)
	for rescan := range 20 {
		tab.BeginRescan()
		for i := range 10 {
			tab.Track(tp("aaa", 10000+rescan*10+i), scanner.FileIdentity{}, now, now.Add(time.Hour))
		}
		for i := range 5 {
			tab.Track(tp("bob", i), scanner.FileIdentity{}, now, now.Add(time.Hour))
		}
		tab.EndRescan(nil, false)
		if got := bobEntries(tab); got != bobBefore {
			t.Fatalf("rescan %d: bob holds %d entries, want %d: a smaller owner must never be evicted", rescan, got, bobBefore)
		}
	}
}

func bobEntries(t *fileTable) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if o := t.owners["/in/bob"]; o != nil {
		return o.entries()
	}
	return 0
}

// V4 and V5: the largest owner has waiting entries and final ones; a small owner
// depositing and removing files every rescan never costs it a done entry.
func TestFileTable_doneEntriesOfAnOwnerThatWaitsAreNeverEvicted(t *testing.T) {
	now := time.Unix(1000, 0)
	entry := int64(len(tp("victim", 0))) + fileOverhead
	own := int64(len("/in/victim")) + ownerOverhead
	tab := newTestTable(2*own+80*entry, 25)
	for i := range 20 {
		tab.Track(tp("victim", i), scanner.FileIdentity{}, now, now)
	}
	for range 20 {
		if p, _, ok := tab.PopDue(now); ok {
			tab.Done(p, time.Time{}, 1)
		}
	}
	fillOwner(tab, "victim", now, now.Add(time.Hour)) // waiting entries until the table is full
	doneBefore := victimDone(tab)
	for rescan := range 20 {
		for i := range 8 {
			p := tp("mallory", rescan*8+i)
			tab.Track(p, scanner.FileIdentity{}, now, now.Add(time.Hour))
			tab.Forget(p)
		}
		if got := victimDone(tab); got != doneBefore {
			t.Fatalf("rescan %d: victim lost done entries (%d, was %d) while it still had waiting ones", rescan, got, doneBefore)
		}
	}
}

func victimDone(t *fileTable) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if o := t.owners["/in/victim"]; o != nil {
		return o.doneRetry.n + o.doneFinal.n
	}
	return 0
}

// A flat deposit in a table of final entries only: one admission per eviction,
// and the "files left in INPUT" condition is raised once refusals pile up.
func TestFileTable_nothingWaitingSingleOwnerEvictsFinalEntriesFirst(t *testing.T) {
	now := time.Unix(1000, 0)
	entry := int64(len(tp("solo", 0))) + fileOverhead
	own := int64(len("/in/solo")) + ownerOverhead
	tab := newTestTable(own+10*entry, 25)
	for i := 0; tab.Track(tp("solo", i), scanner.FileIdentity{}, now, now); i++ {
		if i > 100 {
			t.Fatal("never full")
		}
	}
	for {
		p, _, ok := tab.PopDue(now)
		if !ok {
			break
		}
		tab.Done(p, time.Time{}, 1)
	}
	if !tab.Track(tp("solo", 900), scanner.FileIdentity{}, now, now) {
		t.Error("a new file must be admitted by evicting a final entry")
	}
	if tab.Track(tp("solo", 901), scanner.FileIdentity{}, now, now) {
		t.Error("with a waiting entry the owner is now refused: it yields only when nothing waits")
	}
}

func BenchmarkMonitorDiscover(b *testing.B) {
	for _, tc := range []struct {
		name string
		path func(i int) string
	}{
		{"short paths", func(i int) string { return fmt.Sprintf("/in/u%d/f%d", i%100, i) }},
		{"4 KiB paths", func(i int) string { return fmt.Sprintf("/in/u%d/%s%d", i%100, strings.Repeat("d", 4000), i) }},
	} {
		b.Run(tc.name, func(b *testing.B) {
			now := time.Unix(1000, 0)
			const budget = 64 << 20
			tab := newFileTable(budget, 25, nil, []string{"/in"})
			b.ReportAllocs()
			for i := 0; b.Loop(); i++ {
				tab.Track(tc.path(i), scanner.FileIdentity{}, now, now.Add(time.Hour))
			}
			if tab.Used() > budget {
				b.Fatalf("used %d exceeds %d", tab.Used(), budget)
			}
		})
	}
}

// BenchmarkOwnersUnderPressure: 100 000 owners of one file each, full table,
// admissions: the cost of an operation does not depend on the number of owners.
func BenchmarkOwnersUnderPressure(b *testing.B) {
	for _, owners := range []int{10, 100_000} {
		b.Run(fmt.Sprint(owners, " owners"), func(b *testing.B) {
			now := time.Unix(1000, 0)
			perOwner := int64(len("/in/u000000/f")) + fileOverhead
			tab := newFileTable(int64(owners)*(perOwner+int64(len("/in/u000000"))+ownerOverhead), 25, nil, []string{"/in"})
			for i := range owners {
				tab.Track(fmt.Sprintf("/in/u%06d/f", i), scanner.FileIdentity{}, now, now.Add(time.Hour))
			}
			b.ReportAllocs()
			for i := 0; b.Loop(); i++ {
				p := fmt.Sprintf("/in/n%06d/f", i%owners)
				tab.Track(p, scanner.FileIdentity{}, now, now.Add(time.Hour))
				tab.Done(p, time.Time{}, 1)
			}
		})
	}
}

func TestFileTable_pressureReportIsBoundedWhateverTheOwners(t *testing.T) {
	now := time.Unix(1000, 0)
	tab := newFileTable(1<<20, 25, nil, []string{"/in"})
	for i := range 100_000 {
		tab.Track(fmt.Sprintf("/in/u%d/f", i), scanner.FileIdentity{}, now, now.Add(time.Hour))
	}
	rep := tab.TakePressure()
	if len(rep.Owners) != maxPressureOwners {
		t.Errorf("report names %d owners, want exactly the cap of %d", len(rep.Owners), maxPressureOwners)
	}
	if rep.Others == 0 {
		t.Error("files of the owners beyond the cap must be counted")
	}
	if msg := describePressure(rep); len(msg) > 8<<10 {
		t.Errorf("message of %d bytes, want it bounded", len(msg))
	}
}

func TestFileTable_entryLargerThanTheBudgetIsRefusedWithoutEvicting(t *testing.T) {
	now := time.Unix(1000, 0)
	tab := newTestTable(2000, 25)
	small := tp("u", 1)
	tab.Track(small, scanner.FileIdentity{}, now, now.Add(time.Hour))
	if tab.Track("/in/v/"+strings.Repeat("x", 4000), scanner.FileIdentity{}, now, now) {
		t.Fatal("an entry that alone exceeds the budget must be refused")
	}
	if _, ok := tab.Get(small); !ok {
		t.Error("nothing may be evicted for an entry that can never fit")
	}
	if rep := tab.TakePressure(); rep.Refused != 1 {
		t.Errorf("refused = %d, want 1", rep.Refused)
	}
}

// BenchmarkPurgeBatch measures one batch of the purge: 256 entries under a
// protected folder, ten levels deep, so each one walks up its parents.
func BenchmarkPurgeBatch(b *testing.B) {
	now := time.Unix(1000, 0)
	tab := newFileTable(1<<40, 25, nil, []string{"/in"})
	deep := "/in/u/" + strings.Repeat("d/", 8)
	for i := range purgeBatch {
		tab.Track(fmt.Sprintf("%sf%d", deep, i), scanner.FileIdentity{}, now, now.Add(time.Hour))
	}
	dirs := map[string]struct{}{"/in/u": {}}
	b.ReportAllocs()
	for b.Loop() {
		b.StopTimer()
		tab.BeginRescan()
		for _, f := range tab.files {
			f.missed = 0
		}
		b.StartTimer()
		tab.purgeBatch(dirs, false)
	}
	if tab.Len() != purgeBatch {
		b.Fatalf("tracked = %d, want %d: the protected entries must stay", tab.Len(), purgeBatch)
	}
}

func TestFileTable_beginRescanKeepsTheLeftoverOfAnUnfinishedRescan(t *testing.T) {
	now := time.Unix(1000, 0)
	tab := newTestTable(1<<20, 25)
	seen, left := tp("u", 1), tp("u", 2)
	tab.Track(seen, scanner.FileIdentity{}, now, now.Add(time.Hour))
	tab.Track(left, scanner.FileIdentity{}, now, now.Add(time.Hour))
	tab.BeginRescan()
	tab.Track(seen, scanner.FileIdentity{}, now, now.Add(time.Hour))
	// The rescan stops before EndRescan: "left" was never visited and must
	// still be accounted for by the next one.
	tab.BeginRescan()
	checkConsistency(t, tab)
	tab.Track(seen, scanner.FileIdentity{}, now, now.Add(time.Hour))
	tab.EndRescan(nil, false)
	if _, ok := tab.Get(left); ok {
		t.Error("an entry not seen by two rescans must be purged")
	}
	if _, ok := tab.Get(seen); !ok {
		t.Error("an entry seen by the last rescan must be kept")
	}
	checkConsistency(t, tab)
}
