package handler

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/scanner"
)

type ctAction string

const (
	ctRefuse ctAction = "refuse"
	ctGW     ctAction = "G:w"
	ctGR     ctAction = "G:r"
	ctGF     ctAction = "G:f"
	ctER     ctAction = "E:r"
	ctEF     ctAction = "E:f"
)

func ctActionOf(a action) ctAction {
	switch a {
	case actEvictLargestW:
		return ctGW
	case actEvictLargestR:
		return ctGR
	case actEvictLargestF:
		return ctGF
	case actEvictIncomingR:
		return ctER
	case actEvictIncomingF:
		return ctEF
	default:
		return ctRefuse
	}
}

// TestDecide_cardTable copies the decision table of the task card, cell by
// cell: columns are G = W, R, F, 0.
func TestDecide_cardTable(t *testing.T) {
	kinds := []kind{kindW, kindR, kindF, kind0}
	names := map[kind]string{kindW: "W", kindR: "R", kindF: "F", kind0: "0"}
	table := []struct {
		pos  position
		name string
		e    kind
		want [4]ctAction // for G = W, R, F, 0 ; "" for an impossible cell
	}{
		{posIsLargest, "E is G", kindW, [4]ctAction{ctRefuse, "", "", ""}},
		{posIsLargest, "E is G", kindR, [4]ctAction{"", ctER, "", ""}},
		{posIsLargest, "E is G", kindF, [4]ctAction{"", "", ctEF, ""}},
		{posIsLargest, "E is G", kind0, [4]ctAction{"", "", "", ctRefuse}},

		{posSameSize, "same size", kindW, [4]ctAction{ctRefuse, ctRefuse, ctRefuse, ctRefuse}},
		{posSameSize, "same size", kindR, [4]ctAction{ctER, ctER, ctER, ctER}},
		{posSameSize, "same size", kindF, [4]ctAction{ctEF, ctEF, ctEF, ctEF}},
		{posSameSize, "same size", kind0, [4]ctAction{ctGW, ctGR, ctGF, ctRefuse}},

		{posAboveQuota, "smaller, above quota", kindW, [4]ctAction{ctGW, ctGR, ctGF, ctRefuse}},
		{posAboveQuota, "smaller, above quota", kindR, [4]ctAction{ctER, ctER, ctER, ctER}},
		{posAboveQuota, "smaller, above quota", kindF, [4]ctAction{ctEF, ctEF, ctEF, ctEF}},
		{posAboveQuota, "smaller, above quota", kind0, [4]ctAction{ctGW, ctGR, ctGF, ctRefuse}},

		{posUnderQuota, "smaller, under quota", kindW, [4]ctAction{ctGW, ctGR, ctGF, ctRefuse}},
		{posUnderQuota, "smaller, under quota", kindR, [4]ctAction{ctGW, ctGR, ctGF, ctER}},
		{posUnderQuota, "smaller, under quota", kindF, [4]ctAction{ctGW, ctGR, ctGF, ctEF}},
		{posUnderQuota, "smaller, under quota", kind0, [4]ctAction{ctGW, ctGR, ctGF, ctRefuse}},
	}
	cells := 0
	for _, row := range table {
		for i, g := range kinds {
			want := row.want[i]
			if want == "" {
				continue
			}
			cells++
			t.Run(fmt.Sprintf("%s/E=%s/G=%s", row.name, names[row.e], names[g]), func(t *testing.T) {
				if got := ctActionOf(decide(row.pos, row.e, g)); got != want {
					t.Errorf("decide() = %s, want %s", got, want)
				}
			})
		}
	}
	if cells != 52 {
		t.Fatalf("the table holds %d cells, the card says 52", cells)
	}
}

type ctTable struct {
	*fileTable
	now time.Time
}

func newCTTable(files int, owners ...string) *ctTable {
	// Room for `files` entries of the paths below plus the owners themselves.
	limit := int64(files)*(int64(len(ctPath("aaa", 0)))+fileOverhead) + int64(len(owners))*(int64(len("/in/aaa"))+ownerOverhead)
	return &ctTable{fileTable: newFileTable(limit, 25, nil, []string{"/in"}), now: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)}
}

func ctPath(owner string, n int) string { return fmt.Sprintf("/in/%s/f%04d", owner, n) }

func (c *ctTable) track(owner string, n int, delay time.Duration) bool {
	return c.Track(ctPath(owner, n), scanner.FileIdentity{Size: int64(n)}, c.now, c.now.Add(delay))
}

func (c *ctTable) count(owner string) int {
	n := 0
	for i := range 5000 {
		if _, ok := c.Get(ctPath(owner, i)); ok {
			n++
		}
	}
	return n
}

func (c *ctTable) popDue() []string {
	var out []string
	for {
		p, _, ok := c.PopDue(c.now)
		if !ok {
			return out
		}
		out = append(out, p)
	}
}

func TestFileTableContract_V1_oldestEntriesOfTheVictimAreSubmitted(t *testing.T) {
	const delay = 3 * time.Second
	c := newCTTable(40)
	for n := range 36 {
		if !c.track("victim", n, delay) {
			t.Fatalf("victim file %d refused while the table has room", n)
		}
	}
	// The pipeline moves a submitted file out of INPUT: it is not found again.
	submitted := map[string]int{}
	for rescan := range 20 {
		c.BeginRescan()
		for n := range 36 {
			if submitted[ctPath("victim", n)] == 0 {
				c.track("victim", n, delay)
			}
		}
		small := ctPath("small", rescan)
		c.Track(small, scanner.FileIdentity{Size: 1}, c.now, c.now.Add(delay))
		c.EndRescan(nil, false)
		c.now = c.now.Add(time.Second)
		for _, p := range c.popDue() {
			submitted[p]++
			c.Forget(p)
		}
		c.Forget(small)
	}
	for n := range 36 {
		if submitted[ctPath("victim", n)] == 0 {
			t.Errorf("victim file %d was never submitted in 20 rescans: only the newest entries may be evicted", n)
		}
	}
	for p, n := range submitted {
		if n > 1 {
			t.Errorf("%s submitted %d times, want once", p, n)
		}
	}
}

func TestFileTableContract_V3_smallerOwnerIsNeverEvicted(t *testing.T) {
	const delay = time.Hour
	c := newCTTable(40)
	for n := range 6 {
		c.track("bob", n, delay)
	}
	for n := range 3 {
		p, _, ok := c.PopDue(c.now.Add(delay))
		if !ok {
			t.Fatal("expected a due entry")
		}
		_ = n
		c.Done(p, time.Time{}, 1)
	}
	for n := range 100 {
		c.track("aaa", n, delay)
	}
	bobBefore := c.count("bob")
	if bobBefore != 6 {
		t.Fatalf("bob holds %d entries, want 6", bobBefore)
	}
	refused := 0
	for rescan := range 20 {
		c.BeginRescan()
		for n := range 6 {
			c.track("bob", n, delay)
		}
		for n := range 20 {
			if !c.track("aaa", 1000+rescan*20+n, delay) {
				refused++
			}
		}
		c.EndRescan(nil, false)
		if got := c.count("bob"); got != bobBefore {
			t.Fatalf("rescan %d: bob holds %d entries, want %d: a smaller owner must never be evicted", rescan, got, bobBefore)
		}
	}
	if refused == 0 {
		t.Error("the flooding owner was never refused")
	}
}

func TestFileTableContract_V4_doneEntriesOfAnOwnerWithWaitingWorkStay(t *testing.T) {
	const delay = time.Hour
	c := newCTTable(40)
	for n := range 30 {
		c.track("big", n, delay)
	}
	for range 5 {
		p, _, ok := c.PopDue(c.now.Add(delay))
		if !ok {
			t.Fatal("expected a due entry")
		}
		c.Done(p, time.Time{}, 1)
	}
	doneBefore := 0
	for n := range 30 {
		if f, ok := c.Get(ctPath("big", n)); ok && f.phase == phaseDone {
			doneBefore++
		}
	}
	if doneBefore != 5 {
		t.Fatalf("big holds %d done entries, want 5", doneBefore)
	}
	for rescan := range 20 {
		c.BeginRescan()
		for n := range 30 {
			c.track("big", n, delay)
		}
		small := ctPath("small", rescan)
		c.Track(small, scanner.FileIdentity{Size: 1}, c.now, c.now.Add(delay))
		c.EndRescan(nil, false)
		c.Forget(small)
		done := 0
		for n := range 30 {
			if f, ok := c.Get(ctPath("big", n)); ok && f.phase == phaseDone {
				done++
			}
		}
		if done != doneBefore {
			t.Fatalf("rescan %d: big holds %d done entries, want %d: none may be evicted while it has waiting entries", rescan, done, doneBefore)
		}
	}
}

func TestFileTableContract_fifthOwnerIsAdmittedAndTheLargestYields(t *testing.T) {
	const delay = time.Hour
	owners := []string{"o1", "o2", "o3", "o4"}
	c := newCTTable(40, append(owners, "o5")...)
	for _, o := range owners {
		for n := range 10 {
			if !c.track(o, n, delay) {
				t.Fatalf("%s file %d refused before the table is full", o, n)
			}
		}
	}
	before := map[string]int{}
	for _, o := range owners {
		before[o] = c.count(o)
	}
	if !c.track("o5", 0, delay) {
		t.Fatal("the fifth owner must be admitted")
	}
	lost := 0
	for _, o := range owners {
		lost += before[o] - c.count(o)
	}
	if lost < 1 {
		t.Error("no owner yielded room to the fifth one")
	}
	if c.Used() > c.maxBytes {
		t.Errorf("used = %d, over the bound %d", c.Used(), c.maxBytes)
	}
}

func TestFileTableContract_hundredThousandWaitingFilesAddNoGoroutine(t *testing.T) {
	tab := newFileTable(1<<40, 25, nil, []string{"/in"})
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	before := runtime.NumGoroutine()
	for n := range 100_000 {
		if !tab.Track(fmt.Sprintf("/in/u%d/f%d", n%50, n), scanner.FileIdentity{Size: 1}, now, now.Add(time.Hour)) {
			t.Fatalf("file %d refused with a huge bound", n)
		}
	}
	if after := runtime.NumGoroutine(); after > before {
		t.Errorf("goroutines = %d, want at most %d: one timer, never one goroutine per file", after, before)
	}
	if tab.Len() != 100_000 || tab.Owners() != 50 {
		t.Errorf("table holds %d files for %d owners, want 100000 and 50", tab.Len(), tab.Owners())
	}
}

func TestFileTableContract_pressureNamesTheFloodingOwner(t *testing.T) {
	const delay = time.Hour
	c := newCTTable(30)
	n := 0
	for c.track("aaa", n, delay) {
		n++
	}
	if n < 20 {
		t.Fatalf("aaa was refused after %d files: no refusal is allowed while the table has room", n)
	}
	if !c.track("bbb", 0, delay) {
		t.Fatal("a file of another owner must be admitted by evicting a waiting entry of aaa")
	}
	if c.track("aaa", 5000, delay) {
		t.Error("a new file of the largest owner must be refused")
	}
	report := c.TakePressure()
	p := report.Owners["/in/aaa"]
	if p == nil || p.Waiting < 1 || p.RefusedFiles < 1 {
		t.Fatalf("pressure = %+v, want aaa named with an eviction and a refusal", report)
	}
	if again := c.TakePressure(); len(again.Owners) != 0 || again.Refused != 0 {
		t.Errorf("pressure after a take = %+v, want it reset", again)
	}
}

func TestFileTableContract_unreadableFolderProtectsOnlyItsSubtreeForTenRescans(t *testing.T) {
	c := newCTTable(40)
	locked, gone := "/in/u/locked/a.bin", "/in/u/other/b.bin"
	c.Track(locked, scanner.FileIdentity{Size: 1}, c.now, c.now.Add(time.Hour))
	c.Track(gone, scanner.FileIdentity{Size: 1}, c.now, c.now.Add(time.Hour))
	c.BeginRescan()
	c.EndRescan([]string{"/in/u/locked"}, false)
	if _, ok := c.Get(gone); ok {
		t.Error("a file outside the unreadable folder, not seen, must be purged at once")
	}
	for rescan := 1; rescan <= 10; rescan++ {
		if _, ok := c.Get(locked); !ok {
			t.Fatalf("file purged at rescan %d, want it protected for 10 rescans", rescan)
		}
		c.BeginRescan()
		c.EndRescan([]string{"/in/u/locked"}, false)
	}
	if _, ok := c.Get(locked); ok {
		t.Error("after 10 consecutive rescans the file must be purged as if it had disappeared")
	}
}

func TestFileTableContract_depth2TeamMembersShareTheAdmission(t *testing.T) {
	const delay = time.Hour
	rules := []scanner.OwnerRule{{Root: "/in", Depth: 2}}
	path := func(team, user string, n int) string { return fmt.Sprintf("/in/%s/%s/f%04d", team, user, n) }
	entry := int64(len(path("eq1", "alice", 0))) + fileOverhead
	limit := 3*(int64(len("/in/eq1/alice"))+ownerOverhead) + 40*entry
	tab := newFileTable(limit, 25, rules, []string{"/in"})
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	for n := 0; tab.Track(path("eq1", "alice", n), scanner.FileIdentity{Size: 1}, now, now.Add(delay)); n++ {
		if n > 1000 {
			t.Fatal("the table never fills")
		}
	}
	if !tab.Track(path("eq1", "bob", 0), scanner.FileIdentity{Size: 1}, now, now.Add(delay)) {
		t.Error("bob, same team as alice, must be admitted: the owner is the user folder")
	}
	if !tab.Track(path("eq2", "carol", 0), scanner.FileIdentity{Size: 1}, now, now.Add(delay)) {
		t.Error("carol, another team, must be admitted")
	}
	teamFile := "/in/eq1/team.txt"
	tab.Track(teamFile, scanner.FileIdentity{Size: 1}, now, now.Add(delay))
	if got := scanner.OwnerOf(teamFile, rules, []string{"/in"}); got != "/in/eq1" {
		t.Errorf("owner of a file in the team folder = %q, want /in/eq1", got)
	}
	if tab.Owners() < 3 {
		t.Errorf("owners = %d, want alice, bob and carol", tab.Owners())
	}
}
