package scanner

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/plugins"
)

// treeNode is a member of a random archive tree: a plain file (detected or not) or
// an archive of other members, that the extractor may fail on and the plugins may
// decide on.
type treeNode struct {
	id       int
	archive  bool
	kids     []*treeNode
	detect   bool
	slow     time.Duration
	plugin   int // 0 none, 1 waiver, 2 refusal with an error, 3 refusal as malware
	plugWait time.Duration
	failEx   bool
	exWait   time.Duration
}

func (n *treeNode) name() string {
	if n.archive {
		return fmt.Sprintf("a%d.zip", n.id)
	}
	return fmt.Sprintf("f%d.bin", n.id)
}

func (n *treeNode) String() string {
	s := n.name()
	if n.detect {
		s += "!"
	}
	if n.failEx {
		s += "<extractor down>"
	}
	if n.plugin > 0 {
		s += fmt.Sprintf("<plugin %d>", n.plugin)
	}
	if len(n.kids) > 0 {
		parts := make([]string, len(n.kids))
		for i, k := range n.kids {
			parts[i] = k.String()
		}
		s += "[" + strings.Join(parts, " ") + "]"
	}
	return s
}

// prng is a small deterministic generator (xorshift): the trees must be the same
// for a seed, and nothing here needs a good source of randomness.
type prng struct{ state uint64 }

func (p *prng) Intn(n int) int {
	p.state ^= p.state << 13
	p.state ^= p.state >> 7
	p.state ^= p.state << 17
	return int(p.state>>1) % n
}

// randomTree is a tree of members, deterministic for a seed.
func randomTree(rng *prng) *treeNode {
	next := 0
	var gen func(depth int) *treeNode
	gen = func(depth int) *treeNode {
		next++
		n := &treeNode{id: next, slow: time.Duration(rng.Intn(15)) * time.Millisecond}
		if depth < 5 && rng.Intn(3) == 0 {
			n.archive = true
			for range 1 + rng.Intn(4) {
				n.kids = append(n.kids, gen(depth+1))
			}
			if rng.Intn(5) == 0 {
				n.failEx, n.exWait = true, time.Duration(rng.Intn(100))*time.Millisecond
			}
			if depth > 0 && rng.Intn(3) == 0 {
				n.plugin, n.plugWait = 1+rng.Intn(3), time.Duration(rng.Intn(20))*time.Millisecond
			}
		} else {
			n.detect = rng.Intn(4) == 0
		}
		return n
	}
	top := &treeNode{id: 0, archive: true, failEx: rng.Intn(6) == 0}
	for range 2 + rng.Intn(4) {
		top.kids = append(top.kids, gen(1))
	}
	return top
}

// biasedTree is the shape that loses a detection when an archive is abandoned
// without waiting for its members: a slow detected member beside a sub-archive that
// holds a slow member and a nested archive whose extraction fails. The order of
// the members and the delays are drawn, so that the failure meets the members in
// flight at every stage of their analysis.
func biasedTree(rng *prng) *treeNode {
	next := 0
	leaf := func(slow int, detect bool) *treeNode {
		next++
		return &treeNode{id: next, slow: time.Duration(slow) * time.Millisecond, detect: detect}
	}
	shuffle := func(kids []*treeNode) []*treeNode {
		for i := len(kids) - 1; i > 0; i-- {
			j := rng.Intn(i + 1)
			kids[i], kids[j] = kids[j], kids[i]
		}
		return kids
	}
	next++
	failing := &treeNode{id: next, archive: true, failEx: true, exWait: time.Duration(rng.Intn(40)) * time.Millisecond}
	next++
	inner := &treeNode{id: next, archive: true}
	inner.kids = shuffle([]*treeNode{leaf(5+rng.Intn(60), false), failing, leaf(rng.Intn(10), false)})
	next++
	middle := &treeNode{id: next, archive: true}
	middle.kids = shuffle([]*treeNode{leaf(rng.Intn(10), false), inner})
	top := &treeNode{id: 0, archive: true}
	top.kids = shuffle([]*treeNode{leaf(20+rng.Intn(80), true), middle})
	if rng.Intn(2) == 0 {
		top.kids = append(top.kids, leaf(rng.Intn(10), false))
	}
	return top
}

// failureReached tells whether an extraction that fails is reached: no archive
// above it fails itself, and none is decided by a plugin, which ends it before its
// members are sent.
func failureReached(n *treeNode) bool {
	if n.archive && n.failEx {
		return true
	}
	if n.plugin > 0 && n.id != 0 {
		return false
	}
	return slices.ContainsFunc(n.kids, failureReached)
}

// Whatever the shape of an archive, whenever its extractor goes down, whatever the
// plugins decide on its members and however long its members take, a detection is
// never lost: one action runs for the archive, it is malware, and it is never
// delivered; nothing stays in the archive handler.
func TestArchiveDetection_randomTreesNeverLoseADetection(t *testing.T) {
	iterations := 40
	if testing.Short() {
		iterations = 8
	}
	for seed := range int64(iterations) {
		rng := &prng{state: uint64(seed+1) * 0x9e3779b97f4a7c15}
		top := randomTree(rng)
		if seed%2 == 1 {
			top = biasedTree(rng)
		}
		byID, byName := map[int]*treeNode{}, map[string]*treeNode{}
		var reg func(n *treeNode)
		reg = func(n *treeNode) {
			byID[n.id], byName[n.name()] = n, n
			for _, k := range n.kids {
				reg(k)
			}
		}
		reg(top)

		var detected atomic.Int32
		extract := func(src, outputDir string, _ plugins.ExtractLimits) (plugins.Extraction, error) {
			b, err := os.ReadFile(filepath.Clean(src))
			if err != nil {
				return plugins.Extraction{}, err
			}
			i := bytes.LastIndex(b, []byte("TAG"))
			if i < 0 {
				return plugins.Extraction{}, plugins.ErrUnsupportedFormat
			}
			var id int
			if _, err = fmt.Sscanf(string(b[i+3:]), "%d", &id); err != nil {
				return plugins.Extraction{}, plugins.ErrUnsupportedFormat
			}
			n := byID[id]
			if n == nil || !n.archive {
				return plugins.Extraction{}, plugins.ErrUnsupportedFormat
			}
			if n.failEx {
				time.Sleep(n.exWait)
				return plugins.Extraction{}, fmt.Errorf("7z: %w", plugins.ErrExtractorUnavailable)
			}
			files := make([]string, 0, len(n.kids))
			for _, k := range n.kids {
				content := fmt.Sprintf("C-%d", k.id)
				if k.archive {
					content = zipOf(t, 10) + fmt.Sprintf("TAG%d", k.id)
				}
				p := filepath.Join(outputDir, k.name())
				if err = os.WriteFile(p, []byte(content), 0o600); err != nil {
					return plugins.Extraction{}, err
				}
				files = append(files, p)
			}
			return plugins.Extraction{Files: files}, nil
		}
		var leaked int
		after := func(c *Connector) {
			for range 100 {
				c.archiveStatus.RLock()
				leaked = len(c.archiveStatus.statusByID)
				c.archiveStatus.RUnlock()
				if leaked == 0 {
					return
				}
				time.Sleep(20 * time.Millisecond)
			}
		}
		r := runAcc(t, accSetup{
			files:   map[string]string{"evil.zip": zipOf(t, 10) + "TAG0"},
			extract: extract, workers: 4, maxDepth: 8, remove: seed%2 == 0, after: after,
			submit: func(n string) (gdetect.Result, error) {
				node := byName[n]
				if node == nil {
					return gdetect.Result{}, nil
				}
				time.Sleep(node.slow)
				if node.detect {
					detected.Add(1)
					return gdetect.Result{Malware: true, Malwares: []string{"evil"}}, nil
				}
				return gdetect.Result{}, nil
			},
			scanFile: func(name, _, _ string, _ bool) *datamodel.Result {
				node := byName[filepath.Base(name)]
				if node == nil || node.plugin == 0 {
					return nil
				}
				time.Sleep(node.plugWait)
				switch node.plugin {
				case 1:
					return &datamodel.Result{}
				case 2:
					return &datamodel.Result{Error: errors.New("refused")}
				}
				detected.Add(1)
				return &datamodel.Result{Malware: true, Malwares: []string{"plugin"}}
			},
		})
		if leaked != 0 {
			t.Errorf("seed %d: %d archive statuses left behind: %s", seed+1, leaked, top)
		}
		delivered := r.exists(r.out, "evil.zip")
		switch {
		case detected.Load() == 0 && len(r.captures) > 1:
			t.Errorf("seed %d: %d actions for one archive: %s", seed+1, len(r.captures), top)
		case detected.Load() == 0 && failureReached(top) && delivered:
			t.Errorf("seed %d: an archive whose extraction failed was delivered with no detection: %s", seed+1, top)
		case detected.Load() == 0:
		case len(r.captures) != 1 || !r.captures[0].result.Malware || delivered:
			t.Errorf("seed %d: a detection was lost (%d actions, delivered %t): %s", seed+1, len(r.captures), delivered, top)
		}
	}
}
