package scanner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"regexp/syntax"
	"slices"
	"unicode/utf8"

	"github.com/glimps-re/host-connector/pkg/datamodel"
)

const (
	// maxPathPatterns bounds each list of a PathFilter.
	maxPathPatterns = 256
	// maxPathPatternLen bounds a pattern, in bytes.
	maxPathPatternLen = 1024
	// maxPathPatternsBytes bounds the patterns of both lists together: parsing a
	// pattern made of Unicode classes costs milliseconds.
	maxPathPatternsBytes = 32 << 10
	// maxPathRepeat bounds a counted repeat ({n}, {n,m}) of a pattern.
	maxPathRepeat = 100
	// maxPatternProgram and maxFilterProgram bound the estimated program of one
	// pattern and of all of them, and maxFilterRanges the rune ranges of their
	// character classes: RE2 runs in time linear in the length of the path times
	// the size of the program, and compiling a large class costs memory. The
	// estimate comes from the parse tree: nothing is compiled before it passed.
	// The same limits are in the SDK validation of the configuration.
	maxPatternProgram = 512
	maxFilterProgram  = 4096
	maxFilterRanges   = 4096
	// maxMatchedPath bounds a path matched against the rules, in bytes: a longer
	// one is never truncated, which would hide the end of the name.
	maxMatchedPath = 4096
	// maxEchoedPattern is how much of a refused pattern an error repeats.
	maxEchoedPattern = 64
)

// ErrInvalidPathFilter is wrapped by the error NewPathFilter returns.
var ErrInvalidPathFilter = errors.New("invalid filepath_filter")

// errPathTooLong is the failure of a path too long to be matched, when forbidden
// paths are set: it is neither let through nor taken for malware.
var errPathTooLong = fmt.Errorf("%w: path too long to check the path rules", errInnerPermanent)

type pathRule struct {
	pattern string
	re      *regexp.Regexp
}

// PathFilter applies the forbidden and skipped path rules (Go regular
// expressions, RE2: linear time) to the logical path of a file: the path of the
// file, or for a member of an archive the path of the top-level archive followed
// by the path of the member. It is immutable and safe for concurrent use; a nil
// PathFilter applies no rule.
type PathFilter struct {
	forbidden, skipped []pathRule
}

// NewPathFilter compiles the rules. The error wraps ErrInvalidPathFilter and is
// returned for: a list of more than 256 patterns, patterns of more than 32 KiB in
// all, an empty pattern, one of more than 1024 bytes, one in both lists, one that
// is not a regular expression, one that repeats more than 100 times, patterns whose
// estimated program is over 512 instructions each or 4096 in all, character
// classes of more than 4096 rune ranges in all, and one that matches the empty
// string. Nothing is compiled before the estimate passed.
func NewPathFilter(forbidden, skipped []string) (*PathFilter, error) {
	if err := checkPathPatterns(forbidden, skipped); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPathFilter, err)
	}
	f := &PathFilter{}
	var err error
	var budget pathBudget
	if f.forbidden, err = compilePathRules("forbidden_paths", forbidden, &budget); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPathFilter, err)
	}
	if f.skipped, err = compilePathRules("skipped_paths", skipped, &budget); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPathFilter, err)
	}
	return f, nil
}

func checkPathPatterns(forbidden, skipped []string) error {
	for _, l := range []struct {
		name     string
		patterns []string
	}{{"forbidden_paths", forbidden}, {"skipped_paths", skipped}} {
		if len(l.patterns) > maxPathPatterns {
			return fmt.Errorf("%s: the list has %d patterns, at most %d", l.name, len(l.patterns), maxPathPatterns)
		}
	}
	total := 0
	for _, p := range forbidden {
		total += len(p)
	}
	for _, p := range skipped {
		total += len(p)
	}
	if total > maxPathPatternsBytes {
		return fmt.Errorf("the patterns of both lists hold %d bytes, at most %d in all", total, maxPathPatternsBytes)
	}
	inForbidden := make(map[string]struct{}, len(forbidden))
	for _, p := range forbidden {
		inForbidden[p] = struct{}{}
	}
	for _, l := range []struct {
		name     string
		patterns []string
	}{{"forbidden_paths", forbidden}, {"skipped_paths", skipped}} {
		for i, p := range l.patterns {
			switch {
			case p == "":
				return fmt.Errorf("%s[%d]: an empty pattern matches every path", l.name, i)
			case len(p) > maxPathPatternLen:
				return fmt.Errorf("%s[%d]: the pattern is %d bytes, at most %d", l.name, i, len(p), maxPathPatternLen)
			}
			if _, both := inForbidden[p]; both && l.name == "skipped_paths" {
				return fmt.Errorf("skipped_paths[%d]: the pattern %s is also in forbidden_paths", i, echoPathPattern(p))
			}
		}
	}
	return nil
}

// pathBudget is what the patterns already accepted of the program and of the rune
// ranges that the lists may hold together.
type pathBudget struct{ program, ranges int }

// compilePathRules compiles the patterns of one list, once their estimated size
// passed the bounds; budget counts, across the lists, what the patterns take.
func compilePathRules(list string, patterns []string, budget *pathBudget) ([]pathRule, error) {
	rules := make([]pathRule, 0, len(patterns))
	for i, p := range patterns {
		tree, err := syntax.Parse(p, syntax.Perl)
		if err != nil {
			// The error quotes the whole pattern: only its code is said.
			reason := "the expression cannot be parsed"
			if se, ok := errors.AsType[*syntax.Error](err); ok {
				reason = string(se.Code)
			}
			return nil, fmt.Errorf("%s[%d]: the pattern %s is not a valid regular expression (%s)", list, i, echoPathPattern(p), reason)
		}
		if n := largestRepeat(tree); n > maxPathRepeat {
			return nil, fmt.Errorf("%s[%d]: the pattern %s repeats %d times, at most %d", list, i, echoPathPattern(p), n, maxPathRepeat)
		}
		insts, ranges := estimatePattern(tree)
		switch {
		case insts > maxPatternProgram:
			return nil, fmt.Errorf("%s[%d]: the pattern %s is estimated at %d instructions, at most %d", list, i, echoPathPattern(p), insts, maxPatternProgram)
		case budget.program+insts > maxFilterProgram:
			return nil, fmt.Errorf("%s[%d]: the patterns are estimated at more than %d instructions in all", list, i, maxFilterProgram)
		case budget.ranges+ranges > maxFilterRanges:
			return nil, fmt.Errorf("%s[%d]: the character classes of the patterns hold more than %d ranges in all", list, i, maxFilterRanges)
		}
		budget.program += insts
		budget.ranges += ranges
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: the pattern %s cannot be compiled", list, i, echoPathPattern(p))
		}
		if re.MatchString("") {
			return nil, fmt.Errorf("%s[%d]: the pattern %s matches the empty string, so every path", list, i, echoPathPattern(p))
		}
		rules = append(rules, pathRule{pattern: p, re: re})
	}
	return rules, nil
}

// saturated is the value an estimate stops at: far above any bound, and far from
// an overflow.
const saturated = 1 << 30

func estAdd(a, b int) int { return min(a+b, saturated) }

func estMul(a, b int) int {
	if a != 0 && b > saturated/a {
		return saturated
	}
	return min(a*b, saturated)
}

// programOverhead is what any compiled program holds besides the expression: the
// failure and match instructions, the capture of the whole match.
const programOverhead = 4

// estimatePattern is estimateProgram with the fixed part of a program.
func estimatePattern(re *syntax.Regexp) (insts, ranges int) {
	insts, ranges = estimateProgram(re)
	return estAdd(insts, programOverhead), ranges
}

// estimateProgram is an upper bound of the instructions that compiling the parsed
// (not simplified) expression gives, with the counted repeats multiplied out as
// Simplify would, and the rune ranges of its character classes (counted once: the
// copies of a repeated class share them). The tree is walked, never expanded.
// The SDK validation holds a copy: keep them the same.
func estimateProgram(re *syntax.Regexp) (insts, ranges int) {
	sub := func() (int, int) {
		insts, ranges := 0, 0
		for _, s := range re.Sub {
			i, r := estimateProgram(s)
			insts, ranges = estAdd(insts, i), estAdd(ranges, r)
		}
		return insts, ranges
	}
	switch re.Op {
	case syntax.OpLiteral:
		return len(re.Rune), 0
	case syntax.OpCharClass:
		return 1, len(re.Rune) / 2
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return 2, 0
	case syntax.OpCapture, syntax.OpStar, syntax.OpPlus, syntax.OpQuest:
		i, r := sub()
		return estAdd(i, 2), r
	case syntax.OpRepeat:
		i, r := sub()
		if re.Max < 0 {
			return estAdd(estMul(re.Min, i), estAdd(i, 2)), r
		}
		return estAdd(estMul(re.Max, i), estAdd(estMul(re.Max-re.Min, 2), 2)), r
	case syntax.OpConcat:
		return sub()
	case syntax.OpAlternate:
		i, r := sub()
		return estAdd(i, len(re.Sub)), r
	default:
		return 1, 0
	}
}

// largestRepeat is the largest bound of a counted repeat in the tree.
func largestRepeat(re *syntax.Regexp) int {
	n := 0
	if re.Op == syntax.OpRepeat {
		n = max(re.Min, re.Max)
	}
	for _, sub := range re.Sub {
		n = max(n, largestRepeat(sub))
	}
	return n
}

// echoPathPattern quotes at most maxEchoedPattern bytes of a pattern, cut on a
// character boundary.
func echoPathPattern(p string) string {
	if len(p) <= maxEchoedPattern {
		return fmt.Sprintf("%q", p)
	}
	cut := maxEchoedPattern
	for cut > 0 && !utf8.RuneStart(p[cut]) {
		cut--
	}
	return fmt.Sprintf("%q...", p[:cut])
}

// empty tells whether the filter has no rule.
func (f *PathFilter) empty() bool {
	return f == nil || len(f.forbidden) == 0 && len(f.skipped) == 0
}

// pathDecision is what the rules say of one path.
type pathDecision int

const (
	pathUnruled pathDecision = iota
	pathSkipped
	pathForbidden
	pathTooLong
)

// decide matches the rules against the logical path name and its raw form (the
// path as the file system gives it: control characters and invalid UTF-8 are
// kept, which name leaves out). A forbidden rule that matches either form
// forbids; the path is skipped only when a skipped rule matches both forms, and
// only if skip is set. A form over maxMatchedPath is never truncated nor skipped:
// with forbidden paths set, the path cannot be checked. rule is the pattern that
// decided.
func (f *PathFilter) decide(name, raw string, skip bool) (d pathDecision, rule string) {
	forms := []string{name}
	if raw != "" && raw != name {
		forms = append(forms, raw)
	}
	for _, form := range forms {
		if len(form) > maxMatchedPath {
			if len(f.forbidden) > 0 {
				return pathTooLong, ""
			}
			return pathUnruled, ""
		}
	}
	for _, r := range f.forbidden {
		if slices.ContainsFunc(forms, r.re.MatchString) {
			return pathForbidden, r.pattern
		}
	}
	if !skip {
		return pathUnruled, ""
	}
	for _, form := range forms {
		hit := ""
		for _, r := range f.skipped {
			if r.re.MatchString(form) {
				hit = r.pattern
				break
			}
		}
		if hit == "" {
			return pathUnruled, ""
		}
		rule = hit
	}
	return pathSkipped, rule
}

// skipsPath tells whether the rules skip the path (a forbidden rule overrides).
func (f *PathFilter) skipsPath(name, raw string) bool {
	if f.empty() {
		return false
	}
	d, _ := f.decide(name, raw, true)
	return d == pathSkipped
}

// hasForbidden tells whether the filter has a forbidden rule.
func (f *PathFilter) hasForbidden() bool {
	return f != nil && len(f.forbidden) > 0
}

func (f *PathFilter) refusal(d pathDecision, rule, name, location, sha256 string) *datamodel.Result {
	location = filepath.Clean(location)
	switch d {
	case pathTooLong:
		logger.Debug("path too long for the path rules", "location", location, "sha256", sha256)
		return &datamodel.Result{Filename: name, Location: location, SHA256: sha256, Error: errPathTooLong}
	case pathForbidden:
		logger.Debug("filtered file based on its path (forbidden)", "file", name, "location", location, "sha256", sha256, "regexp", rule)
		return forbiddenResult(name, location, sha256, sizeAt(location))
	}
	return nil
}

// forbiddenResult is the refusal of a file for its path.
func forbiddenResult(name, location, sha256 string, size int64) *datamodel.Result {
	return &datamodel.Result{
		Filename:       name,
		Location:       location,
		Malware:        true,
		SHA256:         sha256,
		Score:          1000,
		Malwares:       []string{"forbidden_file_path"},
		MalwareReason:  datamodel.FilteredFilePath,
		FilteredVolume: size,
		FileSize:       size,
	}
}

// Apply decides on the file at logical path name (raw is the same path as the
// file system gives it), which is really at location (possibly a temporary
// folder: only its size is read there). A forbidden path is refused as malware,
// whatever any skipped path says. A path too long to be checked is an error when
// forbidden paths are set. A skipped path is a waiver. nil: no rule matches. A file
// that cannot be examined does not escape a forbidden path.
func (f *PathFilter) Apply(name, raw, location, sha256 string) *datamodel.Result {
	return f.apply(name, raw, location, sha256, true)
}

// apply is Apply, with the skipped paths ignored when skip is false.
func (f *PathFilter) apply(name, raw, location, sha256 string, skip bool) *datamodel.Result {
	if f.empty() {
		return nil
	}
	d, rule := f.decide(name, raw, skip)
	switch d {
	case pathForbidden, pathTooLong:
		return f.refusal(d, rule, name, location, sha256)
	case pathSkipped:
		location = filepath.Clean(location)
		info, err := os.Stat(location)
		if err != nil {
			// A file that cannot be read is not waived: it goes on to be analyzed,
			// and fails there if it must.
			logger.Debug("a file matching a skipped path cannot be read, not waived", "location", location, "error", err)
			return nil
		}
		logger.Debug("filtered file based on its path (skipped)", "file", name, "location", location, "sha256", sha256, "regexp", rule)
		return &datamodel.Result{
			Filename:       name,
			Location:       location,
			SHA256:         sha256,
			Score:          -500,
			FilteredVolume: info.Size(),
			FileSize:       info.Size(),
		}
	}
	return nil
}

// sizeAt is the size of the file at location, 0 when it cannot be read: the size
// only feeds the reports, it must not decide the verdict.
func sizeAt(location string) int64 {
	info, err := os.Stat(filepath.Clean(location))
	if err != nil {
		logger.Debug("could not read the size of a file refused for its path", "location", location, "error", err)
		return 0
	}
	return info.Size()
}
