package datamodel

import (
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func worstReport() Report {
	name := strings.Repeat("\x01", 60<<10)
	r := Report{Filename: name, Error: name, Malwares: make([]string, 500)}
	for i := range r.Malwares {
		r.Malwares[i] = name
	}
	r.ErrorExtractedFiles = map[string]string{}
	for i := range 5000 {
		r.NotAnalyzedExtractedFiles = append(r.NotAnalyzedExtractedFiles, NotAnalyzedFile{FileName: name, Reason: NotAnalyzedTooBig})
		r.ErrorExtractedFiles[fmt.Sprintf("%d%s", i, name[:900])] = name[:1000]
		r.MaliciousExtractedFiles = append(r.MaliciousExtractedFiles, ExtractedFile{
			FileName: fmt.Sprintf("%d%s", i, name), Malwares: r.Malwares,
			ExtractedFiles: []ExtractedFile{{FileName: name, Malwares: r.Malwares}},
		})
	}
	r.NotAnalyzedExtractedCount = 5000
	return r
}

func TestReportBound_worstCaseFitsMaxReportSize(t *testing.T) {
	r := worstReport()
	r.Bound()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > MaxReportSize {
		t.Errorf("encoded report = %d bytes, want <= %d", len(b), MaxReportSize)
	}
	if len(r.Malwares) > MaxReportMalwares || r.NotAnalyzedExtractedCount != 5000 {
		t.Errorf("malwares %d, count %d: lists must be cut and counters exact", len(r.Malwares), r.NotAnalyzedExtractedCount)
	}
}

func TestReportBound_smallReportIsUntouched(t *testing.T) {
	r := Report{Filename: "/in/f", Malwares: []string{"m"}, NotAnalyzedExtractedFiles: []NotAnalyzedFile{{FileName: "a"}}}
	r.Bound()
	if r.Filename != "/in/f" || len(r.Malwares) != 1 || len(r.NotAnalyzedExtractedFiles) != 1 || r.Error != "" {
		t.Errorf("report changed: %+v", r)
	}
}

func BenchmarkReportBound_worstCase(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		r := worstReport()
		r.Bound()
	}
}

func encodedLen(t *testing.T, r Report) int {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return len(b)
}

// One field of several MiB, in any place, does not get past the limit.
func TestReportBound_oneHugeValueIsCut(t *testing.T) {
	huge := strings.Repeat("\x01", 5<<20)
	tests := map[string]Report{
		"error value":   {ErrorExtractedFiles: map[string]string{"a": huge}},
		"error key":     {ErrorExtractedFiles: map[string]string{huge: "a"}},
		"gmalware url":  {GMalwareURL: huge},
		"moved to":      {MovedTo: huge},
		"type":          {FileType: huge},
		"node url":      {MaliciousExtractedFiles: []ExtractedFile{{FileName: "a", GMalwareURL: huge}}},
		"nested node":   {MaliciousExtractedFiles: []ExtractedFile{{FileName: "a", ExtractedFiles: []ExtractedFile{{FileName: huge}}}}},
		"quarantine":    {QuarantineLocation: huge},
		"many errors":   {ErrorExtractedFiles: manyErrors(5000, huge[:1000])},
		"node malwares": {MaliciousExtractedFiles: []ExtractedFile{{FileName: "a", Malwares: manyNames(1000, huge[:5000])}}},
	}
	for name, r := range tests {
		t.Run(name, func(t *testing.T) {
			r.Bound()
			if n := encodedLen(t, r); n > MaxReportSize {
				t.Errorf("encoded report = %d bytes, want <= %d", n, MaxReportSize)
			}
		})
	}
}

func manyErrors(n int, text string) map[string]string {
	m := make(map[string]string, n)
	for i := range n {
		m[fmt.Sprintf("m%d", i)] = text
	}
	return m
}

func manyNames(n int, text string) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = text
	}
	return out
}

// What attests a passage without analysis is cut last: other content that
// bloats the report is cut first, and the list of the files not analyzed stays
// whole.
func TestReportBound_theListOfFilesNotAnalyzedIsCutLast(t *testing.T) {
	name := strings.Repeat("x", 100)
	r := Report{ErrorExtractedFiles: manyErrors(1000, strings.Repeat("\x01", 1000)), Malwares: manyNames(64, strings.Repeat("\x01", 1000))}
	for range 1000 {
		r.NotAnalyzedExtractedFiles = append(r.NotAnalyzedExtractedFiles, NotAnalyzedFile{FileName: name, Reason: NotAnalyzedTooBig})
	}
	r.Bound()
	if len(r.NotAnalyzedExtractedFiles) != 1000 {
		t.Errorf("%d files not analyzed kept, want all 1000: other content must give way first", len(r.NotAnalyzedExtractedFiles))
	}
	if n := encodedLen(t, r); n > MaxReportSize {
		t.Errorf("encoded report = %d bytes, want <= %d", n, MaxReportSize)
	}
}

// The caller's data is not modified.
func TestReportBound_leavesWhatTheCallerSharesAlone(t *testing.T) {
	long := strings.Repeat("a", 5000)
	list := []NotAnalyzedFile{{FileName: long}}
	errs := map[string]string{"k": long}
	names := []string{long}
	r := Report{NotAnalyzedExtractedFiles: list, ErrorExtractedFiles: errs, Malwares: names}
	r.Bound()
	if list[0].FileName != long || errs["k"] != long || names[0] != long {
		t.Error("Bound changed the slices and the map of the caller")
	}
}

// Even a report far above the caps is made to fit in bounded memory and size.
// The time depends on the machine: it is logged, and asserted only with
// HC_WORST_CASE_TIME=1.
func TestReportBound_worstCaseIsCheap(t *testing.T) {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	r := worstReport()
	start := time.Now()
	r.Bound()
	took := time.Since(start)
	runtime.ReadMemStats(&after)
	t.Logf("Bound took %s", took)
	if os.Getenv("HC_WORST_CASE_TIME") == "1" && took > 20*time.Second {
		t.Errorf("Bound took %s", took)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 2<<30 {
		t.Errorf("Bound allocated %d MiB", alloc>>20)
	}
	if n := encodedLen(t, r); n > MaxReportSize {
		t.Errorf("encoded report = %d bytes, want <= %d", n, MaxReportSize)
	}
}

// A value a plugin sets on every node (a hash of 1 KiB of control characters)
// is measured, not estimated: the report still fits.
func TestReportBound_nodeValuesOfAPluginAreMeasured(t *testing.T) {
	r := Report{}
	sha := strings.Repeat("\x01", MaxListedNameLen)
	for i := range MaxReportMaliciousFiles {
		r.MaliciousExtractedFiles = append(r.MaliciousExtractedFiles, ExtractedFile{FileName: fmt.Sprintf("m%d", i), SHA256: sha})
	}
	r.Bound()
	if n := encodedLen(t, r); n > MaxReportSize {
		t.Errorf("encoded report = %d bytes, want <= %d", n, MaxReportSize)
	}
}

// Two names that share their first MaxListedNameLen bytes stay two entries once
// cut: the count of failed members the report gives does not drop, and none of
// the error lines is lost.
func TestReportBound_errorKeysStayDistinctAfterTheCut(t *testing.T) {
	prefix := strings.Repeat("p", MaxListedNameLen)
	tests := map[string]map[string]string{
		"names of 1100 bytes sharing 1024": {
			prefix + strings.Repeat("a", 76): "first",
			prefix + strings.Repeat("b", 76): "second",
		},
		// Keys over the limit that already end in a mark and a hash: the cut must
		// not take off what tells them apart.
		"keys already carrying a hash": {
			prefix + truncationMark + "-1111aaaa": "first",
			prefix + truncationMark + "-2222bbbb": "second",
		},
		"one just over, one just under": {
			prefix + "x":                          "over",
			prefix[:MaxListedNameLen-1] + "yy":    "over too",
			strings.Repeat("z", MaxListedNameLen): "exact",
		},
	}
	for name, errs := range tests {
		t.Run(name, func(t *testing.T) {
			r := Report{ErrorExtractedFiles: maps.Clone(errs)}
			r.Bound()
			if len(r.ErrorExtractedFiles) != len(errs) {
				t.Fatalf("%d entries after the cut, want %d", len(r.ErrorExtractedFiles), len(errs))
			}
			values := map[string]bool{}
			for k, v := range r.ErrorExtractedFiles {
				if len(k) > MaxListedNameLen {
					t.Errorf("a key of %d bytes", len(k))
				}
				values[v] = true
			}
			for _, v := range errs {
				if !values[v] {
					t.Errorf("the error %q is lost", v)
				}
			}
			again := Report{ErrorExtractedFiles: maps.Clone(errs)}
			again.Bound()
			if !maps.Equal(r.ErrorExtractedFiles, again.ErrorExtractedFiles) {
				t.Error("the keys depend on the order of the map: they must be the same every time")
			}
		})
	}
}

// The limit of entries and of bytes stay, with colliding names.
func TestReportBound_collidingErrorKeysKeepTheCaps(t *testing.T) {
	prefix := strings.Repeat("p", MaxListedNameLen)
	errs := map[string]string{}
	for i := range 3 * MaxListedSubfiles {
		errs[fmt.Sprintf("%s%06d", prefix, i)] = "e"
	}
	r := Report{ErrorExtractedFiles: errs}
	r.Bound()
	if got := ListedErrors(r.ErrorExtractedFiles); got != MaxListedSubfiles {
		t.Errorf("%d entries listed, want the cap of %d", got, MaxListedSubfiles)
	}
	if got := failuresOf(r.ErrorExtractedFiles); got != 3*MaxListedSubfiles {
		t.Errorf("failures = %d, want %d", got, 3*MaxListedSubfiles)
	}
	for k := range r.ErrorExtractedFiles {
		if len(k) > MaxListedNameLen {
			t.Fatalf("a key of %d bytes", len(k))
		}
	}
}

// A key taken by another name (a hash collision someone searched for) is made
// distinct with a counter, within the byte limit.
func TestUniqueKey_aTakenKeyGetsACounter(t *testing.T) {
	name := strings.Repeat("n", MaxListedNameLen+50)
	out := map[string]string{}
	keys := make([]string, 0, 3)
	for range 3 {
		k := UniqueKey(name, out, nil)
		out[k] = "x"
		keys = append(keys, k)
	}
	if keys[0] == keys[1] || keys[1] == keys[2] || keys[0] == keys[2] {
		t.Fatalf("keys %q, %q, %q are not distinct", keys[0][len(keys[0])-12:], keys[1][len(keys[1])-12:], keys[2][len(keys[2])-12:])
	}
	for _, k := range keys {
		if len(k) > MaxListedNameLen {
			t.Errorf("a key of %d bytes", len(k))
		}
	}
}

// A short name that another key already holds does not replace it: it gets the
// hashed form, as a long one would.
func TestUniqueKey_aShortNameAlreadyTakenIsKeptApart(t *testing.T) {
	taken := map[string]string{"a.txt": "first"}
	got := UniqueKey("a.txt", taken, nil)
	if got == "a.txt" || !strings.HasPrefix(got, "a.txt-") || len(got) != len("a.txt")+keyHashLen {
		t.Errorf("a taken short name became %q", got)
	}
	if free := UniqueKey("b.txt", taken, nil); free != "b.txt" {
		t.Errorf("a free short name became %q", free)
	}
}

// Many names forced onto one key (a collision found on purpose) are all kept, and
// each costs a step, not a pass over the ones before it: the resume counter
// remembers where the counter of a base stands. Counted in lookups of the keys
// taken, not in time.
func TestUniqueKey_manyNamesOnOneKeyCostOneStepEach(t *testing.T) {
	name := strings.Repeat("n", MaxListedNameLen+50)
	taken := map[string]string{}
	var lookups int
	used := func(key string) bool {
		lookups++
		_, ok := taken[key]
		return ok
	}
	resume := map[string]int{}
	for i := range MaxListedSubfiles {
		k := uniqueKey(name, used, resume)
		if _, dup := taken[k]; dup {
			t.Fatalf("name %d got the key of an earlier one", i)
		}
		taken[k] = "x"
	}
	if len(taken) != MaxListedSubfiles {
		t.Errorf("%d keys, want %d", len(taken), MaxListedSubfiles)
	}
	if limit := 3 * MaxListedSubfiles; lookups > limit {
		t.Errorf("%d lookups for %d names, want at most %d: a pass over the earlier keys each time", lookups, MaxListedSubfiles, limit)
	}
}

// The longest key a counter can make is still within the limit: the room kept
// for the counter covers the biggest one a map can need, and a few more.
func TestUniqueKey_theCounterStaysWithinTheByteLimit(t *testing.T) {
	name := strings.Repeat("n", 2*MaxListedNameLen)
	for _, counter := range []int{2, MaxListedSubfiles + 1, 9999} {
		taken := map[string]string{}
		base := UniqueKey(name, taken, nil)
		taken[base] = "x"
		resume := map[string]int{base: counter}
		key := UniqueKey(name, taken, resume)
		if want := base + counterMark + strconv.Itoa(counter); key != want {
			t.Fatalf("counter %d: key %q, want %q", counter, key[len(key)-14:], want[len(want)-14:])
		}
		if len(key) > MaxListedNameLen {
			t.Errorf("counter %d: a key of %d bytes, over %d", counter, len(key), MaxListedNameLen)
		}
	}
	if countDigits != len(strconv.Itoa(MaxListedSubfiles+1)) {
		t.Errorf("room for %d digits, a map of %d keys needs %d", countDigits, MaxListedSubfiles+1, len(strconv.Itoa(MaxListedSubfiles+1)))
	}
}

// Bound of a bound is the same: the keys it makes, and the count it makes of what
// it leaves out, are kept as they are, and so are the failed files it stands for.
func TestReportBound_isIdempotentOnTheErrorsItMakes(t *testing.T) {
	prefix := strings.Repeat("p", MaxListedNameLen)
	many := func(n int, withCount int) map[string]string {
		errs := map[string]string{}
		for i := range n {
			errs[fmt.Sprintf("f%04d", i)] = "e"
		}
		if withCount > 0 {
			errs[MoreErrorsKey] = MoreErrorsText(withCount)
		}
		return errs
	}
	collide := map[string]string{"short.txt": "s", "dup": "d", "a\xffb": "x", "a\xfeb": "y"}
	for i := range 20 {
		collide[fmt.Sprintf("%s%04d", prefix, i)] = "e"
	}
	tests := map[string]map[string]string{
		"names that collide once cut":      collide,
		"a full map of the scanner":        many(MaxListedSubfiles, 500),
		"over the cap, without a count":    many(MaxListedSubfiles+7, 0),
		"over the cap, with a count":       many(MaxListedSubfiles+7, 30),
		"just at the cap, without a count": many(MaxListedSubfiles, 0),
		"a count and few entries":          many(3, 12),
	}
	for name, errs := range tests {
		t.Run(name, func(t *testing.T) {
			total := failuresOf(errs)
			once := Report{ErrorExtractedFiles: maps.Clone(errs)}
			once.Bound()
			twice := Report{ErrorExtractedFiles: maps.Clone(once.ErrorExtractedFiles)}
			twice.Bound()
			if !maps.Equal(once.ErrorExtractedFiles, twice.ErrorExtractedFiles) {
				t.Error("bounding a bounded report changed its errors")
			}
			if got := ListedErrors(once.ErrorExtractedFiles); got > MaxListedSubfiles {
				t.Errorf("%d entries listed, want at most %d", got, MaxListedSubfiles)
			}
			if got := failuresOf(once.ErrorExtractedFiles); got != total {
				t.Errorf("listed plus not listed = %d, want %d", got, total)
			}
		})
	}
}

// Two names that differ only in bytes that are not UTF-8 are two entries in the
// JSON of a report too: encoding/json writes both with U+FFFD, and a decoder
// keeps the last of two equal keys.
func TestReportBound_invalidUTF8ErrorKeysStayDistinctInJSON(t *testing.T) {
	errs := map[string]string{
		"a\xffb":                          "one",
		"a\xfeb":                          "two",
		"a�b":                             "three",
		strings.Repeat("\xff", 400):       "long one",
		strings.Repeat("\xfe", 400):       "long two",
		"ok.txt":                          "fine",
		strings.Repeat("\xff", 2000):      "over the limit one",
		strings.Repeat("\xfe", 2000):      "over the limit two",
		strings.Repeat("é", 600) + "\xff": "mixed",
	}
	r := Report{ErrorExtractedFiles: maps.Clone(errs)}
	r.Bound()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var back Report
	if err = json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.ErrorExtractedFiles) != len(errs) {
		t.Fatalf("%d entries after the JSON round trip, want %d", len(back.ErrorExtractedFiles), len(errs))
	}
	values := map[string]bool{}
	for k, v := range back.ErrorExtractedFiles {
		if !utf8.ValidString(k) || len(k) > MaxListedNameLen {
			t.Errorf("key %q is not valid UTF-8 within %d bytes", k[:min(len(k), 20)], MaxListedNameLen)
		}
		values[v] = true
	}
	for _, v := range errs {
		if !values[v] {
			t.Errorf("the error %q is lost", v)
		}
	}
}

func TestUniqueKey_aNameThatIsNotUTF8IsReadableAndKeptApart(t *testing.T) {
	taken := map[string]string{}
	one := UniqueKey("a\xffb", taken, nil)
	taken[one] = "x"
	two := UniqueKey("a\xfeb", taken, nil)
	if one == two {
		t.Fatalf("two names that differ in an invalid byte got the key %q", one)
	}
	for _, k := range []string{one, two} {
		if !strings.HasPrefix(k, "a�b-") || !utf8.ValidString(k) {
			t.Errorf("key %q is not the readable name and a hash", k)
		}
	}
	if valid := UniqueKey("a�b", taken, nil); valid != "a�b" {
		t.Errorf("a valid name became %q", valid)
	}
}

// The count of the failed files not listed is kept by the bound, whatever the
// names sort like, and counts what the bound leaves out itself: the entries
// listed and the count make the number of failed files.
func TestReportBound_theMoreErrorsKeySurvivesAndCountsWhatItDrops(t *testing.T) {
	const alreadyNotListed = 4
	errs := map[string]string{MoreErrorsKey: MoreErrorsText(alreadyNotListed)}
	for i := range MaxListedSubfiles {
		errs[fmt.Sprintf("f%04d", i)] = "e"
	}
	errs["\u2027after"] = "sorts after the sentinel"
	total := alreadyNotListed + MaxListedSubfiles + 1
	r := Report{ErrorExtractedFiles: errs}
	r.Bound()
	if got := ListedErrors(r.ErrorExtractedFiles); got != MaxListedSubfiles {
		t.Errorf("%d entries listed, want the cap of %d", got, MaxListedSubfiles)
	}
	if _, ok := r.ErrorExtractedFiles[MoreErrorsKey]; !ok || len(r.ErrorExtractedFiles) != MaxListedSubfiles+1 {
		t.Errorf("%d entries, want the cap and the count of the others", len(r.ErrorExtractedFiles))
	}
	if got := failuresOf(r.ErrorExtractedFiles); got != total {
		t.Errorf("listed plus not listed = %d, want the %d failed files", got, total)
	}
}

// What the scanner makes for an archive with 1500 failed members (1000 listed and
// a count of 500) goes through the bound as it is: both cap the entries listed.
func TestReportBound_aFullMapOfTheScannerIsKeptAsItIs(t *testing.T) {
	const failed = 1500
	errs := map[string]string{MoreErrorsKey: MoreErrorsText(failed - MaxListedSubfiles)}
	for i := range MaxListedSubfiles {
		errs[fmt.Sprintf("f%04d", i)] = "e"
	}
	r := Report{ErrorExtractedFiles: maps.Clone(errs)}
	r.Bound()
	if !maps.Equal(r.ErrorExtractedFiles, errs) {
		t.Errorf("the map changed: %d entries, count %q", len(r.ErrorExtractedFiles), r.ErrorExtractedFiles[MoreErrorsKey])
	}
	if got := failuresOf(r.ErrorExtractedFiles); got != failed {
		t.Errorf("listed plus not listed = %d, want %d", got, failed)
	}
}

// Bound makes the sentinel itself when it leaves entries out and there was none.
func TestReportBound_makesTheMoreErrorsKeyWhenItDropsEntries(t *testing.T) {
	const failed = MaxListedSubfiles + 7
	errs := map[string]string{}
	for i := range failed {
		errs[fmt.Sprintf("f%04d", i)] = "e"
	}
	r := Report{ErrorExtractedFiles: errs}
	r.Bound()
	if got := ListedErrors(r.ErrorExtractedFiles); got != MaxListedSubfiles {
		t.Errorf("%d entries listed, want %d", got, MaxListedSubfiles)
	}
	if got := failuresOf(r.ErrorExtractedFiles); got != failed {
		t.Errorf("listed plus not listed = %d, want %d", got, failed)
	}
}

// Nothing is left out, nothing is added: no sentinel appears for a few entries.
func TestReportBound_noMoreErrorsKeyWhenNothingIsDropped(t *testing.T) {
	r := Report{ErrorExtractedFiles: map[string]string{"a": "x", "b": "y"}}
	r.Bound()
	if _, ok := r.ErrorExtractedFiles[MoreErrorsKey]; ok || len(r.ErrorExtractedFiles) != 2 {
		t.Errorf("errors = %v", r.ErrorExtractedFiles)
	}
}

func TestParseMoreErrors(t *testing.T) {
	for _, n := range []int{0, 1, 500, 123456} {
		if got := ParseMoreErrors(MoreErrorsText(n)); got != n {
			t.Errorf("ParseMoreErrors(MoreErrorsText(%d)) = %d", n, got)
		}
	}
	if got := ParseMoreErrors(MoreErrorsText(MaxFileCount + 5)); got != MaxFileCount {
		t.Errorf("a count over the bound reads %d, want %d", got, MaxFileCount)
	}
	// Past the clamp, whatever the size of an int: these must not read as 0 on 32 bits.
	for _, v := range []string{"1073741825 more", "2147483648 more", "4294967296 more", "9999999999 more"} {
		if got := ParseMoreErrors(v); got != MaxFileCount {
			t.Errorf("ParseMoreErrors(%q) = %d, want the clamp %d", v, got, MaxFileCount)
		}
	}
	if got := ParseMoreErrors("1073741824 more"); got != MaxFileCount {
		t.Errorf("the clamp itself reads %d, want %d", got, MaxFileCount)
	}
	if got := ParseMoreErrors("1073741823 more"); got != MaxFileCount-1 {
		t.Errorf("just under the clamp reads %d, want %d", got, MaxFileCount-1)
	}
	if got := ParseMoreErrors("99999999999999999999999 more"); got != MaxFileCount {
		t.Errorf("an overflowing count reads %d, want %d", got, MaxFileCount)
	}
	if got := ParseMoreErrors("0000000000005 more"); got != 5 {
		t.Errorf("a count with leading zeros reads %d, want 5", got)
	}
	if got := ParseMoreErrors("0000 more"); got != 0 {
		t.Errorf("a count of zeros reads %d, want 0", got)
	}
	for _, v := range []string{"", "many more", "-3 more", "x", "+5 more", "5", "5x more", " 5"} {
		if got := ParseMoreErrors(v); got != 0 {
			t.Errorf("ParseMoreErrors(%q) = %d, want 0", v, got)
		}
	}
}

// A member named like the sentinel is listed under another key.
func TestUniqueKey_aMemberNamedLikeTheSentinelIsRenamed(t *testing.T) {
	got := UniqueKey(MoreErrorsKey, map[string]string{}, nil)
	if got == MoreErrorsKey || !strings.HasPrefix(got, MoreErrorsKey+"-") {
		t.Errorf("a member named like the sentinel got the key %q", got)
	}
}

// The cuts that fit a report to its size keep the count of the failed files
// whole: the entries they drop are added to it, and it is made if there was none.
func TestShrinkErrors_theCountOfTheFailedFilesStaysWhole(t *testing.T) {
	const listed, already = 50, 10
	for name, withSentinel := range map[string]bool{"with the sentinel": true, "the sentinel made by the cut": false} {
		t.Run(name, func(t *testing.T) {
			errs := map[string]string{}
			total := listed
			for i := range listed {
				errs[fmt.Sprintf("f%02d", i)] = "e"
			}
			if withSentinel {
				errs[MoreErrorsKey] = MoreErrorsText(already)
				total += already
			}
			for _, keep := range []float64{0.9, 0.5, 0.1, 0} {
				got := shrinkErrors(maps.Clone(errs), keep)
				if sum := failuresOf(got); sum != total {
					t.Errorf("keep %v: listed plus not listed = %d, want %d", keep, sum, total)
				}
			}
		})
	}
}

// A report over its size is cut where the errors are: the bulk of the other lists
// puts it over 4 MiB, the errors are cut, and what is cut is counted: the
// entries listed and the count are the failed files that there were.
func TestReportBound_whenTheErrorsAreCutTheCountKeepsThemAll(t *testing.T) {
	long := strings.Repeat("x", MaxListedNameLen)
	r := Report{ErrorExtractedFiles: map[string]string{}}
	for i := range MaxListedSubfiles {
		r.ErrorExtractedFiles[fmt.Sprintf("%04d%s", i, long[:700])] = long
		r.MaliciousExtractedFiles = append(r.MaliciousExtractedFiles, ExtractedFile{
			FileName: fmt.Sprintf("m%04d%s", i, long[:700]), SHA256: long, GMalwareURL: long,
		})
	}
	before := Report{ErrorExtractedFiles: maps.Clone(r.ErrorExtractedFiles), MaliciousExtractedFiles: slices.Clone(r.MaliciousExtractedFiles)}
	if size := before.encodedSize(); size <= MaxReportSize {
		t.Fatalf("setup: the report is %d bytes, want it over %d", size, MaxReportSize)
	}
	r.Bound()
	if size := r.encodedSize(); size > MaxReportSize {
		t.Fatalf("encoded report = %d bytes, want <= %d", size, MaxReportSize)
	}
	if got := ListedErrors(r.ErrorExtractedFiles); got >= MaxListedSubfiles {
		t.Errorf("%d errors still listed: the cut did not reach them", got)
	}
	if got := failuresOf(r.ErrorExtractedFiles); got != MaxListedSubfiles {
		t.Errorf("listed plus not listed = %d, want %d", got, MaxListedSubfiles)
	}
}

// The last resort, which empties the lists, keeps the number of failed files.
func TestShrinkToFit_theLastResortKeepsTheCountOfTheFailedFiles(t *testing.T) {
	r := Report{
		Filename:            strings.Repeat("f", MaxReportSize+1),
		ErrorExtractedFiles: map[string]string{"a": "x", "b": "y", "c": "z", MoreErrorsKey: MoreErrorsText(10)},
		Malwares:            []string{"m"},
	}
	r.shrinkToFit()
	if r.Malwares != nil || r.MaliciousExtractedFiles != nil || r.NotAnalyzedExtractedFiles != nil {
		t.Error("the lists are not emptied")
	}
	if got := failuresOf(r.ErrorExtractedFiles); got != 13 || ListedErrors(r.ErrorExtractedFiles) != 0 {
		t.Errorf("errors = %v, want only the count of the 13 failed files", r.ErrorExtractedFiles)
	}
	none := Report{Filename: strings.Repeat("f", MaxReportSize+1)}
	none.shrinkToFit()
	if none.ErrorExtractedFiles != nil {
		t.Errorf("a report without failures got errors: %v", none.ErrorExtractedFiles)
	}
}

// failuresOf is the number of failed files a map of errors stands for, as a
// reader of a report works it out: an oracle that does not share the helper the
// code uses (failureCount), so that a mistake there is not hidden by the test.
func failuresOf(errs map[string]string) int {
	return ListedErrors(errs) + ParseMoreErrors(errs[MoreErrorsKey])
}

func TestCutText(t *testing.T) {
	if got := CutText("short", 10); got != "short" {
		t.Errorf("CutText(short) = %q", got)
	}
	got := CutText(strings.Repeat("é", 10), 5)
	if got != truncationMark {
		t.Errorf("CutText under the length of the mark = %q, want the mark alone", got)
	}
	got = CutText(strings.Repeat("é", 100), 50)
	if len(got) > 50 || !strings.HasSuffix(got, truncationMark) || !utf8.ValidString(got) {
		t.Errorf("CutText = %q (%d bytes)", got, len(got))
	}
}

// The search for a free counter stops: a map that would hold more keys than it
// can (everything is taken) gets a valid key in a bounded number of lookups, not a
// loop under the lock of the caller.
func TestUniqueKey_theSearchForACounterIsBounded(t *testing.T) {
	name := strings.Repeat("n", MaxListedNameLen+50)
	var lookups int
	everythingTaken := func(string) bool { lookups++; return true }
	key := uniqueKey(name, everythingTaken, map[string]int{})
	if limit := maxCounterTries + 3; lookups > limit {
		t.Errorf("%d lookups, want at most %d", lookups, limit)
	}
	if len(key) > MaxListedNameLen || !utf8.ValidString(key) {
		t.Errorf("the key is %d bytes or not valid UTF-8", len(key))
	}
	for _, name := range []string{"short", "a\xffb"} {
		lookups = 0
		got := uniqueKey(name, everythingTaken, nil)
		if lookups > maxCounterTries+3 || len(got) > MaxListedNameLen || !utf8.ValidString(got) {
			t.Errorf("%q: %d lookups, key of %d bytes", name, lookups, len(got))
		}
	}
}

// Past the bound the counter is kept to the room it has, so that the key stays
// within the limit even when the precondition is broken.
func TestUniqueKey_theFallbackCounterStaysWithinTheRoomForIt(t *testing.T) {
	name := strings.Repeat("n", 2*MaxListedNameLen)
	base := uniqueKey(name, func(string) bool { return false }, nil)
	everythingTaken := func(string) bool { return true }
	got := uniqueKey(name, everythingTaken, map[string]int{base: 1 << 30})
	if len(got) > MaxListedNameLen {
		t.Errorf("a key of %d bytes, over %d", len(got), MaxListedNameLen)
	}
	if want := base + counterMark + strconv.Itoa(maxCounter); got != want {
		t.Errorf("the counter is not clamped: key ends %q, want %q", got[len(got)-12:], want[len(want)-12:])
	}
	limit := 1
	for range countDigits {
		limit *= 10
	}
	if maxCounter != limit-1 {
		t.Errorf("maxCounter = %d, want the largest number of %d digits (%d)", maxCounter, countDigits, limit-1)
	}
}

func TestAddCount(t *testing.T) {
	tests := []struct {
		name string
		a, b int
		want int
	}{
		{"small counts", 3, 4, 7},
		{"zero", 0, 0, 0},
		{"to the ceiling exactly", MaxFileCount - 1, 1, MaxFileCount},
		{"one under, plus two", MaxFileCount - 1, 2, MaxFileCount},
		{"one under, plus nothing", MaxFileCount - 1, 0, MaxFileCount - 1},
		{"two halves just under the ceiling", MaxFileCount/2 - 1, MaxFileCount / 2, MaxFileCount - 1},
		{"two halves, exactly the ceiling", MaxFileCount / 2, MaxFileCount / 2, MaxFileCount},
		{"over the ceiling", MaxFileCount, 1, MaxFileCount},
		{"two counts at the ceiling", MaxFileCount, MaxFileCount, MaxFileCount},
		{"an absurd count", math.MaxInt, 5, MaxFileCount},
		{"two absurd counts", math.MaxInt, math.MaxInt, MaxFileCount},
		{"a negative count counts for nothing", -5, 3, 3},
		{"two negative counts", math.MinInt, -1, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AddCount(tt.a, tt.b); got != tt.want {
				t.Errorf("AddCount(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// The count of the files not analyzed that a report or a plugin gives is kept to
// the ceiling, and never under the files listed.
func TestReportBound_theCountOfTheFilesNotAnalyzedHasACeiling(t *testing.T) {
	for _, tt := range []struct {
		name        string
		count, want int
	}{
		{"absurd", math.MaxInt, MaxFileCount},
		{"at the ceiling", MaxFileCount, MaxFileCount},
		{"negative", -3, 2},
		{"under the listed", 1, 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := Report{NotAnalyzedExtractedCount: tt.count, NotAnalyzedExtractedFiles: []NotAnalyzedFile{{FileName: "a"}, {FileName: "b"}}}
			r.Bound()
			if r.NotAnalyzedExtractedCount != tt.want {
				t.Errorf("count = %d, want %d", r.NotAnalyzedExtractedCount, tt.want)
			}
		})
	}
}
