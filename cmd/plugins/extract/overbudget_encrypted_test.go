package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/glimps-re/host-connector/pkg/plugins"
)

// overBudgetTechnical is the technical listing of a 7z archive of n members, of
// which flags[i] is the Encrypted line of member i ("" for no line at all).
func overBudgetTechnical(n int, flags, extra, tail map[int]string) string {
	var b strings.Builder
	b.WriteString("7-Zip 25.01\n\nListing archive: a.7z\n\n--\nPath = a.7z\nType = 7z\nPhysical Size = 100\n\n----------\n")
	for i := range n {
		fmt.Fprintf(&b, "Path = f%d\nFolder = -\n", i)
		b.WriteString(extra[i])
		flag, ok := flags[i]
		if !ok {
			flag = "-"
		}
		if flag != "" {
			fmt.Fprintf(&b, "Encrypted = %s\n", flag)
		}
		b.WriteString("Method = LZMA2:12\n")
		b.WriteString(tail[i])
		b.WriteString("\n")
	}
	return b.String()
}

func overBudgetPlugin(t *testing.T, tableMembers int, technical string) *SevenZipExtractPlugin {
	t.Helper()
	lines := make([]string, tableMembers)
	for i := range lines {
		lines[i] = listingLine(fmt.Sprintf("f%d", i), 0)
	}
	sze := fakeWithListings(t, listing(nil, lines...), technical)
	return &SevenZipExtractPlugin{sze: sze, logger: sze.logger, consoleLogger: sze.logger}
}

var overBudgetLimits = plugins.ExtractLimits{MaxFiles: 2, MaxTotalSize: 1 << 30, CheckOnly: true}

func TestCheckOnly_aListingOverTheBudgetFollowsItsTechnicalListing(t *testing.T) {
	tests := []struct {
		name         string
		technical    string
		wantErr      error
		wantPossible bool
		wantSkipped  int
	}{
		{"all plain", overBudgetTechnical(5, nil, nil, nil), nil, false, 5},
		{"one member encrypted", overBudgetTechnical(5, map[int]string{4: "+"}, nil, nil), plugins.ErrEncrypted, false, 0},
		{"a block without an Encrypted line", overBudgetTechnical(5, map[int]string{2: ""}, nil, nil), plugins.ErrArchiveAnomaly, true, 0},
		{"a flag that is neither + nor -", overBudgetTechnical(5, map[int]string{1: "?"}, nil, nil), plugins.ErrArchiveAnomaly, true, 0},
		{"fewer members than listed", overBudgetTechnical(4, nil, nil, nil), plugins.ErrArchiveAnomaly, true, 0},
		{"no member at all", "7-Zip 25.01\n\n--\nPath = a.7z\nType = 7z\n", plugins.ErrArchiveAnomaly, true, 0},
		{"an AES method with the flag cleared", strings.Replace(overBudgetTechnical(5, nil, nil, nil), "Method = LZMA2:12", "Method = AES-256 Store", 1), plugins.ErrEncrypted, false, 0},
		{"a forged AES method in a comment after the real one is only a false positive", overBudgetTechnical(5, nil, nil, map[int]string{2: "Comment = x\nMethod = AES-256\n"}), plugins.ErrEncrypted, false, 0},
		{"a forged plain method before the real AES one does not hide it", replaceNth(overBudgetTechnical(5, nil, map[int]string{2: "Comment = x\nMethod = Store\n"}, nil), "Method = LZMA2:12", "Method = AES-256 Store", 3), plugins.ErrEncrypted, false, 0},
		{"a forged AES method in the comment of the archive is not believed", strings.Replace(overBudgetTechnical(5, nil, nil, nil), "Physical Size = 100\n", "Comment = x\nMethod = AES-256\nPhysical Size = 100\n", 1), nil, false, 5},
		{"a forged AES method as the first line of a block is only a false positive", overBudgetTechnical(5, nil, map[int]string{2: "Method = AES-256\n"}, nil), plugins.ErrEncrypted, false, 0},
		{"a forged line in the comment of the archive is not believed", strings.Replace(overBudgetTechnical(5, nil, nil, nil), "Physical Size = 100\n", "Comment = x\nEncrypted = +\nType = zip\nPhysical Size = 100\n", 1), nil, false, 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin := overBudgetPlugin(t, 5, tt.technical)
			got, err := plugin.ExtractFile(fakeArchiveNamed(t, "a.7z"), t.TempDir(), overBudgetLimits)
			if tt.wantErr == nil {
				if err != nil || got.SkippedCount != tt.wantSkipped {
					t.Fatalf("ExtractFile() = %+v, %v, want %d skipped and no error", got, err, tt.wantSkipped)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
			if possible := errors.Is(err, plugins.ErrEncryptionPossible); possible != tt.wantPossible {
				t.Errorf("encryption possible = %t, want %t (%v)", possible, tt.wantPossible, err)
			}
			if errors.Is(tt.wantErr, plugins.ErrEncrypted) && errors.Is(err, plugins.ErrArchiveAnomaly) {
				t.Errorf("an encrypted member is not an anomaly: %v", err)
			}
		})
	}
}

// A second member field before the first member, or a second separator, is a
// forged listing: held as an anomaly, never delivered.
func TestCheckOnly_aForgedTechnicalListingOverTheBudgetIsAnAnomaly(t *testing.T) {
	forged := overBudgetTechnical(5, nil, map[int]string{2: "----------\n"}, nil)
	plugin := overBudgetPlugin(t, 5, forged)
	_, err := plugin.ExtractFile(fakeArchiveNamed(t, "a.7z"), t.TempDir(), overBudgetLimits)
	if !errors.Is(err, plugins.ErrArchiveAnomaly) || !errors.Is(err, plugins.ErrEncryptionPossible) {
		t.Fatalf("error = %v, want an anomaly with the encryption possible", err)
	}
}

// A timeout of the second pass is not a verdict on the document: it is retried,
// neither encrypted nor damaged.
func TestCheckOnly_aTimeoutOfTheTechnicalListingOverTheBudgetIsNotAVerdict(t *testing.T) {
	lines := []string{listingLine("f0", 0), listingLine("f1", 0), listingLine("f2", 0)}
	for name, wantErr := range map[string]error{"deadline": context.DeadlineExceeded, "cancel": context.Canceled} {
		t.Run(name, func(t *testing.T) {
			sze := fakeWithListings(t, listing(nil, lines...), overBudgetTechnical(3, nil, nil, nil))
			sze.sevenZipPath = slowTechnical(t, sze.sevenZipPath)
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			if errors.Is(wantErr, context.Canceled) {
				ctx, cancel = context.WithCancel(t.Context())
				defer cancel()
				time.AfterFunc(time.Second, cancel)
			}
			_, err := sze.checkOnly(ctx, fakeArchiveNamed(t, "a.7z"), plugins.ExtractLimits{MaxFiles: 1, MaxTotalSize: 1 << 30, CheckOnly: true})
			if !errors.Is(err, wantErr) || errors.Is(err, ErrInvalidPassword) || errors.Is(err, plugins.ErrArchiveAnomaly) {
				t.Fatalf("error = %v, want %v, neither encrypted nor an anomaly", err, wantErr)
			}
		})
	}
}

// slowTechnical is a 7z that never answers `l -slt`, and is otherwise the one given.
func slowTechnical(t *testing.T, target string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "7zslow")
	body := "#!/bin/sh\nfor a in \"$@\"; do [ \"$a\" = -slt ] && exec sleep 30; done\nexec " + target + " \"$@\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, modeScript); err != nil {
		t.Fatal(err)
	}
	return path
}

// An extractor that cannot run during the second pass is a failure of the host,
// retried: not damage, which as_file with encrypted: pass could deliver.
func TestCheckOnly_anUnavailableExtractorDuringTheTechnicalListingIsRetried(t *testing.T) {
	lines := []string{listingLine("f0", 0), listingLine("f1", 0), listingLine("f2", 0)}
	sze := fakeWithListings(t, listing(nil, lines...), overBudgetTechnical(3, nil, nil, nil))
	path := filepath.Join(t.TempDir(), "7zgone")
	body := "#!/bin/sh\nrm -f \"$0\"\nexec " + sze.sevenZipPath + " \"$@\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, modeScript); err != nil {
		t.Fatal(err)
	}
	sze.sevenZipPath = path
	_, err := sze.checkOnly(t.Context(), fakeArchiveNamed(t, "a.7z"), plugins.ExtractLimits{MaxFiles: 1, MaxTotalSize: 1 << 30, CheckOnly: true})
	if !errors.Is(err, plugins.ErrExtractorUnavailable) || errors.Is(err, plugins.ErrArchiveAnomaly) || errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("error = %v, want ErrExtractorUnavailable, neither an anomaly nor encrypted", err)
	}
}

// replaceNth replaces the n-th (1-based) occurrence of old.
func replaceNth(s, old, repl string, n int) string {
	parts := strings.SplitAfter(s, old)
	if len(parts) <= n {
		return s
	}
	parts[n-1] = strings.TrimSuffix(parts[n-1], old) + repl
	return strings.Join(parts, "")
}

// A member that names AES as its method is not plain, whatever its Encrypted line
// says: the proof that an archive holds no encrypted content must not hold.
func TestExcludesEncryption_anAESMethodIsNotPlain(t *testing.T) {
	tests := map[string]struct {
		technical string
		want      bool
	}{
		"all plain":                    {overBudgetTechnical(1, nil, nil, nil), true},
		"an AES method, flag cleared":  {strings.Replace(overBudgetTechnical(1, nil, nil, nil), "Method = LZMA2:12", "Method = AES-256 Store", 1), false},
		"an AES method in a comment":   {overBudgetTechnical(1, nil, nil, map[int]string{0: "Comment = x\nMethod = AES-256\n"}), false},
		"an AES line in the archive's": {strings.Replace(overBudgetTechnical(1, nil, nil, nil), "Physical Size = 100\n", "Method = AES-256\nPhysical Size = 100\n", 1), true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			sze := listingSevenZip(t, tt.technical)
			if got := sze.excludesEncryption(t.Context(), "a.7z", provable()); got != tt.want {
				t.Errorf("excludesEncryption() = %t, want %t", got, tt.want)
			}
		})
	}
}
