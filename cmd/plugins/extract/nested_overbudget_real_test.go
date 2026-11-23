//go:build linux

package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/pkg/scanner"
)

// A document inside an archive gets the budget its parent left: a parent filled to
// the limit leaves it none, with no padding of the document itself. The check of
// the document must still tell an encrypted member (review F1 of T62).
func TestNested_aDocumentOverTheBudgetOfItsParentIsStillCheckedForEncryption(t *testing.T) {
	const outerFiles = 20
	build := func(t *testing.T, inner []byte) []byte {
		members := map[string][]byte{"inner.docx": inner}
		for i := range outerFiles {
			members[fmt.Sprintf("f%03d.txt", i)] = []byte(fmt.Sprintf("plain file %d", i))
		}
		return t17Zip(t, members)
	}
	encrypted := withEncryptedMember(t, packageZip(t, "docx"), "ZipCrypto")
	plain := packageZip(t, "docx")
	// The outer archive has outerFiles+1 members: the budget left to the document is
	// maxFiles-(outerFiles+1). A spent budget (negative, clamped to 0) goes through
	// the same check; it is pinned by the scanner unit tests, since an outer archive
	// over the budget is itself left out before its document is reached.
	for name, maxFiles := range map[string]int{"budget of 1 left": outerFiles + 2, "budget of 0 left": outerFiles + 1} {
		t.Run(name+"/encrypted member", func(t *testing.T) {
			r := runT17(t, t17Setup{name: "outer.zip", content: build(t, encrypted), maxFiles: maxFiles})
			if r.exists(r.out, "outer.zip") || !r.exists(r.in, "outer.zip") || r.submissionsOf("outer.zip") != 0 {
				t.Errorf("the outer archive must stay in INPUT and never reach OUTPUT (in %t, out %t)", r.exists(r.in, "outer.zip"), r.exists(r.out, "outer.zip"))
			}
		})
		// An encrypted member follows the encrypted policy, not extract_error: under
		// encrypted: pass the operator accepts it, and the archive goes through.
		t.Run(name+"/encrypted member under encrypted pass", func(t *testing.T) {
			r := runT17(t, t17Setup{name: "outer.zip", content: build(t, encrypted), maxFiles: maxFiles, policy: scanner.Unanalyzable{Encrypted: scanner.PolicyPass}})
			if !r.exists(r.out, "outer.zip") {
				t.Error("under encrypted: pass the archive must be delivered, as an encrypted member and not as damage")
			}
		})
		t.Run(name+"/plain document", func(t *testing.T) {
			r := runT17(t, t17Setup{name: "outer.zip", content: build(t, plain), maxFiles: maxFiles})
			got := r.one(t, "outer.zip")
			if got.result.Error != nil || got.result.Malware || !r.exists(r.out, "outer.zip") {
				t.Fatalf("result = %+v, delivered %t, want the outer archive delivered", got.result, r.exists(r.out, "outer.zip"))
			}
			var listed int
			for _, f := range got.result.NotAnalyzedSubfiles {
				if strings.HasPrefix(f.FileName, "inner.docx/") && f.Reason == datamodel.NotAnalyzedExtractLimit {
					listed++
				}
			}
			if listed != 3 {
				t.Errorf("members of the document listed under it = %d in %+v, want 3", listed, got.result.NotAnalyzedSubfiles)
			}
		})
	}
}
