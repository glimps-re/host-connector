//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"testing"
)

// corpusEnv names the directory of real archives the corpus test walks: signed APKs,
// which pad their entries with zeros before a signing block. They are read for their
// listing and headers only, never run, and none is committed; the test is skipped
// when the variable is not set. With corpusEnv+"_ALL" set to any value it walks
// every *.apk of the directory instead of the samples below, whatever their names.
const corpusEnv = "GLIMPS_APK_CORPUS"

// corpusAPKs are the SHA256 of the signed APKs the test is held to: one of them has
// a gap of 2 994 zero bytes between entries, and five pad with 316 to 11 180 zero
// bytes before a signing block that is aligned to 4096.
var corpusAPKs = []string{
	"3a91e5ace8cbd8a29968bd400c63f893d4300422a17db9d0df2162f49d1c0388",
	"49f8eb9779b3096ca81339c7a6d3cad6a8fc20b3d91ffe103c19935d330ad0aa",
	"63f2a545be1cc0cba6fb103f5429c5b9a7470e2939c57fc04810811e01f77ccf",
	"75f804d346dc48de24e447e262da09b75bb20405095bcee2ab2a775800158ef9",
	"9fff83aa30ea383794ceb84e5fd1a7b7594f1ea1a34fe8ae114505d5e3d9d362",
}

func TestWalkZip_realSignedAPKs(t *testing.T) {
	dir := os.Getenv(corpusEnv)
	if dir == "" {
		t.Skipf("%s is not set", corpusEnv)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("%s is set to %q: %v", corpusEnv, dir, err)
	}
	t.Cleanup(func() {
		if cerr := root.Close(); cerr != nil {
			t.Error(cerr)
		}
	})
	names := make([]string, 0, len(corpusAPKs))
	for _, sha := range corpusAPKs {
		names = append(names, sha+".apk")
	}
	all := os.Getenv(corpusEnv+"_ALL") != ""
	if all {
		var globErr error
		if names, globErr = fs.Glob(root.FS(), "*.apk"); globErr != nil || len(names) == 0 {
			t.Fatalf("no *.apk in %q (%v)", dir, globErr)
		}
	}
	plugin := realPlugin(t)
	ran := 0
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			f, err := root.Open(name)
			if err != nil {
				t.Fatalf("not in the corpus: %v", err)
			}
			defer func() {
				if cerr := f.Close(); cerr != nil {
					t.Error(cerr)
				}
			}()
			hash := sha256.New()
			if _, err = io.Copy(hash, io.LimitReader(f, 1<<30)); err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(hash.Sum(nil)); !all && got+".apk" != name {
				t.Fatalf("the file has the SHA256 %s: it is not the sample the name says", got)
			}
			info, err := f.Stat()
			if err != nil {
				t.Fatal(err)
			}
			sink := newListSink(1<<62, 1_000_000, 1<<62)
			if err = plugin.sze.list(t.Context(), f.Name(), nil, sink); err != nil {
				t.Skipf("7-Zip does not list it: %v", err)
			}
			if sink.archiveType != zipType {
				t.Skipf("7-Zip types it %q", sink.archiveType)
			}
			ran++
			if _, err = walkZip(t.Context(), f, info.Size(), sink.table.entries, sink.table.folders); err != nil {
				t.Errorf("walkZip() = %v, want the signed APK accepted", err)
			}
		})
	}
	if !all && ran != len(corpusAPKs) {
		t.Fatalf("%d of the %d samples were walked", ran, len(corpusAPKs))
	}
}
