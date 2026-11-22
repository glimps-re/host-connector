//go:build linux

// Package test holds the acceptance tests that run the real binary against a
// fake GLIMPS Malware Detect and a fake console.
//
// A verdict counts as given by the fake GLIMPS Malware Detect only when its
// answer was written and flushed and the request was still alive: what the
// server cannot see is a connector that received the bytes and dropped them.
//
// The scenarios need the e2e build tag. The shutdown tests and the self-tests
// of the invariant, the fakes and the helpers carry only the linux tag, so a
// plain `go test ./test/` runs them too, and so does `go test ./...`: the 6
// shutdown tests build GMHost and the plugins (cgo, 7zzs), and -short skips
// them. The full suite takes longer than the default 10-minute timeout of go
// test, so set one:
//
//	go test -race -tags e2e -timeout 30m ./test/
//
// Prerequisites: the Go toolchain with cgo, and cmd/plugins/extract/7zzs (the
// extract plugin embeds it, the build fails without it). The browser scenarios
// need chromium, chromium-browser or google-chrome in the PATH, run as a
// non-root user (Chrome refuses root); they are skipped when it is absent, or
// fail with E2E_REQUIRE_BROWSER=1.
//
// Each scenario ends with the OUTPUT invariant (invariant_test.go), even when
// it fails early.
//
// The scenarios are described in docs/e2e-tests.md.
package test
