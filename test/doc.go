//go:build linux

// Package test holds the acceptance tests that run the real binary against a
// fake GLIMPS Malware Detect and a fake console.
//
// A verdict counts as given by the fake GLIMPS Malware Detect only when its
// answer was written and flushed and the request was still alive: what the
// server cannot see is a connector that received the bytes and dropped them.
//
// Layout:
//
//	internal/harness         build, instance, invariant, shared helpers
//	internal/fakes/errlog    what the fakes failed to read or write
//	internal/fakes/gmalware  the fake GLIMPS Malware Detect
//	internal/fakes/console   the fake console
//	core                     scenarios of the core (session plugin only)
//	plugins                  scenarios that enable extract, report or
//	                         filetype_filter, or assert the session plugin
//
// The scenarios need a build tag: e2e for both packages, e2e_core or
// e2e_plugins for one of them. The three browser scenarios also need the
// realbrowser tag, and fail without a browser or when run as root. Every file
// under internal carries at most the linux tag, so a plain `go test ./test/...`
// runs the self-tests of the harness and the fakes, and the tests of the
// document builders of plugins, without building GMHost. Set a timeout above
// the default 10 minutes of go test:
//
//	go test -race -tags e2e -p 1 -parallel 4 -timeout 30m ./test/...
//	go test -race -tags e2e_core -parallel 4 -timeout 30m ./test/core/
//	go test -race -tags e2e_plugins -parallel 4 -timeout 30m ./test/plugins/
//
// The scenarios written with harness.Run run in parallel; -parallel bounds how
// many connectors run at once. -p 1 runs one package at a time, so the tests
// that stay serial (timing-sensitive ones) never share the machine with the
// scenarios of the other package.
//
// GMHost and the plugins are built once into the user cache folder
// (gmhost-e2e/<key>), shared by both packages and by later runs. The key hashes
// the toolchain and every file of the repository but test/, docs/, hidden
// folders, *_test.go and *.md: a change to the product code rebuilds, a change
// to a test does not. Only the latest build is kept.
//
// Prerequisites: the Go toolchain with cgo, and cmd/plugins/extract/7zzs (the
// extract plugin embeds it, the build fails without it).
//
// Each scenario ends with the OUTPUT invariant (internal/harness/invariant.go),
// even when it fails early.
//
// The scenarios are described in docs/e2e-tests.md.
package test
