# End-to-end test suite

This page describes what the suite in `test/` covers, how it is built, and what
it leaves out. It is written for developers and reviewers. How to run it is in
`test/doc.go` and in the "Testing" section of the README; section 1 only
recalls what is needed to read the rest.

## 1. Purpose and how to run

The suite runs the real GMHost binary, as an operator would, against a fake
GLIMPS Malware Detect (GMalware) and a fake console. Files are dropped in
INPUT; the scenarios then check where each file ends up (OUTPUT, the
quarantine, or still in INPUT), what the session reports say, what the service
was sent and what the console was told.

In short (see `test/doc.go` for the details and the prerequisites):

```bash
go test -race -tags e2e -p 1 -parallel 4 -timeout 30m ./test/...
go test -race -tags e2e_core -parallel 4 -timeout 30m ./test/core/
go test -race -tags e2e_plugins -parallel 4 -timeout 30m ./test/plugins/
```

Four points to keep in mind:

- The scenarios of `test/core` carry `linux && (e2e || e2e_core)`, those of
  `test/plugins` `linux && (e2e || e2e_plugins)`. The two browser scenarios
  (`plugins/report_test.go`) also need `realbrowser`. Every file of
  `test/internal` carries only `linux`, and so do the tests of the document
  builders (`plugins/documents_test.go`): a plain `go test ./test/...` runs
  these 21 self-tests and builds no binary; 110 tests with
  `-tags e2e,realbrowser`.
- The binary and the plugins are built once, into `gmhost-e2e/<key>` in the
  user cache folder, and reused by both packages and by later runs until the
  product code changes (section 2). Without the 7-Zip binary in
  `cmd/plugins/extract/7zzs` that build fails.
- The scenarios written with `harness.Run` run in parallel; `-parallel` bounds
  how many connectors run at once. The tests that start an instance by hand stay
  serial: Go runs them first, alone. `-p 1` runs one package at a time, so they
  never share the machine with the scenarios of the other package.
- A scenario is in `plugins` when it enables a plugin beyond the always-loaded
  `session` (`extract`, `report`, `filetype_filter`) or asserts a behaviour of
  the session plugin (its `delay`, `max_duration`, `max_spool_size`,
  `remove_empty_dirs`, `inflight_timeout`, spool); otherwise it is in `core`.

## 2. Architecture: what is real and what is simulated

### Real

- **GMHost and its plugins.** `buildAll` (`internal/harness/build.go`) builds
  the binary and the `session` and `extract` plugins from source with the same
  toolchain (a plugin only loads in the binary it was built with), the three at
  once. `buildPlugin` builds other plugins from `cmd/plugins/<name>` when a
  scenario asks for them (the scenarios use `report` and `filetype_filter`).
  The builds go to `gmhost-e2e/<key>` in the user cache folder. The key hashes
  `go version`, `GOOS`, `GOARCH`, `CGO_ENABLED`, `GOFLAGS` and every file of
  the repository except `test/`, `docs/`, hidden folders, `*_test.go` and
  `*.md`, embedded assets included. A lock on `gmhost-e2e/lock` serializes the
  test processes: the first builds, the others reuse the folder once its `done`
  marker is written. A new key removes the folders of the older ones.
- **The embedded 7-Zip.** The `extract` plugin embeds `7zzs`; the connector
  runs it for real. Some tests also run a copy of it directly to build their
  inputs (7z archives with encrypted headers, AES-encrypted zips, a solid 7z).
- **Chrome.** The two browser scenarios use a real Chromium or Chrome to render
  the PDF session report. One of them puts a small Go program in front of the
  browser (`buildBrowserStub`): it starts the real browser until a marker file
  exists, then fails.
- **The filesystem.** INPUT, OUTPUT, the work folder, the exports and the
  quarantine are real folders under `t.TempDir()`. Signals are real signals.

### Simulated: the fake GMalware (`internal/fakes/gmalware`)

`gmalware.GMalware` is an `httptest` server that speaks the lite API v2 the
connector client uses (`/api/versions`, `/status`, `/submit`, `/results/`,
`/search/`).

- **What it answers.** A submission is read through its multipart body and
  hashed; the analysis ID is derived from the SHA256. A result is
  `done`, with score 0 when the content is clean, or score 1000 and the
  malware name `Test.Malware` when it is programmed as malicious. `/search/`
  answers 404 (no cache), except during an injected failure.
- **How verdicts are scripted.** By content, keyed by SHA256:
  `MarkMalicious`, `MarkMaliciousWithError` (a detection and an analysis error
  in the same result) and `MarkAnalysisError` (an error and no detection).
  Content that was never marked is clean.
- **Errors.** `FailWith(status)` makes the submit, results and search requests
  answer that HTTP status until `FailWith(0)`; `/api/versions` and
  `/api/lite/v2/status` are not affected, nor is submit in hang mode. The
  outage and retry scenarios use it with 503.
- **Slowness.** `DelaySubmissions` makes every submission wait before it is
  answered (it gives up if the client goes away). `DelayResults` makes every
  result wait, `DelayResultOf` the result of one content only; neither stops
  when the request is cancelled: the handler goes on, as a slow server does,
  and must notice that nobody listens. The T20a scenarios use `DelayResultOf`
  to hold the only worker; the other two are used by the self-tests only.
- **No answer.** `gmalware.New(t, true)` makes a server that reads the whole
  submission and then never answers, until the client goes away. The shutdown
  tests use it to stop the connector in the middle of an analysis.
- **Dropped connections.** The fake never closes a connection itself. It sees
  an upload cut short only where it drains a body: in hang mode and for an
  injected failure. There, a connection closed or reset counts as an aborted
  upload; a body cut short counts as one only if the scenario announced it
  (`ExpectAbortedUploads`), otherwise it is an error. The final check requires
  exactly the announced number. On a normal submission a body that cannot be
  read gets a 400 and nothing is recorded: the content is then never "given",
  so the invariant still catches its delivery. Write errors from a client that
  went away are notes, not failures (`internal/fakes/errlog`, shared with the
  fake console). No scenario announces an abort today; the mechanism is
  covered by the self-tests.
- **What counts as a verdict given.** `Given(sha)` is true only when the
  answer was written and flushed without error and the request was still alive
  afterwards. A verdict the client did not wait for, or that never reached it,
  is not "given", so a connector that fails open cannot pass for one that
  analyzed the file. The invariant relies on this.
- **What it remembers.** The file name of every submission
  (`SubmittedNames`, read from the raw `Content-Disposition`, so the scenarios
  can check the label the service is told), the time of every search request
  (`Searches`: each analysis attempt starts with one), the number of
  submissions, of answers and of failures it injected.

### Simulated: the fake console (`internal/fakes/console`)

`console.Console` plays the connector manager of the agent mode, with the SDK
protocol: `register`, `config`, `tasks`, `events` and `metrics`.

- A request that strays from the protocol (unknown route, wrong method, wrong
  `Authorization: ApiKey` value, undecodable event) is answered 400 and
  recorded; every recorded protocol error fails the test at its end.
- `register` and `config` serve the configuration the test sets
  (`SetConfig`); an `update-config` task makes the connector read it.
- `tasks` waits a fixed 300 ms before it answers with the pending tasks (none
  when the queue is empty): it is not a long poll. `Push` queues a task (`stop`, `start`,
  `update-config`, `restore`). A task leaves the queue only once its answer was
  delivered, so a poll left by a dead process does not take the tasks of the
  next one. The fake re-delivers rather than lose a task; the real manager is
  stricter about what it hands out.
- `events` are kept in order. The scenarios read the acknowledgement of a task
  (`WaitAck`, with its error text) and the events by type: errors
  (`ErrorTypes`), resolutions (`ResolvedTypes`), mitigations
  (`MitigationReasons`).
- `metrics` are accepted and dropped; no scenario asserts them.

### Scenarios (`internal/harness/scenario.go`)

Most tests are one call, `harness.Run(t, harness.Scenario{...})`, that holds
the input and the expected output side by side:

- **Input.** `Agent`, `Hang` (the service never answers), `Timeout`, `Config`
  merged over the default, `Plugins` by folder name of `cmd/plugins` (an entry
  turns the plugin on; `extract` also sets `extract: true`; the `session` entry
  is merged over its default), the `Files` added to INPUT at start (path below
  the owner folder, content, verdict of the service, archive `Members`), then
  `Steps` played in order: `AddFileToInput`, `Await` (a file reaches an
  intermediate outcome), `AwaitDelivered` (files in OUTPUT, reports not
  looked at), `Restore`, `RestoreID`, `UpdateConfig`, `Task`, `Restart`,
  `ServiceDown`, `ServiceUp`, `AwaitServiceFailure`, `AwaitConsoleError` and
  `Stop` (SIGTERM, clean exit).
- **Expected output.** `Want` gives an `Outcome` per file, and per archive
  member as `"archive.zip/dir/member.txt"`: where it is (`Input`, `Output`,
  `Quarantine`, `Nowhere`), the malware or not-analyzed reason and the error of
  its report entries, `Restored`, the `Container` format, the names it was
  submitted under, the number of submissions, whether the service gave a
  verdict, its malicious and not-analyzed members, and an `Entry` function for
  a computed check. The whole run has `WantMitigations` (exact),
  `WantConsoleErrors`, `WantConsoleResolved`, `WantSessionReports`, `WantGone`
  (folders of INPUT removed) and `WantRefused` (the start is refused; the text
  is looked for in the log).
- **Checked without being written.** A file in OUTPUT has exactly its bytes.
  Every report entry of a file must match its outcome, and an entry with an
  error fails unless the outcome declares it. Reports are found by
  `Filename`, the INPUT path, with each byte that is not UTF-8 read as
  U+FFFD, as JSON writes it. With the move on, a file in the quarantine has
  one detection report per malicious entry. The number of containers equals the
  number of files wanted in the quarantine. After a restore, the container and
  the temporary file are gone. The expectations of the invariant (section 3)
  are derived from the files, the outcomes and the steps.
- **History.** The report entries an `Await` saw are the history of the file:
  the later checks look at the newer entries, or at the last one when there is
  none.
- **Waiting and the table.** `Run` waits up to 60 s for every outcome; an
  outcome in INPUT must then hold for 12 s. On failure, or when the process
  exits first, it prints one row per file and per run-wide check with what is
  wanted and what is observed, ✓ or ✗; past 50 rows only the ✗ rows are shown.
  `Run` returns the instance, for the few checks the outcome cannot express
  (the console lines of the names tests).
- **Logs.** A scenario asserts on the log only where it is the subject: the
  console lines of the names tests and the reason of a refused start.

The other tests start the instance by hand (`harness.Start`), because they
measure what a scenario does not express: timings and signals (shutdown, slow
writer, retry intervals), the work folder during a bomb, the spool, inotify
watches, a concurrent writer, a 5 GiB file, a crash, the PDF report, a name the
connector chooses (destination conflict), a label capped below its path, or a
single extraction seen only in the log. They run serially.

### What the harness does (`internal/harness`)

- **Instance launch.** `harness.Start` creates INPUT with an owner folder `tom`
  below it, the work folder, OUTPUT and an exports folder for the session
  reports, which sits outside OUTPUT because the connector refuses reports
  below the destination of the move. The quarantine location is only
  configured; the connector creates it. It writes the configuration and the
  plugins file as JSON, starts `GMHost` in its own process group with
  `--shutdown-timeout` (4 s unless the scenario sets it) and either
  `monitoring` or, with `Options.Agent`, `agent` against the fake console.
- **Configuration.** The default has two workers, the move, quarantine and log
  actions on, quarantine password `infected`, a pre-scan, a modification delay
  of 1 s, a session delay of 2 s and the default extraction limits. A scenario
  merges its keys over it (`Options.Config`), turns plugins on with their
  configuration (`Options.Plugins`, the `session` entry merged over its
  default) and may fix the order of the plugins (`Order`).
  Because the harness has to know the analysis size limit for the invariant,
  it refuses a configuration with `gmalware_syndetect` on.
- **Dropping files.** `Drop` writes below the owner folder; `Create` makes a
  sparse file; `InOutput`, `Gone`, `OutputHas` and `ReportsOf` read the result.
- **Waiting.** `wait.WaitFor` (`internal/wait`) polls every 50 ms for at most
  60 s. The instance method `in.WaitFor`, which the scenarios use, also fails
  at once if the process exits meanwhile (a connector that refused its
  configuration is not waited for until the deadline); the package function
  has no such check. Facts that must *not* happen are judged
  over a window: `Run` holds an outcome in INPUT for 12 s once its report is
  written; in the tests started by hand, `StaysInInput` first waits for the log
  to name the file, then watches OUTPUT for 12 s and checks that the file is
  still in INPUT.
- **Signals and restarts.** `Signal` sends a signal; `Restart` stops with
  SIGTERM and starts again on the same folders with a changed configuration;
  `CrashAndRestart` kills the process group with SIGKILL first.
- **Logs.** The output of the process is kept in a bounded buffer: past 8 MiB
  only the last 4 MiB are kept, cut on a byte rather than a line, and the log
  then starts with a marker saying so. It is printed when a test fails.
  `LogHas` looks for a line: `Run` uses it for a refused start and to know a
  restart is watching again; some tests started by hand check log lines.
- **End of every test.** `finish` (a cleanup, so it also runs when the test
  failed early) sends SIGTERM if the process still runs, waits up to 20 s,
  then runs the OUTPUT invariant (section 3), reports the errors recorded by
  the fake GMalware, checks the announced aborted uploads, and reports the
  protocol errors of the fake console. A second cleanup kills the whole
  process group so that no 7-Zip outlives the test.

## 3. The OUTPUT invariant

Defined in `internal/harness/invariant.go`. It holds the connector to its
promise: **what is in OUTPUT is there for a reason that the reports and the
service confirm.**

**What it checks.** For every regular file in OUTPUT (except detection
reports, below):

- it appears in a session report of the exports folder;
- it was analyzed by the service with a clean verdict (`Given`, not malware),
  *or* its report carries a not-analyzed reason that the file justifies:
  `empty` only for a zero-length file, `too-big` only above the effective
  `max_file_size`, any other reason (encrypted, extract limit, extract error,
  policy skipped, restored, analysis error) only if the scenario declared it;
- no entry says malicious or lists a malicious member, none is in error (unless
  another valid report exists for the same content, as after an outage), and
  nothing the test programmed as malware is there;
- an archive is held to the members the scenario declared: none programmed as
  malware, at least one seen by the service, none failed; an archive that was
  not declared is a violation;
- members listed as not analyzed in a report need a justified reason too;
- anything that is not a regular file (link, device) is a violation, and so is
  an unreadable report. A detection report larger than 64 MiB is a violation
  (the read is capped, so padding cannot hide data behind the cap).

**Detection reports.** The `*-lockreport*.json` file the connector leaves where
it moved a malicious file is allowed, but it must be exactly one report of a
malicious file the test programmed (or of a declared archive with such a
member), with nothing after it, an ID that matches the quarantine container of
that file, and that container present. Unknown fields are refused. Two
exceptions: a malware that the scenario declared restored (`Release`) may have
lost its container, if the reports show the restore; and with `QuarantineOff`
a detection report with no mitigation ID is accepted. A user file that borrows
the name is flagged.

**What a scenario declares** (`in.Expect`, of type `Expectations`; `harness.Run`
derives it from the files, the outcomes and the steps): the
reasons it allows (`Allow`), contents that a plugin or a path rule treats as
malware (`Flag`, or `FlagSHA256` for a content too large to hold), the members
of the archives it delivers (`Archive`), malware an operator restored
(`Release`, `ReleaseSHA256`, `ReleaseCopies`: delivered on purpose, with the
restored mark), contents whose report a crash lost (`CrashLost`: allowed in
OUTPUT without a report only if the service analyzed them clean) and a
quarantine that is off (`QuarantineOff`).

**When it runs.** At the end of every test that starts an instance, after the
process has stopped, whether the test passed or not.

**Self-test.** `internal/harness/invariant_test.go` runs the checker on folders
filled by hand and requires each case to give the expected violation or none:
`TestOutputViolations` (a table of 45 cases: missing report,
malicious, error, undeclared reasons, size-based reasons, restored malware,
copies, archives, crash), the lock-report tests (traps, archives, restored
malware, quarantine off) and `TestEffectiveMaxFileSize`. Each fake has its own
self-tests beside it (section 5).

## 4. Organization

```txt
test/
  doc.go                      package documentation: layout, tags, how to run
  internal/
    wait/                     WaitFor, Poll
    harness/                  build.go, instance.go, scenario.go, wait.go,
                              invariant.go, maxsize.go, helpers.go, and
                              their self-tests
    fakes/errlog/             what a fake failed to read or write
    fakes/gmalware/           the fake GMalware
    fakes/console/            the fake console
  core/                       delivery_test.go, console_test.go,
                              analysis_test.go, paths_test.go, restore_test.go,
                              quarantine_test.go, names_test.go, shutdown_test.go
  plugins/                    extract_archives_test.go,
                              extract_limits_test.go, extract_encryption_test.go,
                              extract_paths_test.go, filetype_filter_test.go,
                              session_test.go, report_test.go, lifecycle_test.go,
                              documents_test.go
```

`internal` limits the harness and the fakes to the `test/` tree. Helpers used
by one side only stay in that side's package as plain functions taking the
instance (the archive builders, 7-Zip helpers, `seenMembers` and `spoolFiles`
in `plugins`; `inotifyWatches` and `consoleLinesOf` in `core`). The identifiers P*, T*,
Q*, D* in the comments of the scenarios refer to the tasks of the project;
`p3/T*` marks the tests of the third phase. The tests rewritten from the
former in-process tests carry `T11`, `T14a` or `T20a`; those rewritten from
`pkg/quarantine` name the test they come from.

## 5. Catalogue

110 tests. The "Needs" column gives the prerequisite beyond the Go toolchain,
`—` for none: **browser** (the `realbrowser` tag, Chromium or Chrome in the
`PATH` and a non-root user; the test fails otherwise), **7-Zip** (the `7zzs`
binary, which the test runs directly to build its input). Every instance
builds the `extract` plugin, which needs `7zzs`, so a scenario that starts an
instance before it builds its input fails at that build without `7zzs`; only
`TestAESDocumentHasNoEncryptionFlag` is skipped. Every test that starts an
instance also skips under `-short`. A name is given without its `TestE2E_`
prefix; the prefix of the other tests is kept. Tests with sub-tests (`t.Run`)
are one row. Files are relative to `test/`.

### Delivery and monitoring

| Test | File | Sets up | Asserts | Needs |
| --- | --- | --- | --- | --- |
| `cleanDeliveredMaliciousQuarantined` | `core/delivery_test.go` | One clean and one malicious file dropped. | The clean file is in OUTPUT; the malware left INPUT, is in the quarantine under its ID (the only container) and has one detection report in OUTPUT. | — |
| `gmalwareOutageThenRecovery` | `core/delivery_test.go` | The service answers 503 to every submission, result and search request; a file is dropped; later the service recovers. | During the outage the file stays in INPUT and its report gives the injected error; after recovery it is delivered and reported clean. | — |
| `destinationConflictKeepsBoth` | `core/delivery_test.go` | Move mode `copy`, then `rename`; a second file of the same name is dropped once the first is delivered and has left INPUT. | Two files in OUTPUT, the first untouched, and the report of the second names the conflict. | — |
| `watcherSwitch` | `core/delivery_test.go` | `disable_fs_watcher` true with a 2 s rescan, then false with a 1 h rescan. | The process holds no inotify watch when disabled and some otherwise; a file dropped later is delivered in both cases. | — |
| `emptyFoldersRemoved` | `plugins/session_test.go` | `remove_empty_dirs` on; a file dropped two folders deep. | After delivery and the session report the emptied folders are gone from INPUT. | — |
| `slowUploadAndWriterThatKeepsTheFileOpen` | `core/delivery_test.go` | A writer appends to a file every 400 ms for 12 rounds, with a modification delay of 5 s, and keeps it open. | Nothing is submitted or delivered while it writes; the file is delivered whole once it pauses; a write after the delivery does not change OUTPUT. | — |
| `manyFilesWithATinyTable` | `core/delivery_test.go` | Agent mode; 3000 files with 180-character names, `max_tracked_memory` at its 1 MiB minimum, 3 s rescan. | Every file is delivered, and the console received a `host-monitor-pressure` error (proof that the table overflowed). | — |
| `anUnchangedFileLeftInInputIsAnalyzedOnceOverManyRescans` | `core/delivery_test.go` | Move off, watcher off, 1 s rescan; one file. | It is submitted once over about 12 rescans. | — |
| `aModifiedFileIsAnalyzedAgain` | `core/delivery_test.go` | The same; the file is rewritten after its first analysis. | Each version is submitted exactly once. | — |
| `aTransientFailureIsRetriedWithGrowingDelaysAndNeverTooOften` | `core/delivery_test.go` | The same, the service answers 503. | The attempts (search requests) are spaced by at least the backoff, and the second delay is not shorter than half the first. | — |

### Console and configuration

| Test | File | Sets up | Asserts | Needs |
| --- | --- | --- | --- | --- |
| `consoleStopThenStart` | `core/console_test.go` | Agent mode; the console pushes `stop` then `start`. | Both tasks are acknowledged without error; a file dropped after the restart is delivered. | — |
| `invalidConfigureKeepsTheOldConfiguration` | `core/console_test.go` | Agent mode; the console serves a configuration with an invalid move mode, then a valid one, each followed by `update-config`. | The invalid one is acknowledged with an error and reported to the console as `host-config-rejected`, the old configuration keeps delivering; the valid one is accepted and resolves the error. | — |
| `refusedAtStart` | `core/console_test.go` | A start with the work folder under a watched path. | It exits with an error and the log gives the message that says how to fix it. | — |
| `aPluginMisconfigurationIsRefusedAtStart` | `plugins/lifecycle_test.go` | Two starts: a browser path that does not exist, a 7-Zip path that does not exist. | Each exits with an error and the log gives the message that says how to fix it. | — |

### Archives and extraction

| Test | File | Sets up | Asserts | Needs |
| --- | --- | --- | --- | --- |
| `archives` | `plugins/extract_archives_test.go` | One zip with clean members, one with a malicious member. | The clean one is delivered; the other is quarantined whole and never reaches OUTPUT. | — |
| `theHeadersOfAZipAreWalked` | `plugins/extract_archives_test.go` | Eight hand-made zips: a control, records hidden after a folder or between entries, zero padding, a stored jar in a jar, a byte after the end, decoy end-of-directory records. | The honest ones are delivered after each member was analyzed; the others stay in INPUT and are reported "damaged or inconsistent". | — |
| `extractErrorAsFile` | `plugins/extract_archives_test.go` | `extract_error` at `error` or `as_file` with cut archives, a plain zip followed by an encrypted one, and members with a name over 255 bytes, a path over 4096 bytes or 70 folders deep. | Each stays in INPUT over a 12 s window, whatever the policy, reported with its error (damaged or inconsistent, or encrypted). | — |
| `aHeaderEncryptedSevenZipWithADefaultPassword` | `plugins/extract_archives_test.go` | A 7z with encrypted headers and the password `infected`, with clean members, then with a detected member. | Clean: delivered, every member analyzed. Detected: quarantined, not delivered. | 7-Zip |
| `aDetectionBesideAWaivedNestedArchiveWins` | `plugins/extract_archives_test.go` | A zip with a malicious member and a nested zip that a skipped path waives. | The outer archive is quarantined and never delivered. | — |
| `aDetectionBeatsAnUnexaminableNestedArchive` | `plugins/extract_archives_test.go` | A zip with a malicious member and a nested encrypted zip (the default encrypted policy, `error`). | The outer archive is quarantined, not left in INPUT in error. | — |
| `anArchiveMemberIsSubmittedUnderItsArchivePath` | `plugins/extract_archives_test.go` | A zip, a nested zip and a plain file. | The service is told the host path of the archive plus the member path (nested archives included), the plain file keeps its path, and no label holds the work folder or `..`. | — |
| `anArchiveWithATooBigMemberIsExtractedOnlyOnce` | `plugins/extract_archives_test.go` | Move off, watcher off, 1 s rescan, `max_file_size` 1 MiB; a zip with a small member and a 2 MiB member. | The failed extraction is logged once over about 8 rescans: the archive is not extracted again. | — |

### Size limits and bombs

| Test | File | Sets up | Asserts | Needs |
| --- | --- | --- | --- | --- |
| `unanalyzablePolicyPass` | `core/analysis_test.go` | `max_file_size` 1 MiB, policies `too_big` and `empty` at `pass`; a 2 MiB file and an empty file. | Both are delivered and reported not analyzed, `too-big` and `empty`. | — |
| `extractionBombsAreStopped` | `plugins/extract_limits_test.go` | A zip and a gzip that inflate to 64 MiB, with the recursive extraction limit at 4 MiB. | Each is reported with an error naming the extraction limits, stays in INPUT and is not delivered. | — |
| `aForgedZipOfEmptyPackedMembersIsABomb` | `plugins/extract_limits_test.go` | A zip of 40 members, each declaring 90 MB with no packed byte, under the default limits. | The log says "potential ZipBomb" within 30 s, the file stays in INPUT, and the work folder never held more than 64 MiB. | — |
| `aSolidSevenZipWithAHugeFirstMemberIsLeftOutAndNotWrittenOut` | `plugins/extract_limits_test.go` | A solid 7z whose first member is 150 MiB of zeros. | The file stays in INPUT, the log says it was left out by the extraction limits, and the work folder never held more than 64 MiB. | 7-Zip |
| `anOverLimitDocumentIsDeliveredWithItsMembersUnchecked` | `plugins/extract_limits_test.go` | A docx, a jar and an apk of 10,001 entries. | Each is analyzed whole, submitted under its own path and delivered; its report lists members as not analyzed for the extract limit with the exact count. | — |
| `anOverLimitDocumentThatIsMalwareIsQuarantined` | `plugins/extract_limits_test.go` | An over-limit docx that the service flags. | It is quarantined, and its report lists no unchecked member. | — |
| `anOrdinaryZipOverTheLimitsIsStillHeld` | `plugins/extract_limits_test.go` | A plain zip of 10,001 entries beside an over-limit docx. | The docx is delivered; the zip stays in INPUT, reported as left out by the extraction limits. | — |
| `TestTreeSize` | `plugins/extract_limits_test.go` | Helper test: a folder with files, a sub-folder and two symlinks. | `treeSize` adds regular files only (links count for nothing) and fails on a missing folder. | — |

### Encryption

| Test | File | Sets up | Asserts | Needs |
| --- | --- | --- | --- | --- |
| `anOverLimitDocumentWithAnEncryptedMemberStaysInInput` | `plugins/extract_encryption_test.go` | For docx, jar and apk: an over-limit document with one ZipCrypto member, and a control without. | The control is delivered; the encrypted one stays in INPUT, reported with the encrypted-file error. | — |
| `aDocumentInAFullArchiveIsCheckedForEncryption` | `plugins/extract_encryption_test.go` | An outer zip of 9,999 plain files holding a document with an encrypted member, and the same outer zip with a plain document. | The first is held in INPUT with the encrypted error; the second is delivered, analyzed, with the document members listed as not analyzed for the extract limit (`word/document.xml` among them). | — |
| `anOverLimitEncryptedDocumentFollowsTheEncryptedPolicy` | `plugins/extract_encryption_test.go` | Policy `encrypted` at `pass`; an over-limit docx with an encrypted member. | It is delivered and a report entry says not analyzed for `encrypted`. | — |
| `anEncryptedDocumentInAFullArchiveFollowsTheEncryptedPolicy` | `plugins/extract_encryption_test.go` | Policy `encrypted` at `pass`; the full outer archive holding an encrypted document. | The outer archive is delivered and its report marks the encrypted outcome. | — |
| `anOverLimitDocumentWithAnAESMemberWithoutFlagIsHeldAsEncrypted` | `plugins/extract_encryption_test.go` | An over-limit docx whose last member is AES-encrypted with the encryption flag cleared in both headers. | It stays in INPUT, reported with the encrypted-file error: the method is what counts. | 7-Zip |
| `TestAESDocumentHasNoEncryptionFlag` | `plugins/extract_encryption_test.go` | Helper test: builds the AES document of the previous scenario. | The member is method 99 and its flag is clear in the local and central headers; without clearing, the local flag is set. | 7-Zip |

### Analysis errors and detections

| Test | File | Sets up | Asserts | Needs |
| --- | --- | --- | --- | --- |
| `aDetectionWithAnAnalysisErrorIsMalware` | `core/analysis_test.go` | Agent mode; a file whose result carries a detection and an analysis error. | Quarantined, not delivered; the report says malicious with the reason `malware-detected`; the console mitigation reason is `malware`. | — |
| `aDetectionWithAnAnalysisErrorInAnArchiveIsMalware` | `plugins/extract_archives_test.go` | The same for a zip with such a member beside a member in error. | The same outcome for the archive. | — |
| `analysisErrorPolicy` | `core/analysis_test.go` | `analysis_error` at `error`, `mitigate` and `pass`; a file whose analysis fails and a malware whose analysis also fails. | The malware is always quarantined. The failed file stays in INPUT (`error`), is quarantined (`mitigate`) or is delivered and reported `analysis-error` (`pass`). | — |
| `analysisErrorInAnArchiveMember` | `plugins/extract_archives_test.go` | The same three values; a zip with a member whose analysis fails. | `error`: stays in INPUT, reported in error; `mitigate`: quarantined; `pass`: delivered. | — |
| `passNeverBypassesTheOtherPolicies` | `plugins/extract_archives_test.go` | `analysis_error` at `pass`, `encrypted` and `too_big` at `error`; an encrypted zip and a 2 MiB file over a 1 MiB limit. | Both stay in INPUT. | — |

### Path and type rules

| Test | File | Sets up | Asserts | Needs |
| --- | --- | --- | --- | --- |
| `pathFiltersJudgeTheLogicalPath` | `plugins/extract_paths_test.go` | Path rules (forbidden and skipped) with the extract plugin; files in plain, trusted and forbidden folders, a zip with a member under a forbidden folder, a clean zip. | Forbidden file and archive are quarantined (two containers); the trusted file is delivered without analysis and reported skipped; ordinary content is analyzed. | — |
| `corePathRules` | `plugins/extract_paths_test.go` | The same rules applied by the core (no filter plugin, extract on), with the skipped folder `/tom/trusted/`, plus a file both forbidden and in a skipped folder. | Forbidden paths are quarantined, including the file that is also skipped; the skipped file is reported skipped and never analyzed. | — |
| `aNewlineInAnArchiveNameDoesNotEscapeAForbiddenPath` | `plugins/extract_paths_test.go` | Rule `^/.*\.zip$`; a zip named `pack\nx.zip`. | It is quarantined. | — |
| `pathRulesMatchTheRawAndTheSanitizedName` | `core/paths_test.go` | Forbidden `\.exe[^/]*$`, skipped `/tom/trusted[^/]*/` and `a_b\.txt$`; names with a trailing newline, an invalid UTF-8 byte and a control character. | The newline name is quarantined; the invalid-UTF-8 folder is skipped; the control-character file is analyzed, not skipped. | — |
| `aRefusedSkippedArchiveNamesItsForbiddenMembers` | `plugins/extract_paths_test.go` | A zip of two `.exe` members in a skipped folder, `.exe` forbidden. | Quarantined; its report names both members among the malicious ones. | — |
| `aSkippedArchiveIsStillCheckedAgainstTheForbiddenPaths` | `plugins/extract_paths_test.go` | Two zips in a skipped folder, one with a forbidden member. | The one without is delivered, skipped, with no member analyzed; the other is quarantined. | — |
| `aForbiddenTypeInsideAZipIsRefused` | `plugins/filetype_filter_test.go` | `filetype_filter` forbidding `image/png`; a zip with a real PNG and one without. | The archive with the PNG is quarantined; the other is delivered. | — |
| `aRefusalBeatsAnExemption` | `plugins/filetype_filter_test.go` | A skipped folder plus a forbidden type; the same PNG outside and inside the folder. | Both copies are quarantined (two containers); the skipped text file is delivered unanalyzed. | — |
| `aSkippedTypeIsNotWaivedForALargeFile` | `plugins/filetype_filter_test.go` | `skipped_types` with `image/png`; a small PNG and a PNG followed by 9 MiB of zeros. | The small one is delivered unanalyzed and reported skipped; the large one is analyzed. | — |
| `aZeroWidthSpaceAfterTheExtensionDoesNotEscapeAForbiddenPath` | `plugins/extract_paths_test.go` | A zip with a member `a.exe` followed by U+200B, `\.exe$` forbidden. | Quarantined; the report names the member with the reason `filtered-filepath`. | — |
| `theFoldedNameDoesNotWidenASkipRule` | `core/paths_test.go` | Skip rules `/tom/a\.log$` and `/tom/skipped/.*\.log$`; files `a<U+200B>.log` and `skipped/b<U+200B>.log`. | The first is analyzed (not skipped), the second is skipped and not analyzed. | — |
| `aSkipRuleThatOnlyMatchesTheMangledFolderNoLongerSkips` | `core/paths_test.go` | A skip rule that only the folded form of `trusted\xff` matches. | The file is analyzed and not reported skipped. | — |
| `aVariationSelectorAfterTheExtensionDoesNotEscapeAForbiddenPath` | `plugins/extract_paths_test.go` | As the zero-width test with U+FE0F. | Quarantined; the member is named with the reason `filtered-filepath`. | — |

### Restore

| Test | File | Sets up | Asserts | Needs |
| --- | --- | --- | --- | --- |
| `quarantineRestore` | `core/restore_test.go` | Agent mode; a malware quarantined in `tar`, then `zip` containers; the console pushes `restore`. | The container has the right format; nothing reached OUTPUT before the restore; the restored content is delivered. | — |
| `restoreNeverReplacesAFile` | `core/restore_test.go` | A growing file occupies the original place; the console asks to restore. | Refused with "destination already exists", container kept, the other file unchanged, nothing in OUTPUT; after the place is free the same restore works. | — |
| `restoreWithoutRegistryEntryOutsideWatchedFolders` | `core/restore_test.go` | The connector restarts on another watched folder, losing the in-memory registry; then a restore. | Refused ("below a watched path"), container kept, no file written to the original place or delivered. | — |
| `restoreWithoutRegistryEntryUnderAWatchedFolder` | `core/restore_test.go` | The same restart, with the folder unchanged. | The restore is served, the file is delivered, and the console gets a `quarantine-restore-unregistered` error. | — |
| `aRestoredFileIsListedAsNotAnalyzed` | `core/restore_test.go` | A malware quarantined then restored, and a clean file. | One restored entry with reason `restored` and the restored mark, no detection or error; the earlier detection stays in the reports; the clean file has no reason. | — |
| `aRestoredFileIsStillHeldToThePathRules` | `core/restore_test.go` | A restored content, then the same content under a forbidden path and elsewhere. | Delivered elsewhere; quarantined under the forbidden path with the reason `filtered-filepath`. | — |
| `aRestoredContentDepositedElsewhereIsNotQuarantinedAgain` | `core/restore_test.go` | A restored malware, then the same content dropped in another folder. | It is delivered, the number of containers does not change, and its report entry carries the restored mark. | — |
| `aRestoredFileOfAForbiddenTypeIsQuarantinedAgain` | `plugins/filetype_filter_test.go` | A PNG quarantined for its forbidden type, then restored. | It is quarantined again and never delivered, with a detection report each time and two `filetype` mitigations. | — |
| `aRestoredArchiveIsCheckedAgainstTheForbiddenPaths` | `plugins/extract_paths_test.go` | With `\.exe$` forbidden: a restored archive without a match, and one with a `.exe` member. | The first is delivered; the second is quarantined again and the report names the member; the mitigations are `malware`, `malware`, `filepath`. | — |
| `aRestoredArchiveWhoseNamesCannotBeListedStaysInInput` | `plugins/extract_paths_test.go` | A 7z with encrypted headers and an unknown password, quarantined then restored, with `.exe` forbidden; its old detection report is removed first. | It stays in INPUT with no new submission, and is not retried. | 7-Zip |
| `aRefusedRestoredFileStaysInInputWithoutRetry` | `core/restore_test.go` | A restored malware; then the console turns quarantine and delete off; the content is dropped under a forbidden path. | It stays in INPUT, no container is created, and it is reported once. | — |

### Quarantine containers

| Test | File | Sets up | Asserts | Needs |
| --- | --- | --- | --- | --- |
| `aContainerIsWrittenInItsFormatAndRestoredWhole` | `core/quarantine_test.go` | Agent mode; malware quarantined in `zip`, `tar` and the default format: plain, empty (`empty` at `mitigate`), 255-byte name, binary content; then restored. | The container starts as a zip only in the zip format; the restored file is delivered with its content, no temporary file is left and the container is removed. | — |
| `aFormatChangeKeepsTheOldContainersRestorable` | `core/quarantine_test.go` | A tar container, then `update-config` to zip and a second malware. | The new container is a zip; both are restored and delivered with their content. | — |
| `anUnknownQuarantineFormatIsRefused` | `core/quarantine_test.go` | Format `rar` at start; then, once a first file is delivered with `tar`, on `update-config`. | The start is refused with the validation error of the `format` key; the task is acknowledged with that error and the next malware goes to a tar container. | — |
| `aHostileRestoreIDIsRefused` | `core/quarantine_test.go` | Restores with IDs that are not 64 hex characters (traversal, slash, NUL, newline, absolute path). | Each is acknowledged with "invalid quarantine id". | — |
| `aSparseFileOver5GiBIsRestored` | `core/quarantine_test.go` | Opt-in with `GMHOST_LARGE_TESTS=1`; a sparse file over 5 GiB quarantined under `too_big` at `mitigate`, in tar and zip. | It is restored and delivered with its size and its last bytes. | — |

### Sessions and reports

| Test | File | Sets up | Asserts | Needs |
| --- | --- | --- | --- | --- |
| `sessionsCloseAndReopen` | `plugins/session_test.go` | Session delay 2 s; two files dropped one after the other. | Two session reports, each with one entry for its file. | — |
| `sessionReportGeneratedByTheBrowser` | `plugins/report_test.go` | Agent mode with the `report` plugin and the real browser; a malware is dropped. | The exports hold only a `%PDF` file with the reserved name, and no `session-report-fallback` error was sent. | browser |
| `failingReportGeneratorFallsBackToJSON` | `plugins/report_test.go` | The browser is replaced by a stub that fails once a marker file exists; one retry. | One JSON report is written under the reserved name with the delivered file, no PDF, and the console gets `session-report-fallback`. | browser |
| `aSessionIsClosedAtMaxDuration` | `plugins/session_test.go` | Session delay 1 h, `max_duration` 5 s. | A private spool (mode 600) exists while open and no report yet; the session closes by itself with one report and no spool; the next file opens a second session. | — |
| `aSessionIsClosedAtMaxSpoolSize` | `plugins/session_test.go` | `max_spool_size` 1 MiB (the minimum), delay 1 h, 3000 files; SIGTERM once they are delivered. | Every file is delivered, and there are exactly two session reports. | — |
| `theSpoolOfACrashedRunIsRemovedWithAWarning` | `plugins/session_test.go` | A file delivered with its session open; the process is killed with SIGKILL and restarted. | The log warns that one session report was lost; the old work folder and the spool are removed. | — |
| `aDepositOfSeveralHundredFilesBehindASaturatedWorkerIsOneSessionAndOneReport` | `plugins/session_test.go` | One worker; 150 files of `tom`, a slow analysis of a file of `jerry`, 150 more files of `tom`. | `tom` gets one report with the 300 files. | — |
| `aPendingFileThatChangesBeforeBeingTakenNeverBlocksTheSession` | `plugins/session_test.go` | One worker held by the slow analysis of `jerry`; a waiting file of `tom` is deleted, rewritten, replaced by a link, emptied, or deleted and recreated. | The session of `tom` closes and its report is not empty. | — |
| `aQueueSaturatedBeyondTheInflightTimeoutClosesTheSessionWithAWarn` | `plugins/session_test.go` | `inflight_timeout` 3 s, one worker held 20 s; two files of `tom` wait. | The session closes before the slow analysis ends, with a warning giving the pending count; each of the three files is in exactly one report. | — |

### Labels and names

| Test | File | Sets up | Asserts | Needs |
| --- | --- | --- | --- | --- |
| `aLongLabelIsCappedKeepingTheTail` | `plugins/extract_archives_test.go` | A member whose label (host path plus member path) exceeds 4096 bytes. | The label sent is at most 4096 bytes, starts with `…`, keeps the tail of the path and is valid UTF-8. | — |
| `aBidiOverrideInANameIsMaskedForTheServiceAndTheConsoleOnly` | `core/names_test.go` | A malware named with U+202E. | The service gets `_`, the console line shows U+FFFD, the JSON report keeps the raw name. | — |
| `aNewlineAndAnOverrideInANameMakeOneConsoleLine` | `core/names_test.go` | A name with a newline, `time: forged` and U+202E. | One console line with both characters shown as U+FFFD and no forged line. | — |
| `aNameThatImitatesTheNextFieldsStaysInsideTheQuotes` | `core/names_test.go` | Names `x, flagged: false` and one with a quote and fake fields. | One console line each, holding the quoted name followed by the real fields. | — |

### Shutdown

These tests carry the tags of their package, like the other scenarios. Where
a row says the service never answers, the fake GMalware is in hang mode.

| Test | File | Sets up | Asserts | Needs |
| --- | --- | --- | --- | --- |
| `TestShutdown_sigtermDuringTheAnalysisOfAnArchive` | `plugins/lifecycle_test.go` | A zip being analyzed, the service never answers; SIGTERM, timeout 4 s. | Exit code 0 within the timeout plus 2 s, work folder removed, no process left under it, the archive still in INPUT, and the log has the stop messages. | — |
| `TestShutdown_sigtermWritesTheReportOfAnOpenSession` | `plugins/session_test.go` | A delivered file in a session open for 1 h; SIGTERM. | Exit 0 and one report that names the file. | — |
| `TestShutdown_aSecondSignalStopsImmediately` | `core/shutdown_test.go` | Analysis blocked, timeout 30 s; two SIGTERM. | The process ends within 3 s, killed by SIGTERM (the default action). | — |
| `TestShutdown_aTooShortTimeoutRefusesToStart` | `core/shutdown_test.go` | `--shutdown-timeout 1s`. | The start is refused with a message naming `shutdown_timeout`. | — |
| `TestShutdown_sigintStopsLikeSigterm` | `core/shutdown_test.go` | Analysis blocked; SIGINT. | Exit 0, the log names the `interrupt` signal, work folder removed. | — |
| `TestShutdown_sigtermStopsTheAgent` | `core/shutdown_test.go` | The same in agent mode. | Exit 0, work folder removed, the stop summary is in the log. | — |

### Self-tests of the invariant, the fakes and the helpers

These carry the `linux` tag only. They start no connector; some start the fake
servers. They check the tools the scenarios rely on.

| Test | File | Sets up | Asserts | Needs |
| --- | --- | --- | --- | --- |
| `TestOutputViolations` | `internal/harness/invariant_test.go` | OUTPUT and reports filled by hand, one case per rule. | The checker returns the expected violation, or none for the legitimate cases. | — |
| `TestOutputViolations_lockReport` | `internal/harness/invariant_test.go` | Detection reports with traps (not a report, unknown field, trailing data, a second report, a clean file behind the name, a file not programmed as malware, no container in the quarantine, the mitigation ID of another file, no SHA256). | Each trap is flagged; a real detection is accepted. | — |
| `TestOutputViolations_lockReportOfAnArchive` | `internal/harness/invariant_test.go` | A detection report of an archive, declared or not. | Accepted only for a declared archive with a malware or flagged member. | — |
| `TestOutputViolations_lockReportOfARestoredMalware` | `internal/harness/invariant_test.go` | A detection report whose container is gone. | Flagged until the restore is declared and the reports show it. | — |
| `TestOutputViolations_lockReportWithoutContainerWhenTheQuarantineIsOff` | `internal/harness/invariant_test.go` | A detection report with no mitigation ID. | Flagged, except when the scenario declares the quarantine off. | — |
| `TestOutputViolations_lockReportTraps` | `internal/harness/invariant_test.go` | A detection report padded past the read bound; a programmed malware named like a report. | Both are flagged. | — |
| `TestEffectiveMaxFileSize` | `internal/harness/invariant_test.go` | Size values and `gmalware_syndetect` forms. | Values above 100 MiB, zero, are brought to 100 MiB; invalid values and syndetect on are refused. | — |
| `TestRows` | `internal/harness/scenario_test.go` | Folders, reports, detection reports, submissions and console events filled by hand, one case per check of `harness.Run`. | Each row of the table says what is wanted and observed, and passes or fails as it should. | — |
| `TestTable` | `internal/harness/scenario_test.go` | Rows that pass and fail, few and many. | The exact rendering of the table; past 50 rows only the failing ones are shown. | — |
| `TestInstance_expectAbortedUploads` | `internal/harness/instance_test.go` | Two announcements on an instance. | The instance and the fake both count three. | — |
| `TestErrLog` | `internal/fakes/errlog/errlog_test.go` | Failing writers and cut bodies. | A closed connection is a note; other failures, and unannounced or excess cut bodies, are errors; an announced abort is noted once; a cancelled request does not excuse one. | — |
| `TestGMalware_programmable` | `internal/fakes/gmalware/gmalware_test.go` | The fake asked directly. | Verdict per content, 404 for an unknown analysis, outage and recovery, delay. | — |
| `TestGMalware_givenOnlyOnceWritten` | `internal/fakes/gmalware/gmalware_test.go` | A result written to a failing writer, then to a recorder. | The verdict is given only in the second case. | — |
| `TestGMalware_givenOnlyToAClientThatWaited` | `internal/fakes/gmalware/gmalware_test.go` | A slow result with a client that gives up, then one that waits. | Given only to the client that waited. | — |
| `TestGMalware_recordsTheSubmittedName` | `internal/fakes/gmalware/gmalware_test.go` | Submissions under several names. | The raw names are kept in order, per content; a caller cannot change them. | — |
| `TestGMalware_delayResultOf` | `internal/fakes/gmalware/gmalware_test.go` | One content whose result is delayed, and another. | Only the result of that content waits. | — |
| `TestGMalware_searches` | `internal/fakes/gmalware/gmalware_test.go` | Search requests, answered or during an outage. | Each one is recorded, in order. | — |
| `TestFakeConsole_protocol` | `internal/fakes/console/console_test.go` | Protocol errors sent to the fake console. | Wrong method, no key, unknown route and bad event give 400 and four recorded errors; an unacknowledged task is not acknowledged. | — |
| `TestBigDocument` | `plugins/documents_test.go` | The document builder for docx, jar, apk, with and without an encrypted member. | Entry count, head entries, encrypted members, size, uniqueness; a plain zip is not typed as a document. | — |
| `TestOuterWithDocument` | `plugins/documents_test.go` | The outer archive builder. | 10,000 entries below the limit on its own, the document last, readable members. | — |
| `TestOverLimitViolations` | `plugins/documents_test.go` | The over-limit report checker on a good entry and eight altered ones. | The good entry passes; each alteration gives its violation. | — |

## 6. Known limits

- **Linux only.** Every file carries the `linux` build tag. The harness uses
  `/proc`, process groups, signals and inotify counts. The Windows build of the
  connector (README) has no scenario here.
- **The real GMalware is never used.** The fake gives the same constant answers
  for every file (score 0 or 1000, one malware name) and has no detection
  logic: it tests how the connector reacts to verdicts, not detection. Its
  `/search/` answers 404, except during an injected failure, and `gmalware_syndetect` is not modelled (the
  harness refuses it, since the size limit differs).
- **The real console is not used.** The fake re-delivers tasks and does not
  reproduce the stricter handing-out of the real manager. Metrics are accepted
  and not checked.
- **Cut uploads have no scenario.** The harness can count aborted uploads, but
  only the self-tests exercise it. The service failures in scenarios are a 503
  outage, the hang of the shutdown tests and the slow result of one content
  (T20a). Cut uploads are seen only where the fake drains a body (hang mode,
  injected failure); on a normal submission an unreadable body is not
  recorded, and only the invariant, which never sees a verdict "given" for it,
  catches a delivery.
- **Local filesystems only.** Every folder is under `t.TempDir()`; CephFS, NFS
  and other network filesystems, whose limits the README describes (dates,
  locks, inotify), are not covered. The watcher-off mode that is meant for them
  is checked only on a local disk.
- **Absence is judged over a window of 12 s.** An outcome in INPUT is held
  for 12 s once its report is written (`harness.Run`), or once the log names
  the file (`StaysInInput`); a later delivery would not be seen. The other
  "not delivered" checks are made at one moment; the invariant at the end of
  the test covers OUTPUT.
- **Sizes are small on disk.** The largest file dropped is about 9 MiB, apart
  from the opt-in sparse file of over 5 GiB. The bombs claim much more once
  inflated: 64 MiB for the zip and the gzip, 150 MiB for the solid 7z, and
  3.6 GB declared by the forged zip, from files of a few KB to a few MB.
- **Two modes only.** Scenarios start the connector in `monitoring` or `agent`
  mode; other commands (`scan`, `quarantine`, `version`) are not run.
- **Browser and 7-Zip scenarios depend on the machine.** The two PDF scenarios
  run only with the `realbrowser` tag, and then fail without a browser or as
  root.
