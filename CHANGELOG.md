# Changelog

## [Unreleased]

### Security

- dependencies: echo 4.16.1, golang.org/x/crypto 0.59.0, x/net 0.62.0, x/text 0.44.0, x/sys 0.50.0, brotli 1.2.7, klauspost/compress 1.20.2. Three advisories have no upstream fix and are not reachable: GO-2026-6875 and GO-2026-6872 (echo proxy and rate limiter middlewares, unused) and GO-2026-5932 (golang.org/x/crypto/openpgp, pulled by the archive library at init only, never called)

### Added

- session: the reports of an open session are kept on disk (`<work_dir>/session/<random>.jsonl`, JSON Lines, mode `0600`) and no longer in memory: the RAM of a session no longer grows with its size, only the reports in error stay in memory (16 MiB for the plugin, then spilled to the spool with a warning; a later success of the same file then adds a second line). New keys `max_duration` (default `24h`, must be positive) and `max_spool_size` (default `1GiB`, at least `1MiB`) close a session at once; the next deposit opens a new one. A spool that cannot be written (disk full) closes its session at once, reported with what it holds, with the console error `session-spool-error`; if even the JSON report fails, the spool is copied as is (`.jsonl`). The spools of a crashed run are deleted at the next start with a warning that gives the number of session reports lost (no recovery). The session plugin refuses a connector that has no work directory. In a session report the reports in error held in memory now come last, sorted by file name, after the others in arrival order. New `datamodel.SessionSpoolDir` (the folder of the spools under the work directory) and `datamodel.SessionSpoolExt`
- monitoring: a `modification_delay` under 1 s is accepted, and logs a warning each time the configuration is applied (at start, and at a reconfiguration by the console) that says what it risks: a file still being written may be analyzed incomplete, and a rewrite of the same size within one timestamp tick of the file system is not seen by the identity check (the delay must exceed the timestamp granularity of the file system)
- report plugin: the PDF has a section "Fichiers non analysés" and a counter for the files and archive members that reached the output without a complete analysis (reason in plain words, archive of origin), so that what `unanalyzable_policy` lets through and what a filter plugin waives is visible in the session report
- report plugin: the PDF is bounded. Every section stops at 300 rows with "… et N autres", the counters stay exact, the count of the failed members of an archive included, however many failed (up to 2^30); the blocked archives and their malicious members share the 300 rows of their section (3 rows per archive plus one per member). Every name, error and threat shown in the PDF is cut to 100 bytes (control, invisible and bidirectional characters become "�", ZWNJ and ZWJ included, so some Persian or Indic names and emoji sequences show "�" in the PDF; a file shows at most 2 threat names then "… (+N autres)"; the JSON report keeps more: up to 64 threat names per file, each text up to 1024 bytes, within its 4 MiB bound), so that long names cannot lengthen the rendering; the worst cases are measured with the real browser by a test, which checks the size always and the time on demand (`HC_WORST_CASE_TIME=1`), under half of the 2 minutes and 64 MiB the rendering is bounded by on a machine that is not overloaded. Custom templates must be updated to show the new data (`NbFileNotAnalyzed`, `NotAnalyzedFiles`, `More*`, `MoreExtracted`)
- report plugin: under extreme load (a load average of about 19) rendering the worst-case PDF can exceed the 2 minutes of the rendering timeout; the attempt then fails like any other failed generation (1 + `report_retries` attempts, one per check, about 8 minutes with the defaults for a session alone, and more when other sessions wait, since their attempts follow one another) and the session gets its JSON report instead; the real-browser test of the worst cases can fail on an overloaded machine (it checks the size always, and the time only with `HC_WORST_CASE_TIME=1`)
- report plugin: a report with an error is listed among the files in error and no longer counted as analyzed (a file whose action failed, such as a quarantine, is in error and not analyzed); the failed members of an archive are counted once, not again with the summary error of their archive
- datamodel: new `ExtractedErrorsTransient`, `ExtractedErrorsPermanent`, `ExtractedErrorsSummary` and `IsExtractedErrorsSummary`: the one place where the summary error of an archive with failed members is built and recognized, by the scanner and by the report plugin
- datamodel: new `UniqueKey`, `CutText`, `MoreErrorsKey`, `MoreErrorsText`, `ParseMoreErrors`, `ListedErrors`, `MaxFileCount` and `AddCount`: the one place where the keys of the failed files of an archive are made (unique, valid UTF-8, within 1 KiB, the key of the count of the files not listed kept apart) and where a text is cut, used by the scanner, by `Report.Bound` and by the report plugin; `Bound` keeps the count of the files not analyzed to `MaxFileCount` and the plugin adds its counts without wrapping around, so that an absurd count set by a plugin cannot make a count negative. `Bound` also adds the entries it leaves out to the count of the files not listed, so that the entries listed and that count always make the number of failed files
- stop on a signal: `SIGTERM` and `SIGINT` stop the connector like the order of the console (`agent`, `monitoring` and `scan`; before, the process died on `SIGTERM` without closing anything, leaving its work directory, an extraction in progress, and the reports of the open sessions). New local key `shutdown_timeout` (flag `--shutdown-timeout`, default `8s`, at least `2s`): files being processed finish within it minus a reserve, are then cut and left in place, the sessions write their report, the plugins close (the `extract` plugin kills its 7-Zip) and the work directory is removed; a second signal stops at once; a summary is logged; exit code `1` if the delay was exceeded. `Connector.Shutdown(drain, closing)`, `Handler.Shutdown` and `plugins.Interrupter` are new. Fix: after a stop whose wait was cut, the plugins used to be closed with an expired context and could no longer write their reports; they now always get a live one
- quarantine: `quarantine.format: zip` writes password-protected ZIP files (ZipCrypto) openable with common archive tools; `tar` stays the default and both formats are always restorable. With `zip`, the quarantine password must be considered public (warning at each configuration)
- monitoring: `monitoring.disable_fs_watcher` (flag `--disable-fs-watcher`) stops all filesystem watches, files are found by the pre-scan and the periodic rescan only; it requires `monitoring.period` (configuration refused otherwise). Settable from the console

### Changed

- plugins (breaking change): the `filesize_filter` plugin is removed, from the sources, the packages (`.goreleaser.yml`), the example plugins file and the README. An entry for it in the plugins file (by its name, or naming `filesize_filter.so` or `filesize.so`) is not loaded and does not fail the start (unless the plugins file has nothing else, which is refused): it logs a warning that names each ignored entry and the policy of `too_big` in force, and raises the console error `plugin-removed-filesize-filter` at each configuration applied (resolved by the next one without the entry). Oversized files are no longer quarantined by a plugin: set `unanalyzable_policy.too_big: mitigate` to keep that behaviour (nothing is switched on for you: the policy stays `error`, an oversized file stays in INPUT as an error). The warning is also reported again when a rollback replays a configuration that has such an entry, and its text is bounded (50 entries, 256 bytes each)
- actions (behavior change): when quarantining, moving or removing a file fails, its report now carries a short error ("the file could not be quarantined", "…moved to the destination", "…removed"; the cause stays in the log, and no path is added), where it used to carry none. The file is therefore counted as in error, not as analyzed, in the session reports and the PDF, and, while the connector runs, a failure repeated on a file that is still in INPUT (to be retried) opens no new session; a file that left INPUT after an error (quarantined, deleted or moved) is not remembered, so that the same bytes dropped again get their session. The lock report written next to a detection that could not be moved carries the same text. A quarantine refused because the content was restored is not a failure (the next pass handles the file as restored). A file whose analysis failed (without an error of the pipeline) gets "the file could not be analyzed" (the text of the service stays in the log), so that it is counted as in error and not as analyzed; an archive that lists its failed members is not an error of its own. A restored file whose action failed now has its report sent too. An error the report already had (of the analysis, or a refusal with its own reason) is kept
- session: the empty folders left below a session are removed once its report is written (`remove_empty_dirs`, **on by default**, `cleanup_timeout` 2m; Linux only; `false` restores the previous behavior). Announce it: a tree of empty folders a user prepared before depositing is removed after `delay` of inactivity. The root folder, the session folders and the folders changed less than `delay` ago stay; nothing is followed (every folder is opened from its parent with `O_NOFOLLOW` and removed with `unlinkat(AT_REMOVEDIR)`), at most 128 levels are walked. The removal runs in its own goroutine after the report (never at stop, never delaying a report), keeps the work directory by device and inode, and logs what it removed, kept and failed to remove
- unanalyzable files (behavior change: with the default `too_big: error`, an archive with a member over `max_file_size` now stays in INPUT as an error, for good and without a second extraction, where it used to be moved as clean; and an archive a plugin lets through, by `skipped_types` or a path rule, now reaches the output marked `policy-skipped`, where it used to stay in place because its hash was lost): `unanalyzable_policy.too_big` and `unanalyzable_policy.encrypted` (`error` by default, `pass` or `mitigate`) and `unanalyzable_policy.empty` (`skip` by default, or `mitigate`) are supported; `empty` defaults to `pass`, which is a behavior change: an empty file left in INPUT used to be skipped, and is now delivered as a new empty file (marked `empty` in the reports) and its source removed. Set `unanalyzable_policy.empty: skip` to keep the previous behavior. The `scan` command now analyzes empty files too (the default policy) and prints `not analyzed (empty)` for them without `--verbose`; use `unanalyzable_policy.empty: skip` to ignore them as before. `pass` needs `move.mode: copy` while the move action is on, and the console refuses to save that combination: it is refused with `rename`, and when the key is left out with `rename` the effective policy is `skip`, with a warning at each start, so that a site kept in `rename` still starts. Behavior change: an archive whose password is unknown (or whose encryption 7-Zip cannot name) was submitted as a plain file and moved as clean; with the default `encrypted: error` it now stays in INPUT as an error, visible in the log and the reports. An archive is now extracted, or listed to find out it is encrypted, whatever `extract_min_size` (a password-protected zip of a few KB used to be submitted as a plain file and moved), and an archive that the depth or the budget of the extraction does not let open (`recursive_extract_max_depth`, `recursive_extract_max_files`, `recursive_extract_max_size`) used to be analyzed as a plain file and now follows `too_big` as well, listed as `extract-limit`; an archive that fails for good under `error` is reported with its error. Members the extraction leaves out because of its limits follow `too_big` too: by default the archive stays in INPUT as an error (it used to be moved with them unanalyzed), with `pass` they are listed as not analyzed, with `mitigate` the archive is malware (`too-big`). `pass` marks the file `not-analyzed-reason` (`too-big`, `encrypted`, `empty`, or `policy-skipped` for a file an `OnScanFile` plugin let through, now visible in every report), with the new `Result` and `Report` fields `NotAnalyzedReason`, `NotAnalyzedSubfiles` and `NotAnalyzedExtractedFiles` (capped at 1000, exact counts); `mitigate` gives the result the former `filesize_filter` gave (`too-big`, `empty`, `encrypted` malware reasons, mapped to the console reason `invalid`). A file too big let through by `pass` is moved by name, as in `rename` mode, and says "content not verified". A `Report` is bounded by construction (`datamodel.MaxReportSize`, 4 MiB). `Report.Error` carries the error of the file. An `OnFileScanned` plugin cannot erase `NotAnalyzed*`. The core now sets `Source.TooBig` itself, from its own decision
- unanalyzable files: `unanalyzable_policy.extract_error: as_file` is supported (default `error`). An archive that the extractor finds damaged or inconsistent is, with `as_file`, analyzed as a plain file and delivered when nothing is detected, marked `extract-error`, **only when 7-Zip proved that it holds no encrypted content** (complete listing, no failure on the data of any member, every member plain and extracted, no data before or after the archive, which can hold another archive that 7-Zip does not list): member names too long or too deep and warnings of the headers only. Any other damaged archive follows `unanalyzable_policy.encrypted`, and the report error says "encrypted, or damaged and it cannot be told which". A warning and the console error `extract-error-as-file` are raised at each configuration applied with `as_file`. Behavior change with the default `error`: a damaged archive is now a definitive failure (one report with a fixed error text, stays in INPUT, no retry) where it was retried silently without a report; a 7-Zip killed, cut by its timeout, a failure of the host or an extractor that is down is still retried, and an output flood of 7-Zip, which used to be retried, is definitive. Members left out because the extraction breached its budget (more bytes than announced, too many relaunches) are now listed `extract-limit` and follow `too_big`, where they made the archive an extract-error. New `plugins.ErrArchiveAnomaly` and `plugins.ErrEncryptionPossible`, returned by an extractor for damage (an extractor that does not return them is retried only); the extract plugin returns a damaged archive as an error (with an `extract-error` entry for the report), counts a failed checksum (`CRC Failed`) and a line of the table that the parser cannot read, the exit code 2 of 7-Zip when it prints nothing, and the lines `ERROR: <path> : <path>` of an archive it cannot open among the damage, and its timeout wraps `context.DeadlineExceeded`. `config.CheckImplemented`, `config.ErrNotImplemented` and `pkg/config/pending.go` are removed: every key the schema declares is supported
- extraction (behavior change, a bypass closed): a file whose content is typed as an archive (zip, 7z, rar, gzip, bzip2, xz, zstd, tar, cab, cpio, ar, deb, rpm, xar, chm: the types the type detector reports) that the extractor refuses ("not an archive") used to be submitted as a plain file and delivered whatever the policy, while the entries it still holds were recoverable (a zip cut before its central directory, a 7z with a changed byte of its start header). It is now damaged with an encryption possible: a definitive failure kept in INPUT by default; with `as_file`, the `encrypted` policy decides (`extract_error: as_file` with `encrypted: pass` delivers it marked `encrypted`); also as a member. The type is read once, before the extractor works, and a type that cannot be read counts as an archive. Accepted false positives: any file typed as an archive that 7-Zip cannot open stays in INPUT (a truncated download, a text that starts with `BZh`, `PK\x03\x04` or `070707`, an unusual deb, rpm, cab or xz). Without the extract plugin, a valid tar, cpio, cab or xar that the built-in extractor cannot open now stays in INPUT as well: install the extract plugin. Limits unchanged: bytes in front of a complete archive (an MZ or ELF stub of a self-extracting archive, a junk header) make the file typed as something else, analyzed as such, with its embedded archive neither listed, extracted nor checked for encryption; and the types the detector does not report (arj, lha, lzh, lzma, .Z, lz4, wim, iso, dmg, vhd, vdi, vmdk, qcow, squashfs) are not covered, so a damaged password-protected archive of those formats is still a plain file
- extraction (behavior change, a bypass closed, only with the extract plugin and `extract` on): the zip-family files (`docx`, `xlsx`, `pptx`, `jar`, `apk`, `odt`, `epub`, typed from the names of their first entries) are checked by the extractor before being submitted whole (new `plugins.ExtractLimits.CheckOnly`: listing held to the extraction budget and test of every member with a password nobody knows, nothing written), so that a zip named like a document no longer carries encrypted members past `encrypted: error`, a member encrypted with a known password included (nothing is extracted, so nothing would be analyzed). A truncated or damaged document, and one holding an encrypted member, now stay in INPUT by default (`encrypted: pass` submits them whole, marked `encrypted`). Office and package files are read once more by 7-Zip (CPU, no disk), whatever their size. Limit: an archive embedded in a document is not looked into. Every call of 7-Zip meant to run without a password (listing, first attempt of an extraction, check) now passes a random password drawn once per process instead of `-p-`, which 7-Zip reads as the literal password `-`: an archive encrypted with `-` is encrypted, no longer opened by the first attempt. A fat jar or apk over the extraction budget is blocked by default (accepted false positive)
- move: `move.mode` (`copy` by default, or `rename`) and `move.min_throughput` (default `10MiB`) are supported. In `copy` mode the analyzed file is copied through the verified descriptor, checked against the analyzed SHA256, and published without ever linking or renaming the source inode, so a depositor that keeps the file open for writing cannot change what reaches the destination; the source is removed through the verified handle. Costs one more read and write per moved file; a copy slower than `min_throughput` (plus a minute) or finding the destination full is abandoned and retried as a failure of a resource, with the console event `host-move-resource`. A file too big to be analyzed that the policy lets through is the only one still moved by rename. `rename` keeps the previous behavior and warns (log and console event `host-move-rename`) at each configuration applied. `quarantine.MoveVerifiedCopy`, `MoveEmpty` and `CopyVerified` are new; the copy made when a file system refuses links is now verified against the analyzed SHA256 too. Behavior change: with the default, a moved file is no longer the same inode as the deposited one
- sessions: a session is no longer closed while files detected under its folder wait for a worker or for their stability delay (a user's files held behind another user's long analysis used to end in several sessions and several reports). New `HCContext.PendingFiles(dir)` and `HCContext.NotifyReportWritten(...)` (plugins that implement the interface must add them; the mock does), read from the monitoring table. A waiting file does not count as activity; `inflight_timeout` (default `24h`) closes a session that stayed idle that long whatever waits, with a warning. A file that ended in error appears once in its session report (also an archive abandoned without report), and its retries neither keep the session open nor open another; a report coming after its session was closed opens one that writes a complementary report. A report is never lost: each attempt has its own `report_timeout` (default `2m`), failed attempts are retried (`report_retries`, default 3), then a JSON report is written instead with a console error `session-report-fallback`; at most 64 sessions wait; at stop each open session gets its report, with a bound of its own for the fallback, and a summary is logged. Reports are written atomically and without replacement: a temporary file `.gmhost-tmp-*` in the export folder, then published only if the name is free, so an existing file at that name is never truncated or removed; a report file has mode `0644`; a console message gives the path and SHA256 of each report written. A report that cannot be written at all is lost loudly (`session-report-lost`), a backlog of sessions is raised as `session-report-backlog`, the name of a report is cut for a long folder name, the stop gives the JSON fallbacks a reserve of the deadline of `Close`. `report_timeout` and `inflight_timeout` must be positive. `datamodel.WriteReportsJSON` is exported
- report plugin: Chrome no longer leaves folders in the temporary folder of the system (`org.chromium.Chromium.*`, one set per PDF). Each rendering gets a folder `<work_dir>/report/profile-*` with three folders in it (`data`, `tmp`, `home`, mode `0700`), and the browser is started with `TMPDIR`, `HOME` and the `XDG_*` folders pointing there (on Windows `TMP`, `TEMP` and `USERPROFILE`), the rest of the environment kept; everything goes away with the rendering. Chrome puts a Unix socket under `TMPDIR`, and a socket path is limited to about 100 bytes: `TMPDIR` is a short link `gmhc-<random>` in the temporary folder of the system (or `/tmp` when that one is longer than 38 bytes or not owned by root or the connector account, or writable by its group or by others without the sticky bit) pointing to the folder of the rendering, removed when the browser exits and purged at start when dangling, so the length of `work_dir` does not matter
- quarantine: a content restored from quarantine is now safe by content, wherever it is deposited and by whoever (before, one arbitrary entry of the registry decided, so restoring a content could be undone by another copy of it, and the file was quarantined again at the next rescan). The empty content is matched per location only. The registry is searched through an index created at opening (existing registries are migrated). `Quarantiner.IsRestored(ctx, location, sha256)` takes the location; `Quarantine` of an entry already restored returns `quarantine.ErrRestored` and writes nothing; the file is retried (not a definitive failure). The report of a restored file carries `has-been-restored`. A quarantine refused with `ErrRestored` is a retry and the move and delete actions do nothing on that pass (no detection report is written); a restoration and a quarantine of the same content at two places do not serialise, and the result stays closed (the second copy is quarantined)
- quarantine (behavior change): a restoration never replaces an existing file (it fails with "destination already exists"; before, a file at the destination was overwritten). It is published with a hard link, else `RENAME_NOREPLACE`, and only else by a rename under a lock (a narrow window against another process, documented). The registry entry of a registered container is marked restored before the publication and put back if it fails; an entry that cannot be put back raises the console error `quarantine-restore-unmark-failed` (`quarantine.ErrRestoreRollbackFailed`). A container without entry is published first and registered after; when the registry then fails the file is there, unknown to it, and the console error `quarantine-restore-not-registered` is raised (`quarantine.ErrRestoredNotRegistered`). A restoration is refused toward the quarantine folder, the work directory, the staging area, the temporary names, a NUL and a path with `..`. The `.lock` is opened without following a link or blocking, and its content must match its id; `quarantine list` reads the top level only. A `.lock` without registry entry is now restored (decision Q30), only below a monitored path and to the path of its own index, with a console warning `quarantine-restore-unregistered`; `quarantine.ErrNoRegistryEntry` is removed. New on `*QuarantineHandler`: `SetWorkDir` and `SetUnregisteredRestoreHook` (set by the connector as soon as its connector is made; the hook runs in a goroutine of its own; `quarantine.Config` is unchanged). The `quarantine restore` command warns when its registry is in memory
- plugins: `GenerateReport` (the `HCContext` method and the plugin hook) now takes the reports as a sequence (`iter.Seq2[datamodel.Report, error]`, read once) and returns a `plugins.GeneratedReport{Content io.ReadCloser, Extension string}`: the extension comes from the generator, so without the `report` plugin the session report is a valid `.json` file instead of JSON named `.pdf`. The default generator writes into a pipe as the sequence is read; a failing sequence fails the content and the `session` plugin leaves no partial report. Third-party report plugins must adapt to the new signature. The exported `datamodel.GenerateReport` is removed (the default generator now lives in the connector; `datamodel.ReportsSeq` adapts a slice). The memory of a generation is still proportional to the number of files of the session (the spool comes later)
- monitoring: a file left in INPUT is no longer read and sent to the analysis again at every rescan. The pipeline reports the end of every accepted file (`scanner.Config.OnFileDone`, `scanner.FileOutcome`, `Monitor.FileDone`): a definitive outcome is remembered until the file changes (the rescan compares its metadata, no content is read); a failure that may go away is retried after `2 × period`, doubling at each failure up to `64 × period` (one hour at most, ±20 % jitter) and given up at the 8th failure, except failures of a resource (timeout or full disk of an action, extractor down) which are never given up; a file modified while it was being analyzed waits for stability again, with or without a rescan. Plugins: every file or top-level archive for which `OnStartScanFile` was called now gets exactly one `OnFileScanned`, with an `Error` when its processing was abandoned (extractor down in the middle of an archive, archive lost by the handler, shutdown, file changed). The `session` plugin used to keep such a file "in progress" and its session open until shutdown. A file refused without failure (empty, link, temporary name) and a path refused by the link checks are definitive until the file changes; a removal of the source refused with EACCES, EPERM or EROFS is a definitive failure; a file rewritten during each analysis is reopened at once twice, then at most once an hour. Limit: without `monitoring.period` a retry waits for the next event on the file
- plugins: the `filename` given to `OnScanFile` is now the logical path of the file: its real path at the first level, and for an extracted file the path of its top-level archive followed by its path inside the archive (`/in/alice/a.zip/x/y.exe`; control characters of a name, at any level, become `_`), built from where the file really was extracted, never from the name the archive declares; the same holds for a nested archive (`isArchive` true), and `location` stays the real path. `filepath_filter` now matches `forbidden_paths` and `skipped_paths` on this path instead of the path in the temporary folder: the rules aimed at it (`^/tmp/.*`, as in the example configuration) stop matching and the example no longer flags the content of every archive. Anchor allow rules on the archive prefix (`^/in/...`): an unanchored rule also matches a member name chosen by the archive. A forbidden path is now applied even when the file cannot be examined. Reports keep their keys
- stability: the file the connector acts on is the one whose stability was observed and which was analyzed. The monitor identifies a file by device, inode, size, modification time and change time (`scanner.FileIdentity`; size and modification time elsewhere than Linux) and hands it to the pipeline with that identity. Public API change: `handler.OnNewFileFunc` is now `func(file string, id scanner.FileIdentity) (accepted bool, err error)` and `Connector.SubmitFile(ctx, input, want)` is new (`ScanFile` is kept). The file is opened once (never blocking on a FIFO, never following a link unless `follow_symlinks`), and its hash, its analysis (the connector looks the SHA256 up, submits the content read from the descriptor and waits for the result itself, so that the client makes no temporary copy; the SHA256 the service reports must match, for extracted members too), the plugins (`location` is a `/proc/<pid>/fd/<N>` path on Linux) and the extraction of archives (a link to the descriptor, in a folder of its own beside the output folder) read that descriptor. On Linux the connector refuses to start when `/proc/<pid>/fd` cannot be used; elsewhere it logs, at start, that the deposit path is used. After the last read the descriptor and the name are checked again, the descriptor is closed, and only then comes the action: a file substituted by `rename`, rewritten in place with its time restored, whose folder was swapped, or whose upload resumed is left untouched. The pre-scan and a folder created or moved into a monitored path go through the stability delay, walked by one queue; with `follow_symlinks: true` a link to a folder is never walked, by the monitor or by `scan`. A change made during the analysis is still only picked up at the next rescan (never with `monitoring.period: 0`)
- move: a file moved to the destination no longer overwrites a file already there (data loss): it is stored as `<name>.conflict-<UTC time>[-n]<ext>`, reported in `move-conflict-of` and warned; the same rule applies to the `-lockreport` file, whose name no longer collides within the same minute; moves across file systems go through the private `.gmhost-staging` folder (setuid and setgid are no longer copied) which the consumers of the destination must ignore; a destination error no retry can fix (name too long, parent is a file, destination is a directory, file outside the source) is final
- reserved name: a deposited file whose name starts with `report-session-` (any letter case) is no longer moved to the destination, it stays in place and its report carries an error. Announce it to the users: such a file never passes through the airlock any more
- monitoring: the memory of the monitor no longer depends on the number or the length of the file names dropped: the table of tracked files is bounded in bytes (`monitoring.max_tracked_memory`, default `256MiB`) and one timer replaces one timer per waiting file. Below the bound nobody is limited; when it is full the owner holding the most (one per user folder, or per session folder at the `depth` of the `session` plugin, which now declares it with `HCContext.SetTrackingOwners`) yields first, and a refused or evicted file is found again at the next rescan (without periodic rescan, only when it is written to again), with a warning and a console event naming the owners (raised at the end of a rescan, or, without periodic rescan, as soon as a file is refused or evicted and at most once a minute). `monitoring.max_tracked_dir_percent` (default 25) is the share above which an owner is visited first. The purge of a rescan works in batches without blocking, and a folder that cannot be read only protects its own files, for at most 10 consecutive rescans
- symbolic links: with `follow_symlinks: false` (default), a file whose path crosses a symbolic link below its monitored path is refused when prepared and right before the action (move, delete, quarantine, restored-file handling, archive actions): it is left in place with a warning; `quarantine` restoration checks every component of the destination path, creates missing folders level by level from the monitored path (`os.Root`) and refuses a swapped parent, whatever the user replaced it with; the rescan examines links themselves. `follow_symlinks: true` with move, delete or quarantine now logs a warning at start, in the log and in the console (the checks are off). A user folder mounted through a symbolic link under a monitored path is now refused: monitor its target, or mount the folder without a link (bind mount). A restoration outside the monitored paths checks its whole path from the filesystem root: a link is accepted only when it belongs to root in a directory of root that is not writable by the group or by others (at most 8 links, no exception for the sticky bit), and no folder is created there. Windows junctions count as links
- archives: an archive in which an extracted file failed (submission, timeout, unreadable or lost file, sub-archive that could not be extracted, inconsistent plugin result) is no longer moved as clean: it gets an error, stays in place, and the failed files are listed in `error-subfiles` (1000 failed files of 1 KiB plus a count of the others; the keys stay distinct after the cut, so two names that share their first KiB, differ only in bytes that are not UTF-8, or are one path twice, are all listed). An analysis error inside an archive is reported on the archive. An archive that changed or cannot be read at the end of its analysis is cleaned up and notified to the plugins with an error instead of leaking its temporary folder. A malicious archive that also failed on a member still gets its detection report when moving is on
- work directory: archives are extracted under a private `gmhost-<random>` directory (mode `0700`) of `work_dir` (default: the system temporary directory), removed at stop; crashed processes' leftovers are purged at start. It is never scanned nor monitored, a sub-archive no longer starts a scan of its own (one session per archive), and plugins can ask for it with `HCContext.GetWorkDir()` (new). The default base is the system temporary directory (`TMPDIR` honored): a site that monitors `/tmp` must set `work_dir` elsewhere. A `work_dir` that is, or lies under, a monitored path refuses to start; a warning is logged when it is on a memory filesystem, or when `move.destination` is under a monitored path. Windows: no orphan purge, no real lock, ACLs inherited from the parent
- plugins: `session` ignores files under the work directory, and a folder named `..x` is no longer taken for a path outside its root
- quarantine: restoration compares the SHA256 of the restored content with the registry before replacing anything: a wrong quarantine password (tar format has no integrity check) now fails and keeps the `.lock` instead of restoring random bytes. Only 64-character hexadecimal identifiers are accepted. Quarantining a file whose size changes while it is read fails and keeps nothing. Files named `.gmhost-tmp-*` are never scanned
- quarantine: restoration refuses a content larger than its `.lock` file (the 5 GB fixed limit does not exist anymore) or whose size differs from the size recorded in the container; hardened restoration path (destination directory checked, exclusive temporary file named `.gmhost-tmp-<name>-<hex>`, `fsync`, atomic rename)
- plugins: loaded in the order of the plugins file (same configuration, same verdict); a duplicate plugin name is a startup error. `scanner.PluginConfig` gains `Name` and `Connector.LoadPlugins` takes a `[]PluginConfig`
- plugins: `OnScanFile` no longer lets an allow-list placed first hide a deny-list placed after: the first refusal (malware or error) wins, otherwise the first waiver applies
- plugins: an empty plugins file, a plugin without `file`, or any configured plugin on Windows now stops the startup instead of loading nothing
- plugins: every `OnFileScanned` callback is now called, chained in order (before, the first non-nil result stopped the others, e.g. `session` was not notified); a plugin cannot clear `Error`, `Malware` or `AnalysisError` (restored, with a warning)
- plugins: a plugin entry accepts only `file` and `config`, and each `config` is decoded strictly: a misspelled or unknown key (`confg:`, `forbidden_pathes:`) now stops the startup, naming the key, instead of leaving a filter silently inactive. Remove any stray key from your plugins file. Anchors, aliases and merge keys are refused at every level, the same plugin file declared under two names is refused, and configuration errors never quote a value (they can be passwords)
- plugins: a waiver (an `OnScanFile` result that skips the analysis) must carry no detection trace (`MalwareReason`, `Malwares`, `MaliciousSubfiles`, `ErrorSubfiles`); otherwise it is a refusal, and when it does not say so (no `Malware`, `Error` or `AnalysisError`) the core sets an "inconsistent plugin result" error: the file is neither analyzed nor moved. `OnFileScanned` plugins also cannot erase `MalwareReason`, `Malwares`, `MaliciousSubfiles` or `ErrorSubfiles`, and receive a deep copy of the result, and a partial removal (one entry of `Malwares`, `MaliciousSubfiles` or `ErrorSubfiles`, a subfile turned clean) is restored too. `Register*` calls made after `Init` are ignored with a warning
- report: the browser that renders the PDF is checked at start and at every configuration: new key `chrome_path` (empty: looked up in PATH), same executable checks as `seven_zip_path`, and a test rendering of an empty page (30 s at most, no process survives). A missing, unsafe or unable-to-run browser now refuses to start instead of failing at the first report; a connector running as root is refused (Chrome keeps its sandbox, which it does not accept as root): run it under a dedicated service account. At most 2 browsers run at once, a rendering is bounded to 2 minutes and a report PDF to 64 MiB, and the browser is also told not to resolve, prefetch or use a proxy. The browser profile lives under the private work directory and is removed after each report. The page is rendered with JavaScript off and every network or `file:` request refused: a custom template must embed its images and styles
- archives: 7z extraction is hardened. Member names are literal (`-spd`): a member named `*` or `?` no longer widens the extraction. The listing is read as a stream (no 256 MB capture; 1,000,000 entries, 64 KiB per line and 4,096 bytes per member name at most) and `stderr` is capped at 1 MiB. What 7z produced is counted against what the listing announced, and anything 7z reports (data after the end of the archive, warnings, errors, a forged member table in an archive comment, a skipped member sharing the name of an extracted one, a control character in a name, a count mismatch) gives the archive an `extract-error` instead of being swallowed. 7z's messages are read by their exact label, never by a name they quote, and a refused link is tolerated only when it is the only error. The extractor applies the strictest of its own keys and the global limits (`max_file_size`, remaining recursive budgets). An archive 7z recognizes but fails to extract is now an error and is no longer submitted as a plain file (only a file 7z, or the default extractor, says is not an archive is); so is an archive from which nothing could be extracted while members were left out. `ExtractFile` changes signature (`plugins.ExtractLimits` in, `plugins.Extraction` out): third-party extraction plugins must be rebuilt. Still open until lot E (see § 7.14 of the plan): an archive whose members are all under the limits but of which a part is skipped is analyzed without the skipped members, which are reported nowhere yet, and, until the entry on the extraction limits below, the limits bound the sizes the archive announces, not the bytes written
- extract: the 7-Zip binary is checked at start and at every configuration: the embedded one is now deployed in the private work directory (`extract-bin`, mode `0500`, removed at stop or if the start fails) instead of the system temporary directory, where it leaked; a `7zzs` found in `PATH` is no longer taken (set `seven_zip_path` to use another one), and a configured or deployed binary goes through the executable checks. It is run on a reference archive with the real options, and the connector refuses to start with a 7-Zip that cannot run (the message names `noexec` file systems) or is older than 7-Zip 25.01 or whose listing does not match what the analysis relies on (version, names not sanitized, no `Tail Size`, moved columns). When the extractor cannot be run at all, archives are no longer submitted nor put in definitive error: the extraction fails with `extractor-unavailable`, the console error `host-extractor-unavailable` is raised once and resolved as soon as an extraction shows that 7-Zip runs (whatever it concluded about the archive); an extractor failure on a nested archive leaves the top archive in place without a final result. Also fixed: the output of 7-Zip that the plugin does not read is now drained under the same cap instead of without bound, and 7-Zip is run in its own process group
- extract (breaking): the keys `max_file_size`, `max_extracted_files` and `max_total_extracted_size` are removed from the plugin. The connector refuses to start, or keeps its previous configuration, if one is still in the plugins file: the limits are now the global ones, passed at each extraction. Adjust the global values if the old ones must be kept:

  | Removed plugin key | Replaced by (main configuration) | Scope change |
  | --- | --- | --- |
  | `max_file_size` | `max_file_size` | the global value applies to every member |
  | `max_extracted_files` | `recursive_extract_max_files` | per archive becomes all levels of one scan |
  | `max_total_extracted_size` | `recursive_extract_max_size` | per archive becomes all levels of one scan |

  A member past the limits is no longer skipped silently nor written then rejected: it is reported `too-big` (past the per-member limit) or `extract-limit` (past the budget announced by the listing). The limits now bound what 7-Zip really writes, not the sizes the archive announces (gzip, bzip2 and other stream formats announce wrong or no sizes: such a member weighs the largest size allowed). On Linux the kernel limits the size of each file 7-Zip writes (`RLIMIT_FSIZE`, bounded by what is left of the budget) and forbids core dumps; on every system the output folder is measured every 250 ms and 7-Zip is stopped past the byte or file budget (folders count), and the bytes produced are measured after 7-Zip whatever it answered. A member found past the limit is reported alone and the rest of its batch is extracted again (8 relaunches per batch, 16 per extraction); an archive that writes more than it announced, a path nested 64 folders deep, or an output that cannot be measured is an `extract-error`, never `too-big`, so `too_big: pass` never lets it through. 7-Zip has 2 minutes plus the time to read the archive and write the budget at 5 MiB/s (1 hour at most) instead of a fixed hour. The "announced sizes" gap of the previous entry on archives is closed by this change; the leak of members skipped by the policy (§ 7.14) remains until lot E.
- actions on the verified file: the actions no longer receive a path but a `Source` (deposit path, monitored root, verified identity, and on Linux the descriptor opened without following any link). A quarantine reads the file from that descriptor and records the deposit path only as a name; a deletion removes the file by name in the folder it was opened in and only if it still is the verified inode; a move checks the identity right before moving. A file replaced or modified since its verification is neither quarantined, deleted nor moved. A named pipe or a device put in place of a file is refused without blocking. Restoration opens its destination folder without following any link (and writes inside it), and a link swapped in between the check and the write makes it fail with the `.lock` kept. The third-party actions and the quarantiner implementations change signature (`Action.Handle` takes a `scanner.Source`, `Quarantiner.Quarantine` takes the opened file). On Linux the connector opens each deposited file once, below its monitored path and without following any link, and keeps that descriptor open during the actions: the move of a file by rename (default mode) now links the verified inode from that descriptor (`linkat` on `/proc/self/fd/N`, falling back to a copy read from the descriptor when the file system refuses the link) and then removes the old name through the handle, taking the destination back if the removal fails; a file swapped for another at the instant of the move is never published, and the old by-name rename fallback is gone. A named pipe or device put in place of a file is refused without blocking a worker. With `follow_symlinks: true`, a deposited path that is a symbolic link (or reached through one) is analyzed and may be quarantined (read through the descriptor), but a deletion or a move of it is refused with a permanent error ("the source is a symbolic link") and reported as such: the link and its target stay, and nothing is reported deleted for content that is still there. Windows and other systems keep the descriptor closed during the actions, which re-check the identity by name (limit documented)
- configuration: a configuration is validated before anything is applied. A `Configure` that fails validation changes nothing and raises the console error `host-config-rejected` (kept until a `Configure` succeeds, with an hourly reminder in the logs). One that fails while being applied is rolled back to the previous configuration; the connector stops completely only when there was none or when the rollback fails too. A first start with an invalid configuration no longer leaves a half-built connector: `Start` fails the same way, without panic, until the cause is fixed
- configuration: keys sent by the console that this version does not know are applied without effect and raise the console error `host-config-unknown-keys` (resolved by the next `Configure` without such keys), instead of being ignored silently
- configuration: the filesystem watches are set up before the quarantine is reconfigured, so a missing monitored path never leaves the quarantine half migrated
- quarantine: a reconfiguration (new directory, registry, format or password) is all or nothing: the new registry is prepared beside the current one, the `.lock` files are moved, and the registry and the password switch last. Any error puts the files back and leaves the previous registry and password in service
- quarantine: the quarantine directory is checked at every application of the configuration. It is refused, with the `chown` and `chmod` commands that fix it, when it belongs to another account than the connector or root or is writable by its group or by others; and when it is, is under, or contains a monitored path, `move.destination` or the work directory. A missing directory is created with mode `0700`. A site whose quarantine directory is group-writable or placed under a monitored path will not start after the update: run `chown <connector account> <dir> ; chmod 700 <dir>` or move the quarantine directory
- plugins: a relative `exports` directory of the `session` plugin is now refused (an output directory must be absolute so the connector can check where it is)
- plugins: the files loaded into the process (plugin `.so`, plugins file) are checked before they are opened: no link that is not a system link in their path, owned by root or the connector account, not writable by others (a group-writable one only warns, a refusal when the connector runs as root). A plugin cannot raise or clear the events of the core (`host-*`, `gmalware*`)
- plugins: a plugin may implement `Validator`: `Validate` runs for every plugin before a configuration is applied (with the previous one still running) in a scratch directory removed afterwards. `HCContext` gains `DeclareExecutable` (safety checks on a binary: owner, permissions, location), `DeclareOutputDir`, `NotifyError` and `NotifyResolution`. The connector refuses an output directory under a monitored path or the quarantine directory, and an executable under a monitored path, `move.destination` or an output directory. The plugins of the repository validate their configuration; `Close` of each is safe to call twice
- configuration file: a file that cannot be read or parsed, holds a mistyped value or a key the connector does not declare now stops the connector with an error naming the file and the key (never a value), instead of starting with defaults or ignoring the key. An absent file is still accepted, except when it is given with `--config`. Values are typed strictly like the console JSON (`workers: "4"`, `true` or `2.5` for a number are refused: quote strings, do not quote numbers) and a duration needs a unit (`5` is refused, `5m` is accepted; `0` stays valid). Upgrade notes: a leftover key such as the `cache:` section of the former `rsc/config.yml` must be removed or the connector will not start; and `follow_symlinks: true`, which had no effect from the file until now (the SDK key lacked its `mapstructure` tag), now takes effect: links are followed and the symbolic link checks are off. Remove the key to keep the previous behaviour
- configuration: connector-integration SDK v0.10.0 declares the new keys (`monitoring.*`, `move.mode`, `move.min_throughput`, `work_dir`, `unanalyzable_policy.*`, `quarantine.format`); a key set to a value not supported yet by this version is refused instead of being silently ignored

### Fixed

- monitoring: a directory that cannot be read during a periodic rescan no longer stops the walk of the other directories

## [v1.5.6]

### Fixed

- release: ship filepath-filter plugin in release archives
- go: bump to go1.27

## [v1.5.5]

### Fixed

- Windows: monitoring deadlock (`fatal error: all goroutines are asleep`, or monitoring silently stuck) when files or folders are removed or created while other changes are notified, e.g. while setting up monitoring of large directories (rfsnotify update)
- monitoring setup no longer fails when a sub-directory is removed while monitored paths are walked
- print action failing with `file already closed` for analyses ongoing during a reconfiguration, which also prevented their mitigation event from reaching the console
- Windows: out of memory when monitoring large directory trees (64KB per sub-directory), monitoring now costs a single watch per monitored path, and starts immediately (rfsnotify update)

## [v1.5.4]

### Fixed

- Handling properly file changing between their listing and their actual scan

## [v1.5.3]

### Fixed

- clarify error notifications sent to console

## [v1.5.2]

### Added

- extract_min_size config, file at or below extract_min_size (default to 8KB) will directly send to analyze without extraction

## [v1.5.1]

### Fixed

- restoration: recreate original directory tree

### Changed

- Detect: size idle connection pool to number of analysis workers.

### Added

- logs: add more logs

## [v1.5.0]

### Added

- metrics via connector-manager
- more logs for connector-manager actions

### Fixed

- close file monitor before scanner during reconfiguration (which previously caused "connector is shutting down" errors)

## [v1.4.7]

### Fixed

- Fix race condition on finishArchiveAnalysis
- Fix finish archive when scanned by a plugin

## [v1.4.6]

### Fixed

- Fix SHA256 compute bottleneck
- Fix quarantine restore on different mount points (cross-device fallback)

### Changed

- Print action timestamps use RFC3339 format

## [v1.4.5]

### Fixed

- Action timeout is now proportional to file size
- Fix orphaned .lock files when quarantine fails midway
- Fix race condition ongoinganalysis clean too early
- Fix version at build

## [v1.4.4]

### Fixed

- Fix syndetect analysis ID lookup in cached result polling

## [v1.4.3]

### Changed

- modify messages print by Print options
- print option now append to file if provided and exists

### Fixed

- Fix ongoing analysis leaks

## [v1.4.2]

### Added

- user tags archive with top level archive name is now push in case or archive

### Fixed

- Fixed session plugin not receiving callbacks for nested archives containing only sub-archives, which caused sessions to never close and reports to not be generated
- Delete rescan unused option and fix doc for period option.
- Fixed report duration refers now to session duration
- Analyzed volume is now based on input file when submit to gdetect
- ModDelay is now used when a file is seen by rescan

### Changed

- session plugin : tag are now push with session-<id>-<start time timestamp> as seen in report
- session plugin : report now are named report-session-id-<start time timestamp>.pdf

### Deleted

- session plugin: remove useless delete_inputs option

## [v1.4.1]

### Added

- analysis error in mitigation 

## [v1.4.0] - 2026-01-22

### Changed

- use recursive extraction

## [v1.3.0]

### Added

- GMalwareExpertURL in ConnectorCommonConfig

## [v1.2.0] - 2026-01-19

### Added

- SHA256 in mitigation info
- plugin can register gdetect.WaitForOptions to specify submit options
- session plugin add session id in user tags

## [v1.1.1] - 2026-01-06

### Fixed

- Channel closed twice in some cases, resulting in a panic

## [v1.1.0] - 2025-12-11

### Added

- filepath_filter plugin

## [v1.0.3] - 2025-12-04

### Fixed

- GLIMPS Malware's analysis error logging and treatment
- Do not move file when there's an error in the analysis
- Console log error when action(s) failed
- Update embedded 7zzs version
- Unique name for lock report
- Syndetect error message

## [v1.0.2] - 2025-11-25

### Fixed

- Filesize plugin's logger
- Don't start connector after error at setup
- Filetype magic default dir loading is optional

## [v1.0.1] - 2025-11-20

### Fixed

- Release CI
- Update crypto deps

## [v1.0.0] - 2025-11-20

### Added

- Add agent cli that handles connector manager integration

### Changed

- AES ciphering now use CTR instead of deprecated OFB
- Add plugin capability with extract, filetype filter, session, and report plugins
- Config fields

### Fixed

- monitoring handle recursive fsnotify

## [v0.4.4] - 2025-06-25

- update go to 1.24.4
- fix worker dying when error on action handling

## [v0.4.3] - 2025-03-17

- fix file filtering
- update go to 1.24.1
- update go-gdetect to v1.4.0

## [v0.4.2] - 2024-12-18

- fix log message for archive with empty files

## [v0.4.1] - 2024-12-04

### Fixed

- destination path for move action

## [v0.4.0] - 2024-10-23

### Added

- move action

## [v0.3.1] - 2024-10-16

### Fixed

- Handle when two files with the same name are put into quarantine

## [v0.3.0] - 2024-10-08

### Added

- syndetect API support

## [v0.2.1] - 2024-09-19

### Fixed

- Check if analysis is done when using detect cache
- Do not skip badly restored file

## [v0.2.0] - 2024-07-12

### Added

- Extraction feature

### Changed

- Golangci-lint

### Fix

- Help message for config file
- Proceed checks when scanning file in a folder
- Use default quarantine location
- Cache file creation when not existing
- Export windows executable in console mode
- msi installation

## [v0.1.0] - 2024-02-23

### Added

- First host connector version
    - Scan file/folder feature
    - Monitor folder
    - Quarantine and cache handling
