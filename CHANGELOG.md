# Changelog

## [Unreleased]

### Security

- dependencies: echo 4.16.1, golang.org/x/crypto 0.59.0, x/net 0.62.0, x/text 0.44.0, x/sys 0.50.0, brotli 1.2.7, klauspost/compress 1.20.2. Three advisories have no upstream fix and are not reachable: GO-2026-6875 and GO-2026-6872 (echo proxy and rate limiter middlewares, unused) and GO-2026-5932 (golang.org/x/crypto/openpgp, pulled by the archive library at init only, never called)

### Added

- quarantine: `quarantine.format: zip` writes password-protected ZIP files (ZipCrypto) openable with common archive tools; `tar` stays the default and both formats are always restorable. With `zip`, the quarantine password must be considered public (warning at each configuration)
- monitoring: `monitoring.disable_fs_watcher` (flag `--disable-fs-watcher`) stops all filesystem watches, files are found by the pre-scan and the periodic rescan only; it requires `monitoring.period` (configuration refused otherwise). Settable from the console

### Changed

- quarantine: a content restored from quarantine is now safe by content, wherever it is deposited and by whoever (before, one arbitrary entry of the registry decided, so restoring a content could be undone by another copy of it, and the file was quarantined again at the next rescan). The empty content is matched per location only. The registry is searched through an index created at opening (existing registries are migrated). `Quarantiner.IsRestored(ctx, location, sha256)` takes the location; `Quarantine` of an entry already restored returns `quarantine.ErrRestored` and writes nothing; the file is retried (not a definitive failure). The report of a restored file carries `has-been-restored`. A quarantine refused with `ErrRestored` is a retry and the move and delete actions do nothing on that pass (no detection report is written); a restoration and a quarantine of the same content at two places do not serialise, and the result stays closed (the second copy is quarantined)
- plugins: `GenerateReport` (the `HCContext` method and the plugin hook) now takes the reports as a sequence (`iter.Seq2[datamodel.Report, error]`, read once) and returns a `plugins.GeneratedReport{Content io.ReadCloser, Extension string}`: the extension comes from the generator, so without the `report` plugin the session report is a valid `.json` file instead of JSON named `.pdf`. The default generator writes into a pipe as the sequence is read; a failing sequence fails the content and the `session` plugin leaves no partial report. Third-party report plugins must adapt to the new signature. The exported `datamodel.GenerateReport` is removed (the default generator now lives in the connector; `datamodel.ReportsSeq` adapts a slice). The memory of a generation is still proportional to the number of files of the session (the spool comes later)
- quarantine: a content restored from quarantine is now safe by content, wherever it is deposited and by whoever (before, one arbitrary entry of the registry decided, so restoring a content could be undone by another copy of it, and the file was quarantined again at the next rescan). The empty content is matched per location only. The registry is searched through an index created at opening (existing registries are migrated). `Quarantiner.IsRestored(ctx, location, sha256)` takes the location; `Quarantine` of an entry already restored returns `quarantine.ErrRestored`, a definitive failure, and writes nothing. The report of a restored file carries `has-been-restored`
- monitoring: a file left in INPUT is no longer read and sent to the analysis again at every rescan. The pipeline reports the end of every accepted file (`scanner.Config.OnFileDone`, `scanner.FileOutcome`, `Monitor.FileDone`): a definitive outcome is remembered until the file changes (the rescan compares its metadata, no content is read); a failure that may go away is retried after `2 × period`, doubling at each failure up to `64 × period` (one hour at most, ±20 % jitter) and given up at the 8th failure, except failures of a resource (timeout or full disk of an action, extractor down) which are never given up; a file modified while it was being analyzed waits for stability again, with or without a rescan. Plugins: every file or top-level archive for which `OnStartScanFile` was called now gets exactly one `OnFileScanned`, with an `Error` when its processing was abandoned (extractor down in the middle of an archive, archive lost by the handler, shutdown, file changed). The `session` plugin used to keep such a file "in progress" and its session open until shutdown. A file refused without failure (empty, link, temporary name) and a path refused by the link checks are definitive until the file changes; a removal of the source refused with EACCES, EPERM or EROFS is a definitive failure; a file rewritten during each analysis is reopened at once twice, then at most once an hour. Limit: without `monitoring.period` a retry waits for the next event on the file
- plugins: the `filename` given to `OnScanFile` is now the logical path of the file: its real path at the first level, and for an extracted file the path of its top-level archive followed by its path inside the archive (`/in/alice/a.zip/x/y.exe`; control characters of a name, at any level, become `_`), built from where the file really was extracted, never from the name the archive declares; the same holds for a nested archive (`isArchive` true), and `location` stays the real path. `filepath_filter` now matches `forbidden_paths` and `skipped_paths` on this path instead of the path in the temporary folder: the rules aimed at it (`^/tmp/.*`, as in the example configuration) stop matching and the example no longer flags the content of every archive. Anchor allow rules on the archive prefix (`^/in/...`): an unanchored rule also matches a member name chosen by the archive. A forbidden path is now applied even when the file cannot be examined. Reports keep their keys
- stability: the file the connector acts on is the one whose stability was observed and which was analyzed. The monitor identifies a file by device, inode, size, modification time and change time (`scanner.FileIdentity`; size and modification time elsewhere than Linux) and hands it to the pipeline with that identity. Public API change: `handler.OnNewFileFunc` is now `func(file string, id scanner.FileIdentity) (accepted bool, err error)` and `Connector.SubmitFile(ctx, input, want)` is new (`ScanFile` is kept). The file is opened once (never blocking on a FIFO, never following a link unless `follow_symlinks`), and its hash, its analysis (the connector looks the SHA256 up, submits the content read from the descriptor and waits for the result itself, so that the client makes no temporary copy; the SHA256 the service reports must match, for extracted members too), the plugins (`location` is a `/proc/<pid>/fd/<N>` path on Linux) and the extraction of archives (a link to the descriptor, in a folder of its own beside the output folder) read that descriptor. On Linux the connector refuses to start when `/proc/<pid>/fd` cannot be used; elsewhere it logs, at start, that the deposit path is used. After the last read the descriptor and the name are checked again, the descriptor is closed, and only then comes the action: a file substituted by `rename`, rewritten in place with its time restored, whose folder was swapped, or whose upload resumed is left untouched. The pre-scan and a folder created or moved into a monitored path go through the stability delay, walked by one queue; with `follow_symlinks: true` a link to a folder is never walked, by the monitor or by `scan`. A change made during the analysis is still only picked up at the next rescan (never with `monitoring.period: 0`)
- move: a file moved to the destination no longer overwrites a file already there (data loss): it is stored as `<name>.conflict-<UTC time>[-n]<ext>`, reported in `move-conflict-of` and warned; the same rule applies to the `-lockreport` file, whose name no longer collides within the same minute; moves across file systems go through the private `.gmhost-staging` folder (setuid and setgid are no longer copied) which the consumers of the destination must ignore; a destination error no retry can fix (name too long, parent is a file, destination is a directory, file outside the source) is final
- reserved name: a deposited file whose name starts with `report-session-` (any letter case) is no longer moved to the destination, it stays in place and its report carries an error. Announce it to the users: such a file never passes through the airlock any more
- monitoring: the memory of the monitor no longer depends on the number or the length of the file names dropped: the table of tracked files is bounded in bytes (`monitoring.max_tracked_memory`, default `256MiB`) and one timer replaces one timer per waiting file. Below the bound nobody is limited; when it is full the owner holding the most (one per user folder, or per session folder at the `depth` of the `session` plugin, which now declares it with `HCContext.SetTrackingOwners`) yields first, and a refused or evicted file is found again at the next rescan (without periodic rescan, only when it is written to again), with a warning and a console event naming the owners (raised at the end of a rescan, or, without periodic rescan, as soon as a file is refused or evicted and at most once a minute). `monitoring.max_tracked_dir_percent` (default 25) is the share above which an owner is visited first. The purge of a rescan works in batches without blocking, and a folder that cannot be read only protects its own files, for at most 10 consecutive rescans
- symbolic links: with `follow_symlinks: false` (default), a file whose path crosses a symbolic link below its monitored path is refused when prepared and right before the action (move, delete, quarantine, restored-file handling, archive actions): it is left in place with a warning; `quarantine` restoration checks every component of the destination path, creates missing folders level by level from the monitored path (`os.Root`) and refuses a swapped parent, whatever the user replaced it with; the rescan examines links themselves. `follow_symlinks: true` with move, delete or quarantine now logs a warning at start, in the log and in the console (the checks are off). A user folder mounted through a symbolic link under a monitored path is now refused: monitor its target, or mount the folder without a link (bind mount). A restoration outside the monitored paths checks its whole path from the filesystem root: a link is accepted only when it belongs to root in a directory of root that is not writable by the group or by others (at most 8 links, no exception for the sticky bit), and no folder is created there. Windows junctions count as links
- archives: an archive in which an extracted file failed (submission, timeout, unreadable or lost file, sub-archive that could not be extracted, inconsistent plugin result) is no longer moved as clean: it gets an error, stays in place, and the failed files are listed in `error-subfiles` (bounded to 1000 entries of 1 KiB). An analysis error inside an archive is reported on the archive. An archive that changed or cannot be read at the end of its analysis is cleaned up and notified to the plugins with an error instead of leaking its temporary folder. A malicious archive that also failed on a member still gets its detection report when moving is on
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
