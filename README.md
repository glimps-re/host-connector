# GLIMPS Malware Host Connector

[![Build Status](https://github.com/glimps-re/host-connector/actions/workflows/go.yml/badge.svg)](https://github.com/glimps-re/host-connector/actions/workflows/go.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/glimps-re/host-connector)](https://goreportcard.com/report/github.com/glimps-re/host-connector)
[![GoDoc](https://pkg.go.dev/badge/github.com/glimps-re/host-connector?status.svg)](https://pkg.go.dev/github.com/glimps-re/host-connector?tab=doc)
[![Release](https://github.com/glimps-re/host-connector/actions/workflows/release.yml/badge.svg)](https://github.com/glimps-re/host-connector/actions/workflows/release.yml)

A security agent tool to scan files and folders for malware using GLIMPS Malware Detect on Windows and GNU/Linux host systems.

## Features

- **File and folder scanning**: Scan individual files or entire directory structures
- **Real-time monitoring**: Watch directories for changes and automatically scan new/modified files
- **Archive extraction**: Extract and scan content from various archive formats
- **Quarantine management**: Automatically quarantine malicious files with encryption
- **Multiple actions**: Configurable actions when malware is detected (quarantine, delete, move, log)
- **Plugin system**: Extensible architecture with built-in plugins for specialized processing (**ONLY FOR GNU/Linux**)

## Architecture

GMHost is built on a modular plugin architecture that enables extensible file processing capabilities:

**Processing Flow**:
1. **File Detection**: Files are discovered through scan or monitoring commands
2. **Plugin Pipeline**: Files pass through registered plugins in sequence
3. **Analysis**: Clean files are sent to GLIMPS Malware Detect for analysis
4. **Action Processing**: Results trigger configured actions (quarantine, delete, move, etc.)
5. **Reporting**: Session and report plugins generate consolidated output

**Plugin Integration Points**:
- **OnStartScanFile**: Intercept files before analysis (filtering, preprocessing)
- **OnScanFile**: Replace GLIMPS Malware analysis
- **WithWaitForOptions**: Modify submission options before analysis
- **OnFileScanned**: Process analysis results (logging, custom actions)
- **OnReport**: Handle generated reports (consolidation, forwarding)
- **ExtractFile**: Custom archive extraction logic
- **GenerateReport**: Custom report generation and formatting

## Usage

```bash
GLIMPS Malware Host connector is a tool to scan files with GLIMPS Malware Detect

Usage:
  GMHost [flags]
  GMHost [command]

Available Commands:
  agent       Start monitoring location with GLIMPS Malware host under Connector manager control
 Global config will not be used.
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  monitoring  Start monitoring location with GLIMPS Malware host
  quarantine  Handle GLIMPS Malware host quarantined files
  scan        Scan folders

Flags:
      --config string                       config file (default "/etc/gmhost/config.yml")
  -d, --debug                               print debug strings
      --extract                             Enable archive extraction (archives are unpacked and contents scanned)
      --extract-min-size string             Minimum file size to attempt extraction (e.g., '8KB') (default "8KB")
      --extract-workers int                 Number of concurrent workers for archive extraction (default 2)
      --follow-symlinks                     Follow symbolic links when scanning directories (if disabled, symlinks are skipped)
      --gmalware-syndetect                  Use syndetect API to analyze files
      --gmalware-token string               GLIMPS Malware Detect token
      --gmalware-url string                 GLIMPS Malware Detect url (E.g https://gmalware.ggp.glimps.re)
  -h, --help                                help for GMHost
      --insecure                            do not check certificates
      --max-file-size string                Maximum file size to scan directly (e.g., '100MB') (default "100MiB")
      --move-destination string             Target directory for moving clean files (preserves subdirectory structure)
      --move-source string                  Source directory filter (only clean files within this path are moved to destination)
      --print-location string               File path for scan reports (leave empty to print to stdout)
      --quarantine string                   Directory path where quarantined files are stored (default "/var/lib/gmhost/quarantine")
      --quarantine-registry string          Path to the database that store quarantined and restored file entry (leave empty for in-memory store, lost on restart)
      --recursive-extract-max-depth int     Maximum depth for recursive archive extraction (default 10)
      --recursive-extract-max-files int     Maximum total number of files for recursive archive extraction (default 10000)
      --recursive-extract-max-size string   Maximum total size for recursive archive extraction (default "5GB")
      --shutdown-timeout duration           Time allowed to stop on SIGTERM or SIGINT (at least 2s) (default 8s)
      --timeout duration                    Time allowed to analyze each file (default 5m0s)
  -v, --verbose                             Report all scanned files, including clean files (not just malware detections)
      --workers int                         Number of concurrent workers for file analysis (default 4)

Use "GMHost [command] --help" for more information about a command.
```

## Commands

### Scan

Scan files or directories for malware.

```bash
GMHost scan [flags] [path...]

Scan-specific Flags:
      --gui    enable graphical user interface showing scan progress (Windows only)
```

**Examples:**
```bash
# Scan a single file
GMHost scan /path/to/file.exe

# Scan a directory
GMHost scan /path/to/directory

# Scan with GUI (Windows)
GMHost scan --gui C:\Users\Username\Downloads
```

### Monitoring

Start real-time monitoring of directories for file changes.

```bash
Start monitoring location with GLIMPS Malware host

Usage:
  GMHost monitoring [flags] [path...]

Flags:
  -h, --help                   help for monitoring
      --mod-delay duration     Wait time after file modification before scanning (e.g., '30s', prevents scanning incomplete writes) (default 30s)
      --pre-scan               Immediately scan all existing files in monitored paths when monitoring starts
      --disable-fs-watcher     Do not watch filesystem events, only pre-scan and periodic rescan (requires --scan-period)
      --scan-period duration   If set, enable periodic rescan. Time interval between periodic re-scans (e.g., '1h', '30m') (default 0s - disabled)
```

**Examples:**
```bash
# Monitor a directory with pre-scan
GMHost monitoring --pre-scan /home/user/Downloads

# Monitor with periodic re-scanning
GMHost monitoring --scan-period 1h /path/to/watch
```

### Quarantine

Manage quarantined files.

```bash
Handle GLIMPS Malware host quarantined files

Usage:
  GMHost quarantine [command]

Available Commands:
  list        List GLIMPS Malware host quarantined files
  restore     Restore quarantined files
```

**Examples:**
```bash
# List quarantined files
GMHost quarantine list

# Restore a specific file by ID
GMHost quarantine restore d86b21405852d8642ca41afae9dcf0f532e2d67973b0648b0af7c26933f1becb
```

### Agent

Start monitoring location with GLIMPS Malware Host under Connector Manager control.
The configuration is pushed by the Connector Manager and replaces the local one.

```bash
GMHost agent [flags]

Flags:
  -h, --help                      help for agent
      --console-api-key string    Connector Manager API key
      --console-insecure          if set, skip certificate check
      --console-url string        Connector Manager URL
```

**Examples**
```bash
GMHost agent --console-url="http://localhost:8080" --console-api-key=apikey
```

## Configuration

The default configuration file is located at:
- **Linux**: `~/.config/gmhost/config.yml` if it exists, otherwise `/etc/gmhost/config.yml`
- **Windows**: `%APPDATA%\gmhost\config.yml`

The file is read strictly: invalid YAML, a mistyped value or an unknown key makes the connector refuse to start, with an error naming the file and the key. A missing file is accepted: defaults and flags apply.

In agent mode, a configuration pushed by the console is validated before it is applied. If it is refused, the connector keeps the previous one, keeps processing files and raises the console error `host-config-rejected` until a valid configuration is received. After a restart the connector does not start with a rejected configuration: fix it in the console. Keys unknown to this version are ignored and listed in the console error `host-config-unknown-keys`.

### Example Configuration

Every key, with its default value (except `paths`, the GMalware URL and token, and the path examples):

```yaml
# Analysis
gmalware_api_url: https://gmalware.ggp.glimps.re
gmalware_api_token: 00000000-00000000-00000000-00000000-00000000
gmalware_expert_url: ""
gmalware_timeout: 5m
gmalware_user_tags: []
gmalware_no_cert_check: false
gmalware_syndetect: false
gmalware_bypass_cache: false

# Global
paths:
  - /home/user/Downloads
workers: 4
max_file_size: 100MiB
follow_symlinks: false
work_dir: ""                     # system temporary directory
shutdown_timeout: 8s
plugins_config: ""               # e.g. /etc/gmhost/plugins.yml
debug: false

# Archive extraction
extract: false
extract_workers: 2
extract_min_size: 8KB
recursive_extract_max_depth: 10
recursive_extract_max_size: 5GB
recursive_extract_max_files: 10000

# Files that cannot be fully analyzed
unanalyzable_policy:
  too_big: error
  encrypted: error
  empty: pass
  analysis_error: error
  extract_error: error

# Path rules
filepath_filter:
  forbidden_paths: []
  skipped_paths: []

actions:
  delete: true
  quarantine: true
  move: false
  print: true
  log: true

monitoring:
  prescan: false
  period: 0s
  modification_delay: 30s
  disable_fs_watcher: false
  max_tracked_memory: 256MiB
  max_tracked_dir_percent: 25

quarantine:
  location: /var/lib/gmhost/quarantine
  password: infected
  registry: ""                   # in memory
  format: tar

move:
  source: ""
  destination: ""
  mode: copy
  min_throughput: 10MiB

print:
  location: ""                   # stdout
  verbose: false

# Connector Manager (agent command)
console:
  url: ""
  api-key: ""
  insecure: false
```

Sizes accept units such as `8KB`, `100MiB` or `5GB`. Durations use Go syntax (`30s`, `5m`, `1h`).

### Configuration Options

#### GLIMPS Malware Detect

- **`gmalware_api_url`** (required, flag `--gmalware-url`, env `GMALWARE_URL`): URL of the GLIMPS Malware API. At every start and configuration the service must answer `GET /api/lite/v2/status` (`GET /api/v1/status` with syndetect) with HTTP 200. With go-gdetect v1.6.6, a `404` on that endpoint makes the configuration hang and blocks submissions.
- **`gmalware_api_token`** (required, flag `--gmalware-token`, env `GMALWARE_TOKEN`): API token.
- **`gmalware_expert_url`**: URL of the GLIMPS Malware expert interface (optional).
- **`gmalware_timeout`** (default `5m`, flag `--timeout`): Time allowed to analyze each file.
- **`gmalware_user_tags`**: Tags added to every submission.
- **`gmalware_no_cert_check`** (default `false`, flag `--insecure`): Skip TLS certificate verification.
- **`gmalware_syndetect`** (default `false`, flag `--gmalware-syndetect`): Use the syndetect API.
- **`gmalware_bypass_cache`** (default `false`): Ask GMalware to analyze again instead of answering from its cache.

A file is submitted under its host path. A member of an archive is submitted as `<archive path>/<member path>`.

#### Global Settings

- **`paths`** (required, at least 1): Directories or files to monitor and scan. On the command line, they are given as arguments.
- **`workers`** (default `4`, flag `--workers`): Number of files analyzed concurrently.
- **`max_file_size`** (default `100MiB`, flag `--max-file-size`): Largest file submitted to GMalware. A larger file is extracted if it is an archive and `extract` is on, at any level: a nested archive over `max_file_size` is opened as long as its members fit the extraction budget. Otherwise it follows `unanalyzable_policy.too_big`.
- **`follow_symlinks`** (default `false`, flag `--follow-symlinks`): Follow symbolic links. When off, links are skipped, and a file whose path crosses a link is left in place with a warning. Turning it on disables this protection, and a warning is logged when move, delete or quarantine is active.
- **`work_dir`** (default: system temporary directory, `TMPDIR` honored): Base of the private working directory used for extractions and plugin files. A `gmhost-<random>` sub-directory is created there and removed at stop. The connector refuses to start if it is a monitored path or lies under one. Use a local disk: `tmpfs` uses RAM, and locks are unreliable on network file systems.
- **`shutdown_timeout`** (default `8s`, at least `2s`, flag `--shutdown-timeout`, local only: not managed by the console): Time allowed to stop on `SIGTERM`/`SIGINT`. Files being processed may finish during part of this time, then they are left in place and processed again at the next start. Set it below the orchestrator's stop delay (`docker stop -t`, systemd `TimeoutStopSec`). A second signal stops at once. The exit code is `1` if the delay was exceeded.
- **`plugins_config`**: Path to the plugins configuration file (GNU/Linux only, see [Plugin System](#plugin-system)).
- **`debug`** (default `false`, flag `-d`): Enable debug logging.

On Linux, `/proc` must be available: the connector refuses to start without it.

#### Extraction Settings

- **`extract`** (default `false`, flag `--extract`): Extract archives and analyze their members (see [Archive Extraction](#archive-extraction)).
- **`extract_workers`** (default `2`, flag `--extract-workers`): Number of archives extracted concurrently. Keep it well below `workers` (1:10 to 1:20).
- **`extract_min_size`** (default `8KB`, flag `--extract-min-size`): Files at or below this size are analyzed whole instead of being extracted. Archives of a known format are extracted whatever their size.
- **`recursive_extract_max_depth`** (default `10`): Maximum nesting level. Deeper archives are not opened and follow `unanalyzable_policy.too_big`.
- **`recursive_extract_max_size`** (default `5GB`): Maximum total size extracted from one top-level file, across all levels. A member that is not an archive can be written to `work_dir` up to what is left of this budget before it is refused as too big for GMalware: size `work_dir` for `extract_workers` × `recursive_extract_max_size`.
- **`recursive_extract_max_files`** (default `10000`): Maximum number of files extracted from one top-level file, across all levels.

A member is bounded only by what is left of `recursive_extract_max_size`; `max_file_size` does not limit extraction. Members left out by these limits, or non-archive members larger than `max_file_size` (not submitted), follow `unanalyzable_policy.too_big`.

#### Unanalyzable Policy

`unanalyzable_policy` decides what happens to a file that cannot be fully analyzed. `error` leaves the file in place (in INPUT) and reports it. `pass` delivers it, marked with the reason in the reports. `mitigate` treats it as malware (quarantined or deleted).

- **`too_big`** (`error` | `pass` | `mitigate`, default `error`): Files larger than `max_file_size` that are not extracted (an archive is), and archive members left out by the extraction limits.
- **`encrypted`** (`error` | `pass` | `mitigate`, default `error`): Archives protected by an unknown password. This also covers damaged archives that may hide encrypted content.
- **`empty`** (`pass` | `skip` | `mitigate`, default `pass`): Files of size 0. `pass` delivers a new empty file, `skip` leaves the file in place with a warning. `pass` is refused with `move.mode: rename`. If the key is absent with `rename`, `skip` is used.
- **`analysis_error`** (`error` | `pass` | `mitigate`, default `error`): Files GMalware failed to analyze. A file with a detection is always malware, whatever this value.
- **`extract_error`** (`error` | `as_file`, default `error`): Archives the extractor finds damaged or inconsistent. `error` leaves them in place and does not retry until they change. `as_file` analyzes the archive as a plain file, but only when the extractor proved it holds no encrypted content. Otherwise the archive follows `encrypted`. A console warning `extract-error-as-file` is raised while `as_file` is set.

**Risk of `pass`:** a depositor can often make an analysis fail or an archive unreadable on purpose. `pass` then lets unverified files through. Prefer `error` or `mitigate`.

Files that reach the output without a full analysis are listed in the log, in the `print` output and in the reports (`not-analyzed-reason`).

#### Path Rules

`filepath_filter` applies Go regular expressions (RE2, unanchored unless anchored) to the path of every file, and to `<archive path>/<member path>` for archive members. The rules run before analysis and before the plugins.

- **`forbidden_paths`**: Matching files are treated as malware. A forbidden path always wins over a skipped one.
- **`skipped_paths`**: Matching files are delivered without analysis, marked `skipped-path`. A skipped archive is not extracted. Forbidden types and forbidden paths still apply to it.

Limits, which refuse the configuration if exceeded:
- 256 patterns per list, 1024 bytes per pattern and 32 KiB in all
- no empty pattern, no pattern in both lists, and no pattern that matches the empty string
- counted repeats of at most 100
- an estimated 512 instructions per pattern and 4096 in all (about 125 three-letter alternatives fit in one pattern)

A path longer than 4096 bytes is never skipped. When `forbidden_paths` is set, such a file stays in INPUT with an error.

**Risk of `skipped_paths`:** depositors choose their file, folder and member names. Anchor patterns on folders depositors cannot create (`^/srv/in/trusted/`), never on a bare name or extension. To catch hidden trailing characters, write extension rules as `\.exe[^/]*$`. `(?i)` makes a pattern case-insensitive.

```yaml
filepath_filter:
  forbidden_paths:
    - '\.exe[^/]*$'
  skipped_paths:
    - '^/srv/in/trusted/'
```

#### Actions

What happens after a file is analyzed:
- **`delete`** (default `true`): Delete malicious files (after quarantine if enabled).
- **`quarantine`** (default `true`): Store malicious files encrypted in the quarantine directory.
- **`move`** (default `false`): Move clean files from `move.source` to `move.destination`.
- **`print`** (default `true`): Print scan results (see `print`).
- **`log`** (default `true`): Log detections in the connector logs.

#### Monitoring

- **`prescan`** (default `false`, flag `--pre-scan`): Scan existing files when monitoring starts.
- **`period`** (default `0s`: disabled, flag `--scan-period`): Interval between periodic rescans. Temporary failures (network, timeout, disk full) are retried with growing delays. Without a period, a failed file is only retried when it is written to again.
- **`modification_delay`** (default `30s`, flag `--mod-delay`): A file is analyzed only once it has stayed unchanged for this delay. This prevents analyzing incomplete writes. A value under `1s` logs a warning. A console configuration without the key gives `0`.
- **`disable_fs_watcher`** (default `false`, flag `--disable-fs-watcher`): Do not watch file system events, and rely on pre-scan and periodic rescan. Requires `period`. Meant for network file systems (e.g. CephFS).
- **`max_tracked_memory`** (default `256MiB`, at least `1MiB`): Memory bound of the table of files waiting for their `modification_delay`. When it is full, the user folder that holds the most files yields first. Files refused this way are picked up again at the next rescan, so set a `period` if the table can overflow.
- **`max_tracked_dir_percent`** (default `25`, 0–100): Share of the table above which a user folder yields first when the table is full.

#### Quarantine

- **`location`** (default `/var/lib/gmhost/quarantine` on Linux, `%APPDATA%\gmhost\quarantine` on Windows, flag `--quarantine`): Directory of quarantined files (`<sha256>.lock`). It is created with mode `0700` if missing. It must belong to the connector account (or root), must not be writable by group or others, and must not overlap a monitored path, `move.destination` or the work directory. Otherwise the configuration is refused. Avoid `/tmp`, which may be cleaned automatically.
- **`password`** (default `infected`): Password used to encrypt quarantined files. It is needed to restore them.
- **`registry`** (default: in memory, lost on restart, flag `--quarantine-registry`): Database of quarantined and restored files. A released file, seen again at the same path with the same content, is neither analyzed nor filtered (path rules, OnScanFile plugins, size limit; a released archive is neither listed nor extracted); the same content elsewhere is a new file.
- **`format`** (`tar` | `zip`, default `tar`): Container for new quarantined files. `zip` uses traditional PKWARE encryption and opens with Windows Explorer or 7-Zip. Existing files of both formats stay restorable. With `zip`, consider the password **public**, since ZipCrypto is easily broken: don't reuse it elsewhere. A warning is logged at each configuration.

#### Move

- **`source`** (flag `--move-source`): Only clean files under this directory are moved.
- **`destination`** (flag `--move-destination`): Target directory. The subdirectory structure is preserved.
- **`mode`** (`copy` | `rename`, default `copy`): `copy` copies the analyzed content, checks its SHA256, then removes the source, so exactly what was analyzed is delivered. `rename` moves the file itself: it is cheaper, but a writer holding the file open can still change it. A console warning `host-move-rename` is raised while `rename` is set.
- **`min_throughput`** (default `10MiB`): Minimum copy speed per second in `copy` mode. A copy that takes longer than `size / min_throughput + 1 minute` is abandoned and retried.

#### Print

- **`location`** (default: stdout, flag `--print-location`): File the scan results are written to.
- **`verbose`** (default `false`, flag `-v`): Also report clean files.

#### Console

Connector Manager connection, used by the `agent` command:
- **`url`** (flag `--console-url`): Connector Manager URL.
- **`api-key`** (flag `--console-api-key`): Connector Manager API key.
- **`insecure`** (default `false`, flag `--console-insecure`): Skip TLS certificate verification.

## Archive Extraction

When `extract` is enabled, archives are unpacked and each member is analyzed. Archives inside archives are extracted too, within the [extraction limits](#extraction-settings).

**Supported formats:** ZIP, GZIP, TAR, BZIP2, RAR, 7Z, ISO, Brotli, LZ4, XZ, Zstandard, S2, Snappy, Zlib, LZW, plus the formats of the extract plugin (7-Zip).

**Conditions to attempt extraction:**
- file size must be > `extract_min_size`, unless the file is an archive of a known format
- file's MIME type must be in the list below

Allowed types for extraction:
```go
"application/x-archive"              // .ar
"application/x-arj"                  // .arj
"application/vnd.ms-cab-compressed"  // .cab
"application/x-cpio"                 // .cpio
"application/x-iso9660-image"        // .iso
"application/x-qemu-disk"            // .qcow, .qcow2
"application/x-lha"                  // .lha
"application/x-lzh-compressed"       // .lzh
"application/vnd.rar"                // .rar
"application/x-virtualbox-vhd"       // .vhd, .vhdx
"application/x-7z-compressed"        // .7z
"application/x-xz"                   // .xz, .tar.xz
"application/x-bzip2"                // .bz2, .tar.bz2
"application/gzip"                   // .gz, .tar.gz, .tgz
"application/x-tar"                  // .tar
"application/x-lzma"                 // .lzma, .tar.lzma
"application/vnd.ms-htmlhelp"        // .chm
"application/x-ms-wim"               // .wim
"application/x-compress"             // .Z
"application/zip"                    // .zip
"application/x-rpm"                  // .rpm
"application/x-apple-diskimage"      // .dmg
"application/vnd.debian.binary-package" // .deb
"application/zstd"                   // .zst, .tar.zst
"application/x-xar"                  // .xar, .pkg
"application/vnd.squashfs"           // .squashfs, .snap, .appimage
"application/x-squashfs"             // .squashfs
"application/x-lz4"                  // .lz4, .tar.lz4

// default MIME type, kept in case identification failed, or for specific raw file formats like flat VMDK
"application/octet-stream"

// MIME types absent from default libmagic database
"application/x-vmdk"                 // .vmdk
"application/x-lzh"                  // .lzh
"application/x-lzh-archive"          // .lzh
"application/x-rar-compressed"       // .rar
"application/x-vhd"                  // .vhd, .vhdx
"application/x-virtualbox-vdi"       // .vdi
```
MIME type detection is done using https://github.com/gabriel-vasile/mimetype.

**Important notes:**
- If any member is malicious, the whole archive is malicious. Members are never removed from an archive.
- Members are extracted to the work directory and cleaned up after analysis.
- An archive with a member that could not be analyzed stays in place, unless `unanalyzable_policy` decides otherwise.
- A file typed as an archive that cannot be opened (truncated, corrupted) is handled as damaged (`extract_error`). It stays in INPUT by default.
- Office documents and packages (docx, xlsx, pptx, odt, epub, jar, apk) are analyzed whole. They are first checked for encrypted members, which follow `encrypted`.
- Zip bombs (members declaring more than 3 GB with a ratio over 100) are reported and not extracted.

## Actions

Each sequence of actions has a timeout of **30 seconds per GB** (rounded up to the next GB, minimum 30 seconds).
Examples: 1MB -> 30s ; 500MB -> 30s ; 1,2GB -> 60s ; 2GB -> 60s

### Quarantine

- **When**: Malware is detected
- **Effect**: Stores an encrypted copy of the file in the quarantine directory, with its metadata

### Delete

- **When**: Malware is detected (after quarantine if enabled)
- **Effect**: Removes the original malicious file

### Move

- **When**: The file is under `move.source`
- **Effect**:
  - **Clean files**: Moved to the destination, preserving the directory structure. Files are published atomically through a `.gmhost-staging` folder at the root of the destination: consumers must ignore it.
    - A file never replaces an existing one. It is stored next to it as `<name>.conflict-<UTC time>[-n]<ext>`, with a warning. After 6 conflicting names, the file stays in place with an error.
    - Setuid and setgid bits are never copied.
    - A file named `report-session-*` (any case, any depth) is never moved: it stays in place with an error.
  - **Malicious files**: Not moved. A `.locked.json` report is written at the destination path.
  - **Files in error**: Not moved, and neither is an archive with a member that could not be analyzed. The report lists the failed members (`error-subfiles`).

### Print

- **When**: Always (`print.verbose` to include clean files)
- **Effect**: Outputs scan results to stdout or `print.location`

### Log

- **When**: Always
- **Effect**: Logs scan information using structured logging

## Plugin System

GMHost features an extensible plugin architecture that allows for specialized processing of files during the scanning pipeline. Plugins can intercept files at various stages, perform custom analysis, generate reports, and integrate with external systems.

### Built-in Plugins

GMHost includes several built-in plugins (**GNU/Linux only**):

- **extract**: Extracts and scans content from various archive formats
- **filetype_filter**: Filters files based on file type patterns (allow/deny lists)
- **session**: Manages scanning sessions and tracks progress
- **report**: Generates and formats scan reports

### Plugin Configuration

Plugins are configured in a separate YAML file referenced by `plugins_config`. Each entry has two keys:
- **`file`**: The plugin shared object (e.g. `extract.so`)
- **`config`**: The plugin options (see below)

```yaml
# In config.yml
plugins_config: /etc/gmhost/plugins.yml
```

Plugins are called in the order of the file. The recommended order is filters first, then `session`. The connector refuses to start if:
- the file is empty or larger than 1 MiB
- a plugin name or plugin file is declared twice
- the file uses YAML anchors, aliases or merge keys
- a key is unknown
- a plugin is configured on Windows, which does not support plugins

Entries named `filesize_filter`, `filepath_filter` or `error_filter` (or pointing to their `.so` files) are not plugins: they are ignored with a warning and a console error. Use `unanalyzable_policy` and `filepath_filter` instead. A file that holds only such entries is refused.

A complete example is available at `rsc/plugin_config.yml`.

#### Extract Plugin

Extracts archives with an embedded 7-Zip (ZIP, RAR, 7Z, TAR, GZIP, BZIP2, ISO, disk images, etc.). Size limits are the global ones (`recursive_extract_*`; `max_file_size` bounds only what is submitted, not what is extracted).

| Key | Default | Description |
|---|---|---|
| `default_passwords` | `["infected"]` | Passwords tried on encrypted archives |
| `seven_zip_path` | `""` (embedded binary) | Absolute path of a 7-Zip binary |

```yaml
extract:
  file: extract.so
  config:
    default_passwords:
      - infected
    seven_zip_path: ""
```

Behavior that can block files or the start:
- 7-Zip is checked at every start and configuration. The connector refuses to start if the binary is missing, unsafe (not owned by root or the connector account, or writable by others), older than 25.01, or cannot run (for example `work_dir` on a `noexec` file system). A `7zzs` found in `PATH` is never used.
- Malformed or suspicious archives are refused and stay in INPUT (by default, see `extract_error`):
  - zips with junk before them, gaps or inconsistent headers, and self-extracting zips
  - archives with data after their end
  - member names a file system cannot hold
- An archive with many hard links to one big file counts each link in the extraction budget, and can exceed it.

#### FileType Filter Plugin

Filters files by MIME type, as detected by libmagic. `libmagic` must be installed (see [Installation](#linux)).

| Key | Default | Description |
|---|---|---|
| `forbidden_types` | `[]` | MIME types treated as malware |
| `skipped_types` | `[]` | MIME types delivered without analysis, marked `skipped-type` |

```yaml
filetype_filter:
  file: filetype_filter.so
  config:
    forbidden_types:
      - application/x-executable
      - application/x-msdownload
    skipped_types:
      - text/plain
      - image/png
```

- List types as `type/subtype`, case-insensitive, without parameters. Any other entry is refused.
- `application/octet-stream` (unrecognized content) cannot be in `skipped_types`.
- A file larger than 7 MiB is never skipped by `skipped_types`, because its type is detected from part of the file only. It is analyzed.
- When `forbidden_types` is set, a file whose type cannot be detected (unreadable, timeout after 5 s) is refused and stays in INPUT. Without it, the file is analyzed.
- **Risk:** `skipped_types` lets files through on their type alone, and a crafted file can fake its type. List only types you accept unanalyzed.

#### Session Plugin

Groups files into sessions by folder, and writes one consolidated report per session when it closes.

| Key | Default | Description |
|---|---|---|
| `root_folder` | — (required) | Absolute base path the sessions are computed from |
| `depth` | `1` | Number of folder levels under `root_folder` that identify a session |
| `delay` | `15m` | Inactivity delay before a session is closed |
| `exports` | `[]` | Directories where session reports are written |
| `report_timeout` | `6m` | Time given to each attempt to write a report (must be positive) |
| `report_retries` | `3` | Failed attempts retried before writing a JSON report instead |
| `inflight_timeout` | `24h` | Longest a session is held open by files still waiting or processing |
| `max_duration` | `24h` | Longest a session stays open, whatever its activity |
| `max_spool_size` | `1GiB` | Size of a session's pending reports on disk that closes it (at least `1MiB`) |
| `remove_empty_dirs` | `true` | Remove empty folders below a session once its report is written (Linux only) |
| `cleanup_timeout` | `2m` | Time given to that removal for one session |

```yaml
session:
  file: session.so
  config:
    root_folder: /tmp/samples/
    depth: 2
    delay: 30s
    exports: ["/var/reports"]
```

**Session ID examples** (with `depth: 2` and `root_folder: /tmp/samples/`):
- `/tmp/samples/user_a/batch1/file1.txt` → session `user_a/batch1`
- `/tmp/samples/user_b/upload/file2.txt` → session `user_b/upload`

- A report is named `report-session-<id>-<start>.<ext>`. It is written atomically and never replaces an existing file. A console message gives its path and SHA256.
- If a report cannot be generated (PDF failure, timeout), a JSON report is written instead (console error `session-report-fallback`). If nothing can be written, the console error `session-report-lost` names the session.
- Pending reports are kept on disk in `<work_dir>/session`. Size the work directory for `max_spool_size` × the number of sessions open at once. On a full disk, the session is closed at once (console error `session-spool-error`).
- `root_folder` must not be the base of the work directory.
- Reports of sessions still open when the process is killed (`SIGKILL`, crash) are lost.

#### Report Plugin

Renders session reports as PDF from an HTML template, with the pure-Go renderer [htmltopdf](https://github.com/glimps-re/htmltopdf): no browser or external process is needed, and the connector may run as root.

| Key | Default | Description |
|---|---|---|
| `template_path` | `""` (embedded template) | Custom HTML template (Go `html/template`) |
| `chrome_path` | — | Deprecated, ignored: a warning is logged when it is set. Remove it from the configuration |

```yaml
report:
  file: report.so
  config:
    template_path: ""
```

**Look of the PDF** (embedded template, GLIMPS colors): the verdict comes first, a red banner "N fichier(s) bloqué(s)", an amber one "Analyse incomplète" when nothing is blocked but a file is in error or not analyzed, or a green one "Aucune menace détectée" when everything was analyzed and nothing blocked, with the conclusion, then four tiles (Bloqués, Fichiers malveillants, Non analysés, Fichiers en erreur) and a line of the other figures (files listed and analyzed, volumes). The sections that follow (blocked files, blocked archives, not analyzed, in error) each have a counter; a file takes one row, its name in bold and its SHA-256 below, its threats as badges. The header is on the first page only; the footer `TLP:AMBER` and "Page N of M" are on every page. `template_path` still loads a custom template, which replaces this one entirely.

**Rendering:**
- The fonts are embedded in the plugin (Liberation Sans, DejaVu Sans; licences in [LICENSES.md](LICENSES.md)): nothing to install on the host.
- The renderer is checked on an empty page at every start and configuration; a failure refuses the start.
- One PDF renders in at most 60 s and 64 MiB, with at most 2 renderings at a time; the renderer limits (boxes, styles, work) are bounded below the htmltopdf defaults. A report over a limit falls back to the JSON report.
- No JavaScript, network or file access. A custom template must inline its styles (`<style>`); `<img>`, `url()`, `<script>` and `@font-face` are not supported and are dropped.

**Template data:**
- `ScanID`, `ScanStartTime`, `Duration`
- `NbFileSubmitted`, `NbFileAnalyzed`, `NbFileNotAnalyzed`
- `FileVolume`, `AnalyzedVolume`, `FilteredVolume`
- `TotalMitigated`, `TotalMalware`, `TotalErrors`: `TotalMalware` counts the files detected as malware, not the refusals by path, type or policy
- `MitigatedFiles`, `MitigatedArchives`, `ErrorFiles`, `NotAnalyzedFiles`
- `MoreMitigatedFiles`, `MoreMitigatedArchives`, `MoreErrorFiles`, `MoreNotAnalyzed`: the number of entries left out of each list, which stops at 300 rows

Long names are shortened in the PDF. The JSON report keeps more detail.

### Plugin Development

#### Plugin Interface

All plugins must implement the `plugins.Plugin` interface:

```go
type Plugin interface {
    GetDefaultConfig() (config any)
    Init(config any, hcc HCContext) error
    Close(ctx context.Context) error
}
```

`Close` has no effect when called a second time or on a plugin whose `Init` failed or never ran, and a failed `Init` leaves nothing behind (no goroutine, file or process).

A plugin may also implement `plugins.Validator`:

```go
type Validator interface {
    Validate(config any, vc ValidationContext) error
}
```

The connector calls `Validate` for every plugin before it applies a configuration (start and `Configure`), with the connector still running the previous one: `Validate` checks the configuration and what `Init` needs (binaries, paths) and changes nothing of the plugin in service. Write it as a function of the package, not as a method that writes into the receiver. `vc.GetWorkDir()` is a scratch directory removed when it returns. `vc.DeclareExecutable(path)` checks that a binary is safe to run (absolute, links resolved, regular and executable, owned by root or the connector account, not writable by others; writable by the group only warns, unless the connector runs as root) and records it: call it before running the binary, in `Validate` and in `Init`. `vc.DeclareOutputDir(path)` records a directory the plugin writes to. After the validation and after `Init`, the connector refuses an output directory that is, or is under, a monitored path or the quarantine directory, and an executable under a monitored path, under `move.destination` or under an output directory. A failing `Validate` stops a first start, and makes a `Configure` fail with the previous configuration kept.

The `Register*` methods of `HCContext` are valid during `Init` only: later calls are ignored with a warning. The error returned by `Init` is logged and shown to the operator as is: never include a configuration value in it, it may be a secret.

#### HCContext Interface

Plugins interact with the host connector through the `HCContext` interface:

```go
type HCContext interface {
    SetExtractFile(f ExtractFile)
    RegisterOnStartScanFile(f OnStartScanFile)
    RegisterOnScanFile(f OnScanFile)
    RegisterWithWaitForOptions(f WithWaitForOptionsFunc)
    RegisterOnFileScanned(f OnFileScanned)
    RegisterOnReport(f OnReport)
    RegisterGenerateReport(f GenerateReport)
    GenerateReport(ctx context.Context, reportContext datamodel.ScanContext, reports iter.Seq2[datamodel.Report, error]) (GeneratedReport, error)
    GetLogger() *slog.Logger
    GetConsoleLogger() *slog.Logger
    GetWorkDir() string
    DeclareExecutable(path string) error
    DeclareOutputDir(path string) error
    SetTrackingOwners(root string, depth int) error
    PendingFiles(dir string) int
    NotifyError(ctx context.Context, key string, err error)
    NotifyResolution(ctx context.Context, key string, message string)
}
```

`SetTrackingOwners(root, depth)` lets a plugin that lays files out in sub-folders of `root` (such as `session`) tell the monitor that its owners are the folders `depth` levels below `root`, absolute path required; it is accepted during `Init` only, and a malformed declaration makes `Init` fail. Without any declaration, an owner is the first folder below the shortest monitored path. `PendingFiles(dir)` gives the number of files detected under the owner folder `dir` that have not finished processing (0 for any other folder).

#### Callback Types

Plugins can register callbacks for different stages of the scanning pipeline:

- **`OnStartScanFile`**: Called before a file begins scanning
- **`OnScanFile`**: Replace GLIMPS Malware analysis with custom logic. Called in plugin file order. A result that is not malware, has no `Error` and no `AnalysisError` is a *waiver* (the file is not analyzed); any other non-nil result is a *refusal*. The first refusal wins and stops the chain. A waiver is kept but the following plugins are still called, so a deny-list placed after an allow-list still applies. Without refusal, the first waiver applies; without any result, the file is analyzed. When an archive is waived by its type or its path, its content is not filtered either (a sub-archive all the members of which the extraction left out is not shown to `OnScanFile` either: its members never existed for the plugins)
- **`WithWaitForOptionsFunc`**: Modify submission options before analysis
- **`OnFileScanned`**: Called after a file completes scanning. Every plugin is called, in plugin file order, each receiving the current result; a non-nil return replaces it. A plugin can harden a result, never soften it: a non-nil `Error`, `Malware=true` and a non-empty `AnalysisError`, `MalwareReason`, `Malwares`, `MaliciousSubfiles` and `ErrorSubfiles` are restored by the connector (with a warning naming the plugin)
- **`OnReport`**: Called when a scan report is generated
- **`GenerateReport`**: Custom report generation function. The reports come as a sequence (`iter.Seq2[datamodel.Report, error]`), to be read once; an error of the sequence must end the generation with that error. It returns a `GeneratedReport{Content io.ReadCloser, Extension string}`: the content is not nil exactly when the error is nil, the caller closes it on every path, and the extension (a dot, then letters or digits, 16 characters at most, `.pdf`, `.json`…) names the file the content belongs in. Without a generator plugin the content is a JSON array and the extension is `.json`
- **`ExtractFile`**: Custom archive extraction logic

#### Example Plugin Structure

```go
package main

import (
    "context"
    "errors"
    "log/slog"
    "github.com/glimps-re/host-connector/pkg/plugins"
)

type MyPlugin struct {
    logger *slog.Logger
    config MyConfig
}

type MyConfig struct {
    Setting1 string `yaml:"setting1"`
    Setting2 int    `yaml:"setting2"`
}

var HCPlugin MyPlugin

func (p *MyPlugin) GetDefaultConfig() (config any) {
    return &MyConfig{
        Setting1: "default",
        Setting2: 42,
    }
}

func (p *MyPlugin) Init(config any, hcc plugins.HCContext) error {
    cfg, ok := config.(*MyConfig)
    if !ok {
        return errors.New("bad config type")
    }
    p.config = *cfg
    p.logger = hcc.GetLogger()
    // Register callbacks
    hcc.RegisterOnStartScanFile(p.OnStartScanFile)
    return nil
}

func (p *MyPlugin) Close(ctx context.Context) error {
    // Cleanup plugin resources
    return nil
}

func (p *MyPlugin) OnStartScanFile(file string, sha256 string) *gdetect.Result {
    // Custom file processing logic
    return nil
}

func main() {}
```

#### Plugin Compilation

Plugins are compiled as Go modules and loaded dynamically:

```bash
go build -buildmode=plugin -o myplugin.so main.go
```

#### Testing

GMHost includes comprehensive unit tests for all built-in plugins. Run plugin tests:

```bash
# Test specific plugin
cd cmd/plugins/session && go test -v

# Test with coverage
go test -cover

# Test all plugins
find cmd/plugins -name "*_test.go" -execdir go test \;
```

The end-to-end suite (`test/`) runs the real binary against fake services. Its scenarios are split into `test/core` (tag `e2e_core`) and `test/plugins` (tag `e2e_plugins`); the tag `e2e` selects both. A plain `go test ./test/...` runs only the self-tests of the harness and the fakes, without building GMHost. The full suite takes longer than the default 10-minute timeout of `go test`, so set one:

```bash
go test -race -tags e2e -timeout 30m ./test/...

# One side
go test -race -tags e2e_core -timeout 30m ./test/core/
go test -race -tags e2e_plugins -timeout 30m ./test/plugins/

# A single scenario
go test -race -tags e2e_plugins -timeout 30m -run 'TestE2E_archives$' ./test/plugins/

# Lint, including the suite
golangci-lint run --build-tags e2e ./test/...
```

It needs the Go toolchain and `cmd/plugins/extract/7zzs` (embedded in the extract plugin at build time: the build fails without it); no browser is needed. See `test/doc.go`. The scenarios are described in [docs/e2e-tests.md](docs/e2e-tests.md).

### Security Considerations

- **Sandboxing**: Plugins run in the same process space as GMHost
- **Resource Limits**: Configure appropriate limits to prevent resource exhaustion
- **Input Validation**: Plugins should validate all input data
- **Logging**: Use structured logging for audit trails
- **Error Handling**: Robust error handling prevents plugin failures from affecting the main application

## Installation

### Windows

Download the MSI installer from the [releases page](https://github.com/glimps-re/host-connector/releases) and run it. This will:
- Install GMHost to `C:\Program Files\GMHost\`
- Add right-click context menu items for scanning
- Create a default configuration file

### Linux
#### Prerequisites

GMHost requires **libmagic** to be installed on the host (used for file type detection):

```bash
# Debian / Ubuntu
sudo apt update && sudo apt install libmagic1

# RHEL / Rocky / Fedora
sudo dnf install file-libs
```
#### Install GMHost
Download the appropriate binary from the [releases page](https://github.com/glimps-re/host-connector/releases):

```bash
# Download and install
wget https://github.com/glimps-re/host-connector/releases/latest/download/gmhost-linux-amd64
chmod +x gmhost-linux-amd64
sudo mv gmhost-linux-amd64 /usr/local/bin/gmhost

# Create config directory
sudo mkdir -p /etc/gmhost
```

## Windows Integration

### Add to Startup

To run GMHost monitoring at Windows startup:

```powershell
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "GMHost" /t REG_SZ /F /D "C:\Program Files\GMHost\gmhost.exe monitoring"
```

### Context Menu

The Windows installer automatically adds context menu items:
- Right-click any file or folder: "GMHost-Scan"
- Right-click `.lock` files: "GMHost-Restore"

## Quarantine Management

### List Quarantined Files

```bash
GMHost quarantine list
```

Output example:
```
|ID                                                              |Reason                   |File                |
|d86b21405852d8642ca41afae9dcf0f532e2d67973b0648b0af7c26933f1becb|malware: eicar           |eicar.txt           |
```

### Restore Files

```bash
# Restore by ID
GMHost quarantine restore d86b21405852d8642ca41afae9dcf0f532e2d67973b0648b0af7c26933f1becb

# Restore by filename (if .lock extension is included)
GMHost quarantine restore d86b21405852d8642ca41afae9dcf0f532e2d67973b0648b0af7c26933f1becb.lock
```

- A restoration never overwrites a file: it fails with "destination already exists".
- Use `--quarantine-registry` with the same registry as the monitoring process. Otherwise the monitoring process is not told about the restoration and quarantines the file again.
- A released file is not analyzed again at its location (see `quarantine.registry`).

**Warning**: Only restore files if you are certain they are safe. Restored files will be in their original, unencrypted form.

## Environment Variables

GMHost respects the following environment variables:
- **`GMALWARE_TOKEN`**: GLIMPS Malware Detect authentication token (used by `--gmalware-token` flag)
- **`GMALWARE_URL`**: GLIMPS Malware Detect API endpoint (used by `--gmalware-url` flag)
- **`TMPDIR`**: Base of the work directory when `work_dir` is not set (Unix)

## Logging

GMHost uses structured JSON logging. Log levels can be controlled with flags:

- **Default**: INFO level and above
- **`--debug` / `-d`**: DEBUG level and above
- **`--verbose` / `-v`**: Print more detailed scan information to console

Example log entry:
```json
{"time":"2024-01-25T12:55:00Z","level":"INFO","msg":"info scanned","file":"/path/to/file","sha256":"abc123...","malware":true,"malwares":["trojan.win32.test"]}
```

## Performance Considerations

- **Workers**: Increase `workers` for faster scanning of many files, but be mindful of system resources and CPU usage
- **Extract Workers**: Adjust `extract_workers` based on your archive extraction workload
- **File size limits**: Adjust `max_file_size` based on your needs and GLIMPS Malware Detect limits
- **Network timeouts**: Increase `gmalware_timeout` for large files or slow connections
- **Symlinks**: Disable `follow_symlinks` (the default) if you don't need to scan linked directories: it improves performance and keeps the symbolic link checks on

## Troubleshooting

### Common Issues

1. **"File too large" warnings**: Increase `max_file_size` or enable `extract` for archives
2. **Permission denied**: Ensure GMHost has read access to target directories and write access to quarantine locations
3. **Connection timeouts**: Check network connectivity to GLIMPS Malware Detect and increase `gmalware_timeout`
4. **High CPU usage**: Reduce number of `workers` or adjust monitoring frequency

### Debug Mode

Enable debug logging for detailed troubleshooting:

```bash
GMHost --debug scan /path/to/problematic/file
```

## Security Notes

- Quarantined files are encrypted but should still be handled with care
- The quarantine password is stored in plain text in the configuration file
- GMHost requires network access to GLIMPS Malware Detect for analysis
- Consider firewall rules to restrict GMHost's network access to only necessary endpoints

## Support

- **Documentation**: [GitHub Repository](https://github.com/glimps-re/host-connector)
- **Issues**: [GitHub Issues](https://github.com/glimps-re/host-connector/issues)
- **API Documentation**: [GoDoc](https://pkg.go.dev/github.com/glimps-re/host-connector)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
