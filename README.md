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
      --config string                config file (default "/etc/gmhost/config.yml")
  -d, --debug                        print debug strings
      --extract                      Enable archive extraction (archives are unpacked and contents scanned)
      --extract-min-size string      Minimum file size to attempt extraction (e.g., '8KB'). Files at or below this size are sent for analysis instead of being extracted (default: 8KB) (default "8KB")
      --extract-workers int          Number of concurrent workers for archive extraction (default: 2, used when extract is enabled) (default 2)
      --follow-symlinks              Follow symbolic links when scanning directories (if disabled, symlinks are skipped)
      --gmalware-syndetect           Use syndetect API to analyze files
      --gmalware-token string        GLIMPS Malware Detect token
      --gmalware-url string          GLIMPS Malware Detect url (E.g https://gmalware.ggp.glimps.re)
  -h, --help                         help for GMHost
      --insecure                     do not check certificates
      --max-file-size string         Maximum file size to scan directly (e.g., '100MB'). Files exceeding this are extracted if 'extract' is enabled, otherwise rejected (default "100MiB")
      --move-destination string      Target directory for moving clean files (preserves subdirectory structure)
      --move-source string           Source directory filter (only clean files within this path are moved to destination)
      --print-location string        File path for scan reports (leave empty to print to stdout)
      --quarantine string            Directory path where quarantined files are stored (files are encrypted with .lock extension) (default "/var/lib/gmhost/quarantine")
      --quarantine-registry string   Path to the database that store quarantined and restored file entry (leave empty for in-memory store, lost on restart)
      --recursive-extract-max-depth int     Maximum depth for recursive archive extraction (default: 10) (default 10)
      --recursive-extract-max-files int     Maximum total number of files for recursive archive extraction (default: 10000) (default 10000)
      --recursive-extract-max-size string   Maximum total size for recursive archive extraction (default: 5GB) (default "5GB")

      --timeout duration             Time allowed to analyze each file (default 0s)
  -v, --verbose                      Report all scanned files, including clean files (not just malware detections)
      --workers int                  Number of concurrent workers for file analysis (default: 4, affects CPU usage) (default 4)

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

Start monitoring location with GLIMPS Malware Host under Connector Manager control
Global config will not be used.

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

## Plugin System

GMHost features an extensible plugin architecture that allows for specialized processing of files during the scanning pipeline. Plugins can intercept files at various stages, perform custom analysis, generate reports, and integrate with external systems.

### Built-in Plugins

GMHost includes several built-in plugins (**GNU/Linux only**):

- **extract**: Extracts and scans content from various archive formats
- **filetype_filter**: Filters files based on file type patterns (allow/deny lists)
- **filepath_filter**: Filters files based on file path patterns (allow/deny lists), on the logical path of extracted files
- **filesize_filter**: Filters files based on maximum size, treating oversized files as threats
- **error_filter**: Marks files with analysis errors as malicious for proper handling
- **session**: Manages scanning sessions and tracks progress
- **report**: Generates and formats scan reports

### Plugin Configuration

Plugins are configured via a separate YAML file referenced in the main configuration:

```yaml
# In config.yml
plugins_config: /etc/gmhost/plugins.yml
```

Plugins are loaded in the order of the file, and that order is the callback order: with the same file, the verdict is always the same. A plugin name must appear only once. Recommended order: filters, then `error_filter`, then `session`. An empty plugins file, a duplicate name, YAML anchors, aliases and merge keys, unknown keys (only `file` and `config` per plugin, and the options each plugin documents), the same plugin file declared twice, and files over 1 MiB are refused at startup, with an error naming the key and never quoting a value; on Windows, which does not support plugins, a configured plugin also refuses to start.

A complete example configuration is available at `rsc/plugin_config.yml`. Below are the configuration options for each built-in plugin:

#### Extract Plugin

Extracts and scans content from various archive formats (ZIP, RAR, 7Z, TAR, GZIP, BZIP2, ISO, etc.).

Extraction size limits are the global ones (`max_file_size`, `recursive_extract_max_files`, `recursive_extract_max_size`); the former `max_file_size`, `max_extracted_files` and `max_total_extracted_size` keys of this plugin are removed and refused at start. The plugin configuration:

```yaml
extract:
  file: extract.so
  config:
    default_passwords:                # Passwords for encrypted archives
      - infected
      - password
    seven_zip_path: ""                # Absolute path of a 7-Zip binary (the embedded one, deployed in the work directory, if empty)
```

**When upgrading:** check `seven_zip_path`. A `7zzs` found in `PATH` is no longer used, and a 7-Zip older than 25.01 is refused at start.

**Key Features:**
- Uses the embedded 7-Zip binary, deployed in the private work directory (a `7zzs` found in `PATH` is never used); the binary is checked and run on a reference archive at every start and configuration, and the connector refuses to start if it is missing, unsafe, cannot run (for example `work_dir` on a `noexec` file system) or is not a supported version
- Prevents extraction bombs through size and count limits (centralized in host connector config), applied to the bytes really written: the kernel limits each file (`RLIMIT_FSIZE`) and the output folder is measured every 250 ms while 7-Zip writes, so an archive that lies about its sizes (gzip, bzip2) is stopped during the write
- Handles symlinks securely
- Hard links: the size of each name counts in the budget, so an archive of many hard links to one big file can exceed the budget and end in `extract-error` (strict on purpose)
- Supports password-protected archives

**Important note:**
- Files exceeding following limits will be skipped (not extracted):
  - `recursive_extract_max_size` (`--recursive-extract-max-size`)
  - `recursive_extract_max_files` (`--recursive-extract-max-files`)
- Zip bomb protection : an archive is considered a zip bomb if total size to extract is > 3GB and if ratio between size to extract and compressed size is > 100 (files above `max_file_size` are excluded from calculation because skipped anyway).

#### FileType Filter Plugin

Filters files based on MIME type detection using libmagic.

```yaml
filetype_filter:
  file: filetype_filter.so
  config:
    forbidden_types:                  # MIME types to flag as malicious (Score=1000)
      - application/x-executable
      - application/x-msdos-program
      - application/x-msdownload
    skipped_types:                    # MIME types to mark as safe (Score=-500)
      - text/plain
      - image/jpeg
      - image/png
```

**Key Features:**
- Real-time MIME type detection
- Early filtering reduces processing load
- Configurable allow/deny lists

#### FilePath Filter Plugin

Filters files based on their path, using regular expressions. A file extracted from an archive is matched on its logical path: the path of the top-level archive followed by the member's path, joined by `/` (`^/in/alice/.*\.exe$` matches `/in/alice/a.zip/x/y.exe`). The temporary folder the archive is extracted into is never part of it, so rules aimed at it (such as `^/tmp/.*`) no longer match. `skipped_paths` and `forbidden_paths` both apply to the members of archives, on their logical path; anchor an allow rule on the archive prefix (`^/in/...`), since an unanchored one also matches a member name chosen by the archive. The logical path is ambiguous by nature: `/in/a.zip/b.zip/x` names a file of a folder `b.zip` as well as one of a nested archive `b.zip`. Control characters in a member name are replaced by `_`.

```yaml
filepath_filter:
  file: filepath.so
  config:
    forbidden_paths:                  # regexp paths to flag as malicious (Score=1000)
      - "^.*\\.exe$"                    # all exe files
    skipped_paths:                    # regexp paths to mark as safe (Score=-500)
      - "^.*.png$"                      # all png files
      - "^.*.jpg$"                      # all jpg files
```

**Key Features:**
- Early filtering reduces processing load
- Configurable allow/deny lists

#### FileSize Filter Plugin

Filters files exceeding a maximum size threshold.

```yaml
filesize_filter:
  file: filesize.so
  config:
    max_size: "100MB"                 # Human-readable size (supports B, KB, MB, GB, TB)
```

**Key Features:**
- Treats oversized files as threats (Score=1000)
- Flexible size parsing with units
- Default: 100MB

#### Error Filter Plugin

Marks files with analysis errors as malicious for proper handling.

```yaml
error_filter:                     # No configuration required
  file: error_filter.so
```

**Key Features:**
- Automatically flags files with analysis errors
- Ensures error cases are properly reviewed
- Sets MalwareReason to `AnalysisError`

#### Session Plugin

Manages scanning sessions by grouping files based on directory structure.

```yaml
session:
  file: session.so
  config:
    depth: 2                          # Directory depth for session grouping
    delay: 30s                        # Delay before closing inactive sessions
    root_folder: /tmp/samples/        # Base path for session ID calculation (required)
    exports: []                       # Base directories for session reports (e.g., ["/var/reports"])
    report_timeout: 2m                # Time given to each attempt to write the report of a session
    report_retries: 3                 # Failed attempts retried before the JSON fallback
    inflight_timeout: 24h             # Longest a session is held open by files that do not end or wait
    remove_empty_dirs: true           # Remove the empty folders left below a session (default: true)
    cleanup_timeout: 2m               # Time given to that removal for one session
```

**Session ID Examples** (with `depth: 2` and `root_folder: /tmp/samples/`):
- `/tmp/samples/user_a/batch1/file1.txt` → session `user_a/batch1`
- `/tmp/samples/user_b/upload/file2.txt` → session `user_b/upload`

**Key Features:**
- Thread-safe file tracking
- Automatic session closure with configurable delay: a session stays open while one of its files is being processed, and while files detected under its folder still wait (for their stability delay, for a worker): a long analysis of another user's file no longer cuts a session in two. A waiting file does not count as activity: a session that has been idle for `inflight_timeout` is closed whatever waits, with a warning, and the files still waiting open a new session. A file whose processing failed appears once, with its error, in the report of its session, and its retries neither keep the session open nor open another one; a report that comes after its session was closed opens a new one, which writes a complementary report
- Consolidated report generation, never lost: each attempt is bounded by `report_timeout`, a failed attempt is retried at the next check (`report_retries` times), then a JSON report is written instead (console error `session-report-fallback` until a normal report succeeds). At most 64 sessions are kept waiting for their report after an attempt: past that, the oldest get their JSON report at once, with the console error `session-report-backlog`. A report that cannot be written at all (JSON included) is lost loudly: an Error log and the console error `session-report-lost` name the session, and it is not tried again. A report is written to each export on its own: one that fails is said with its own error and only the missing exports are retried. At stop, the attempts of the monitor are cut and every open session gets its report: the generators get the stop deadline less a reserve (half of what is left, at most 10 s) in which the JSON fallbacks are written, and when the deadline has expired already the fallbacks get one second in all (the shutdown guard kills the process right after). A summary is logged. The name of a report is cut, with a short hash of the session, when the folder name is long, so that the report keeps a valid file name. In this version the reports of a session are kept in memory until it closes
- A report is written atomically and never replaces a file: it goes to a temporary file (`.gmhost-tmp-*`, mode `0644`: a report is meant to be read by others) in the export folder, is synced, then takes its final name `report-session-<id>-<start>.<ext>` only if that name is free. An existing file of that name is never opened, truncated or removed, whatever fails; if the name is taken anyway (nobody else can create it) it is an anomaly, logged and raised in the console, and the report is written under a conflict name. After each report a console message gives its path and SHA256, so it can be authenticated from the console and not from the folder
- **Empty folders** (`remove_empty_dirs`, **on by default**, Linux only): once the report of a session is written, the empty folders below the session folder are removed, deepest first, within `cleanup_timeout`, one session at a time. The root folder and the session folder itself are never removed, nor is a folder changed less than `delay` ago (that is the grace period: a folder prepared by a user before a deposit is removed once it has been empty and untouched for `delay`), nor the work directory (recognized by its device and inode, read at the start of each removal, so a differently spelled path or a link to it does not matter; it is never entered). Nothing is followed: every folder is opened from its parent without following links and removed with `unlinkat(AT_REMOVEDIR)`, which removes folders only and refuses one that is not empty, so a link, a file or a folder swapped in during the walk is never removed and nothing outside the session is reached. The removal runs in a goroutine of its own, after the report is written and never at stop, so a slow or stuck file system cannot delay a report (at most 64 sessions wait; past that the removal is skipped for the newest, with a warning). The walk holds one descriptor per level, at most 129 open at once (the session folder and 128 levels below it; a deeper part is left, with a warning), and logs one line per session with what it removed, kept and failed to remove, and reads a folder about a thousand names at a time. A file left in place keeps its folder. `remove_empty_dirs: false` restores the previous behavior
- The session reads `HCContext.PendingFiles(dir)` (new): plugins can ask the core how many files detected under the owner whose folder is `dir` (root followed by depth directories, as declared with `SetTrackingOwners`) have not finished processing; any other folder gives 0. `report_timeout`, `inflight_timeout` must be positive and `report_retries` not negative, otherwise the configuration is refused; a Warn is logged when `inflight_timeout` is shorter than `delay`, which disarms the waiting files

#### Report Plugin

Generates comprehensive scan reports in PDF format.

```yaml
report:
  file: report.so
  config:
    template_path: ""                  # Path to custom HTML template (uses embedded default if empty)
    chrome_path: ""                    # Absolute path of Chrome/Chromium (found in PATH if empty)
```

**Prerequisites:**
- Google Chrome or Chromium must be installed on the host to generate PDF reports. On Debian:
```bash
  sudo apt update && sudo apt install chromium
```

- The browser is checked at every start and every configuration: it must pass the executable checks (absolute path, owned by root or the connector account, not writable by others) and render an empty page to a PDF within 30 s, otherwise the connector refuses to start (or keeps its previous configuration). The Chrome sandbox stays on, so a connector running as root is refused: run it under a dedicated service account.
- The browser is restricted: JavaScript is off and every network or `file:` request of the page is refused. A custom template must embed its images and styles (`data:` URIs, inline `<style>`).

**Key Features:**
- PDF report generation
- Reports are rendered from an HTML template, then converted to PDF using chromedp
- Customizable templates using Go's html/template syntax
- A section "Fichiers non analysés" and a counter list the files and the members of archives that reached the output without a complete analysis (too big, empty, encrypted, left out by the extraction, anomaly of the extraction, let through by a filter plugin, restored), with the reason in plain words and the archive of origin; a size the archive does not give is shown as "—". A file whose analysis or action failed carries an error: it is listed among the files in error and is not counted among the analyzed files (so a file blocked and then failing to be quarantined is blocked and in error, not analyzed). The failed members of an archive are listed and counted one by one, and their archive's summary error is not counted again; the count is exact, except beyond 1000 failed members of one archive (the report of an archive keeps that many). Every section of the PDF (blocked files, blocked archives, files in error, files not analyzed) stops at 300 rows, followed by "… et N autres"; the counters stay exact. The blocked archives and their malicious members share the 300 rows of their section, an archive costing 3 rows (its title, its details, the head of its table) plus one per member shown, and the members left out of an archive are counted under it. Every name, error and threat shown in the PDF is cut to 100 bytes (head and tail around "…"), so that the time to render does not depend on the length of a depositor's names (control, invisible and bidirectional characters become "�" in the PDF, ZWNJ and ZWJ included, so some Persian or Indic names and emoji sequences show "�" there; a file shows at most 2 threat names, then the count of the others); the JSON report keeps more: up to 64 threat names per file, each text up to 1024 bytes, within its 4 MiB bound. The worst cases are measured with the real browser by a test, and stay under half of the limits (2 minutes, 64 MiB). A custom template does not show these files until it uses the new fields (`NbFileNotAnalyzed`, `NotAnalyzedFiles`, `MoreNotAnalyzed`, `MoreMitigatedFiles`, `MoreMitigatedArchives`, `MoreErrorFiles`, and `MoreExtracted` of an archive) and its lists may now be cut

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
    NotifyError(ctx context.Context, key string, err error)
    NotifyResolution(ctx context.Context, key string, message string)
}
```

`SetTrackingOwners(root, depth)` lets a plugin that lays files out in sub-folders of `root` (such as `session`) tell the monitor that its owners are the folders `depth` levels below `root`, absolute path required; it is accepted during `Init` only, and a malformed declaration makes `Init` fail. Without any declaration, an owner is the first folder below the shortest monitored path.

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

### Security Considerations

- **Sandboxing**: Plugins run in the same process space as GMHost
- **Resource Limits**: Configure appropriate limits to prevent resource exhaustion
- **Input Validation**: Plugins should validate all input data
- **Logging**: Use structured logging for audit trails
- **Error Handling**: Robust error handling prevents plugin failures from affecting the main application



## Configuration

The default configuration file is located at:
- **Linux**: `/etc/gmhost/config.yml` or `~/.config/gmhost/config.yml`
- **Windows**: `%APPDATA%\gmhost\config.yml`

The file is read strictly: invalid YAML, a mistyped value or a key the connector does not know (a typo such as `too_bg: pass`, or an option removed from an older version) makes the connector refuse to start, with an error naming the file and the key. Only an absent file is accepted, and the defaults and flags apply.

### Example Configuration

```yaml
workers: 4
extract: true
extract_workers: 2
extract_min_size: 8KB
max_file_size: 100MiB
follow_symlinks: false
paths:
  - C:\Users\YourUser\Documents
  - /home/user/Downloads
actions:
  delete: true
  quarantine: true
  move: false
  print: true
  log: true
monitoring:
  prescan: true
  period: 1h
  modification_delay: 30s
gmalware_api_url: https://gmalware.ggp.glimps.re
gmalware_api_token: 00000000-00000000-00000000-00000000-00000000
gmalware_timeout: 5m
gmalware_user_tags: ["Server1"]
gmalware_no_cert_check: false
gmalware_syndetect: false
gmalware_bypass_cache: false
quarantine:
  location: C:\Program Files\GMHost\quarantine
  password: infected
  registry: C:\Program Files\GMHost\quarantine.db
move:
  source: C:\path\to\source
  destination: C:\path\to\destination
print:
  location: C:\Program Files\GMHost\reports.log
  verbose: false
plugins_config: /etc/gmhost/plugins.yml
debug: false
```

### Configuration Options

Some keys are declared by the configuration schema before this version supports them (`unanalyzable_policy.extract_error: as_file`). Setting one of them to such a value makes the configuration refused, naming the key; remove the key.

A configuration is validated before it is applied. When the console sends one that cannot be applied, the connector keeps the previous configuration, keeps processing files, and raises the console error `host-config-rejected`; the error stays until a `Configure` succeeds, and a reminder is logged every hour. After a restart the connector receives the rejected configuration again and does not start: fix it in the console. Keys unknown to this version of the connector (the console is newer) are applied without effect and listed in the console error `host-config-unknown-keys`: update the connector for them to apply.

#### Global Settings

- **`workers`**: Number of concurrent workers for file analysis (default: 4, affects CPU usage)
- **`extract_workers`**: Number of concurrent workers for archive extraction (default: 2, used when extract is enabled)
- **`extract`**: Enable archive extraction (archives are unpacked and contents scanned)
- **`extract_min_size`**: Minimum file size to attempt extraction (e.g., '8KB'). Files at or below this size are sent for analysis instead of being extracted (default: 8KB), except the archives of a known format (zip, 7z, tar, rar, ...), which are extracted, or listed to find out they are encrypted, whatever their size; a small unknown binary is not looked at by the extractor
- **`max_file_size`**: Maximum file size to send for analyze (e.g., '100MB'). Files exceeding this are extracted if 'extract' is enabled, otherwise rejected
- **`unanalyzable_policy`**: what becomes of a file that is not analyzed in full. Each key takes `error`, `pass` or `mitigate` (`empty` takes `pass`, `skip` or `mitigate`). `too_big` (default `error`) applies to a file larger than `max_file_size` that is not extracted, to a member of an archive that is, and to an archive the depth or the budget of the extraction does not let open (listed as `extract-limit`), to the members the extraction leaves out because of its limits (a member over `max_file_size`, too many members, too large a total; they are listed as `extract-limit` or `too-big`): `error` keeps a file too big as an error that stays in INPUT, as before; an archive with a member too big, which used to be moved as if it were clean, now stays in INPUT as well, definitively and without being extracted again (use `pass` or `mitigate` to decide otherwise), `pass` lets the file through (it is moved, deleted or reported as any other file) and marks it `not-analyzed-reason: too-big`, `mitigate` treats it as malware with the reason `too-big` (the result of the former `filesize_filter` plugin). A file too big that `pass` lets through is moved as in `rename` mode: its content was not verified, and the console line says "content not verified". `encrypted` (default `error`) does the same for an archive whose password is unknown (7-Zip says `Unsupported Method` for an encryption it cannot name as well as for an unsupported compression: that line, like a data error in an encrypted member, only makes an archive `encrypted` when its technical listing marks a member encrypted and no password opened it; in a zip it is always an extraction error); an archive of which only some members resist the passwords is treated as encrypted as a whole, unless a known password opened it and it failed on a corrupted one, which is an extraction error (a run of hint lines, that is data errors, that named fewer members than the batch held, or in a zip a password accepted by the check of its members); a member refused with `Wrong password` is partial encryption, even after members were extracted: the archive is `encrypted`; a 7z archive every member of which is corrupted, with a known password, cannot be told from an unknown password and stays `encrypted`, while a 7z archive that mixes a member with an unknown password and a plain one (which the known password extracts) is an extraction error; the same goes for members that share a name, of which one cannot be decrypted: the archive is an extraction error, not `encrypted`. Under `encrypted: pass`, a 7z archive whose members all fail their check with a known password (corrupted, or a tampered checksum) is passed as encrypted, with the same exposure as one with an unknown password: its content was not analyzed; the classification relies on the output of 7-Zip 25.01, the version embedded (older versions, p7zip 16.02 for instance, print member names unescaped and are not supported); an encrypted archive inside an archive is a member under the same policy: it is submitted first when it is within `max_file_size` (a malicious verdict wins whatever the policy), then `error` keeps it in INPUT, `pass` marks it `encrypted`, `mitigate` makes it malware with the reason `encrypted`. `empty` (default `pass`) applies to a file of size 0: `pass` delivers it, as a new empty file made in the destination by the move in `copy` mode, marked `empty` in the reports, and removes the source; it is refused with `move.mode: rename`, and when the key is left out with `rename` the files are skipped instead, with a warning at each start; a file that receives data between the check of its size and its removal is left in place and the empty copy is taken back (it is analyzed at the next scan); with `follow_symlinks: true`, a link to an empty file is reported as passed but, like any link, is neither moved nor deleted; `skip` ignores the file with a warning in the log (once per file) and leaves it in place; `mitigate` makes it malware with the reason `empty` (quarantined, and restorable). `extract_error` only accepts `error`. Every file that reaches the output without a full analysis, a file let through by an `OnScanFile` plugin included (`policy-skipped`), is written in the log, in the console line of the `inform` action (even without `--verbose`) and in the JSON reports (`not-analyzed-reason`, `not-analyzed-subfiles` with an exact count); the lists of a report are capped at 1000 entries and a report never exceeds 4 MiB. A plugin cannot erase these marks in `OnFileScanned`
- **`follow_symlinks`**: Follow symbolic links when scanning directories (default: false: symlinks are skipped, and a file whose path crosses a symlink below its monitored path is refused when it is prepared and again right before the action, so a user cannot make the connector read, move, delete or quarantine another tree's files by swapping a folder for a link; a refused file is left in place with a warning). Enabling it switches these checks off: a warning is logged at start when move, delete or quarantine are active
- **`paths`**: List of directories or files to monitor and scan (can be absolute or relative paths, required, minimum 1)
- **`plugins_config`**: Path to plugins configuration file (required for host connector plugin functionality, GNU/Linux only)
- **`debug`**: Enable debug logging (default: false)
- **`work_dir`**: Base directory of the connector private working directory (default: the system temporary directory, `TMPDIR` honored). A `gmhost-<random>` sub-directory (mode `0700`) is created there for archive extractions and plugin files, and removed at stop; the directories left by a crashed process are purged at the next start (only a real `gmhost-*` directory of the same user, mode `0700`, with a free `.lock`). The connector never scans this directory and plugins ignore it. On Unix, Chrome gets a `data`, a `tmp` and a `home` folder per rendering inside the work directory (`TMPDIR`, `HOME` and the `XDG_*` folders point there), so it leaves nothing in the temporary folder of the system. Its `TMPDIR` is a short link `gmhc-<random>` made in the temporary folder of the system (or `/tmp` when that folder is longer than 38 bytes, or not owned by root or the connector account, or writable by its group or by other accounts without the sticky bit; only that folder is checked, not the ones above it: the start of a rendering fails if `/tmp` is not usable either) and pointing to the `tmp` folder of the rendering: Chrome puts a Unix socket there, which a path of more than about 100 bytes would break, so `work_dir` may be as long as needed. The link is removed after the browser exits, and the links of a connector that did not stop cleanly (dangling, named `gmhc-*`, owned by the connector account) are removed at start. Do not share the temporary folder between connectors of the same account that cannot see each other's `work_dir` (containers): each would remove the other's links in use. It must not be a monitored path, nor lie under one (the start is refused: each extraction folder would get an inotify watch): a site that monitors `/tmp` must set `work_dir` elsewhere. A warning is logged when `move.destination` is under a monitored path. On Windows there is no orphan purge, no real lock, and the folder inherits the ACLs of its parent: choose a dedicated, restricted base. Use a local disk: a memory filesystem (`tmpfs`) uses RAM (warning at start), and file locks are unreliable on network filesystems (CephFS)
- **`shutdown_timeout`**: Time allowed to stop on `SIGTERM` or `SIGINT` (flag `--shutdown-timeout`, default `8s`, at least `2s`; local to the machine, the console does not manage it). Set it under the delay of the orchestrator (`docker stop -t`, systemd `TimeoutStopSec`). A signal stops the connector the way the console does: no new file is accepted, the files being processed may finish for `shutdown_timeout` minus a reserve of half of it (at most 30 s), then they are cut and left where they are (they are processed again at the next start), then the sessions get their report, the plugins are closed all at once (an extraction running is killed with its 7-Zip) and the work directory is removed, all within `shutdown_timeout`. A second signal stops the process at once. The log gets `stop requested, closing` when the signal arrives and `stop finished` at the end, with the files abandoned or still running, the plugins in error and the work directory removal; the exit code is `0` if the delay was kept, `1` otherwise (a guard ends the process one second after the delay if a plugin does not return). `scan` stops the same way on Ctrl+C. A signal received while a stop ordered by the console is already in progress ends at the guard of the process (code `1`) if that stop outlasts `shutdown_timeout`. The stop of a signal waits for the stop or the configuration of the console already running, with no bound of its own: the guard of the process is what ends it. A plugin that ignores its context is given up on at the end of the closing time (a short grace is kept for the plugins still finishing) and its goroutine stays until the process ends. On Windows only the console version receives Ctrl+C (`os.Interrupt`); the `windowsgui` version gets no signal. Limits: `SIGKILL`, a power cut or an orchestrator delay shorter than `shutdown_timeout` run nothing: the work directory is purged at the next start, and the reports of the sessions still open are lost

#### Actions

Configure what happens when malware is detected:
- **`delete`**: Delete detected malware files automatically (default: true)
- **`quarantine`**: Move malware files to encrypted quarantine storage (requires quarantine configuration, default: true)
- **`move`**: Move clean files from source to destination after scanning (requires move configuration, default: false)
- **`print`**: Output scan results to console or file (see print configuration, default: true)
- **`log`**: Log malware detections (written to connector logs, default: true)

#### Monitoring

- **`prescan`**: Immediately walk all existing files in monitored paths when monitoring starts (default: false). They are tracked like any other file (within `max_tracked_memory`) and handed to the analysis once stable for `modification_delay`: a file still being written is not analyzed early. A folder that appears later is walked the same way, one walk at a time
- **`disable_fs_watcher`**: Do not watch filesystem events: files are found by the pre-scan and the periodic rescan only (default: false). Requires `period`. Meant for network filesystems (e.g. CephFS) where inotify watches are unavailable or too numerous; it also makes the start immediate. A configuration pushed by the console replaces the whole local configuration, so the key must be set there in agent mode
- **`max_tracked_memory`**: Memory bound of the table of files the monitor tracks while they wait for their `modification_delay` (default: `256MiB`, counted in bytes: path lengths included). The table never exceeds it. Below the bound nobody is limited; when it is full, the owner that holds the most (files are grouped into owners: one per user folder, or per session folder at the `depth` of the `session` plugin) yields first, so a flood by one user does not starve the others. A refused or evicted file is not forgotten by the disk: with a periodic rescan it is found again at the next rescan; without one (`period: 0`) it is only found again when it is written to again, so set a `period` on a folder that can overflow. A warning names the owners concerned (at most 32, the others are counted), with a console event raised at the end of a rescan, or, without periodic rescan (`period: 0`), as soon as a file is refused or evicted and then at most once a minute; its resolution is raised after a minute without pressure, with the next file event. Minimum: `1MiB`
- **`max_tracked_dir_percent`**: Share of the table, in percent (default: `25`), above which an owner is visited first when the table is full; it is not a ceiling
- **`period`**: If set, enable periodic rescan. Time interval between periodic re-scans (e.g., '1h', '30m', default: 0, disabled). A file that was processed and is still in INPUT is not read nor sent to the analysis again at each rescan: the rescan only compares its metadata (one stat), and processes it again when it changed. A failure that may go away (analysis timeout, network, I/O, an action that failed) is retried after `2 × period` the first time, then twice as long after each new failure, up to `64 × period` and never more than one hour, shifted randomly by ±20 % so that files that failed together do not come back together; the 8th failure makes it final (log and console message "giving up"). A failure of a resource (an action that timed out or found the disk full, an extractor that is down) is retried the same way but never given up. Definitive outcomes (action done, analysis error, file too big, permanent action failure, restored file, inconsistent plugin result) are never retried. Without `period` (`0`) nothing comes back to a file by itself: a retry waits for the next event on the file that comes after its delay, which starts from one minute. When an action fails after touching the file (a link then an unlink moves its change time), the connector reports the state it left the file in, so that the failure is counted with its delay and not taken for a change made by someone else. A file that its owner rewrites during every analysis waits for stability again each time: the first two reopenings are immediate, the next ones are spaced up to one hour, and it is never given up. A removal of the source refused for a lasting reason (permission, read-only file system) is a definitive failure. When the table is full, a file waiting for a retry can be evicted to make room and its count of failures is then forgotten: under that pressure a file can be attempted more than 8 times. The table is in memory: after a restart the files left in INPUT are processed once again
- **`modification_delay`**: Wait time after file modification before scanning (e.g., '30s', prevents scanning incomplete writes, default: 30s). A file is identified by its device, inode, size, modification time and change time (size and modification time only on Windows and other systems that give no inode or change time), and only handed to the analysis once its identity has been unchanged for this delay; a file still being written restarts the delay. The connector then opens the file once and reads everything through that descriptor: its hash, its analysis (the content is sent to the service from the descriptor, without any temporary copy, and the service must report the same SHA256), the plugins (`location` is a `/proc/<pid>/fd/<N>` path on Linux) and the extraction of archives (through a link to the descriptor). On Linux `/proc` must be usable: it is checked at start and the connector refuses to start without it. Elsewhere plugins and the extractor read the path the file was deposited at, which is logged at start. It checks the descriptor and the name again after the last read. On Linux the descriptor, opened without following any symbolic link below the monitored path, stays open during the actions: a quarantine reads the file from it, a deletion removes that file by name in the folder it was opened in only if the name still is that inode, and the move of a clean file by rename links that same inode into the destination from the descriptor (a copy read from it when the file system refuses links) then removes the old name through the handle, so that swapping the file or one of its folders for another between the check and the action cannot make the connector read, move or delete another file. With `follow_symlinks: true`, a deposited link may be analyzed and quarantined but is never deleted nor moved (the link and its target stay and the report says so). Elsewhere the descriptor is closed before the actions, which re-open the file and compare its identity. A file replaced, rewritten or swapped (even by swapping one of its folders) meanwhile is left in place; it is analyzed again once stable at the next rescan, or at the next event on the file (never with `period: 0` and no further write). Limits: a descriptor open for writing held by the depositor, or a hard link it keeps to the same inode, is not detectable by the connector (it can still change the content after the check; a hard link makes the connector publish a private copy instead of linking), the dates of a CephFS or NFS file are given by the writing client or cached (an identical size and dates can hide a change), FAT and exFAT keep coarse dates, and a FUSE file system without `use_ino` may reuse inode numbers. Elsewhere than on Linux only a few microseconds remain between the final check and the action. A FIFO or a device put in place of a file is refused without blocking. With `follow_symlinks: true`, a link to a folder is never walked.

#### GLIMPS Malware Detect

Top-level configuration fields:
- **`gmalware_api_url`**: GLIMPS Malware API URL (required)
- **`gmalware_api_token`**: GLIMPS Malware API Token (required)
- **`gmalware_timeout`**: gmalware submission timeout (default: 5m)
- **`gmalware_user_tags`**: List of tags set by connector on GLIMPS Malware detect submission
- **`gmalware_no_cert_check`**: Disable certificate check for GLIMPS Malware (default: false)
- **`gmalware_syndetect`**: use syndetect (default: false)
- **`gmalware_bypass_cache`**: bypass gmalware (default: false)

#### Quarantine

- **`location`**: Directory path where quarantined files are stored (files are encrypted with .lock extension)
- **`password`**: Password for encrypting quarantined files (required to restore files later, default: "infected")
- **`registry`**: Path to the database that stores quarantined and restored file entries (leave empty for in-memory store which would be lost on restart). A restored content is considered safe wherever it is deposited, by anyone, from then on: the registry is searched by the SHA256 of the content, not by the place it was quarantined from (a global allow list of that content, by design). The copies of that content still in quarantine are restored one by one. A quarantine refused because the content was restored meanwhile is a retry: nothing is written, moved or deleted for the file on that pass (no detection report next to it), and it is delivered as restored at the next one. A narrow window remains: a restoration of the content at one place and a quarantine of the same content at another do not wait for each other (the locks are per entry); the outcome stays closed, the second copy is quarantined and nothing is delivered. The empty content is the exception: it is matched per location only, restoring one empty file does not make every empty file safe. The report of a restored file says so (`has-been-restored`). A registry made by an older version gets the index of this search at the next start
- **`format`**: Container written for new quarantined files: `tar` (default, encrypted tar) or `zip` (ZIP protected by a password with traditional PKWARE encryption, openable with Windows Explorer, 7-Zip and other common tools). Existing `.lock` files stay restorable whatever the value, and both formats can live in the same directory.

A restoration opens its destination folder one level at a time without following any symbolic link (from the monitored path, or from the root of the file system once the trusted system links of a destination outside the monitored paths are resolved) and writes the temporary file and the rename inside that opened folder: a link swapped in meanwhile makes it fail, and the `.lock` file is kept.

The quarantine directory is created with mode `0700` when missing. At every start and reconfiguration it must belong to the connector account (or root), must not be writable by its group or by others, and must not be, be under, or contain a monitored path, `move.destination` or the work directory. Otherwise the configuration is refused and the error gives the fix: `chown <connector account> <dir> ; chmod 700 <dir>`. A quarantine directory under the base of the work directory (often `/tmp`) may be erased by an automatic clean-up of `/tmp`: prefer a dedicated directory. Changing the directory, the registry, the format or the password is all or nothing: on any error the files are put back and the previous registry and password stay in service.

**Using `format: zip`**
- The quarantine password must be considered **public**. ZipCrypto can be broken with a few known plaintext bytes, and whoever deposited a quarantined file knows its content. Do not reuse this password anywhere else, and do not consider the existing `tar` files of the same directory confidential anymore. A warning is logged, and sent to the console, each time the configuration is applied with this format.
- The entry in the ZIP keeps the name and extension of the original file (the name is sanitized). Opening the archive with the password therefore exposes the original file, executable included: handle it as malware.
- Only ZIP files written by GMHost are read back: exactly the index and the payload, without compression.

#### Move Action

- **`source`**: Source directory filter (only clean files within this path are moved to destination)
- **`destination`**: Target directory for moving clean files (preserves subdirectory structure)
- **`mode`**: `copy` (default) or `rename`, see Move below
- **`min_throughput`**: Minimum copy throughput per second in `copy` mode (default `10MiB`); a copy takes at most `size / min_throughput + 1 minute`

#### Print/Report

- **`location`**: File path for scan reports (leave empty to print to stdout)
- **`verbose`**: Report all scanned files, including clean files (not just malware detections, default: false)

## Archive Extraction

GMHost can extract and analyze files from various archive formats when the `extract` option is enabled:

**Supported formats:**

- ZIP
- GZIP
- TAR
- BZIP2
- RAR
- 7Z
- ISO
- Brotli
- LZ4
- XZ
- Zstandard
- S2
- Snappy
- Zlib
- LZW

**Conditions to attempt extraction:**
- file size must be > `extract_min_size` (`--extract-min-size`, default 8KB), unless the file is an archive of a known format: those are extracted whatever their size (an archive of an unknown type, seen as a plain binary, still needs the size)
- file's MIME type must belong to list of allowed types (see below)

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

**Recursive extraction:**

GMHost uses recursive extraction, meaning archives within archives are automatically extracted.

It is limited by:

- **`recursive_extract_max_depth`**: Maximum nesting level for extraction (default: 10). Beyond it, files are directly sent for analysis.
- **`recursive_extract_max_size`**: Maximum total size of all extracted files across all nesting levels from one root archive (default: 5GB). When reached, remaining files are directly sent for analysis. Note: this limit is checked before each extraction but the size is counted after, so the actual total may exceed this limit by the size of one archive's extracted content.
- **`recursive_extract_max_files`**: Maximum total number of files extracted across all nesting levels from one root archive (default: 10000). When reached, remaining files are directly sent for analysis.

**Important notes:**

- The extractor does not remove malicious files from archives
- If any file in an archive is malicious, the entire archive is considered malicious
- Archive contents are extracted to temporary directories and cleaned up after analysis
- Files larger than `max_file_size` within archives are skipped

## Actions

When a file is scanned, multiple actions can be triggered based on the results (see below).

Each sequence of actions is limited by a timeout proportional to the file size (to adapt to costly operations like quarantine (read + encrypt + write)). Timeout is **30 seconds per GB**, rounded up to the next GB with a minimum of 30 seconds in any case.  
Examples: 1MB -> 30s ; 500MB -> 30s ; 1,2GB -> 60s ; 2GB -> 60s

### Quarantine

- **When**: Malware is detected
- **Effect**: Creates an encrypted, protected copy of the malicious file in the quarantine folder
- **Details**: Files are encrypted using AES with a password and stored with metadata

### Delete

- **When**: Malware is detected (after quarantine if enabled)
- **Effect**: Removes the original malicious file from the filesystem

### Move

- **When**: File is in the source directory
- **Effect**:
  - **Legitimate files**: Moves the file to the destination folder, preserving directory structure
    - A file never replaces one already at the destination: the new one is stored next to it as `<name>.conflict-<UTC time>[-n]<ext>` (the name is cut, never the suffix, to stay within 255 bytes), `moved-to` gives the real path, `move-conflict-of` the original name, and a warning is logged and sent to the console (the first file may have been partial). After 6 names taken, or when the destination is a directory or a parent is a file, the file stays in place with an error: nothing is retried
    - **`move.mode`** (`copy` by default, or `rename`): in `copy` mode nothing reaches the destination by link or rename of the source inode: the connector copies the file it analyzed through its verified descriptor into `.gmhost-staging`, checks that the copy has the SHA256 that was analyzed, publishes it under its final name, and removes the source only if the name still is the analyzed file. What lands in the destination is exactly what was analyzed, whatever a writer that kept the file open does afterwards; a file rewritten during the copy is not published and stays in place. The cost is one more read and one more write of each moved file. Empty files are created new, empty. The copy keeps the permission bits of the source without setuid, setgid, sticky or write for others (write for the group is kept), and the destination folder is flushed to disk before the source is removed, so that a crash cannot lose both. A copy the source name is renamed away from by its depositor between the analysis and the removal can leave the file both at the destination and under its new name: the destination holds exactly what was analyzed. The only exception is a file the pipeline itself declared too big to be analyzed (above `max_file_size`, not analyzed) that `unanalyzable_policy.too_big: pass` lets through: it is moved as in `rename` mode (no analyzed content to check); the decision is the pipeline's, never what a plugin or a member of an archive says, and a large archive that was extracted and analyzed is copied. The copy has a time limit of `size / move.min_throughput + 1 minute` (`move.min_throughput`, default `10MiB`, per second); a copy that exceeds it, or that finds the destination full or its quota used up, is abandoned (the transit file is removed, the source stays), a console error `host-move-resource` is raised until a file is moved again, and the file is retried like any failure of a resource (never given up). `rename` moves the inode itself (link then removal of the old name, a copy only where links are refused): cheaper, but a writer holding the file open can still change what reached the destination. Limit: a destination on a network file system that blocks has no I/O deadline of its own, only the time limit of the copy. `rename` is accepted, with a warning in the log and a console event `host-move-rename` at each configuration applied while the move action is active
    - Files are moved atomically, also across file systems: a copy is first made in the private `.gmhost-staging` folder at the root of the destination, then linked to its final name. Whoever consumes the destination must ignore `.gmhost-staging`. Setuid and setgid bits are never copied
    - **Reserved names**: a file whose name starts with `report-session-`, in any letter case and at any depth, is never moved; it stays in the source folder and the error is reported (`error` of its report). A fake report could otherwise reach the destination. To authenticate a session report, rely on the console event (name and SHA256), not on the file name alone. A file with that name found malicious is quarantined or deleted like any other
  - **Malicious files**: Does not move the file, but creates a `.locked.json` report file at the destination path containing analysis details
  - **Files in error**: Does not move the file. This includes an archive in which an extracted file could not be analyzed (submission failure, timeout, unreadable or lost file, inconsistent plugin result): the archive stays in place, the failed files are listed in the report (`error-subfiles`, at most 1000 entries). Empty files in an archive are still ignored, and files too big follow their own handling

### Print

- **When**: Always (configurable verbosity)
- **Effect**: Outputs scan results to console or specified log file

### Log

- **When**: Always
- **Effect**: Logs detailed scan information using structured logging

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

**Warning**: Only restore files if you are certain they are safe. Restored files will be in their original, unencrypted form.

## Environment Variables

GMHost respects the following environment variables:
- **`GMALWARE_TOKEN`**: GLIMPS Malware Detect authentication token (used by `--gmalware-token` flag)
- **`GMALWARE_URL`**: GLIMPS Malware Detect API endpoint (used by `--gmalware-url` flag)
- **`TMPDIR`**: Temporary directory for archive extraction (Unix)

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
