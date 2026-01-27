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
- **OnFileScanned**: Process analysis results (logging, custom actions)
- **OnReport**: Handle generated reports (consolidation, forwarding)
- **XtractFile**: Custom archive extraction logic
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
      --extract                      Enable archive extraction for files exceeding max_file_size (archives are unpacked and contents scanned)
      --extract-workers int          Number of concurrent workers for archive extraction (default: 2, used when extract is enabled) (default 2)
      --follow-symlinks              Follow symbolic links when scanning directories (if disabled, symlinks are skipped)
      --gmalware-syndetect           Use syndetect API to analyze files
      --gmalware-token string        GLIMPS Malware Detect token
      --gmalware-url string          GLIMPS Malware Detect url (E.g https://gmalware.ggp.glimps.re)
  -h, --help                         help for GMHost
      --insecure                     do not check certificates
      --max-file-size string         Maximum file size to scan directly (e.g., '100MB'). Files exceeding this are extracted if 'extract' is enabled, otherwise rejected (default "100MiB")
      --mod-delay duration           Wait time after file modification before scanning (e.g., '30s', prevents scanning incomplete writes) (default 0s)
      --move-destination string      Target directory for moving clean files (preserves subdirectory structure)
      --move-source string           Source directory filter (only clean files within this path are moved to destination)
      --print-location string        File path for scan reports (leave empty to print to stdout)
      --quarantine string            Directory path where quarantined files are stored (files are encrypted with .lock extension) (default "/var/lib/gmhost/quarantine")
      --quarantine-registry string   Path to the database that store quarantined and restored file entry (leave empty for in-memory store, lost on restart)
      --scan-period duration         Time interval between periodic re-scans (e.g., '1h', '30m', requires rescan enabled) (default 0s)
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
      --scan-period duration   Time interval between periodic re-scans (e.g., '1h', '30m', requires rescan enabled) (default 0s)

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
- **filepath_filter**: Filters files based on file path patterns (allow/deny lists)
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

A complete example configuration is available at `rsc/plugin_config.yml`. Below are the configuration options for each built-in plugin:

#### Extract Plugin

Extracts and scans content from various archive formats (ZIP, RAR, 7Z, TAR, GZIP, BZIP2, ISO, etc.).

```yaml
extract:
  file: extract.so
  config:
    max_file_size: 500MB              # Maximum size for extracted files (supports B, KB, MB, GB, TB)
    max_extracted_files: 1000         # Maximum number of files to extract
    max_total_extracted_size: 3GB     # Maximum total size to extract from archive (supports B, KB, MB, GB, TB)
    default_passwords:                # Passwords for encrypted archives
      - infected
      - password
    seven_zip_path: ""                # Custom 7-Zip binary path (auto-detect if empty)
```

**Key Features:**
- Uses embedded 7-Zip binary for automatic deployment
- Prevents extraction bombs through size and count limits
- Handles symlinks securely
- Supports password-protected archives

**Important note:**
- Files exceeding following limits will be skipped (not extracted):
  - `max_total_extracted_size`
  - `max_extracted_files`
  - `max_file_size`
- Zip bomb protection : an archive is considered a zip bomb if total size to extract is > 3GB and if ratio between size to extract and compressed size is > 100 (files above `max_file_size` are excluded from calculation because skipped anyway).

#### FileType Filter Plugin

Filters files based on MIME type detection using libmagic.

```yaml
filetype_filter:
  file: filetype.so
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

Filters files based on their path, using regular expressions.

```yaml
filepath_filter:
  file: filepath.so
  config:
    forbidden_paths:                  # regexp paths to flag as malicious (Score=1000)
      - "^/tmp/.*"                      # any file in /tmp or its subfolders
      - "^/tmp/[^/]+$"                  # any file strictly in /tmp (not its subfolders)
      - "^.*.exe$"                      # all exe files
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
    remove_inputs: true               # Remove input files after session completion
    root_folder: /tmp/samples/        # Base path for session ID calculation (required)
    exports: []                       # Base directories for session reports (e.g., ["/var/reports"])
```

**Session ID Examples** (with `depth: 2` and `root_folder: /tmp/samples/`):
- `/tmp/samples/user_a/batch1/file1.txt` → session `user_a/batch1`
- `/tmp/samples/user_b/upload/file2.txt` → session `user_b/upload`

**Key Features:**
- Thread-safe file tracking
- Automatic session closure with configurable delay
- Consolidated report generation
- Optional file cleanup

#### Report Plugin

Generates comprehensive scan reports in PDF or HTML format.

```yaml
report:
  file: report.so
  config:
    template_path: ""                  # Path to custom HTML template (uses embedded default if empty)
```

**Key Features:**
- PDF and HTML report generation
- Uses chromedp for HTML-to-PDF conversion
- Customizable templates using Go's html/template syntax

### Plugin Development

#### Plugin Interface

All plugins must implement the `plugins.Plugin` interface:

```go
type Plugin interface {
    Init(configPath string, hcc HCContext) error
    Close(ctx context.Context) error
}
```

#### HCContext Interface

Plugins interact with the host connector through the `HCContext` interface:

```go
type HCContext interface {
    SetXTractFile(f XtractFileFunc)
    RegisterOnStartScanFile(f OnStartScanFile)
    RegisterOnFileScanned(f OnFileScanned)
    RegisterOnReport(f OnReport)
    RegisterGenerateReport(f GenerateReport)
    GenerateReport(reportContext report.ScanContext, reports []report.Report) (io.Reader, error)
    GetLogger() *slog.Logger
}
```

#### Callback Types

Plugins can register callbacks for different stages of the scanning pipeline:

- **`OnStartScanFile`**: Called before a file begins scanning
- **`OnFileScanned`**: Called after a file completes scanning
- **`OnReport`**: Called when a scan report is generated
- **`GenerateReport`**: Custom report generation function
- **`XtractFileFunc`**: Custom file extraction function

#### Example Plugin Structure

```go
package main

import (
    "context"
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

func (p *MyPlugin) Init(configPath string, hcc plugins.HCContext) error {
    p.logger = hcc.GetLogger()
    // Load configuration and register callbacks
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

### Example Configuration

```yaml
workers: 4
extract: true
extract_workers: 2
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
  rescan: true
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

#### Global Settings

- **`workers`**: Number of concurrent workers for file analysis (default: 4, affects CPU usage)
- **`extract_workers`**: Number of concurrent workers for archive extraction (default: 2, used when extract is enabled)
- **`extract`**: Enable archive extraction for files exceeding max_file_size (archives are unpacked and contents scanned)
- **`max_file_size`**: Maximum file size to send for analyze (e.g., '100MB'). Files exceeding this are extracted if 'extract' is enabled, otherwise rejected
- **`follow_symlinks`**: Follow symbolic links when scanning directories (if disabled, symlinks are skipped)
- **`paths`**: List of directories or files to monitor and scan (can be absolute or relative paths, required, minimum 1)
- **`plugins_config`**: Path to plugins configuration file (required for host connector plugin functionality, GNU/Linux only)
- **`debug`**: Enable debug logging (default: false)

#### Actions

Configure what happens when malware is detected:
- **`delete`**: Delete detected malware files automatically (default: true)
- **`quarantine`**: Move malware files to encrypted quarantine storage (requires quarantine configuration, default: true)
- **`move`**: Move clean files from source to destination after scanning (requires move configuration, default: false)
- **`print`**: Output scan results to console or file (see print configuration, default: true)
- **`log`**: Log malware detections (written to connector logs, default: true)

#### Monitoring

- **`prescan`**: Immediately scan all existing files in monitored paths when monitoring starts (default: false)
- **`rescan`**: Enable periodic re-scanning of all files (requires period to be set, default: false)
- **`period`**: Time interval between periodic re-scans (e.g., '1h', '30m', requires rescan enabled, default: 0, disabled)
- **`modification_delay`**: Wait time after file modification before scanning (e.g., '30s', prevents scanning incomplete writes, default: 30s)

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
- **`registry`**: Path to the database that stores quarantined and restored file entries (leave empty for in-memory store which would be lost on restart)

#### Move Action

- **`source`**: Source directory filter (only clean files within this path are moved to destination)
- **`destination`**: Target directory for moving clean files (preserves subdirectory structure)

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
- file size must be > 8KB
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

- **`recursive_extract_max_depth`**: Maximum nesting level for extraction (default: 10). Beyond it, files are directly send for analyze.
- **`recursive_extract_max_size`**: Maximum total size of all extracted files across all nesting levels from one root archive (default: 5GB). When reached, remaining files are directly sent for analyze. Note: this limit is checked before each extraction but the size is counted after, so the actual total may exceed this limit by the size of one archive's extracted content.
- **`recursive_extract_max_files`**: Maximum total number of files extracted across all nesting levels from one root archive (default: 10000). When reached, remaining files are directly send for analyze.

**Important notes:**

- The extractor does not remove malicious files from archives
- If any file in an archive is malicious, the entire archive is considered malicious
- Archive contents are extracted to temporary directories and cleaned up after analysis
- Files larger than `max_file_size` within archives are skipped

## Actions

When a file is scanned, multiple actions can be triggered based on the results:

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
  - **Malicious files**: Does not move the file, but creates a `.locked.json` report file at the destination path containing analysis details

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
- **Symlinks**: Disable `follow_symlinks` if you don't need to scan linked directories to improve performance

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
