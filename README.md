# GLIMPS Malware Detect Host Connector

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
- **Cache system**: Avoid re-scanning files that haven't changed
- **Multiple actions**: Configurable actions when malware is detected (quarantine, delete, move, log)

## Usage

```bash
GLIMPS Malware Host connector is a tool to scan files with GLIMPS Malware Detect

Usage:
  GMHost [flags]
  GMHost [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  monitoring  Start monitoring location with GLIMPS Malware host
  quarantine  Handle GLIMPS Malware host quarantined files
  scan        Scan folders

Global Flags:
      --cache string             location of the cache DB
      --config string            config file (default "/etc/gmhost/config.yml")
      --debug                    print debug strings
      --extract                  extract archive and scan inner files
      --gdetect-token string     GLIMPS Malware Detect token
      --gdetect-url string       GLIMPS Malware Detect url (E.g https://gmalware.ggp.glimps.re)
      --gdetect-syndetect        use syndetect API to analyze files
  -h, --help                     help for GMHost
      --insecure                 do not check certificates
      --max-file-size string     max file size to push to GLIMPS Malware Detect (default "100MiB")
      --move-destination string  folder where legit files will be moved
      --move-source string       root folder from where to move files
      --print-location string    destination file for report logs
      --quarantine string        location of the quarantine folder (default "/var/lib/gmhost/quarantine")
      --quiet                    print no information
      --scan-validity duration   Validity duration for each scan result (default 168h0m0s)
      --timeout duration         Time allowed to analyze each file (default 5m0s)
      --verbose                  print more information
      --workers int              number of files analyzed at the same time (default 4)
```

## Commands

### Scan

Scan files or directories for malware.

```bash
GMHost scan [flags] [path...]

Scan-specific Flags:
      --gui    enable graphical user interface (Windows only)
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
GMHost monitoring [flags] [path...]

Monitoring-specific Flags:
      --mod-delay duration     Time waited between two modifications of a file before submitting it (default 30s)
      --pre-scan               start monitoring with a scan of existing files
      --scan-period duration   re-scan all files every scan-period
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

## Configuration

The default configuration file is located at:
- **Linux**: `/etc/gmhost/config.yml` or `~/.config/gmhost/config.yml`
- **Windows**: `%APPDATA%\gmhost\config.yml`

### Example Configuration

```yaml
workers: 4
extract: true
paths: 
  - C:\Users\YourUser\Documents
  - /home/user/Downloads
actions:
  delete: true
  quarantine: true
  moveLegit: false
  print: true
  log: true
monitoring:
  preScan: true
  reScan: true
  period: 1h
  modificationDelay: 30s
gdetect:
  url: https://gmalware.ggp.glimps.re
  token: 00000000-00000000-00000000-00000000-00000000
  timeout: 5m
  tags: ["Server1"]
  insecure: false
  syndetect: false
quarantine:
  location: C:\Program Files\GMHost\quarantine
  password: infected
cache:
  location: C:\Program Files\GMHost\cache.db
  scanValidity: 168h
move:
  source: C:\path\to\source
  destination: C:\path\to\destination
print:
  location: C:\Program Files\GMHost\reports.log
```

### Configuration Options

#### Global Settings

- **`workers`**: Number of files analyzed simultaneously (1-20, default: 4)
- **`extract`**: Extract and scan archive contents (default: false)
- **`maxFileSize`**: Maximum file size to analyze (default: "100MiB")
- **`paths`**: List of directories to monitor/scan

#### Actions

Configure what happens when malware is detected:
- **`delete`**: Delete malicious files after quarantine (default: true)
- **`quarantine`**: Copy malicious files to quarantine folder (default: true)
- **`moveLegit`**: Move legitimate files after analysis (default: false)
- **`print`**: Print scan results to console (default: true)
- **`log`**: Log scan results (default: true)

#### Monitoring

- **`preScan`**: Scan existing files when starting monitoring (default: true)
- **`reScan`**: Periodically re-scan all files (default: true)
- **`period`**: Time between full re-scans (default: 1h)
- **`modificationDelay`**: Wait time after file modification before scanning (default: 30s)

#### GLIMPS Malware Detect

- **`url`**: GLIMPS Malware Detect API endpoint
- **`token`**: Authentication token for GLIMPS Malware Detect
- **`timeout`**: Maximum time to wait for analysis (default: 5m)
- **`tags`**: Additional tags for submissions (default: ["GMHost"])
- **`insecure`**: Skip SSL certificate verification (default: false)
- **`syndetect`**: Use Syndetect API for analysis (default: false)

#### Quarantine

- **`location`**: Directory to store quarantined files
- **`password`**: Password for encrypting quarantined files (default: "infected")

#### Cache

- **`location`**: Cache database file location (empty for in-memory)
- **`scanValidity`**: How long scan results remain valid (default: 168h)

#### Move Action

- **`source`**: Root directory for files to be moved
- **`destination`**: Target directory for legitimate files

#### Print/Report

- **`location`**: File path for detailed reports (empty for stdout)

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

**Important notes:**

- The extractor does not remove malicious files from archives
- If any file in an archive is malicious, the entire archive is considered malicious
- Archive contents are extracted to temporary directories and cleaned up after analysis
- Files larger than `maxFileSize` within archives are skipped

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

- **When**: No malware is detected and file is in the source directory
- **Effect**: Moves legitimate files to the destination folder, preserving directory structure

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
- **`GDETECT_TOKEN`**: GLIMPS Malware Detect authentication token
- **`GDETECT_URL`**: GLIMPS Malware Detect API endpoint
- **`TMPDIR`**: Temporary directory for archive extraction (Unix)

## Logging

GMHost uses structured JSON logging. Log levels can be controlled with the `--debug` flag:

- **Default**: INFO level and above
- **`--debug`**: DEBUG level and above
- **`--quiet`**: ERROR level only

Example log entry:
```json
{"time":"2024-01-25T12:55:00Z","level":"INFO","msg":"info scanned","file":"/path/to/file","sha256":"abc123...","malware":true,"malwares":["trojan.win32.test"]}
```

## Performance Considerations

- **Workers**: Increase `workers` for faster scanning of many files, but be mindful of system resources
- **Cache**: Enable persistent cache to avoid re-scanning unchanged files
- **File size limits**: Adjust `maxFileSize` based on your needs and GLIMPS Malware Detect limits
- **Network timeouts**: Increase `timeout` for large files or slow connections

## Troubleshooting

### Common Issues

1. **"File too large" warnings**: Increase `maxFileSize` or enable `extract` for archives
2. **Permission denied**: Ensure GMHost has read access to target directories and write access to quarantine/cache locations
3. **Connection timeouts**: Check network connectivity to GLIMPS Malware Detect and increase `timeout`
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
