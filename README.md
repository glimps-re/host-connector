[![Build Status](https://github.com/glimps-re/host-connector/actions/workflows/go.yml/badge.svg)](https://github.com/glimps-re/host-connector/actions/workflows/go.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/glimps-re/host-connector)](https://goreportcard.com/report/github.com/glimps-re/host-connector)
[![GoDoc](https://pkg.go.dev/badge/github.com/glimps-re/host-connector?status.svg)](https://pkg.go.dev/github.com/glimps-re/host-connector?tab=doc)
[![Release](https://github.com/glimps-re/host-connector/actions/workflows/release.yml/badge.svg)](https://github.com/glimps-re/host-connector/actions/workflows/release.yml)

# GMalware Detect host connector 

A agent tool to scan selected folders on a Windows or GNU/Linux hosts.

## Usage


```bash
GMalware Host connector is a tool to scan files with GMalware Detect

Usage:
  GMHost [flags]
  GMHost [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  monitoring  start monitoring location with GMalware host
  quarantine  Handler GMalware host quarantined files
  scan        Scan folders

Flags:
      --cache string             location of the cache DB
      --config string            config file (default is /etc/gmhost/config) (default "/etc/gmhost/config")
      --debug                    print debug strings
      --gdetect-token string     GMalware Detect token
      --gdetect-url string       GMalware Detect url (E.g https://gmalware.ggp.glimps.re)
  -h, --help                     help for GMHost
      --insecure                 do not validate certificates
      --quarantine string        location of the quarantine folder
      --quiet                    print no information
      --scan-validity duration   Validity duration for each scan result (default 168h0m0s)
      --timeout duration         Time allowed to analyze each files (default 5m0s)
      --verbose                  print more information
      --workers uint             number of files analyzed at the same time (default 4)
```


## Configuration

The following default configuration could be used to monitor a `Documents` folder.
When starting `gmhost.exe monitoring`, the tool will start to monitor the folder `C:\\Users\\YourUser\\Documents`.
The files will be pre scanned to ensure that there is not already a malware. Every hour, all the file will be checked again to see if there is a need for a new GDetect scan.
A GDetect scan is valid for one week (168h). When malware are found, it will be moved to quarantine and locked.

```yaml
workers: 4
paths: [
    "C:\\Users\\YourUser\\Documents"
]
actions:
  delete: true
  quarantine: true
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
quarantine:
  location: "C:\\Program Files\\GMHost\\quarantine"
  password: infected
cache:
  location: "C:\\Program Files\\GMHost\\cache"
  scanValidity: 168h
```

## add GMHost to run at startup

```powershell
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "GMHist" /t REG_SZ /F /D "C:\Program Files\GMHost\gmhost.exe monitoring"
```

## restore a file from the quarantine

To restore a file, you need to start by listing the quarantined files. Then use the quarantine file ID to restore it.

```powershell
C:\\Program Files\\GMHost\\gmhost.exe quarantine list
|ID                                                              |Reason                   |File                |
|d86b21405852d8642ca41afae9dcf0f532e2d67973b0648b0af7c26933f1becb|malware: eicar           |eicar.txt           |

C:\\Program Files\\GMHost\\gmhost.exe quarantine restore d86b21405852d8642ca41afae9dcf0f532e2d67973b0648b0af7c26933f1becb
```

## Monitoring

```bash
start monitoring location with GMalware host

Usage:
  GMHost monitoring [flags]

Flags:
  -h, --help                   help for monitoring
      --mod-delay duration     Time waited between two modifications of a file before submitting it (default 30s)
      --pre-scan               start monitoring with a scan
      --scan-period duration   re-scan files every scan-period

Global Flags:
      --cache string             location of the cache DB
      --config string            config file (default is /etc/gmhost/config) (default "/etc/gmhost/config")
      --debug                    print debug strings
      --gdetect-token string     GMalware Detect token
      --gdetect-url string       GMalware Detect url (E.g https://gmalware.ggp.glimps.re)
      --insecure                 do not check certificates
      --quarantine string        location of the quarantine folder
      --quiet                    print no information
      --scan-validity duration   Validity duration for each scan result (default 168h0m0s)
      --timeout duration         Time allowed to analyze each files (default 5m0s)
      --verbose                  print more information
      --workers uint             number of files analyzed at the same time (default 4)
```

## Scan

```bash
Scan folders

Usage:
  GMHost scan [flags]

Flags:
  -h, --help   help for scan

Global Flags:
      --cache string             location of the cache DB
      --config string            config file (default is /etc/gmhost/config) (default "/etc/gmhost/config")
      --debug                    print debug strings
      --gdetect-token string     GMalware Detect token
      --gdetect-url string       GMalware Detect url (E.g https://gmalware.ggp.glimps.re)
      --insecure                 do not validate certificates
      --quarantine string        location of the quarantine folder
      --quiet                    print no information
      --scan-validity duration   Validity duration for each scan result (default 168h0m0s)
      --timeout duration         Time allowed to analyze each files (default 5m0s)
      --verbose                  print more information
      --workers uint             number of files analyzed at the same time (default 4)
```

## Quarantine

```bash
Handler GMalware host quarantined files

Usage:
  GMHost quarantine [flags]
  GMHost quarantine [command]

Available Commands:
  list        List GMalware host quarantined files
  restore     Restore quarantined files

Flags:
  -h, --help   help for quarantine

Global Flags:
      --cache string             location of the cache DB
      --config string            config file (default is /etc/gmhost/config) (default "/etc/gmhost/config")
      --debug                    print debug strings
      --gdetect-token string     GMalware Detect token
      --gdetect-url string       GMalware Detect url (E.g https://gmalware.ggp.glimps.re)
      --insecure                 do not validate certificates
      --quarantine string        location of the quarantine folder
      --quiet                    print no information
      --scan-validity duration   Validity duration for each scan result (default 168h0m0s)
      --timeout duration         Time allowed to analyze each files (default 5m0s)
      --verbose                  print more information
      --workers uint             number of files analyzed at the same time (default 4)
```
