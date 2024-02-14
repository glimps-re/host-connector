[![Build Status](https://github.com/glimps-re/host-connector/actions/workflows/go.yml/badge.svg)](https://github.com/glimps-re/host-connector/actions/workflows/go.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/glimps-re/host-connector)](https://goreportcard.com/report/github.com/glimps-re/host-connector)
[![GoDoc](https://pkg.go.dev/badge/github.com/glimps-re/host-connector?status.svg)](https://pkg.go.dev/github.com/glimps-re/host-connector?tab=doc)
[![Release](https://github.com/glimps-re/host-connector/actions/workflows/release.yml/badge.svg)](https://github.com/glimps-re/host-connector/actions/workflows/release.yml)

# GMalware Detect host connector 

A agent tool to scan selected folders on a Windows or GNU/Linux hosts.

## Usage


```
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
      --cache string           location of the cache DB
      --config string          config file (default is /etc/gmhost/config) (default "/etc/gmhost/config")
      --debug                  print debug strings
      --gdetect-token string   GMalware Detect token
      --gdetect-url string     GMalware Detect url (E.g https://gmalware.ggp.glimps.re)
  -h, --help                   help for GMHost
      --insecure               do not validate certificates
      --mod-delay duration     Time waited between two modifications of a file before submitting it (default 30s)
      --quarantine string      location of the quarantine folder
      --quiet                  print no information
      --scan-validity duration   Validity duration for each scan result (default 168h0m0s)
      --timeout duration       Time (in seconds) allowed to analyze each files (default 5m0s)
      --verbose                print more information
      --workers uint           number of files analyzed at the same time (default 4)
```


## Configuration

```yaml
config: "C:\\Program Files\\gmhost\\config.yml"
workers: 4
debug: false
verbose: false
quiet: false
paths: [
    "C:\\Users\\YourUser\\Documents"
]
actions:
    delete: true
    quarantine: true
    print: true
    log: true
gdetect:
    url: "https://gmalware.ggp.glimps.re"
    token: "00000000-00000000-00000000-00000000-00000000"
    timeout: 5m0s
    tags: ["MyServer1"]
    insecure: false
quarantine:
    location: "C:\\Users\\YourUser\\AppData\\gmhost\\quarantine"
    password: infected
cache:
    location: "C:\\Users\\YourUser\\AppData\\gmhost\\cache"
    scan_validity: 168h15m # for each file, the scan result will be valid for 1 week and 15 minutes
monitoring:
    pre_scan: true
    re_scan: true
    period: 1h
    modification_delay: 30s
```
