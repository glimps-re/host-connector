#!/usr/bin/env sh

mkdir /tmp/samples
mkdir -p /tmp/samples/user_a
mkdir -p /tmp/samples/user_b
mkdir -p /tmp/samples/user_c
mkdir -p /tmp/samples/user_d


cat <<EOF > /tmp/config.yml
workers: 4
paths: []
# extract: false
# maxFileSize: 100MiB
actions:
  delete: true
  quarantine: true
  moveLegit: false
monitoring:
  preScan: true
  reScan: true
  period: 1h
  modificationDelay: 2s
quarantine:
  location: "/tmp/hc_quarantine"
  password: infected
gdetect:
  url: http://127.0.0.1:8081
  token: "ffffffff-ffffffff-ffffffff-ffffffff-ffffffff"
  timeout: 5m
  tags: ["devHC"]
  insecure: true
plugins:
  location: ./bin
  plugins:
    session: ""
    filetype: "/tmp/filetype.yml"
EOF


cat <<EOF > /tmp/filetype.yml
forbidden_types:
  - application/x-pie-executable
skipped_types:
  - text/html
EOF