# Changelog

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
