# Licences

## Embedded fonts

The report plugin embeds these fonts in its binary
(`cmd/plugins/report/fonts/`, from htmltopdf v0.1.0 `testdata/fonts`). Their
licence texts are kept next to them; the fonts' name tables carry their
licence, as the SIL OFL allows, so no licence file is shipped with the binary.

| Font | Files | Licence | Licence text |
|---|---|---|---|
| Liberation Sans 2.x | `LiberationSans-Regular.ttf`, `-Bold`, `-Italic`, `-BoldItalic` | SIL Open Font License 1.1 | `cmd/plugins/report/fonts/LICENSE-Liberation.txt` |
| DejaVu Sans | `DejaVuSans.ttf`, `DejaVuSans-Bold.ttf` | Bitstream Vera Fonts licence; DejaVu changes in the public domain | `cmd/plugins/report/fonts/LICENSE-DejaVu.txt` |

## Go dependencies

Modules linked into the binaries and plugins, from `go-licenses report ./...`
for Linux and for Windows (`GOOS=windows`), merged (`go-licenses check ./...`
passes).

| Module | Version | Licence |
|---|---|---|
| `github.com/Unpackerr/iso9660` | v0.0.3 | BSD-2-Clause |
| `github.com/alecthomas/units` | v0.0.0-20240927000941-0f3dac36c52b | MIT |
| `github.com/andybalholm/brotli` | v1.2.7 | MIT |
| `github.com/bodgit/plumbing` | v1.3.0 | BSD-3-Clause |
| `github.com/bodgit/sevenzip` | v1.6.4 | BSD-3-Clause |
| `github.com/bodgit/windows` | v1.0.1 | BSD-3-Clause |
| `github.com/cavaliergopher/cpio` | v1.0.1 | BSD-3-Clause |
| `github.com/cavaliergopher/rpm` | v1.3.0 | BSD-3-Clause |
| `github.com/cenkalti/backoff/v5` | v5.0.3 | MIT |
| `github.com/coreos/go-semver` | v0.3.1 | Apache-2.0 |
| `github.com/dustin/go-humanize` | v1.0.1 | MIT |
| `github.com/fsnotify/fsnotify` | v1.10.1 | BSD-3-Clause |
| `github.com/gabriel-vasile/mimetype` | v1.4.13 | MIT |
| `github.com/glimps-re/connector-integration` | v0.9.2-0.20261123133504-e74871f47cc1 | MIT |
| `github.com/glimps-re/go-gdetect` | v1.6.6 | MIT |
| `github.com/glimps-re/htmltopdf` | v0.1.0 | MIT |
| `github.com/glimps-re/rfsnotify` | v0.2.0 | MIT |
| `github.com/go-playground/locales` | v0.14.1 | MIT |
| `github.com/go-playground/universal-translator` | v0.18.1 | MIT |
| `github.com/go-playground/validator/v10` | v10.30.3 | MIT |
| `github.com/go-text/typesetting` | v0.3.5 | BSD-3-Clause, MIT, Unlicense |
| `github.com/go-viper/mapstructure/v2` | v2.5.0 | MIT |
| `github.com/gonutz/w32/v2` | v2.12.1 | BSD-3-Clause, MIT |
| `github.com/gonutz/wui/v2` | v2.8.2 | MIT |
| `github.com/google/uuid` | v1.6.0 | BSD-3-Clause |
| `github.com/hashicorp/golang-lru/v2` | v2.0.7 | BSD-3-Clause, MPL-2.0 |
| `github.com/icza/bitio` | v1.1.0 | Apache-2.0 |
| `github.com/inconshreveable/mousetrap` | v1.1.0 | Apache-2.0 |
| `github.com/klauspost/compress` | v1.20.2 | Apache-2.0, BSD-3-Clause, MIT |
| `github.com/labstack/echo/v5` | v5.4.7 | MIT |
| `github.com/leodido/go-urn` | v1.4.0 | MIT |
| `github.com/mattn/go-isatty` | v0.0.22 | MIT |
| `github.com/mewkiz/flac` | v1.0.13 | Unlicense |
| `github.com/mewkiz/pkg` | v0.0.0-20260703220044-4fb89b18cc87 | Unlicense |
| `github.com/mewpkg/term` | v0.0.0-20241026122259-37a80af23985 | Unlicense |
| `github.com/ncruces/go-strftime` | v1.0.0 | MIT |
| `github.com/nwaples/rardecode/v2` | v2.2.5 | BSD-2-Clause |
| `github.com/pelletier/go-toml/v2` | v2.4.3 | MIT |
| `github.com/peterebden/ar` | v0.0.0-20241106141004-20dc11b778e8 | MIT |
| `github.com/pierrec/lz4/v4` | v4.1.27 | BSD-3-Clause |
| `github.com/remyoudompheng/bigfft` | v0.0.0-20230129092748-24d4a6f8daec | BSD-3-Clause |
| `github.com/sagikazarmark/locafero` | v0.12.0 | MIT |
| `github.com/saintfish/chardet` | v0.0.0-20230101081208-5e3ef4b5456d | MIT |
| `github.com/spf13/afero` | v1.15.0 | Apache-2.0 |
| `github.com/spf13/cast` | v1.10.0 | MIT |
| `github.com/spf13/cobra` | v1.10.2 | Apache-2.0 |
| `github.com/spf13/pflag` | v1.0.10 | BSD-3-Clause |
| `github.com/spf13/viper` | v1.21.0 | MIT |
| `github.com/sshaman1101/dcompress` | v0.0.0-20200109162717-50436a6332de | BSD-2-Clause |
| `github.com/stangelandcl/ppmd` | v0.1.1 | MIT |
| `github.com/subosito/gotenv` | v1.6.0 | MIT |
| `github.com/tdewolff/parse/v2` | v2.25.0 | MIT |
| `github.com/therootcompany/xz` | v1.0.1 | CC0-1.0 |
| `github.com/ulikunitz/xz` | v0.5.15 | BSD-3-Clause |
| `github.com/vimeo/go-magic` | v1.0.0 | BSD-2-Clause |
| `go.yaml.in/yaml/v3` | v3.0.5 | MIT |
| `go4.org` | v0.0.0-20260112195520-a5071408f32f | Apache-2.0 |
| `golang.org/x/crypto` | v0.59.0 | BSD-3-Clause |
| `golang.org/x/crypto/openpgp` | v0.1.0-deprecated | BSD-3-Clause |
| `golang.org/x/image` | v0.48.0 | BSD-3-Clause |
| `golang.org/x/net` | v0.63.0 | BSD-3-Clause |
| `golang.org/x/sys` | v0.50.0 | BSD-3-Clause |
| `golang.org/x/text` | v0.44.0 | BSD-3-Clause |
| `golift.io/udf` | v0.0.1 | BSD-3-Clause |
| `golift.io/xtractr` | v0.4.0 | MIT |
| `gopkg.in/yaml.v3` | v3.0.1 | MIT |
| `modernc.org/libc` | v1.73.5 | BSD-3-Clause |
| `modernc.org/mathutil` | v1.7.1 | BSD-3-Clause |
| `modernc.org/memory` | v1.11.0 | BSD-3-Clause |
| `modernc.org/sqlite` | v1.53.0 | BSD-3-Clause |

Test only (not linked into the binaries): `github.com/pdfcpu/pdfcpu` v0.16.4,
Apache-2.0 (text extraction of the report PDF in the tests of
`cmd/plugins/report`); `github.com/google/go-cmp` v0.7.0, BSD-3-Clause.
