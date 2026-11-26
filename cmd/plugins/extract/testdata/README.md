# Test archives

Small benign 7z archives built with the embedded 7-Zip (`7zzs`, 25.01) to
exercise the real extractor on tricky member names. They contain only short
text members.

| File | Content | SHA256 |
| --- | --- | --- |
| wildcard.7z | members named `*`, `?` and `normal.txt` | 8595cf847fc33d18b09735d5a6a8c5a2e74cbba09e61fddae90a14c73ccbf88a |
| lf.7z | `a<LF>b.txt` and `plain.txt` | 25516accbc03bfe9c14c5fa064326c4f1a81316e537eeb414dce429429fa5bf5 |
| cr.7z | `c<CR>d.txt` and `plain.txt` | d667781ac7f9b81d6c56a6a7ebe8bbd832cbbce0ae813e4c15b93621a9ad17d4 |
| esc.7z | `e<ESC>[31mf.txt` and `plain.txt` | 4d904cbc47269d9eee399627c730641ad18875bb6c9a55fe07f8ca026ccff713 |
| twin.7z | `evil<LF>.exe` and `evil_.exe`, which 7-Zip shows with the same name | 3b1c7e8645abecb578d9561cddda3d273025e56da638b3732841457838d61e37 |
| trailing.7z | wildcard.7z followed by 22 bytes of garbage | 8357204c5fc2a1c420e9d534cdb59152a63810672dd0bdd553902022995134fe |

## reference.7z (embedded in the plugin)

Unlike the files above, `reference.7z` is embedded in the extract plugin
(`binary.go`) and extracted by the real 7-Zip at every start: it is the proof of
the 7-Zip version. It must stay a benign archive of three tiny members followed
by trailing bytes.

| Property | Value |
| --- | --- |
| Members | `a.txt` ("A"), `evil_.exe` ("E"), and a member named `evil<LF>.exe` ("HIDDEN") that 7-Zip 25.01 lists as `evil_.exe` too |
| Trailing data | 28 bytes (`TAIL-BYTES-AFTER-THE-ARCHIVE`) appended after the 7z container |
| Built with | 7-Zip (z) 25.01, `-mx0` (stored) |
| Expected | 3 members of 8 bytes in total, a `Tail Size = 28`, 2 files extracted out of 3 announced |
| SHA256 | d32b3e9ef58f734c883455717ed5d8420a70452a4d78f799290eb9a13d4b0c9f |

To rebuild it:

```sh
mkdir src && cd src
printf A > a.txt; printf E > evil_.exe; printf HIDDEN > $'evil\n.exe'
7zzs a -mx0 ../reference.7z a.txt evil_.exe $'evil\n.exe'
cd .. && printf 'TAIL-BYTES-AFTER-THE-ARCHIVE' >> reference.7z
sha256sum reference.7z
```

## sample.bz2

A bzip2 of 70 bytes (`sample.txt`: "honest data " repeated 500 times), written by 7-Zip 25.01
with `7zzs a -tbzip2 sample.bz2 sample.txt`. Its listing gives no size and no packed size: it
is not a bomb. sha256 `4842129ee828247b99ba7c1920fae13441a016b72053acfa868c96aed5a836fb`.
