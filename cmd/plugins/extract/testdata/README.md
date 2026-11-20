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
