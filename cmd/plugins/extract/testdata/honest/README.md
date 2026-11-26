# Honest zip samples

Small zips of one tree (a.txt, sub/b.txt, sub/deep/c.bin, an empty folder), written by
common tools; the extract plugin must not refuse any of them. Generated on 2026-11-21 and
kept only for the tests of the walk of the zip headers (`zipwalk_honest_test.go`).

| file | writer | sha256 |
| --- | --- | --- |
| 7-zip-deflate.zip | 7-Zip 25.01, Deflate | 98de90e8fb24a8d09c5f7df8aca1096b4e022d55780529ab2e43df6e9b9bb124 |
| 7-zip-store.zip | 7-Zip 25.01, Copy | 99e4bf0875069af48df3ecb341397f9324afa8b0a8aa1858d38bdd5d19b9eec9 |
| info-zip.zip | Info-ZIP zip 3.0 | b7cb9fc275fbb30dfb3b41fd9720c282c45147e9829f419d79daac7d90f7d90a |
| python.zip | Python 3 zipfile | fa4811c84730120705cc0c9b49e1ad6286c26ffcc8c1bea6aca7c5ae5f108a95 |
