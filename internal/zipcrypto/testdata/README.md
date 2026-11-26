# testdata provenance

Golden interoperability fixtures for `internal/zipcrypto`'s reader, proving
this package's traditional PKWARE encryption ("ZipCrypto") implementation
decrypts real archives produced by an independent, widely-deployed tool
rather than only round-tripping against itself.

The file contains a single entry, `payload.txt`, with the plaintext:

```
Hello ZipCrypto interop test payload, this is a bit longer than one block.
```

(75 bytes including the trailing newline; synthetic test content, not
malware.) Password: `infected`.

Generated with:

```sh
7z a -tzip -mem=ZipCrypto -mx=0 -pinfected sevenzip_zipcrypto_store.zip  payload.txt
```

Tool version: `7-Zip 25.01 (x64)`.

| File | Method (raw, as read via `archive/zip`) | Flags | Purpose |
|------|------------------------------------------|-------|---------|
| `sevenzip_zipcrypto_store.zip` | 0 (Store) | `0x1` (encrypted, no data descriptor) | Reader accepts ZipCrypto+Store; check byte from CRC-32 high byte (non-data-descriptor path). |

Verified during generation by decrypting each fixture with a standalone
implementation of the same algorithm and confirming both the check byte and
the full plaintext CRC-32 match what 7-Zip itself reports (`7z l -slt`).

SHA-256 of the committed files:

```
fb4fba6e5eb62837518ef8d8d8bd02ff6af8210b214fb42cd721f683d4511590  sevenzip_zipcrypto_store.zip
```
