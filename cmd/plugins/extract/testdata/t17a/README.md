# T17a fixtures

Benign archives built with the embedded 7-Zip (`7zzs` 25.01) from short text
members (`a.txt`, `b.txt`, `p.txt`). The password of the encrypted ones is
`wrong-pw-1` (unknown to the plugin); `known_password.zip` uses `infected`.

| File | Content | SHA256 |
| --- | --- | --- |
| enc_zipcrypto.zip | a.txt, b.txt, ZipCrypto | `f4887d63505ccdf9118f50273908abd0c48bc8c576e085043d3b57eb93276846` |
| enc_aes.zip | a.txt, b.txt, AES-256 | `0652d25ecdaad8e03605c38bef8b2eb1bc2dd17fb52e944c84fbf9555f7fefb9` |
| enc_headers.7z | a.txt, b.txt, encrypted headers and content | `f23cf8dcc27e1e8b2e06897a30794afb04c9d9a895baab5b0f214b8dfa0b5554` |
| enc_content.7z | a.txt, b.txt, encrypted content, plain headers | `33139563a36547954fc086505e8aa1208a430551b7b090bba8eeaa8d62426e64` |
| mixed.zip | p.txt plain, a.txt ZipCrypto | `07284c9cdf4e2a83cfbd1af27e31b1a46455b52dec483f7bc2b12b6527e07fe2` |
| nested_in_plain.zip | p.txt and inner.zip (= enc_zipcrypto.zip), both plain entries | `cce8ae4759bf870a2b56aeb65154e38dc7e130bd284acb1663772744dc9c6b61` |
| known_password.zip | a.txt, ZipCrypto, password `infected` | `97f66a266262517864a7ec5568975f4ac46d09c8c7080cb799a6099fa2619d40` |
| aes_one_corrupt.zip | a.txt, AES-256, password `infected`, one byte of its data flipped | `4617efef7abbbf192d1a591ed4b87d53ac7c4f7ddfdc2123063607e7ec64b904` |
| aes_two_corrupt.zip | a.txt (one byte of its data flipped) and b.txt (intact), AES-256, password `infected` | `7c48d9f85bba2a02509e5889fa09c42a71834715395009bf4d4a75272d6d0415` |
| zc6.zip | m1.txt to m6.txt, ZipCrypto, password `wrong-pw-1` | `54bc878f53950ab2334c99d4515fe4056e978b19ebc4edc6ac2f85f19f139dd8` |
| forged_comment.zip | readable zip, ok.txt and odd.txt (method patched to 127), archive comment `hi\nEncrypted = +\nxx` | `f6e2048a2cff7acd0bdbbe0b49936528d62c6e33a64c9ee169cb8874aff54937` |

| seven_two_corrupt.7z | bad.txt (one byte of its data flipped) and good.txt (intact), 7z non-solid (`-ms=off`), content encrypted, password `infected` | `1f5d886c9cc33ba3da5819abc9b025e0ef97240e93fc6857a9983bb78eb515e1` |

| solid3_corrupt.7z | s1.txt, s2.txt, s3.txt, 7z solid, content encrypted, password `infected`, one byte flipped in the last quarter of the packed data (only s3.txt fails) | `e76c7dd214cb21e8333650a800e1fb74d7b43b26195c70ac4f1d6db36ffe8696` |
| mixed_many.zip | 250 plain members `p1.txt`..`p250.txt` and one ZipCrypto member `zz_secret.txt` (password `wrong-pw-1`): more than one batch of members | `fa09047b0b86a73a3fbe3a77f10033de8534cb8d83c59d80a3bc44acd994d2e2` |

| dup_corrupt.7z | two members both named `x.txt` (made with `7z rn` from `a/x.txt` and `b/x.txt`), 7z non-solid, content encrypted, password `infected`, one byte of the first one's data flipped | `f2d0f042a6b7bc5bd6c618ce0852cbfc35691a5eadc27292e5eec68c198926ed` |

| homonym_mixed.7z | two members named `a.txt` (renamed with `7z rn`): one plain, one encrypted with `wrong-pw-1`, 7z non-solid | `07467a495a97386c6712caf551be3dcce88194d0c120c9b5a3c44c082f60e767` |
| enc_with_empty.7z | six data members and one empty member, 7z non-solid, content encrypted, password `wrong-pw-1` (unknown to the plugin) | `431549bd216d01a4eb1c91ebe1bf40edc8aaab9e8f2c6865546f2494ae4788bd` |

The last ten were made with the same 7-Zip (`7zzs a -tzip -pinfected -mem=AES256`,
`-mem=ZipCrypto`), then patched with a script: a flipped byte in the encrypted
data of a member (after the salt and the password check value), and the method
field of a member set to 127 in its local and central headers.
