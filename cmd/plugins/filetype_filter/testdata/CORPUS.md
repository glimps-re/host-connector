# Corpus of the filetype_filter typing test

`TestTypeOf_agreesWithLibmagicOnTheLargeCorpus` types the files of the directory
named by `HC_FILETYPE_CORPUS` and requires, for each, exactly the type libmagic gives
the file by its name. The test is skipped when the variable is not set. The files are
never committed: they are samples of the GLIMPS malware set (typed, never run), one
binary of the host and one zip made for the test. The directory is flat and holds
hard links or copies (not symbolic links, which a test reading it through an
`os.Root` would refuse) named `<sha256>.<extension>`; the SHA256 of each file is its
name, and the first column of every row.

Each file is over 1 MiB. The type is what `file --mime-type` says of it at the time of
writing (libmagic 5.46).

- `.pie`: a large PIE ELF, a binary of the host (`/usr/bin/btop` of the test machine,
  not a sample): any PIE executable over 1 MiB serves, and the test takes the
  type from libmagic whatever the file.
- `.zip`: a plain zip of one stored member, 20 MiB of `Z`, made with Python's
  `zipfile` (member `pad.bin`, date 2020-01-01, stored), so that the SHA256 below
  can be reproduced.
- `081ff426ca94...xlsm`: an encrypted OLE container (typed `application/encrypted`,
  although named `.xlsm`).

| SHA256 | Kind | Size | Type |
| --- | --- | --- | --- |
| `e2dc1f6e45a7be302736e1b42bb97e6a7877f82e081389b7a8195ea22cf6a10c` | .7z | 1210810 | application/x-7z-compressed |
| `347f2f48608eb60cd92a5b438348bd05508dce9320d107e4463b12f2de3813e6` | .7z | 2111207 | application/x-7z-compressed |
| `e7c8182dff40915a386e2c46409790d5117c1a6d374ae2e990513cae79b94fd0` | .7z | 21452947 | application/x-7z-compressed |
| `ffe9c0bf811722bdd32efec9c15620e6c2c430f188b694186135c9ac3b88ae15` | .apk | 1193511 | application/vnd.android.package-archive |
| `01322e2b318f657a30d39dcb04788094b98c92b4da1bdf2f9dc02c09c38ae418` | .apk | 2097947 | application/vnd.android.package-archive |
| `3a91e5ace8cbd8a29968bd400c63f893d4300422a17db9d0df2162f49d1c0388` | .apk | 3575593 | application/vnd.android.package-archive |
| `63f2a545be1cc0cba6fb103f5429c5b9a7470e2939c57fc04810811e01f77ccf` | .apk | 4039069 | application/vnd.android.package-archive |
| `49f8eb9779b3096ca81339c7a6d3cad6a8fc20b3d91ffe103c19935d330ad0aa` | .apk | 5096121 | application/vnd.android.package-archive |
| `4b38232db89ffc202f41fee493a84b056f1115339439efb6635d170e05bfa85b` | .apk | 21506549 | application/vnd.android.package-archive |
| `75f804d346dc48de24e447e262da09b75bb20405095bcee2ab2a775800158ef9` | .apk | 73015720 | application/vnd.android.package-archive |
| `9fff83aa30ea383794ceb84e5fd1a7b7594f1ea1a34fe8ae114505d5e3d9d362` | .apk | 88251568 | application/zip |
| `acbfbf6fd00fa347a52657e5ca0f5cc6cbcf197a04e2d3fd5dc9235926b319d7` | .doc | 1321364 | application/vnd.openxmlformats-officedocument.wordprocessingml.document |
| `57ead422e5ab5d7dbd1a19705f872c19f5e2d0abf661cc25967db02ad360fbdf` | .doc | 1356451 | text/rtf |
| `2027a5acbfea586f2d814fb57a97dcfce6c9d85c2a18a0df40811006d74aa7e3` | .doc | 1895387 | application/vnd.openxmlformats-officedocument.wordprocessingml.document |
| `ef8e1d204adea8fd3da4e4fec573c880c3e36fc40541907cd235c9bce495df97` | .doc | 2315776 | application/msword |
| `c990512977dae3208f5702df31f9fd0f5696937b5160548dd3baeec5b9099128` | .doc | 2540032 | application/msword |
| `d01785f45dfb5d91a72f530a4c624873246bfbad2b32083ec74bd62239a62ad2` | .docx | 1048590 | application/vnd.openxmlformats-officedocument.wordprocessingml.document |
| `dab55e9391ffa75901cf2a9ffe730b06630bc1022fc3e1daeda18dee5e472954` | .docx | 1506199 | application/vnd.openxmlformats-officedocument.wordprocessingml.document |
| `7305db7f80aeecb435a3de6a97266a8095908e393dc18bc927176f80dfa531c9` | .docx | 2246857 | application/vnd.openxmlformats-officedocument.wordprocessingml.document |
| `a8450af7106c473b5fcd3c16ee1c84553722ab9ec17c2cf6e629b77434bdb575` | .docx | 4152397 | application/vnd.openxmlformats-officedocument.wordprocessingml.document |
| `bf4303728a9e0a2d41032ec10aa0c21a30832e75e1288ffaa6da3949330e6e02` | .docx | 14703775 | application/vnd.openxmlformats-officedocument.wordprocessingml.document |
| `7257be99e7716f8cc3a26f3080eec72da7df4c2f34262b3c2cc50ea988e38535` | .elf | 1062008 | application/x-executable |
| `a40f89f498d651c969f038327cfac9eac4254eed47ff819e3e5d954c896856be` | .elf | 2063952 | application/x-executable |
| `6216b91cff422832c64010b4806b34e33d3931f82db46f81ab41d883208971aa` | .elf | 2097152 | application/x-executable |
| `0fa944876dec7956b856c8ebb5fb2d66b46ff35deaf3b90d0bc35f07fac39365` | .elf | 3233799 | application/x-executable |
| `0cc4c801fb17499105b557a7d2c972170e7f6e1c0ca62855a5e12573ecc3c97c` | .elf | 3420428 | application/x-executable |
| `1a1a8f9ccb66f37f14b5cf2a77e9e8d47400bdec957d9f20729e5c81bfc78be6` | .elf | 3426913 | application/x-executable |
| `0ec9bff7f605ffa83146dbcb486a702edff92240fbab092a5040e871bd43aa00` | .elf | 5046272 | application/x-executable |
| `0a4cdc59ddec746d90858c1538d20838fdbc80c11ceb39cd5737313cf9d94263` | .exe | 1075200 | application/vnd.microsoft.portable-executable |
| `ff929610da21ce2107e91d87767e50dbbfd938d39e7e6ff0d4cc892e2cb78c2a` | .exe | 2342400 | application/vnd.microsoft.portable-executable |
| `ff485295aa61623a812644de7e6fead2c1b36c33fde939e042a783dffdefd7e0` | .exe | 2649880 | application/vnd.microsoft.portable-executable |
| `ff12d7fb90aa1213fe211e6356d78486c8108f258f754cc2f64fcc75b671e517` | .exe | 6564672 | application/vnd.microsoft.portable-executable |
| `0a9c90b8c46c6d38d48f838df56530f0b3558e5415212abc0278c08b882c301e` | .exe | 26841208 | application/vnd.microsoft.portable-executable |
| `636ce7d964c99674456ab10169be1a75bc7e05583f2272cfd03eb650b003a83d` | .gz | 1362563 | application/gzip |
| `d4a1576213580954e906144a0434fc9df19ce746a726504e70597c58ce9a4fd5` | .gz | 1856961 | application/vnd.rar |
| `905a76633c4445dffb5f1c68bac3be4df767c7f3774c833a83e21d15ff752d19` | .iso | 1441792 | application/x-iso9660-image |
| `69c3a92757f79a0020cf1711cda4a724633d535f75bbef2bd74e07a902831d59` | .iso | 20807680 | application/x-iso9660-image |
| `9bcda9f3c4d2080696f278d4a7cd828c652136925747983a5314ba0a2d991e77` | .jar | 1257046 | application/zip |
| `8d72ca85103f44742d04ebca02bff65788fe6b9fc6f5a411c707580d42bbd249` | .jar | 1844296 | application/java-archive |
| `a3d5647315ef95ce7048f07f2145fff4d42a0d0612a7c9930501f250d79c33d9` | .jar | 1844843 | application/java-archive |
| `f096109b5e23f6a1e0c3388d14faf00b1c4be8af5498b11548c8731b96259129` | .jar | 3963842 | application/zip |
| `fe6efc7a63547fc58e1570fee3db65a89e520d732d8a5f54825840936f0ea9f7` | .macho | 9114562 | application/x-mach-binary |
| `42480e52a19bb59d3c462eb08ae26ed2b26f822d47300518f2ffc84b923f7a9e` | .macho | 9249328 | application/x-mach-binary |
| `ee1e5b80a1d3d47c7703ea2b6b64ee96283ab3628ee4fa1fef6d35d1d9051e9f` | .msi | 1487360 | application/x-msi |
| `e054153819d00712c4e34319b4021fe64ccf85c1f472816f4ca2251175e74b5b` | .msi | 1723904 | application/x-msi |
| `35cee7837f460d9e1141e375af8438e868a9e6b8d923ed2673a980fcadfd4774` | .msi | 2495488 | application/x-msi |
| `c6053a9c03ee039402c79b902502fc2617a49de16f5d7c6aea02bbf7a348a3a7` | .msi | 5295104 | application/x-msi |
| `7f56b16279282e68e1abab6cd78b2fef114788fcaa3e532fe1657ba7c8672071` | .msi | 8831057 | application/x-msi |
| `e873dc08f4bdd72c4234d15eafdd325eb33c958be11fb7ad1cd5c5539cb41341` | .msi | 14988288 | application/x-msi |
| `b7278c3c38801c0873759df432bcdf89d3709a7e638a4a150c3f4af179c3372b` | .msi | 21712896 | application/x-msi |
| `2582fb38178916551e4249238c4b8ca8f858c344b9b482a5cd4845508b5e8ce1` | .msi | 54256128 | application/x-msi |
| `911badce569720cd942e3d79332b030b91791f30922c37ab7a4a4c8499050b37` | .pdf | 1049523 | application/pdf |
| `b33bb779496413faeaa55410e7525e8998d5b234f4385e6b3b37406df3e13670` | .pdf | 2287361 | application/pdf |
| `0407f26cbb9adfac889dfae35a13c2131d633eec0c6cf612caca65e1da576f34` | .pdf | 62295014 | application/pdf |
| `044205173eb925c4b13b6e3e062b6cb7737766a4b52d3a3af06232238ae87d89` | .pie | 1510496 | application/x-pie-executable |
| `6ae84efbcd2eef07ab8602e4e61ca47e4b50a7085c7f1e5645f0b8f9ff1a1576` | .rar | 1105296 | application/vnd.rar |
| `1d60712286972a48b34428d6d8c318baa0e5db59908a1d84bd88de4fe92689e5` | .rar | 11084354 | application/vnd.rar |
| `083d20b9e152dcb99035de3573c3ec8efb79ee37e7689e0a17728bcf72312a88` | .rar | 86223578 | application/vnd.rar |
| `941de590c85079b747854a6530398522e1acf019fc15be2e7a15e5c1c60a9e9b` | .tar | 1325251 | application/vnd.rar |
| `a1383e7c1792265d27f29314f059c9d7e04ca8621177f9e6263d7c5b7238b292` | .tar | 2319226 | application/vnd.rar |
| `2d480c7b696975ed15cabc3709953ff3368ac88cdfcf66abd1841b1e8adbdceb` | .xls | 1096192 | application/vnd.ms-excel |
| `f121e8ed0136b54dba3c4cf2dc2a92d82c189d72ae1da1ef8de80014d9bb9676` | .xls | 1425408 | application/vnd.ms-excel |
| `a3456c4ba41324f91608a8413501f399d6aad6cc6613f8c952526ff30f515709` | .xls | 2046976 | application/vnd.ms-excel |
| `e464e896835e7ed86351c7b9a221852c46393226523f2ed15a6e30567b70a727` | .xls | 2745344 | application/vnd.ms-excel |
| `8cdd84285c936da43cf7c4506b6372a4806b0a90d3db29a72eaa7626dc83896b` | .xls | 9897472 | application/vnd.ms-excel |
| `be1267a2b58e923a5e6cffeb6e5a21bf983d581cad19265968b660efae23941a` | .xlsm | 2875443 | application/vnd.openxmlformats-officedocument.spreadsheetml.sheet |
| `8b01aa62a3b8ee347dfd39eaed1a8828280569105b703dd3f5b1f133bbea954b` | .xlsm | 3441813 | application/zip |
| `081ff426ca94307aee5afaf02e76e908b8d63cb58c7c8b9df41ac66114612c29` | .xlsm | 6481920 | application/encrypted |
| `7dbe5f108b59263c9036f16b472ba3c224e12b8fa49343fec15ac4a4066f0622` | .xlsx | 1255282 | application/vnd.openxmlformats-officedocument.spreadsheetml.sheet |
| `6b85cb31821da1c8ed89ef1e6ffe109fde5dbc17d831d5a09b2f780d8e0574c7` | .xlsx | 1457885 | application/vnd.openxmlformats-officedocument.spreadsheetml.sheet |
| `716f031d6df4bc08cc13347decbefa0fcab4c5fa52a3cb27678af2c372b8b403` | .xlsx | 1805028 | application/vnd.openxmlformats-officedocument.spreadsheetml.sheet |
| `f8f1e4cba7ff359de7b01dbe1205bac6d886fb1de9190d4f2f614a76b618a9a1` | .xlsx | 2585445 | application/vnd.openxmlformats-officedocument.spreadsheetml.sheet |
| `d55d4db477fcb2dabf0e6b2b7d665e960a1da95da20ce0863f13a13604db24f8` | .zip | 20971632 | application/zip |

The benchmarks (`BenchmarkTypeOf_*`, with `HC_FILETYPE_BENCH=1`) build their own files:
a real zip of 1 GiB, the 7 MiB worst-case contents, and a PIE (`/usr/bin/ls`) and an
MSI (the largest `.msi` above) **padded with zeros** to 100 MiB and 200 MiB: they
measure the cost of typing a file of that size, not of a genuine 200 MiB MSI.
