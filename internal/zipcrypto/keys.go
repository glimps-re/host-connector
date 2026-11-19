// Package zipcrypto implements traditional PKWARE encryption, commonly
// called "ZipCrypto" (APPNOTE.TXT §6.1, PKWARE ZIP File Format
// Specification, version 6.3.x). It is a domain-free codec: this package
// knows nothing about the ZIP container format, quarantine files, or any
// other caller concept - it only turns a password and a byte stream into
// ciphertext, and back.
//
// ZipCrypto is cryptographically weak by modern standards: it
// has a small effective keyspace against known-plaintext attacks and no
// message authentication code, only a CRC-32. It is implemented here
// because it is the only encryption scheme built into Windows Explorer's
// native ZIP extraction, which is a hard interoperability requirement for
// callers of this package. Callers must not treat it as a confidentiality
// control.
package zipcrypto

import "hash/crc32"

// keys holds the mutable internal state of the ZipCrypto stream cipher: a
// 96-bit value split into three 32-bit words, updated one plaintext byte at
// a time. The algorithm is fully specified by APPNOTE.TXT §6.1.2-6.1.5.
type keys struct {
	key0, key1, key2 uint32
}

// ZipCrypto's fixed initial key state (APPNOTE.TXT §6.1.3).
const (
	initKey0 = 305419896
	initKey1 = 591751049
	initKey2 = 878082192
)

// newKeys derives the initial cipher state from password by feeding every
// byte of it through update, per APPNOTE.TXT §6.1.3.
func newKeys(password []byte) *keys {
	k := &keys{key0: initKey0, key1: initKey1, key2: initKey2}
	for _, c := range password {
		k.update(c)
	}
	return k
}

// crc32Update advances a CRC-32 (IEEE polynomial) accumulator by one byte,
// using the same byte-at-a-time table lookup form ZipCrypto's key schedule
// requires: crc = IEEETable[byte(crc)^b] ^ (crc>>8). hash/crc32's IEEETable
// is the standard CRC-32 (IEEE 802.3) table, which is what APPNOTE.TXT's
// CRC32(crc, b) function in §6.1.2 refers to.
func crc32Update(crc uint32, b byte) uint32 {
	// crc&0xff (rather than a plain narrowing conversion) makes the
	// intentional truncation to the table index explicit: this is the
	// algorithm as specified (APPNOTE.TXT §6.1.2), not an overflow bug.
	return crc32.IEEETable[byte(crc&0xff)^b] ^ (crc >> 8)
}

// update advances all three key words by one plaintext byte c
// (APPNOTE.TXT §6.1.4). It must be called with the plaintext byte, whether
// encrypting or decrypting: the cipher is self-synchronising only on the
// plaintext stream, not the ciphertext.
func (k *keys) update(c byte) {
	k.key0 = crc32Update(k.key0, c)
	k.key1 = (k.key1+(k.key0&0xff))*134775813 + 1
	k.key2 = crc32Update(k.key2, byte((k.key1>>24)&0xff))
}

// streamByte returns the next keystream byte (APPNOTE.TXT §6.1.5),
// without consuming any plaintext or advancing the key state: the caller
// must separately call update with the corresponding plaintext byte.
func (k *keys) streamByte() byte {
	t := k.key2 | 2
	return byte(((t * (t ^ 1)) >> 8) & 0xff)
}

// encryptByte encrypts one plaintext byte and advances the key state.
func (k *keys) encryptByte(p byte) byte {
	s := k.streamByte()
	k.update(p)
	return p ^ s
}

// decryptByte decrypts one ciphertext byte and advances the key state.
func (k *keys) decryptByte(c byte) byte {
	p := c ^ k.streamByte()
	k.update(p)
	return p
}
