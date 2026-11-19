package zipcrypto

import "testing"

// Golden key-schedule vectors. These values were computed with this
// package's own implementation of the APPNOTE.TXT §6.1.2-6.1.5 algorithm
// and independently cross-checked by decrypting real archives produced by
// 7-Zip 25.01 (traditional ZipCrypto) with
// the password "infected" - see testdata/README.md for that provenance.
// This test pins the key schedule itself so any accidental change to the
// arithmetic is caught immediately, independent of the interop fixtures.
func TestNewKeys_GoldenVectors(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantKey0 uint32
		wantKey1 uint32
		wantKey2 uint32
	}{
		{
			name:     "empty password leaves the initial state untouched",
			password: "",
			wantKey0: initKey0,
			wantKey1: initKey1,
			wantKey2: initKey2,
		},
		{
			name:     "infected",
			password: "infected",
			wantKey0: 0x0917ed61,
			wantKey1: 0xcfc8f696,
			wantKey2: 0x5d3e9072,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := newKeys([]byte(tt.password))
			if k.key0 != tt.wantKey0 || k.key1 != tt.wantKey1 || k.key2 != tt.wantKey2 {
				t.Errorf("newKeys(%q) = {%#08x %#08x %#08x}, want {%#08x %#08x %#08x}",
					tt.password, k.key0, k.key1, k.key2, tt.wantKey0, tt.wantKey1, tt.wantKey2)
			}
		})
	}
}

func TestKeys_StreamByte_AfterInfected(t *testing.T) {
	k := newKeys([]byte("infected"))
	if got := k.streamByte(); got != 0x03 {
		t.Errorf("streamByte() after \"infected\" = 0x%02x, want 0x03", got)
	}
}

func TestKeys_EncryptDecryptByte_RoundTrip(t *testing.T) {
	const password = "a site-specific password"
	plaintext := []byte("some bytes to round-trip through the byte-at-a-time cipher, > 32 bytes long")

	enc := newKeys([]byte(password))
	ciphertext := make([]byte, len(plaintext))
	for i, p := range plaintext {
		ciphertext[i] = enc.encryptByte(p)
	}

	dec := newKeys([]byte(password))
	got := make([]byte, len(ciphertext))
	for i, c := range ciphertext {
		got[i] = dec.decryptByte(c)
	}

	if string(got) != string(plaintext) {
		t.Errorf("round trip = %q, want %q", got, plaintext)
	}
}

func TestKeys_WrongPassword_ProducesDifferentStream(t *testing.T) {
	const plaintext = "identifiable plaintext byte sequence"
	enc := newKeys([]byte("right-password"))
	ciphertext := make([]byte, len(plaintext))
	for i := range plaintext {
		ciphertext[i] = enc.encryptByte(plaintext[i])
	}

	dec := newKeys([]byte("wrong-password"))
	got := make([]byte, len(ciphertext))
	for i, c := range ciphertext {
		got[i] = dec.decryptByte(c)
	}

	if string(got) == plaintext {
		t.Errorf("decrypting with the wrong password unexpectedly recovered the plaintext")
	}
}
