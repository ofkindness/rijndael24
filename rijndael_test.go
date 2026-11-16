package rijndael

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"math/rand"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSboxKnownValues(t *testing.T) {
	cases := map[byte]byte{0x00: 0x63, 0x01: 0x7c, 0x53: 0xed, 0xff: 0x16}
	for in, want := range cases {
		if got := sbox[in]; got != want {
			t.Errorf("sbox[%#02x] = %#02x, want %#02x", in, got, want)
		}
		if got := invSbox[want]; got != in {
			t.Errorf("invSbox[%#02x] = %#02x, want %#02x", want, got, in)
		}
	}
}

// FIPS-197 Appendix C.2: AES-192 with a 128-bit block.
func TestFIPS197AES192(t *testing.T) {
	key := mustHex(t, "000102030405060708090a0b0c0d0e0f1011121314151617")
	pt := mustHex(t, "00112233445566778899aabbccddeeff")
	want := mustHex(t, "dda97ca4864cdfe06eaf70a0ec0d7191")

	c, err := NewCipher(key, Size128)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, Size128)
	c.Encrypt(got, pt)
	if !bytes.Equal(got, want) {
		t.Fatalf("encrypt = %x, want %x", got, want)
	}
	back := make([]byte, Size128)
	c.Decrypt(back, got)
	if !bytes.Equal(back, pt) {
		t.Fatalf("decrypt = %x, want %x", back, pt)
	}
}

// With a 16-byte block, Rijndael must match the standard library AES exactly.
func TestMatchesStdlibAES(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for _, keyLen := range []int{Size128, Size192, Size256} {
		for i := 0; i < 200; i++ {
			key := randBytes(rng, keyLen)
			pt := randBytes(rng, Size128)

			ref, err := aes.NewCipher(key)
			if err != nil {
				t.Fatal(err)
			}
			ours, err := NewCipher(key, Size128)
			if err != nil {
				t.Fatal(err)
			}

			want := make([]byte, Size128)
			got := make([]byte, Size128)
			ref.Encrypt(want, pt)
			ours.Encrypt(got, pt)
			if !bytes.Equal(got, want) {
				t.Fatalf("key %d: encrypt mismatch\n got %x\nwant %x", keyLen, got, want)
			}
			ref.Decrypt(want, want)
			ours.Decrypt(got, got)
			if !bytes.Equal(got, want) {
				t.Fatalf("key %d: decrypt mismatch", keyLen)
			}
		}
	}
}

// Round trips for every block and key size, including the 24/24 variant.
func TestRoundTripAllSizes(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	for _, bs := range []int{Size128, Size192, Size256} {
		for _, ks := range []int{Size128, Size192, Size256} {
			key := randBytes(rng, ks)
			c, err := NewCipher(key, bs)
			if err != nil {
				t.Fatalf("block %d key %d: %v", bs, ks, err)
			}
			if c.BlockSize() != bs {
				t.Fatalf("BlockSize() = %d, want %d", c.BlockSize(), bs)
			}
			for i := 0; i < 50; i++ {
				pt := randBytes(rng, bs)
				ct := make([]byte, bs)
				c.Encrypt(ct, pt)
				if bytes.Equal(ct, pt) {
					t.Errorf("block %d key %d: ciphertext equals plaintext", bs, ks)
				}
				back := make([]byte, bs)
				c.Decrypt(back, ct)
				if !bytes.Equal(back, pt) {
					t.Fatalf("block %d key %d: round trip failed", bs, ks)
				}
			}
		}
	}
}

// Server parameters, taken from the Perl code the server side uses:
// pack('C24', ...). The chain list in that code has 23 values; pack pads the
// 24th byte with 0, so the chain ends in 0, not 64.
var (
	serverKey = []byte{
		6, 169, 33, 64, 54, 184, 161, 91, 81, 46, 3, 213,
		52, 18, 0, 6, 61, 175, 186, 66, 157, 158, 180, 48,
	}
	serverChain = []byte{
		61, 175, 186, 66, 157, 158, 180, 48, 180, 34, 218, 128,
		44, 159, 172, 65, 1, 2, 4, 8, 16, 32, 128, 0,
	}
)

func TestFixedServerKeyBlock24(t *testing.T) {
	c, err := NewCipher(serverKey, Size192)
	if err != nil {
		t.Fatal(err)
	}
	pt := make([]byte, Size192)
	for i := range pt {
		pt[i] = byte(i)
	}
	ct := make([]byte, Size192)
	c.Encrypt(ct, pt)
	back := make([]byte, Size192)
	c.Decrypt(back, ct)
	if !bytes.Equal(back, pt) {
		t.Fatalf("round trip failed: %x", back)
	}
}

// CBC with the server key and chain as IV. Two identical plaintext blocks must
// produce different ciphertext blocks, which shows the chaining is active.
func TestServerCBC(t *testing.T) {
	if len(serverChain) != Size192 {
		t.Fatalf("chain has %d bytes, want %d", len(serverChain), Size192)
	}
	c, err := NewCipher(serverKey, Size192)
	if err != nil {
		t.Fatal(err)
	}
	block := make([]byte, Size192)
	for i := range block {
		block[i] = byte(i * 7)
	}
	pt := append(append([]byte{}, block...), block...)

	ct := make([]byte, len(pt))
	cipher.NewCBCEncrypter(c, serverChain).CryptBlocks(ct, pt)
	if bytes.Equal(ct[:Size192], ct[Size192:]) {
		t.Fatal("identical plaintext blocks gave identical ciphertext: chaining inactive")
	}
	back := make([]byte, len(ct))
	cipher.NewCBCDecrypter(c, serverChain).CryptBlocks(back, ct)
	if !bytes.Equal(back, pt) {
		t.Fatal("CBC round trip with server parameters failed")
	}
}

// Block cipher modes from crypto/cipher work with any block size.
func TestCBCBlock24(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	key := randBytes(rng, Size192)
	iv := randBytes(rng, Size192) // random test IV, not the server chain
	c, err := NewCipher(key, Size192)
	if err != nil {
		t.Fatal(err)
	}
	pt := randBytes(rng, 3*Size192)

	ct := make([]byte, len(pt))
	cipher.NewCBCEncrypter(c, iv).CryptBlocks(ct, pt)
	back := make([]byte, len(ct))
	cipher.NewCBCDecrypter(c, iv).CryptBlocks(back, ct)
	if !bytes.Equal(back, pt) {
		t.Fatal("CBC round trip failed")
	}
}

// Known-answer test for the 24-byte block and key variant: ECB encryption of
// pack('a24', "katon92") with the server key. The chain is unused in ECB mode.
func TestKnownAnswer24(t *testing.T) {
	plain := make([]byte, Size192) // pack('a24', ...) pads with NUL
	copy(plain, "katon92")
	want := mustHex(t, "0779633C7C7080C6B4F443E9130B06C8C66BC0BAB9700DAF")

	c, err := NewCipher(serverKey, Size192)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, Size192)
	c.Encrypt(got, plain)
	if !bytes.Equal(got, want) {
		t.Fatalf("ECB encrypt = %X, want %X", got, want)
	}

	back := make([]byte, Size192)
	c.Decrypt(back, got)
	if string(bytes.TrimRight(back, "\x00")) != "katon92" {
		t.Fatalf("decrypt = %q, want %q", back, "katon92")
	}
}

func TestInvalidSizes(t *testing.T) {
	if _, err := NewCipher(make([]byte, 20), Size128); err == nil {
		t.Error("expected KeySizeError for 20-byte key")
	}
	if _, err := NewCipher(make([]byte, Size192), 20); err == nil {
		t.Error("expected BlockSizeError for block size 20")
	}
}

func TestShortBlockPanics(t *testing.T) {
	c, err := NewCipher(make([]byte, Size192), Size192)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if recover() == nil {
			t.Error("expected panic for short input")
		}
	}()
	c.Encrypt(make([]byte, Size192), make([]byte, Size192-1))
}

func randBytes(rng *rand.Rand, n int) []byte {
	b := make([]byte, n)
	rng.Read(b)
	return b
}
