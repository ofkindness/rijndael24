# rijndael24

A Go implementation of the [Rijndael](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) block cipher with independently selectable block and key sizes. Each size can be 16, 24 or 32 bytes (128, 192 or 256 bits).

The project is a self-learning exercise. It was written to reproduce the 24-byte block and 24-byte key variant used by a game-server login protocol, and it works for every other size combination too.

## Status

| Block size | Key size | Verified by |
|---|---|---|
| 16 bytes (AES) | 16, 24, 32 bytes | FIPS-197 AES-192 vector; randomized comparison with `crypto/aes` |
| 24 bytes | 24 bytes | Known-answer vector from the server protocol (ECB) |
| 24 bytes | 16, 32 bytes | Round trips only |
| 32 bytes | any | Round trips only |

## Usage

```go
import "github.com/ofkindness/rijndael24"

key := make([]byte, rijndael.Size192)  // 24-byte key
block, err := rijndael.NewCipher(key, rijndael.Size192)  // 24-byte block
if err != nil {
	// key or block size is not 16, 24 or 32 bytes
}

plain := make([]byte, rijndael.Size192)
copy(plain, "katon92")  // pad with NUL, like Perl's pack('a24', ...)

ciphertext := make([]byte, rijndael.Size192)
block.Encrypt(ciphertext, plain)

decrypted := make([]byte, rijndael.Size192)
block.Decrypt(decrypted, ciphertext)
```

`NewCipher` returns a standard `cipher.Block`. Modes from `crypto/cipher` (CBC, CTR, and so on) work with it. The 24-byte block is used in ECB mode in the server protocol this was written for, so the chain value is not needed for that case.

## Tests

```sh
go test ./...
```

The tests cover:

- S-box known values,
- the FIPS-197 AES-192 vector,
- comparison with `crypto/aes` for 16-byte blocks,
- round trips for all block and key size combinations,
- the 24-byte block known-answer vector (`TestKnownAnswer24`),
- CBC with the server chain as IV,
- invalid-size errors and short-input panics.

## Notes and limitations

- The S-box and round functions use table lookups and are **not constant-time**. Do not use this package where timing side channels matter.
- This is a learning project. It has not been audited.
- The server key and chain appear only as test values in `rijndael_test.go`, copied from the server's Perl code. They are fixed protocol parameters, not secrets for this project.

## References

- [FIPS-197, Advanced Encryption Standard](https://csrc.nist.gov/pubs/fips/197/final): AES-192 test vector.
