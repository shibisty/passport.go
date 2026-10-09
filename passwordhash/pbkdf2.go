// Package passwordhash hashes and verifies passwords, with no external dependencies.
//
// PBKDF2 (RFC 8018) with HMAC-SHA256, using parameters recommended by the OWASP
// Password Storage Cheat Sheet: 600,000 iterations, 16-byte salt. The hash is stored
// as a single string together with its parameters, so old hashes keep
// verifying after the iteration count is raised; NeedsRehash tells you which
// ones to recompute on the user's next login.
//
//	hash, err := passwordhash.Hash(password)          // store in users.password_hash
//	ok, err := passwordhash.Verify(password, hash)
//	if ok && passwordhash.NeedsRehash(hash) { ... }   // recompute and store
package passwordhash

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	algo = "pbkdf2-sha256"
	// DefaultIterations is the OWASP recommendation for PBKDF2-HMAC-SHA256.
	DefaultIterations = 600_000
	saltLen           = 16
	keyLen            = 32
	maxIterations     = 10_000_000 // guards against a corrupted hash that would "hang" verification
)

// ErrInvalidHash means the string does not look like a hash produced by this package.
var ErrInvalidHash = errors.New("passwordhash: unknown or corrupted hash format")

// Hash returns the string "pbkdf2-sha256$600000$<salt>$<hash>" (unpadded base64).
func Hash(password string) (string, error) {
	return hashWith(password, DefaultIterations)
}

func hashWith(password string, iterations int) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("passwordhash: failed to generate salt: %w", err)
	}
	key := pbkdf2HMACSHA256([]byte(password), salt, iterations, keyLen)
	return fmt.Sprintf("%s$%d$%s$%s", algo, iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// Verify compares a password with a hash in constant time.
// A wrong password yields (false, nil); a corrupted hash yields ErrInvalidHash.
func Verify(password, encoded string) (bool, error) {
	iterations, salt, want, err := parse(encoded)
	if err != nil {
		return false, err
	}
	got := pbkdf2HMACSHA256([]byte(password), salt, iterations, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// NeedsRehash reports whether the hash was created with fewer iterations than DefaultIterations
// (or is corrupted). Recompute it after a successful login.
func NeedsRehash(encoded string) bool {
	iterations, _, _, err := parse(encoded)
	return err != nil || iterations < DefaultIterations
}

func parse(encoded string) (iterations int, salt, key []byte, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != algo {
		return 0, nil, nil, ErrInvalidHash
	}
	iterations, err = strconv.Atoi(parts[1])
	if err != nil || iterations < 1 || iterations > maxIterations {
		return 0, nil, nil, ErrInvalidHash
	}
	salt, err = base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil || len(salt) < 8 {
		return 0, nil, nil, ErrInvalidHash
	}
	key, err = base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(key) < 16 || len(key) > 64 {
		return 0, nil, nil, ErrInvalidHash
	}
	return iterations, salt, key, nil
}

// pbkdf2HMACSHA256 is PBKDF2 (RFC 8018, section 5.2) with HMAC-SHA256.
func pbkdf2HMACSHA256(password, salt []byte, iterations, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hLen := prf.Size()
	numBlocks := (keyLen + hLen - 1) / hLen

	dk := make([]byte, 0, numBlocks*hLen)
	u := make([]byte, 0, hLen)
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		prf.Write([]byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)})
		u = prf.Sum(u[:0])
		t := append([]byte(nil), u...)
		for i := 1; i < iterations; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}
