package passwordhash

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// PBKDF2-HMAC-SHA256 vectors from RFC 7914, section 11, and Python hashlib.
func TestPBKDF2Vectors(t *testing.T) {
	cases := []struct {
		password, salt string
		iter, keyLen   int
		want           string
	}{
		{"passwd", "salt", 1, 64, "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"},
		{"Password", "NaCl", 80000, 64, "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"},
		{"pass\x00word", "sa\x00lt", 4096, 16, "89b69d0516f829893c696226650a8687"},
	}
	for _, tc := range cases {
		got := hex.EncodeToString(pbkdf2HMACSHA256([]byte(tc.password), []byte(tc.salt), tc.iter, tc.keyLen))
		if got != tc.want {
			t.Errorf("PBKDF2(%q, %q, %d) = %s, want %s", tc.password, tc.salt, tc.iter, got, tc.want)
		}
	}
}

func TestHashVerify(t *testing.T) {
	h, err := hashWith("correct horse", 1000)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "pbkdf2-sha256$1000$") || strings.Count(h, "$") != 3 {
		t.Fatalf("format: %s", h)
	}
	if ok, err := Verify("correct horse", h); !ok || err != nil {
		t.Fatalf("right password: %v, %v", ok, err)
	}
	if ok, err := Verify("wrong", h); ok || err != nil {
		t.Fatalf("wrong password: %v, %v", ok, err)
	}
	h2, _ := hashWith("correct horse", 1000)
	if h == h2 {
		t.Fatal("same password must produce different hashes (random salt)")
	}
}

func TestDefaultHashUsesOWASPIterations(t *testing.T) {
	if testing.Short() {
		t.Skip("600k iterations — about a second")
	}
	h, err := Hash("pw")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "pbkdf2-sha256$600000$") || NeedsRehash(h) {
		t.Fatalf("Hash must use DefaultIterations: %s", h)
	}
	if ok, _ := Verify("pw", h); !ok {
		t.Fatal("verify default hash")
	}
}

func TestNeedsRehash(t *testing.T) {
	old, _ := hashWith("pw", 100_000) // hash from a previous version of the package
	if !NeedsRehash(old) {
		t.Error("100k iterations should need rehash")
	}
	if ok, err := Verify("pw", old); !ok || err != nil {
		t.Error("old hashes must still verify")
	}
	if !NeedsRehash("garbage") {
		t.Error("broken hash should need rehash")
	}
}

func TestInvalidHashes(t *testing.T) {
	salt := "c2FsdHNhbHRzYWx0" // 12 bytes
	key := strings.Repeat("A", 43)
	for _, h := range []string{
		"",
		"bcrypt$10$x$y",
		"pbkdf2-sha256$abc$" + salt + "$" + key,
		"pbkdf2-sha256$0$" + salt + "$" + key,
		"pbkdf2-sha256$99999999999$" + salt + "$" + key,
		"pbkdf2-sha256$1000$!!!$" + key,
		"pbkdf2-sha256$1000$YQ$" + key, // 1-byte salt
		"pbkdf2-sha256$1000$" + salt + "$!!!",
		"pbkdf2-sha256$1000$" + salt + "$QUFB", // 3-byte key
		"pbkdf2-sha256$1000$" + salt,
	} {
		if ok, err := Verify("pw", h); ok || !errors.Is(err, ErrInvalidHash) {
			t.Errorf("Verify(%q) = %v, %v; want ErrInvalidHash", h, ok, err)
		}
	}
}
