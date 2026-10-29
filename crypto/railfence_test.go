package crypto

import (
	"regexp"
	"testing"
)

func railEncrypt(s string, rails int) string {
	if rails <= 1 {
		return s
	}
	rows := make([][]byte, rails)
	r, dir := 0, 1
	for i := 0; i < len(s); i++ {
		rows[r] = append(rows[r], s[i])
		if r == 0 {
			dir = 1
		} else if r == rails-1 {
			dir = -1
		}
		r += dir
	}
	var out []byte
	for _, row := range rows {
		out = append(out, row...)
	}
	return string(out)
}

func TestRailFenceRoundTrip(t *testing.T) {
	plain := "WEAREDISCOVEREDFLEEATONCE"
	for rails := 2; rails <= 6; rails++ {
		ct := railEncrypt(plain, rails)
		got := string(RailFenceCipher{}.Decrypt([]byte(ct), []byte{byte(rails)}))
		if got != plain {
			t.Fatalf("rails=%d: got %q want %q", rails, got, plain)
		}
	}
}

func TestRailFenceThroughBruteForce(t *testing.T) {
	plain := "flag{rail_fence_through_engine}"
	ct := railEncrypt(plain, 4)
	engine := NewCryptoEngine()
	results := engine.BruteForce(RailFenceCipher{MaxRails: 10}, []byte(ct),
		WithPatternRegex(`flag\{[^}]*\}`))
	if len(results) == 0 {
		t.Fatal("BruteForce found no rail-fence match")
	}
	if !regexp.MustCompile(`flag\{rail_fence_through_engine\}`).Match(results[0].Plaintext) {
		t.Fatalf("unexpected plaintext %q", results[0].Plaintext)
	}
}

func TestSubstitutionDecrypt(t *testing.T) {
	// key maps cipher 'a'+i -> plain; identity-with-swap check.
	key := []byte("bcdefghijklmnopqrstuvwxyza") // a->b? no: cipher a -> plain b
	ct := []byte("Zab!")                        // z->a (wraps), a->b, b->c
	got := string(SubstitutionDecrypt(ct, key))
	if got != "Abc!" {
		t.Fatalf("got %q want %q", got, "Abc!")
	}
}
