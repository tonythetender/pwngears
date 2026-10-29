package magic

import (
	"strings"
	"testing"
)

func caesarEncrypt(s string, shift int) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			b[i] = 'a' + byte((int(c-'a')+shift)%26)
		case c >= 'A' && c <= 'Z':
			b[i] = 'A' + byte((int(c-'A')+shift)%26)
		}
	}
	return string(b)
}

func vigenereEncrypt(s, key string) string {
	b := []byte(s)
	k := 0
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			sh := int(key[k%len(key)] - 'A')
			b[i] = 'a' + byte((int(c-'a')+sh)%26)
			k++
		case c >= 'A' && c <= 'Z':
			sh := int(key[k%len(key)] - 'A')
			b[i] = 'A' + byte((int(c-'A')+sh)%26)
			k++
		}
	}
	return string(b)
}

func xorBytes(s string, key byte) []byte {
	out := make([]byte, len(s))
	for i := range s {
		out[i] = s[i] ^ key
	}
	return out
}

func substEncrypt(s string, encKey []byte) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = encKey[c-'a']
		}
	}
	return string(b)
}

const english = "the quick brown fox jumps over the lazy dog while the children play near the river every single day after the long school year finally comes to its natural end"

// prose is natural English (public-domain) long enough for statistical recovery.
const prose = "it is a truth universally acknowledged that a single man in possession of a good fortune must be in want of a wife however little known the feelings or views of such a man may be on his first entering a neighbourhood this truth is so well fixed in the minds of the surrounding families that he is considered the rightful property of some one or other of their daughters"

func TestAutoSolveCaesar(t *testing.T) {
	ct := caesarEncrypt(english, 7)
	cands := AutoSolve([]byte(ct), WithSolveMethods("caesar"))
	if len(cands) == 0 || string(cands[0].Plaintext) != english {
		t.Fatalf("caesar not recovered; top=%q", top(cands))
	}
}

func TestAutoSolveXOR(t *testing.T) {
	ct := xorBytes(english, 0x5a)
	cands := AutoSolve(ct, WithSolveMethods("xor"))
	if len(cands) == 0 || string(cands[0].Plaintext) != english {
		t.Fatalf("xor not recovered; top=%q", top(cands))
	}
}

func TestAutoSolveVigenere(t *testing.T) {
	ct := vigenereEncrypt(prose, "LEMON")
	cands := AutoSolve([]byte(ct), WithSolveMethods("vigenere"), WithSolveMaxKeyLen(12))
	if len(cands) == 0 {
		t.Fatal("no vigenere candidates")
	}
	got := string(cands[0].Plaintext)
	if !strings.Contains(got, "universally") || !strings.Contains(got, "fortune") {
		t.Fatalf("vigenere not recovered; top=%q", got)
	}
}

func TestAutoSolveSubstitution(t *testing.T) {
	encKey := []byte("qwertyuiopasdfghjklzxcvbnm") // a->q, b->w, ...
	ct := substEncrypt(prose, encKey)
	cands := AutoSolve([]byte(ct), WithSolveMethods("substitution"))
	if len(cands) == 0 {
		t.Fatal("no substitution candidates")
	}
	got := string(cands[0].Plaintext)
	// The compact (word-list-derived) model recovers typical prose to a strongly
	// English decryption; a few rare-letter assignments may remain swapped since
	// words outside the model carry no n-gram signal. Assert the solver found a
	// clearly-English key and recovered distinctive, well-modeled words.
	if cands[0].Score.English < 0.5 {
		t.Fatalf("substitution decryption not English enough (%.3f); top=%q", cands[0].Score.English, got)
	}
	for _, w := range []string{"truth", "universally", "single"} {
		if !strings.Contains(got, w) {
			t.Fatalf("substitution not recovered (missing %q); top=%q", w, got)
		}
	}
}

func TestAutoSolveFlagRanksFirst(t *testing.T) {
	ct := caesarEncrypt("flagisflag{caesar_wins}andmore", 5)
	cands := AutoSolve([]byte(ct), WithSolveFlagRegex(`flag\{[^}]*\}`))
	if len(cands) == 0 || !cands[0].Score.FlagHit {
		t.Fatalf("flag candidate did not rank first; top=%q", top(cands))
	}
}

func top(c []Candidate) string {
	if len(c) == 0 {
		return "<none>"
	}
	return string(c[0].Plaintext)
}
