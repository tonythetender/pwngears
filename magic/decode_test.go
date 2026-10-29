package magic

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestMagicPeelsChain(t *testing.T) {
	flag := "flag{magic_decode_works}"
	// Build hex(base64(rot13(flag))); Magic must peel hex -> base64 -> rot13.
	inner := ROT([]byte(flag), 13)
	b64 := base64.StdEncoding.EncodeToString(inner)
	encoded := hex.EncodeToString([]byte(b64))

	results := Magic([]byte(encoded), WithFlagRegex(`flag\{[^}]*\}`))
	if len(results) == 0 {
		t.Fatal("Magic returned no candidates")
	}
	top := results[0]
	if !top.Score.FlagHit {
		t.Fatalf("top candidate is not a flag hit: %q", top.Output)
	}
	if !strings.Contains(string(top.Output), flag) {
		t.Fatalf("top candidate %q does not contain the flag", top.Output)
	}
	names := make([]string, len(top.Chain))
	for i, l := range top.Chain {
		names[i] = l.Name
	}
	want := []string{"hex", "base64", "rot"}
	if len(names) != 3 || names[0] != want[0] || names[1] != want[1] || names[2] != want[2] {
		t.Fatalf("unexpected chain %v, want %v", names, want)
	}
}

func TestMagicSingleLayer(t *testing.T) {
	flag := "flag{just_base64}"
	encoded := base64.StdEncoding.EncodeToString([]byte(flag))
	results := Magic([]byte(encoded), WithFlagRegex(`flag\{[^}]*\}`))
	if len(results) == 0 || !strings.Contains(string(results[0].Output), flag) {
		t.Fatalf("did not recover single-layer base64 flag; got %+v", results)
	}
}
