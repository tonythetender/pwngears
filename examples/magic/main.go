// Command magic is a complete, runnable example of the offline "scanning"
// toolkit: peel an encoding chain, fingerprint an opaque blob, and auto-solve
// classical ciphers. Run it with `go run ./examples/magic/`.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	. "github.com/tonythetender/pwngears"
)

func main() {
	magicDecode()
	fingerprint()
	solveCiphers()
}

func magicDecode() {
	fmt.Println("== Magic: peel an unknown encoding chain ==")
	// Build hex(base64(rot13("flag{layers_peeled}"))) and let Magic recover it.
	inner := ROT([]byte("flag{layers_peeled}"), 13)
	b64 := base64.StdEncoding.EncodeToString(inner)
	blob := []byte(hex.EncodeToString([]byte(b64)))

	for _, d := range Magic(blob, WithFlagRegex(`flag\{[^}]*\}`)) {
		fmt.Printf("  %q  via %v\n", d.Output, d.Chain)
		break // best candidate
	}
	fmt.Println()
}

func fingerprint() {
	fmt.Println("== Identify: what is this blob? ==")
	for _, blob := range []string{
		"5d41402abc4b2a76b9719d911017c592",                             // md5("hello")
		"$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW", // bcrypt
		"1700000000", // unix timestamp
	} {
		fp := Identify([]byte(blob))
		fmt.Printf("  %-20s charset=%s hashes=%v times=%v\n",
			truncate(blob, 20), fp.Charset, names(fp.HashGuesses), fp.Timestamps)
	}
	fmt.Println()
}

func solveCiphers() {
	fmt.Println("== AutoSolve: identify and crack classical ciphers ==")
	// A Caesar-shifted message and a known flag format.
	ct := []byte("wkh iodj lv iodj{fdhvdu_zdv_hdvb}")
	for _, c := range AutoSolve(ct, WithSolveFlagRegex(`flag\{[^}]*\}`), WithSolveTopN(1)) {
		fmt.Printf("  %-12s %q\n", c.Method, c.Plaintext)
	}
	fmt.Println()
}

func names(gs []HashGuess) []string {
	out := make([]string, 0, len(gs))
	for _, g := range gs {
		out = append(out, g.Name)
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
