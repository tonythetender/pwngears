package magic

import (
	"strings"
	"testing"
)

func hasHash(gs []HashGuess, name string) bool {
	for _, g := range gs {
		if g.Name == name {
			return true
		}
	}
	return false
}

func TestIdentifyMD5(t *testing.T) {
	fp := Identify([]byte("5d41402abc4b2a76b9719d911017c592"))
	if fp.Charset != "hex" {
		t.Errorf("charset = %q, want hex", fp.Charset)
	}
	if !hasHash(fp.HashGuesses, "MD5") {
		t.Errorf("MD5 not among guesses: %+v", fp.HashGuesses)
	}
}

func TestIdentifyBcrypt(t *testing.T) {
	fp := Identify([]byte("$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"))
	if !hasHash(fp.HashGuesses, "bcrypt") {
		t.Errorf("bcrypt not detected: %+v", fp.HashGuesses)
	}
}

func TestIdentifyPNG(t *testing.T) {
	png := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
	fp := Identify(png)
	if fp.FileType == nil || fp.FileType.Ext != "png" {
		t.Fatalf("PNG not detected: %+v", fp.FileType)
	}
}

func TestIdentifyTimestamp(t *testing.T) {
	fp := Identify([]byte("1700000000"))
	found := false
	for _, ts := range fp.Timestamps {
		if ts.Format == "unix seconds" && ts.Time.Year() == 2023 {
			found = true
		}
	}
	if !found {
		t.Fatalf("unix seconds 2023 not among timestamps: %+v", fp.Timestamps)
	}
}

func TestIdentifyEncodings(t *testing.T) {
	fp := Identify([]byte("SGVsbG8gV29ybGQh"))
	joined := strings.Join(fp.Encodings, ",")
	if !strings.Contains(joined, "base64") {
		t.Errorf("base64 not reported: %v", fp.Encodings)
	}
}
