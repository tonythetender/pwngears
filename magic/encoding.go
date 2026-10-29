// Package magic auto-detects and peels encoding layers, identifies opaque blobs
// (hash type, file format, base, timestamp), and auto-solves classical ciphers.
// It is the offline, dependency-free equivalent of reaching for CyberChef
// "Magic", hashid, file and dcode.fr.
package magic

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strconv"
	"strings"

	"github.com/tonythetender/pwngears/crypto"
)

// Each decoder returns (decoded, ok); ok is a charset/shape gate so the Magic
// search never explores a branch that clearly isn't that encoding.

func isB64(s string) bool {
	for _, c := range s {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '+' || c == '/' || c == '-' || c == '_' || c == '=':
		default:
			return false
		}
	}
	return true
}

// B64Decode decodes base64 (standard or URL alphabet, padded or raw).
func B64Decode(s []byte) ([]byte, bool) {
	t := strings.TrimSpace(string(s))
	if len(t) < 4 || !isB64(t) {
		return nil, false
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if out, err := enc.DecodeString(t); err == nil && len(out) > 0 {
			return out, true
		}
	}
	return nil, false
}

// B32Decode decodes standard base32.
func B32Decode(s []byte) ([]byte, bool) {
	t := strings.ToUpper(strings.TrimSpace(string(s)))
	if len(t) < 8 {
		return nil, false
	}
	for _, c := range t {
		if !((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7') || c == '=') {
			return nil, false
		}
	}
	for _, enc := range []*base32.Encoding{base32.StdEncoding, base32.StdEncoding.WithPadding(base32.NoPadding)} {
		if out, err := enc.DecodeString(t); err == nil && len(out) > 0 {
			return out, true
		}
	}
	return nil, false
}

// HexDecode decodes an even-length hex string.
func HexDecode(s []byte) ([]byte, bool) {
	t := strings.TrimSpace(string(s))
	if len(t) < 4 || len(t)%2 != 0 {
		return nil, false
	}
	out, err := hex.DecodeString(t)
	if err != nil || len(out) == 0 {
		return nil, false
	}
	return out, true
}

// BinaryDecode decodes a string of '0'/'1' (whitespace allowed) in 8-bit groups.
func BinaryDecode(s []byte) ([]byte, bool) {
	t := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\t' || r == '\r' {
			return -1
		}
		return r
	}, string(s))
	if len(t) < 8 || len(t)%8 != 0 {
		return nil, false
	}
	for _, c := range t {
		if c != '0' && c != '1' {
			return nil, false
		}
	}
	out := make([]byte, len(t)/8)
	for i := range out {
		v, err := strconv.ParseUint(t[i*8:i*8+8], 2, 16)
		if err != nil {
			return nil, false
		}
		out[i] = byte(v)
	}
	return out, true
}

// DecimalDecode decodes space/comma-separated ASCII decimal byte values.
func DecimalDecode(s []byte) ([]byte, bool) {
	fields := strings.FieldsFunc(string(s), func(r rune) bool {
		return r == ' ' || r == ',' || r == '\n' || r == '\t' || r == '\r'
	})
	if len(fields) < 2 {
		return nil, false
	}
	out := make([]byte, 0, len(fields))
	for _, f := range fields {
		n, err := strconv.Atoi(f)
		if err != nil || n < 0 || n > 255 {
			return nil, false
		}
		out = append(out, byte(n))
	}
	return out, true
}

// URLDecode percent-decodes, if the input actually contains encoded sequences.
func URLDecode(s []byte) ([]byte, bool) {
	t := string(s)
	if !strings.ContainsAny(t, "%+") {
		return nil, false
	}
	out, err := url.QueryUnescape(t)
	if err != nil || out == t {
		return nil, false
	}
	return []byte(out), true
}

// ROT applies a Caesar shift of n, reusing the crypto Caesar implementation.
func ROT(b []byte, n int) []byte {
	return crypto.CaesarCipher{}.Decrypt(b, []byte{byte(((n % 26) + 26) % 26)})
}
