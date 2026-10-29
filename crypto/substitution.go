package crypto

// SubstitutionDecrypt applies a monoalphabetic substitution. key is a 26-byte
// permutation where key[i] is the plaintext letter for ciphertext letter 'a'+i
// (key entries are lowercase a..z). Case is preserved and non-letters pass
// through unchanged.
func SubstitutionDecrypt(ciphertext, key []byte) []byte {
	if len(key) < 26 {
		return append([]byte(nil), ciphertext...)
	}
	out := make([]byte, len(ciphertext))
	for i, c := range ciphertext {
		switch {
		case c >= 'a' && c <= 'z':
			out[i] = key[c-'a']
		case c >= 'A' && c <= 'Z':
			p := key[c-'A']
			if p >= 'a' && p <= 'z' {
				p -= 32
			}
			out[i] = p
		default:
			out[i] = c
		}
	}
	return out
}
