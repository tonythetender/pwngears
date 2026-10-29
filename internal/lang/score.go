// Package lang provides compact, dependency-free English-text scoring used by
// the magic package to rank decode candidates and drive classical-cipher
// solving. The statistical model is derived from an embedded common-word list
// (see tables.go), so nothing is downloaded and the package stays stdlib-only.
package lang

import "strings"

// Printable returns the fraction of bytes that are printable ASCII (including
// space, tab, newline and carriage return).
func Printable(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	n := 0
	for _, c := range b {
		if (c >= 0x20 && c <= 0x7e) || c == '\n' || c == '\t' || c == '\r' {
			n++
		}
	}
	return float64(n) / float64(len(b))
}

func letterCounts(b []byte) (counts [26]int, letters int) {
	for _, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			counts[c-'a']++
			letters++
		case c >= 'A' && c <= 'Z':
			counts[c-'A']++
			letters++
		}
	}
	return
}

// ChiSquaredEnglish returns the chi-squared statistic of the given letter counts
// against English letter frequencies (lower = closer to English). n is the total
// number of letters.
func ChiSquaredEnglish(counts [26]int, n int) float64 {
	if n == 0 {
		return 0
	}
	chi := 0.0
	for i := 0; i < 26; i++ {
		expected := englishLetterFreq[i] / 100.0 * float64(n)
		if expected == 0 {
			continue
		}
		d := float64(counts[i]) - expected
		chi += d * d / expected
	}
	return chi
}

// IndexOfCoincidence returns the index of coincidence of the letters in b, used
// to estimate Vigenere key length (English text is ~0.067, random ~0.038).
func IndexOfCoincidence(b []byte) float64 {
	counts, n := letterCounts(b)
	if n < 2 {
		return 0
	}
	sum := 0.0
	for _, c := range counts {
		sum += float64(c) * float64(c-1)
	}
	return sum / (float64(n) * float64(n-1))
}

func wordBonus(b []byte) float64 {
	fields := strings.Fields(strings.ToLower(string(b)))
	if len(fields) == 0 {
		return 0
	}
	hits := 0
	for _, f := range fields {
		f = strings.Trim(f, ".,;:!?\"'(){}[]")
		if wordSet[f] {
			hits++
		}
	}
	return float64(hits) / float64(len(fields))
}

// EnglishScore returns a 0..1 estimate of how English-like b is (higher is more
// English). It blends printability, letter-frequency fit and known-word density
// — robust for ranking Magic decode candidates.
func EnglishScore(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	p := Printable(b)
	counts, letters := letterCounts(b)
	fit := 0.0
	if letters > 0 {
		fit = 1.0 / (1.0 + ChiSquaredEnglish(counts, letters)/float64(letters))
	}
	letterRatio := float64(letters) / float64(len(b))
	score := 0.45*p + 0.25*wordBonus(b) + 0.30*fit*letterRatio
	if score > 1 {
		return 1
	}
	return score
}

// NgramScore returns the average trigram log-probability of s (higher = more
// English), with add-k smoothing for unseen trigrams. It drives the substitution
// hill-climb, where maximizing it recovers the key.
func NgramScore(s string) float64 {
	letters := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			letters = append(letters, c+32)
		} else if c >= 'a' && c <= 'z' {
			letters = append(letters, c)
		}
	}
	if len(letters) < 3 {
		if len(letters) == 2 {
			return lookup(biLog, string(letters), biFloor)
		}
		return triFloor
	}
	sum := 0.0
	n := 0
	for i := 0; i+3 <= len(letters); i++ {
		sum += lookup(triLog, string(letters[i:i+3]), triFloor)
		n++
	}
	if n == 0 {
		return triFloor
	}
	return sum / float64(n)
}

func lookup(m map[string]float64, key string, floor float64) float64 {
	if v, ok := m[key]; ok {
		return v
	}
	return floor
}
