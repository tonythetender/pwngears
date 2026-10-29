package magic

import (
	"math"
	"math/rand"
	"regexp"
	"sort"

	"github.com/tonythetender/pwngears/crypto"
	"github.com/tonythetender/pwngears/internal/lang"
)

// Candidate is one ranked decryption produced by AutoSolve.
type Candidate struct {
	Method    string
	Key       []byte
	Plaintext []byte
	Score     Score
}

type solveConfig struct {
	flag      *regexp.Regexp
	methods   map[string]bool
	topN      int
	maxKeyLen int
}

// SolveOption configures AutoSolve.
type SolveOption func(*solveConfig)

// WithSolveFlagRegex ranks a decryption matching pat to the top.
func WithSolveFlagRegex(pat string) SolveOption {
	return func(c *solveConfig) {
		if re, err := regexp.Compile(pat); err == nil {
			c.flag = re
		}
	}
}

// WithSolveMethods restricts which solvers run (caesar, xor, vigenere,
// railfence, substitution).
func WithSolveMethods(names ...string) SolveOption {
	return func(c *solveConfig) {
		c.methods = make(map[string]bool, len(names))
		for _, n := range names {
			c.methods[n] = true
		}
	}
}

// WithSolveTopN caps how many ranked candidates are returned (default 5).
func WithSolveTopN(n int) SolveOption { return func(c *solveConfig) { c.topN = n } }

// WithSolveMaxKeyLen bounds the Vigenere key length searched (default 16).
func WithSolveMaxKeyLen(n int) SolveOption { return func(c *solveConfig) { c.maxKeyLen = n } }

// AutoSolve tries the common classical ciphers against ct and returns the most
// English-like (or flag-matching) decryptions, ranked best-first. It composes
// on the crypto cipher implementations for the mechanical decrypt step and adds
// the statistical scoring the crypto BruteForce engine lacks.
func AutoSolve(ct []byte, opts ...SolveOption) []Candidate {
	cfg := solveConfig{topN: 5, maxKeyLen: 16}
	for _, o := range opts {
		o(&cfg)
	}
	use := func(name string) bool { return cfg.methods == nil || cfg.methods[name] }

	var cands []Candidate
	add := func(method string, key, pt []byte) {
		cands = append(cands, Candidate{Method: method, Key: key, Plaintext: pt, Score: scoreText(pt, cfg.flag)})
	}

	if use("caesar") {
		for s := 1; s < 26; s++ {
			add("caesar", []byte{byte(s)}, crypto.CaesarCipher{}.Decrypt(ct, []byte{byte(s)}))
		}
	}
	if use("xor") {
		for k := 0; k < 256; k++ {
			add("xor", []byte{byte(k)}, crypto.XORCipher{}.Decrypt(ct, []byte{byte(k)}))
		}
	}
	if use("vigenere") {
		for _, key := range vigenereKeys(ct, cfg.maxKeyLen) {
			add("vigenere", key, crypto.VigenereCipher{}.Decrypt(ct, key))
		}
	}
	if use("railfence") {
		max := len(ct) / 2
		if max > 20 {
			max = 20
		}
		for rails := 2; rails <= max; rails++ {
			add("railfence", []byte{byte(rails)}, crypto.RailFenceCipher{}.Decrypt(ct, []byte{byte(rails)}))
		}
	}
	if use("substitution") {
		key, pt := solveSubstitution(ct)
		add("substitution", key, pt)
	}

	sort.SliceStable(cands, func(i, j int) bool {
		return cands[i].Score.Rank() > cands[j].Score.Rank()
	})
	if cfg.topN > 0 && len(cands) > cfg.topN {
		cands = cands[:cfg.topN]
	}
	return cands
}

// vigenereKeys estimates likely keys via index of coincidence (to rank key
// lengths) and chi-squared per column (to recover each key letter).
func vigenereKeys(ct []byte, maxKeyLen int) [][]byte {
	letters := onlyUpper(ct)
	if len(letters) < 20 {
		return nil
	}
	type lenScore struct {
		l   int
		ioc float64
	}
	var ranked []lenScore
	for l := 1; l <= maxKeyLen && l < len(letters); l++ {
		sum, groups := 0.0, 0
		for off := 0; off < l; off++ {
			var col []byte
			for i := off; i < len(letters); i += l {
				col = append(col, letters[i])
			}
			if len(col) >= 2 {
				sum += lang.IndexOfCoincidence(col)
				groups++
			}
		}
		if groups > 0 {
			ranked = append(ranked, lenScore{l, sum / float64(groups)})
		}
	}
	sort.Slice(ranked, func(i, j int) bool { return ranked[i].ioc > ranked[j].ioc })

	var keys [][]byte
	for i := 0; i < len(ranked) && i < 2; i++ {
		l := ranked[i].l
		if l < 1 {
			continue
		}
		key := make([]byte, l)
		for off := 0; off < l; off++ {
			var col []byte
			for j := off; j < len(letters); j += l {
				col = append(col, letters[j])
			}
			key[off] = 'A' + byte(bestShift(col))
		}
		keys = append(keys, key)
	}
	return keys
}

// bestShift returns the Caesar shift that makes the column look most English.
func bestShift(col []byte) int {
	best, bestChi := 0, math.MaxFloat64
	for s := 0; s < 26; s++ {
		var counts [26]int
		for _, c := range col {
			counts[(int(c-'A')-s+26)%26]++
		}
		if chi := lang.ChiSquaredEnglish(counts, len(col)); chi < bestChi {
			bestChi = chi
			best = s
		}
	}
	return best
}

func onlyUpper(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c >= 'a' && c <= 'z' {
			out = append(out, c-32)
		} else if c >= 'A' && c <= 'Z' {
			out = append(out, c)
		}
	}
	return out
}

const englishOrder = "etaoinshrdlcumwfgypbvkjxqz"

// solveSubstitution recovers a monoalphabetic substitution key by hill-climbing
// a letter permutation to maximize the trigram score of the decryption, starting
// from a frequency-matched key and using random restarts.
func solveSubstitution(ct []byte) (key, plaintext []byte) {
	start := freqStartKey(ct)
	rng := rand.New(rand.NewSource(1))

	bestKey := append([]byte(nil), start...)
	bestScore := lang.NgramScore(string(crypto.SubstitutionDecrypt(ct, bestKey)))

	for restart := 0; restart < 40; restart++ {
		cur := make([]byte, 26)
		if restart == 0 {
			copy(cur, start)
		} else {
			copy(cur, []byte(englishOrder))
			rng.Shuffle(26, func(i, j int) { cur[i], cur[j] = cur[j], cur[i] })
		}
		curScore := lang.NgramScore(string(crypto.SubstitutionDecrypt(ct, cur)))

		improved := true
		for improved {
			improved = false
			for i := 0; i < 26; i++ {
				for j := i + 1; j < 26; j++ {
					cur[i], cur[j] = cur[j], cur[i]
					sc := lang.NgramScore(string(crypto.SubstitutionDecrypt(ct, cur)))
					if sc > curScore {
						curScore = sc
						improved = true
					} else {
						cur[i], cur[j] = cur[j], cur[i]
					}
				}
			}
		}
		if curScore > bestScore {
			bestScore = curScore
			bestKey = append([]byte(nil), cur...)
		}
	}
	return bestKey, crypto.SubstitutionDecrypt(ct, bestKey)
}

// freqStartKey builds a starting key mapping the most frequent ciphertext
// letters to the most frequent English letters.
func freqStartKey(ct []byte) []byte {
	var counts [26]int
	for _, c := range ct {
		if c >= 'a' && c <= 'z' {
			counts[c-'a']++
		} else if c >= 'A' && c <= 'Z' {
			counts[c-'A']++
		}
	}
	order := make([]int, 26)
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(i, j int) bool { return counts[order[i]] > counts[order[j]] })

	key := make([]byte, 26)
	for i := range key {
		key[i] = byte('a' + i)
	}
	for rank, cipherLetter := range order {
		key[cipherLetter] = englishOrder[rank]
	}
	return key
}
