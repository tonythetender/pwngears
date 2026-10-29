package magic

import (
	"container/heap"
	"crypto/sha256"
	"regexp"
	"sort"

	"github.com/tonythetender/pwngears/internal/lang"
)

// Layer names one decoding step in a chain, e.g. {"base64",""} or {"rot","13"}.
type Layer struct {
	Name  string
	Param string
}

// Score rates how text-like a decoded candidate is.
type Score struct {
	Printable float64
	English   float64
	Ngram     float64
	FlagHit   bool
}

// Rank combines the components into a single sortable value; a flag hit dominates.
func (s Score) Rank() float64 {
	r := 0.6*s.English + 0.4*s.Printable
	if s.FlagHit {
		r += 100
	}
	return r
}

// Decoding is one candidate result: the steps applied, the bytes produced, and
// its score.
type Decoding struct {
	Chain  []Layer
	Output []byte
	Score  Score
}

type magicConfig struct {
	depth    int
	maxNodes int
	flag     *regexp.Regexp
}

// MagicOption configures Magic.
type MagicOption func(*magicConfig)

// WithDepth caps the number of stacked decode layers (default 8).
func WithDepth(n int) MagicOption { return func(c *magicConfig) { c.depth = n } }

// WithFlagRegex marks a decoded candidate matching pat as a flag hit, which
// ranks it to the top and lets the search accept it early.
func WithFlagRegex(pat string) MagicOption {
	return func(c *magicConfig) {
		if re, err := regexp.Compile(pat); err == nil {
			c.flag = re
		}
	}
}

func scoreText(b []byte, flag *regexp.Regexp) Score {
	s := Score{
		Printable: lang.Printable(b),
		English:   lang.EnglishScore(b),
		Ngram:     lang.NgramScore(string(b)),
	}
	// A flag hit is only honored when the caller gives an explicit pattern: a
	// generic brace shape can't distinguish a correctly decoded flag from a
	// ROT/XOR scramble of it (both keep the braces), so it would promote noise.
	if flag != nil {
		s.FlagHit = flag.Match(b)
	}
	return s
}

// Magic auto-detects and strips encoding layers from blob in a scored best-first
// search, returning candidate decode chains ranked best-first (most text-like or
// flag-bearing first). It explores base64/base32/hex/binary/decimal/URL and
// ROT 1..25, bounded by WithDepth and an internal node cap.
func Magic(blob []byte, opts ...MagicOption) []Decoding {
	cfg := magicConfig{depth: 8, maxNodes: 4000}
	for _, o := range opts {
		o(&cfg)
	}

	pq := &nodeHeap{}
	heap.Init(pq)

	seen := map[[32]byte]bool{}
	mark := func(b []byte) bool {
		h := sha256.Sum256(b)
		if seen[h] {
			return false
		}
		seen[h] = true
		return true
	}

	mark(blob)
	heap.Push(pq, &pqItem{data: blob, chain: nil, rank: 0})

	var results []Decoding
	nodes := 0

	expand := func(data []byte, chain []Layer, name, param string, out []byte) {
		if !mark(out) {
			return
		}
		sc := scoreText(out, cfg.flag)
		newChain := append(append([]Layer(nil), chain...), Layer{Name: name, Param: param})
		results = append(results, Decoding{Chain: newChain, Output: out, Score: sc})
		heap.Push(pq, &pqItem{data: out, chain: newChain, rank: sc.Rank()})
		nodes++
	}

	for pq.Len() > 0 && nodes < cfg.maxNodes {
		cur := heap.Pop(pq).(*pqItem)
		if len(cur.chain) >= cfg.depth {
			continue
		}
		if out, ok := B64Decode(cur.data); ok {
			expand(cur.data, cur.chain, "base64", "", out)
		}
		if out, ok := B32Decode(cur.data); ok {
			expand(cur.data, cur.chain, "base32", "", out)
		}
		if out, ok := HexDecode(cur.data); ok {
			expand(cur.data, cur.chain, "hex", "", out)
		}
		if out, ok := BinaryDecode(cur.data); ok {
			expand(cur.data, cur.chain, "binary", "", out)
		}
		if out, ok := DecimalDecode(cur.data); ok {
			expand(cur.data, cur.chain, "decimal", "", out)
		}
		if out, ok := URLDecode(cur.data); ok {
			expand(cur.data, cur.chain, "url", "", out)
		}
		for n := 1; n <= 25; n++ {
			expand(cur.data, cur.chain, "rot", itoa(n), ROT(cur.data, n))
		}
	}

	sort.SliceStable(results, func(i, j int) bool {
		return results[i].Score.Rank() > results[j].Score.Rank()
	})
	if len(results) > 12 {
		results = results[:12]
	}
	return results
}

func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}

// pqItem / nodeHeap form a max-heap by rank for the best-first search.
type pqItem struct {
	data  []byte
	chain []Layer
	rank  float64
}

type nodeHeap []*pqItem

func (h nodeHeap) Len() int           { return len(h) }
func (h nodeHeap) Less(i, j int) bool { return h[i].rank > h[j].rank }
func (h nodeHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *nodeHeap) Push(x any)        { *h = append(*h, x.(*pqItem)) }
func (h *nodeHeap) Pop() any {
	old := *h
	n := len(old)
	it := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	return it
}
