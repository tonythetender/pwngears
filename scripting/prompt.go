package scripting

import (
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"regexp"
	"strconv"
)

// Prompt is one chunk read from the service during a Loop. Its extraction
// helpers mirror web.Response (Match/MatchAll/Flag) on the raw-tube side, so a
// per-round handler reads the same whether the challenge is over HTTP or a
// socket. Parsing helpers return a zero value on no match rather than failing.
type Prompt struct {
	Round int
	Data  []byte
}

func (p *Prompt) Bytes() []byte  { return p.Data }
func (p *Prompt) String() string { return string(p.Data) }

// Match returns the first submatch of pattern (or the whole match if the
// pattern has no groups), or "" if nothing matches.
func (p *Prompt) Match(pattern string) string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return ""
	}
	m := re.FindStringSubmatch(string(p.Data))
	if m == nil {
		return ""
	}
	if len(m) > 1 {
		return m[1]
	}
	return m[0]
}

// MatchAll returns every match of pattern (first submatch per match, else whole).
func (p *Prompt) MatchAll(pattern string) []string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	matches := re.FindAllStringSubmatch(string(p.Data), -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) > 1 {
			out = append(out, m[1])
		} else {
			out = append(out, m[0])
		}
	}
	return out
}

// Group returns the value of the named capture group, or "" if absent.
func (p *Prompt) Group(pattern, name string) string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return ""
	}
	m := re.FindStringSubmatch(string(p.Data))
	if m == nil {
		return ""
	}
	for i, n := range re.SubexpNames() {
		if n == name && i < len(m) {
			return m[i]
		}
	}
	return ""
}

var (
	reInt    = regexp.MustCompile(`-?\d+`)
	reHex    = regexp.MustCompile(`(?:0x)?([0-9a-fA-F]{2,})`)
	reBase64 = regexp.MustCompile(`[A-Za-z0-9+/]{4,}={0,2}`)
)

// Int returns the first integer found in the chunk, or 0.
func (p *Prompt) Int() int {
	s := reInt.FindString(string(p.Data))
	if s == "" {
		return 0
	}
	n, _ := strconv.Atoi(s)
	return n
}

// Ints returns every integer found in the chunk, in order.
func (p *Prompt) Ints() []int {
	all := reInt.FindAllString(string(p.Data), -1)
	out := make([]int, 0, len(all))
	for _, s := range all {
		if n, err := strconv.Atoi(s); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// BigInt returns the first (possibly very large) integer in the chunk, or nil.
func (p *Prompt) BigInt() *big.Int {
	s := reInt.FindString(string(p.Data))
	if s == "" {
		return nil
	}
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil
	}
	return n
}

// Hex decodes the first hex token in the chunk, or returns nil.
func (p *Prompt) Hex() []byte {
	m := reHex.FindStringSubmatch(string(p.Data))
	if m == nil {
		return nil
	}
	s := m[1]
	if len(s)%2 != 0 {
		s = s[:len(s)-1]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

// Base64 decodes the first base64 token in the chunk, or returns nil.
func (p *Prompt) Base64() []byte {
	s := reBase64.FindString(string(p.Data))
	if s == "" {
		return nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b
	}
	return nil
}

// Flag returns the first prefix{...} flag in the chunk, or "".
func (p *Prompt) Flag(prefix string) string {
	re := regexp.MustCompile(regexp.QuoteMeta(prefix) + `\{[^}]*\}`)
	return re.FindString(string(p.Data))
}
