package scripting

import (
	"bytes"
	"context"
	"encoding/binary"
	"hash"
	"math/bits"
	"regexp"
	"runtime"
	"strconv"
	"time"

	"crypto/sha256"

	"github.com/tonythetender/pwngears/internal/pool"
)

// PoWEncoding controls how the brute-forced value X is encoded before hashing
// (and therefore how Suffix reads back). Most CTF gates want a printable
// decimal; use the others when the challenge restricts the answer's form.
type PoWEncoding int

const (
	PoWDecimal PoWEncoding = iota // ASCII decimal, e.g. "42" (default)
	PoWHex                        // ASCII hex, e.g. "2a"
	PoWRaw                        // minimal big-endian bytes
	PoWCharset                    // base-N over a custom charset (see WithPoWCharset)
)

// PoW is the result of a proof-of-work search. Input is the exact bytes that
// were hashed (prefix||Suffix), Suffix is the value X that was found, and
// Digest is sha256(Input).
type PoW struct {
	Input  []byte
	Suffix []byte
	Digest []byte
}

type powConfig struct {
	workers int
	timeout time.Duration
	enc     PoWEncoding
	charset string
}

type PoWOption func(*powConfig)

// WithPoWWorkers sets the number of concurrent search goroutines (default NumCPU).
func WithPoWWorkers(n int) PoWOption { return func(c *powConfig) { c.workers = n } }

// WithPoWTimeout aborts the search after d; the returned PoW is then zero-valued.
func WithPoWTimeout(d time.Duration) PoWOption { return func(c *powConfig) { c.timeout = d } }

// WithPoWEncoding sets how the candidate X is encoded before hashing.
func WithPoWEncoding(e PoWEncoding) PoWOption { return func(c *powConfig) { c.enc = e } }

// WithPoWCharset restricts X to a base-N encoding over the given charset
// (implies PoWCharset).
func WithPoWCharset(s string) PoWOption {
	return func(c *powConfig) {
		c.charset = s
		c.enc = PoWCharset
	}
}

// SolveHashPoW brute-forces a value X such that pred(sha256(prefix||X)) is true,
// searching X concurrently. pred is handed the raw 32-byte digest.
func SolveHashPoW(prefix []byte, pred func(sum []byte) bool, opts ...PoWOption) PoW {
	cfg := powConfig{workers: runtime.NumCPU(), enc: PoWDecimal}
	for _, o := range opts {
		o(&cfg)
	}

	ctx := context.Background()
	var cancel context.CancelFunc
	if cfg.timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, cfg.timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

	prefixCopy := append([]byte(nil), prefix...)
	charset := []byte(cfg.charset)

	type state struct {
		h       hash.Hash
		buf     []byte
		scratch []byte
	}

	idx, ok := pool.BruteCounter(ctx, cfg.workers,
		func() *state { return &state{h: sha256.New(), buf: make([]byte, 0, sha256.Size)} },
		func(st *state, i uint64) bool {
			st.scratch = appendCandidate(st.scratch[:0], i, cfg.enc, charset)
			st.h.Reset()
			st.h.Write(prefixCopy)
			st.h.Write(st.scratch)
			return pred(st.h.Sum(st.buf[:0]))
		})
	if !ok {
		return PoW{}
	}

	suffix := appendCandidate(nil, idx, cfg.enc, charset)
	input := append(append([]byte(nil), prefixCopy...), suffix...)
	sum := sha256.Sum256(input)
	return PoW{Input: input, Suffix: suffix, Digest: sum[:]}
}

// PoWLeadingZeroBits finds X so that sha256(prefix||X) has at least bits leading
// zero bits (the redpwn/kCTF style gate).
func PoWLeadingZeroBits(prefix []byte, bits int, opts ...PoWOption) PoW {
	return SolveHashPoW(prefix, func(sum []byte) bool { return leadingZeroBits(sum) >= bits }, opts...)
}

// PoWLeadingZeroNibbles finds X so that the hex digest starts with k '0' nibbles.
func PoWLeadingZeroNibbles(prefix []byte, k int, opts ...PoWOption) PoW {
	return SolveHashPoW(prefix, func(sum []byte) bool { return leadingZeroBits(sum) >= 4*k }, opts...)
}

// PoWPrefixEquals finds X so that the digest starts with the raw bytes target.
func PoWPrefixEquals(prefix, target []byte, opts ...PoWOption) PoW {
	return SolveHashPoW(prefix, func(sum []byte) bool {
		return len(sum) >= len(target) && bytes.Equal(sum[:len(target)], target)
	}, opts...)
}

// PoWSuffixEquals finds X so that sha256(X) ends with the raw bytes target.
// Unlike the others it hashes X alone (no prefix).
func PoWSuffixEquals(target []byte, opts ...PoWOption) PoW {
	return SolveHashPoW(nil, func(sum []byte) bool {
		return len(sum) >= len(target) && bytes.Equal(sum[len(sum)-len(target):], target)
	}, opts...)
}

// ClearPoW reads one line from t, extracts the challenge with pattern, solves
// it for bits leading zero bits, and sends the answer. pattern must capture the
// prefix (a group named "prefix", else the first group); if it also captures a
// group named "bits", that value overrides the bits argument. It returns the
// solved PoW. For gates that are not a single line, read the challenge yourself
// and call PoWLeadingZeroBits directly.
func ClearPoW(t LoggerTube, pattern string, bits int, opts ...PoWOption) PoW {
	line := string(t.RecvLine())
	re := regexp.MustCompile(pattern)
	m := re.FindStringSubmatch(line)

	prefix := ""
	if m != nil {
		prefix = namedOrFirst(re, m, "prefix")
		if b := namedGroup(re, m, "bits"); b != "" {
			if n, err := strconv.Atoi(b); err == nil {
				bits = n
			}
		}
	}

	pw := PoWLeadingZeroBits([]byte(prefix), bits, opts...)
	t.SendLine(pw.Suffix)
	return pw
}

func namedGroup(re *regexp.Regexp, m []string, name string) string {
	for i, n := range re.SubexpNames() {
		if n == name && i < len(m) {
			return m[i]
		}
	}
	return ""
}

func namedOrFirst(re *regexp.Regexp, m []string, name string) string {
	if v := namedGroup(re, m, name); v != "" {
		return v
	}
	if len(m) > 1 {
		return m[1]
	}
	return m[0]
}

func leadingZeroBits(b []byte) int {
	n := 0
	for _, by := range b {
		if by == 0 {
			n += 8
			continue
		}
		n += bits.LeadingZeros8(by)
		break
	}
	return n
}

func appendCandidate(dst []byte, i uint64, enc PoWEncoding, charset []byte) []byte {
	switch enc {
	case PoWHex:
		return strconv.AppendUint(dst, i, 16)
	case PoWRaw:
		var tmp [8]byte
		binary.BigEndian.PutUint64(tmp[:], i)
		start := 0
		for start < 7 && tmp[start] == 0 {
			start++
		}
		return append(dst, tmp[start:]...)
	case PoWCharset:
		if len(charset) == 0 {
			return strconv.AppendUint(dst, i, 10)
		}
		return appendBaseN(dst, i, charset)
	default:
		return strconv.AppendUint(dst, i, 10)
	}
}

func appendBaseN(dst []byte, i uint64, charset []byte) []byte {
	n := uint64(len(charset))
	start := len(dst)
	if i == 0 {
		return append(dst, charset[0])
	}
	for i > 0 {
		dst = append(dst, charset[i%n])
		i /= n
	}
	s := dst[start:]
	for l, r := 0, len(s)-1; l < r; l, r = l+1, r-1 {
		s[l], s[r] = s[r], s[l]
	}
	return dst
}
