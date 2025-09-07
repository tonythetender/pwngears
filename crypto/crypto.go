package crypto

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"log/slog"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tonythetender/pwngears"
)

type CryptoEngine struct {
	logger *slog.Logger
}

func NewCryptoEngine() *CryptoEngine {
	logger, err := pwngears.NewDefaultLogger("INFO")
	if err != nil {
		log.Fatalf("error generating the default logger: %v", err)
	}
	return &CryptoEngine{
		logger: logger,
	}
}

type Pattern struct {
	Prefix string
	Suffix string
	Regex  *regexp.Regexp
}

func (p Pattern) Match(s string) bool {
	if p.Prefix != "" && !strings.HasPrefix(s, p.Prefix) {
		return false
	}
	if p.Suffix != "" && !strings.HasSuffix(s, p.Suffix) {
		return false
	}
	if p.Regex != nil && !p.Regex.MatchString(s) {
		return false
	}
	return (p.Prefix != "" || p.Suffix != "" || p.Regex != nil)
}

type Cipher interface {
	Name() string
	Keys(ctx context.Context, maxLen int) <-chan []byte
	Decrypt(ciphertext, key []byte) []byte
}

type Result struct {
	Cipher    string
	Key       []byte
	Plaintext []byte
}

type DecryptOptions struct {
	MaxKeyLen    int
	FindAll      bool
	Timeout      time.Duration
	Workers      int
	Pattern      Pattern
	ExactKeyLens []int

	Progress         func(done, total uint64)
	ProgressInterval time.Duration
}

type DecryptOption func(*DecryptOptions)

func WithMaxKeyLength(length int) DecryptOption {
	return func(o *DecryptOptions) {
		o.MaxKeyLen = length
	}
}

func WithFindAllPossibleKeys(all bool) DecryptOption {
	return func(o *DecryptOptions) {
		o.FindAll = all
	}
}

func WithTimeout(time time.Duration) DecryptOption {
	return func(o *DecryptOptions) {
		o.Timeout = time
	}
}

func WithWorkersCount(workersCount int) DecryptOption {
	return func(o *DecryptOptions) {
		o.Workers = workersCount
	}
}

func WithPatternPrefix(prefix string) DecryptOption {
	return func(o *DecryptOptions) {
		o.Pattern.Prefix = prefix
	}
}

func WithPatternSuffix(suffix string) DecryptOption {
	return func(o *DecryptOptions) {
		o.Pattern.Suffix = suffix
	}
}

func WithPatternRegex(regex string) DecryptOption {
	return func(o *DecryptOptions) {
		pattern := regexp.MustCompile(regex)
		o.Pattern.Regex = pattern
	}
}

func WithExactKeyLength(length int) DecryptOption {
	return func(o *DecryptOptions) {
		o.ExactKeyLens = append(o.ExactKeyLens, length)
	}
}

func WithCustomProgressBarFunction(progressFunc func(done, total uint64)) DecryptOption {
	return func(o *DecryptOptions) {
		o.Progress = progressFunc
	}
}

func WithProgressInterval(interval time.Duration) DecryptOption {
	return func(o *DecryptOptions) {
		o.ProgressInterval = interval
	}
}

type lensKey struct{}

func withLens(ctx context.Context, lens []int) context.Context {
	return context.WithValue(ctx, lensKey{}, lens)
}
func lensFromCtx(ctx context.Context, maxLen int) []int {
	if v, ok := ctx.Value(lensKey{}).([]int); ok && len(v) > 0 {
		return v
	}
	out := make([]int, 0, maxLen)
	for l := 1; l <= maxLen; l++ {
		out = append(out, l)
	}
	return out
}

func getDefaultBruteForceOptions() *DecryptOptions {
	return &DecryptOptions{
		MaxKeyLen:        20,
		FindAll:          true,
		Timeout:          0,
		ExactKeyLens:     make([]int, 0),
		Progress:         DefaultProgressBar,
		ProgressInterval: 250 * time.Millisecond,
	}

}

func (c *CryptoEngine) BruteForce(cipher Cipher, ciphertext []byte, options ...DecryptOption) []Result {

	opts := getDefaultBruteForceOptions()

	for _, option := range options {
		option(opts)
	}

	if opts.MaxKeyLen >= 14 && opts.FindAll && opts.Timeout == 0 {
		c.logger.Warn("Using a high maximum key length with the FindAll option and no timeout will take a long time")
	}
	hasPattern := opts.Pattern.Prefix != "" || opts.Pattern.Suffix != "" || opts.Pattern.Regex != nil
	if !hasPattern {
		c.logger.Error("Pattern must include Prefix, Suffix, and/or Regex")
		return nil
	}

	ctx := context.Background()
	var cancel context.CancelFunc
	if opts.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	defer cancel()
	lens := opts.ExactKeyLens
	if len(lens) == 0 {
		for l := 1; l <= opts.MaxKeyLen; l++ {
			lens = append(lens, l)
		}
	}
	ctx = withLens(ctx, lens)

	workers := opts.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	total, known := EstimateTotalKeys(cipher, opts)
	var processed uint64
	progressEvery := opts.ProgressInterval
	if progressEvery <= 0 {
		progressEvery = 250 * time.Millisecond
	}
	stopProg := make(chan struct{})
	if opts.Progress != nil {
		opts.Progress(0, func() uint64 {
			if known {
				return total
			}
			return 0
		}())
		t := time.NewTicker(progressEvery)
		go func() {
			defer t.Stop()
			for {
				select {
				case <-t.C:
					opts.Progress(atomic.LoadUint64(&processed), func() uint64 {
						if known {
							return total
						}
						return 0
					}())
				case <-stopProg:
					opts.Progress(atomic.LoadUint64(&processed), func() uint64 {
						if known {
							return total
						}
						return 0
					}())
					return
				}
			}
		}()
	}

	keyCh := cipher.Keys(ctx, opts.MaxKeyLen)

	type found struct {
		r   Result
		hit bool
	}
	foundCh := make(chan found, workers)

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for key := range keyCh {
				atomic.AddUint64(&processed, 1)

				pt := cipher.Decrypt(ciphertext, key)
				if opts.Pattern.Match(string(pt)) {
					c.logger.Info("match found",
						slog.String("cipher", cipher.Name()),
						slog.String("key", hex.EncodeToString(key)),
						slog.String("plaintext", string(pt)),
					)
					select {
					case foundCh <- found{r: Result{
						Cipher:    cipher.Name(),
						Key:       append([]byte(nil), key...),
						Plaintext: append([]byte(nil), pt...),
					}, hit: true}:
					case <-ctx.Done():
						return
					}
					if !opts.FindAll {
						cancel()
						return
					}
				}
				select {
				case <-ctx.Done():
					return
				default:
				}
			}
		}()
	}

	results := make([]Result, 0, 4)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

loop:
	for {
		select {
		case f := <-foundCh:
			if f.hit {
				results = append(results, f.r)
				if !opts.FindAll {
				}
			}
		case <-done:
			break loop
		case <-ctx.Done():
		}
	}

	if opts.Progress != nil {
		close(stopProg)
	}
	if len(results) == 0 {
		c.logger.Error("no matches found")
		return nil
	}
	return results
}

func generateKeysBaseK(ctx context.Context, alphabet []byte, lens []int, buffer int) <-chan []byte {
	out := make(chan []byte, buffer)
	go func() {
		defer close(out)
		if len(alphabet) == 0 || len(lens) == 0 {
			return
		}
		var recur func(prefix []byte, length int)
		recur = func(prefix []byte, length int) {
			if ctx.Err() != nil {
				return
			}
			if length == 0 {
				cp := append([]byte(nil), prefix...)
				select {
				case out <- cp:
				case <-ctx.Done():
				}
				return
			}
			for _, ch := range alphabet {
				if ctx.Err() != nil {
					return
				}
				recur(append(prefix, ch), length-1)
			}
		}
		for _, L := range lens {
			if L <= 0 {
				continue
			}
			recur(nil, L)
		}
	}()
	return out
}

type XORCipher struct {
	KeyAlphabet []byte
	SkipZero    bool
}

func (x XORCipher) Name() string { return "XOR" }

func (x XORCipher) Keys(ctx context.Context, maxLen int) <-chan []byte {
	lens := lensFromCtx(ctx, maxLen)
	var alpha []byte
	if len(x.KeyAlphabet) > 0 {
		alpha = x.KeyAlphabet
	} else {
		alpha = make([]byte, 256)
		for i := 0; i < 256; i++ {
			alpha[i] = byte(i)
		}
		if x.SkipZero {
			alpha = alpha[1:]
		}
	}
	return generateKeysBaseK(ctx, alpha, lens, 1024)
}

func (x XORCipher) Decrypt(ciphertext, key []byte) []byte {
	if len(key) == 0 {
		return append([]byte(nil), ciphertext...)
	}
	out := make([]byte, len(ciphertext))
	for i := range ciphertext {
		out[i] = ciphertext[i] ^ key[i%len(key)]
	}
	return out
}

type CaesarCipher struct{}

func (c CaesarCipher) Name() string { return "Caesar/ROT" }

func (c CaesarCipher) Keys(ctx context.Context, maxLen int) <-chan []byte {
	out := make(chan []byte, 32)
	go func() {
		defer close(out)
		if maxLen <= 0 {
			return
		}
		for s := 0; s < 26; s++ {
			select {
			case out <- []byte{byte(s)}:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

func rotLetter(ch byte, shift int) byte {
	if ch >= 'A' && ch <= 'Z' {
		return byte('A' + (int(ch-'A')-shift+26)%26)
	}
	if ch >= 'a' && ch <= 'z' {
		return byte('a' + (int(ch-'a')-shift+26)%26)
	}
	return ch
}

func (c CaesarCipher) Decrypt(ciphertext, key []byte) []byte {
	if len(key) == 0 {
		return append([]byte(nil), ciphertext...)
	}
	shift := int(key[0] % 26)
	out := make([]byte, len(ciphertext))
	for i := range ciphertext {
		out[i] = rotLetter(ciphertext[i], shift)
	}
	return out
}

type VigenereCipher struct{}

func (v VigenereCipher) Name() string { return "Vigenere" }

func (v VigenereCipher) Keys(ctx context.Context, maxLen int) <-chan []byte {
	lens := lensFromCtx(ctx, maxLen)
	alpha := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	return generateKeysBaseK(ctx, alpha, lens, 1024)
}

func (v VigenereCipher) Decrypt(ciphertext, key []byte) []byte {
	if len(key) == 0 {
		return append([]byte(nil), ciphertext...)
	}
	out := make([]byte, len(ciphertext))
	k := 0
	for i := range ciphertext {
		ch := ciphertext[i]
		if ch >= 'A' && ch <= 'Z' {
			shift := int(key[k%len(key)] - 'A')
			out[i] = byte('A' + (int(ch-'A')-shift+26)%26)
			k++
		} else if ch >= 'a' && ch <= 'z' {
			shift := int(key[k%len(key)] - 'A')
			out[i] = byte('a' + (int(ch-'a')-shift+26)%26)
			k++
		} else {
			out[i] = ch
		}
	}
	return out
}

func EstimateTotalKeys(cipher Cipher, opts *DecryptOptions) (uint64, bool) {
	lens := opts.ExactKeyLens
	if len(lens) == 0 {
		for l := 1; l <= opts.MaxKeyLen; l++ {
			lens = append(lens, l)
		}
	}
	sumPow := func(base int) (uint64, bool) {
		var total, last uint64
		for _, L := range lens {
			p := uint64(1)
			for i := 0; i < L; i++ {
				if p > ^uint64(0)/uint64(base) {
					return 0, false
				}
				p *= uint64(base)
			}
			last = p
			if total > ^uint64(0)-p {
				return 0, false
			}
			total += p
		}
		_ = last
		return total, true
	}
	switch c := cipher.(type) {
	case XORCipher:
		base := 256
		if len(c.KeyAlphabet) > 0 {
			base = len(c.KeyAlphabet)
		} else if c.SkipZero {
			base = 255
		}
		return sumPow(base)
	case VigenereCipher:
		return sumPow(26)
	case CaesarCipher:
		return 26, true
	default:
		return 0, false
	}
}

func DefaultProgressBar(done, total uint64) {
	if total > 0 {
		pct := float64(done) * 100 / float64(total)
		fmt.Printf("\rProgress: %6.2f%%  (%d / %d)", pct, done, total)
	} else {
		fmt.Printf("\rTried keys: %d", done)
	}
}
