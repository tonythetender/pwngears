package bruteforce

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/tonythetender/pwngears/process"
)

type Bruteforcer struct {
	Charset       string
	MaxLength     int
	Delay         time.Duration
	StopOnSuccess bool
	Workers       int
}

func NewBruteforcer() *Bruteforcer {
	return &Bruteforcer{
		Charset:       "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-{}",
		MaxLength:     50,
		Delay:         0,
		StopOnSuccess: true,
		Workers:       1,
	}
}

func (b *Bruteforcer) workers() int {
	if b.Workers < 1 {
		return 1
	}
	return b.Workers
}

type TestFunc func(payload string) (bool, error)

type GreaterFunc func(pos, value int) (bool, error)

type CharFunc func(pos int, c byte) (bool, error)

func firstTrue[T any](items []T, workers int, test func(T) (bool, error)) (T, bool, error) {
	var zero T
	if workers < 1 {
		workers = 1
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	jobs := make(chan T)
	go func() {
		defer close(jobs)
		for _, it := range items {
			select {
			case jobs <- it:
			case <-ctx.Done():
				return
			}
		}
	}()

	var (
		mu       sync.Mutex
		result   T
		found    bool
		firstErr error
		wg       sync.WaitGroup
	)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range jobs {
				if ctx.Err() != nil {
					return
				}
				ok, err := test(it)
				if err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
					cancel()
					return
				}
				if ok {
					mu.Lock()
					if !found {
						found = true
						result = it
					}
					mu.Unlock()
					cancel()
					return
				}
			}
		}()
	}
	wg.Wait()

	if firstErr != nil {
		return zero, false, firstErr
	}
	return result, found, nil
}

func (b *Bruteforcer) BruteforceCharByChar(prefix, suffix string, testFunc TestFunc) (string, error) {
	result := prefix
	chars := []rune(b.Charset)

	for i := len(prefix); i < b.MaxLength; i++ {
		ch, found, err := firstTrue(chars, b.workers(), func(c rune) (bool, error) {
			if b.Delay > 0 {
				time.Sleep(b.Delay)
			}
			return testFunc(result + string(c) + suffix)
		})
		if err != nil {
			return result, err
		}
		if !found {
			break
		}
		result += string(ch)
		process.Success(fmt.Sprintf("Found: %s", result))
	}

	return result, nil
}

func (b *Bruteforcer) BlindSQL(prefix string, testFunc TestFunc) (string, error) {
	result := ""
	chars := []rune(b.Charset)

	for position := 1; position <= b.MaxLength; position++ {
		pos := position
		ch, found, err := firstTrue(chars, b.workers(), func(c rune) (bool, error) {
			if b.Delay > 0 {
				time.Sleep(b.Delay)
			}
			payload := fmt.Sprintf("%s AND SUBSTRING((SELECT %s),%d,1)='%c'",
				prefix, prefix, pos, c)
			return testFunc(payload)
		})
		if err != nil {
			return result, err
		}
		if !found {
			break
		}
		result += string(ch)
		process.Success(fmt.Sprintf("Position %d: %c (Current: %s)", pos, ch, result))
	}

	return result, nil
}

func (b *Bruteforcer) BinarySearch(greater GreaterFunc) (string, error) {
	var out []byte

	for pos := 1; pos <= b.MaxLength; pos++ {
		lo, hi := 0, 127
		for lo < hi {
			mid := (lo + hi) / 2
			if b.Delay > 0 {
				time.Sleep(b.Delay)
			}
			g, err := greater(pos, mid)
			if err != nil {
				return string(out), err
			}
			if g {
				lo = mid + 1
			} else {
				hi = mid
			}
		}
		if lo == 0 {
			break
		}
		out = append(out, byte(lo))
		process.Success(fmt.Sprintf("Position %d: %c (Current: %s)", pos, lo, string(out)))
	}

	return string(out), nil
}

func (b *Bruteforcer) Scan(test CharFunc) (string, error) {
	var out []byte
	chars := []byte(b.Charset)

	for position := 1; position <= b.MaxLength; position++ {
		pos := position
		c, found, err := firstTrue(chars, b.workers(), func(ch byte) (bool, error) {
			if b.Delay > 0 {
				time.Sleep(b.Delay)
			}
			return test(pos, ch)
		})
		if err != nil {
			return string(out), err
		}
		if !found {
			break
		}
		out = append(out, c)
		process.Success(fmt.Sprintf("Position %d: %c (Current: %s)", pos, c, string(out)))
	}

	return string(out), nil
}

func (b *Bruteforcer) TimingAttack(basePayload string, testFunc func(string) time.Duration, threshold time.Duration) (string, error) {
	result := ""

	for i := 0; i < b.MaxLength; i++ {
		found := false

		for _, char := range b.Charset {
			if b.Delay > 0 {
				time.Sleep(b.Delay)
			}

			testPayload := basePayload + result + string(char)
			duration := testFunc(testPayload)

			if duration > threshold {
				result += string(char)
				found = true
				process.Success(fmt.Sprintf("Timing attack found: %s (took %v)", result, duration))
				break
			}
		}

		if !found {
			break
		}
	}

	return result, nil
}

func (b *Bruteforcer) FuzzParameter(basePayload string, wordlist []string, testFunc TestFunc) ([]string, error) {
	var validPayloads []string

	for _, word := range wordlist {
		if b.Delay > 0 {
			time.Sleep(b.Delay)
		}

		payload := strings.Replace(basePayload, "FUZZ", word, -1)
		success, err := testFunc(payload)
		if err != nil {
			return validPayloads, err
		}

		if success {
			validPayloads = append(validPayloads, word)
			process.Success(fmt.Sprintf("Valid parameter found: %s", word))
		}
	}

	return validPayloads, nil
}

func (b *Bruteforcer) LengthOracle(prefix string, testFunc TestFunc) (int, error) {
	for length := 1; length <= b.MaxLength; length++ {
		testPayload := fmt.Sprintf("%s LENGTH=%d", prefix, length)
		success, err := testFunc(testPayload)
		if err != nil {
			return 0, err
		}

		if success {
			process.Success(fmt.Sprintf("Length found: %d", length))
			return length, nil
		}
	}

	return 0, fmt.Errorf("length not found within max length")
}

func GenerateCharset(options ...string) string {
	charset := ""
	for _, opt := range options {
		switch opt {
		case "lowercase":
			charset += "abcdefghijklmnopqrstuvwxyz"
		case "uppercase":
			charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		case "digits":
			charset += "0123456789"
		case "special":
			charset += "!@#$%^&*()_+-=[]{}|;:,.<>?"
		case "hex":
			charset += "0123456789abcdef"
		case "alphanumeric":
			charset += "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		default:
			charset += opt
		}
	}
	return charset
}
