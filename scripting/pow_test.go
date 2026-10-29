package scripting

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math/bits"
	"strings"
	"testing"
)

func digestLeadingZeroBits(sum []byte) int {
	n := 0
	for _, b := range sum {
		if b == 0 {
			n += 8
			continue
		}
		n += bits.LeadingZeros8(b)
		break
	}
	return n
}

func TestPoWLeadingZeroBits(t *testing.T) {
	prefix := []byte("chal-")
	for _, b := range []int{4, 8, 12} {
		got := PoWLeadingZeroBits(prefix, b)
		sum := sha256.Sum256(got.Input)
		if !bytes.Equal(sum[:], got.Digest) {
			t.Fatalf("bits=%d: Digest != sha256(Input)", b)
		}
		if !bytes.HasPrefix(got.Input, prefix) {
			t.Fatalf("bits=%d: Input does not start with prefix", b)
		}
		if !bytes.Equal(got.Input[len(prefix):], got.Suffix) {
			t.Fatalf("bits=%d: Input != prefix||Suffix", b)
		}
		if z := digestLeadingZeroBits(got.Digest); z < b {
			t.Fatalf("bits=%d: only %d leading zero bits", b, z)
		}
	}
}

func TestPoWLeadingZeroNibbles(t *testing.T) {
	prefix := []byte("x")
	for _, k := range []int{1, 2} {
		got := PoWLeadingZeroNibbles(prefix, k)
		h := hex.EncodeToString(got.Digest)
		if !strings.HasPrefix(h, strings.Repeat("0", k)) {
			t.Fatalf("nibbles=%d: digest %s lacks %d leading zeros", k, h, k)
		}
	}
}

func TestPoWPrefixEquals(t *testing.T) {
	target := []byte{0xab}
	got := PoWPrefixEquals([]byte("p-"), target)
	if !bytes.HasPrefix(got.Digest, target) {
		t.Fatalf("digest %x does not start with %x", got.Digest, target)
	}
}

func TestPoWSuffixEquals(t *testing.T) {
	target := []byte{0x00}
	got := PoWSuffixEquals(target)
	// hashes X alone, so Input == Suffix
	if !bytes.Equal(got.Input, got.Suffix) {
		t.Fatalf("suffix mode should hash X alone: Input=%q Suffix=%q", got.Input, got.Suffix)
	}
	if !bytes.HasSuffix(got.Digest, target) {
		t.Fatalf("digest %x does not end with %x", got.Digest, target)
	}
}

func TestPoWEncodings(t *testing.T) {
	// Charset-restricted X must only contain charset bytes.
	cs := "abcdef0123456789"
	got := PoWLeadingZeroBits([]byte("z"), 8, WithPoWCharset(cs))
	for _, c := range got.Suffix {
		if !strings.ContainsRune(cs, rune(c)) {
			t.Fatalf("charset suffix %q contains out-of-charset byte %q", got.Suffix, c)
		}
	}
	sum := sha256.Sum256(got.Input)
	if digestLeadingZeroBits(sum[:]) < 8 {
		t.Fatalf("charset PoW did not satisfy the gate")
	}
}

func BenchmarkPoW16Bits(b *testing.B) {
	for i := 0; i < b.N; i++ {
		PoWLeadingZeroBits([]byte("bench-"), 16)
	}
}
