package crypto

import "context"

// RailFenceCipher implements the Cipher interface for the rail-fence transposition.
// Its key is a single byte: the number of rails. Because it satisfies Cipher, it
// also works with CryptoEngine.BruteForce (e.g. with a flag Pattern).
type RailFenceCipher struct {
	MaxRails int
}

func (RailFenceCipher) Name() string { return "RailFence" }

func (r RailFenceCipher) Keys(ctx context.Context, maxLen int) <-chan []byte {
	out := make(chan []byte, 16)
	go func() {
		defer close(out)
		max := r.MaxRails
		if max < 2 {
			max = 12
		}
		for rails := 2; rails <= max; rails++ {
			if rails > 255 {
				break
			}
			select {
			case out <- []byte{byte(rails)}:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

func (RailFenceCipher) Decrypt(ciphertext, key []byte) []byte {
	if len(key) == 0 {
		return append([]byte(nil), ciphertext...)
	}
	rails := int(key[0])
	n := len(ciphertext)
	if rails <= 1 || rails >= n {
		return append([]byte(nil), ciphertext...)
	}

	// Map each output position to its rail by walking the zigzag.
	railOf := make([]int, n)
	row, dir := 0, 1
	for i := 0; i < n; i++ {
		railOf[i] = row
		if row == 0 {
			dir = 1
		} else if row == rails-1 {
			dir = -1
		}
		row += dir
	}

	// The ciphertext is the rails read top-to-bottom; refill positions in order.
	out := make([]byte, n)
	idx := 0
	for rr := 0; rr < rails; rr++ {
		for i := 0; i < n; i++ {
			if railOf[i] == rr {
				out[i] = ciphertext[idx]
				idx++
			}
		}
	}
	return out
}
