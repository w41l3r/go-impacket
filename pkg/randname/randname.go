package randname

import (
	"crypto/rand"
	"math/big"
)

const (
	alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits   = "0123456789"
	alnum    = alphabet + digits
)

func Alpha(n int) string {
	return pick(alphabet, n)
}

func Alnum(n int) string {
	return pick(alnum, n)
}

func Hex(n int) string {
	const hex = "0123456789abcdef"
	return pick(hex, n)
}

func pick(charset string, n int) string {
	b := make([]byte, n)
	max := big.NewInt(int64(len(charset)))
	for i := range b {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			b[i] = charset[0]
			continue
		}
		b[i] = charset[idx.Int64()]
	}
	return string(b)
}
