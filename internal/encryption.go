package internal

import "errors"

var errXorLength = errors.New("xor input of unequal length")

// Xor returns a new byte slice containing the byte-by-byte xor-ing of the input slices, which must be of the same length.
func Xor(a, b []byte) []byte {
	if len(a) != len(b) {
		panic(errXorLength)
	}

	dst := make([]byte, len(a))

	// if the size is fixed, we could unroll the loop
	for i, r := range a {
		dst[i] = r ^ b[i]
	}

	return dst
}
