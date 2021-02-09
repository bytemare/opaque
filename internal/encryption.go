package internal

func Xor(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("xoring slices must be of same length")
	}

	dst := make([]byte, len(a))

	// if the size is fixed, we could unroll the loop
	for i, r := range a {
		dst[i] = r ^ b[i]
	}

	return dst
}
