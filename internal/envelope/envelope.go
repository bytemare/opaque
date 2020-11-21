package envelope

import (
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/opaque/internal/envelope/authenc"
)

type Envelope struct {
	SecEnv []byte
	ClrEnv []byte
}

type Configuration struct {
	algo authenc.Identifier
	hash hash.Hash
}

//func New(rwdu, SecEnv, ClrEnv, nonce []byte, config *Configuration) *Envelope {
//	pad, hmacKey, exportKey := keys(rwdu, nonce, len(SecEnv), config.hash)
//
//	c := xor(SecEnv, pad)
//
//}

func xor(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("xoring slices must be of same length")
	}

	dst := make([]byte, 0, len(a))

	// if the size is fixed, we could unroll the loop
	for i, r := range a {
		dst[i] = r ^ b[i]
	}

	return dst
}

func keys(rwdu, nonce []byte, secEnvLength int, hash hash.Hash) (pad, hmacKey, exportKey []byte) {
	keysInfoSuffix := []byte{69, 110, 118, 85} // EnvU
	i := secEnvLength + hash.OutputSize()
	keys := hash.DeriveKey(rwdu, append(nonce, keysInfoSuffix...), secEnvLength+2*hash.OutputSize())
	return keys[:secEnvLength], keys[secEnvLength:i], keys[i:]
}
