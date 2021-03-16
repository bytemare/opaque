package internal

import (
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/group/ciphersuite"
)

const (
	p256PointLength  = 33
	p256ScalarLength = 32
	p384PointLength  = 49
	p384ScalarLength = 48
	p521PointLength  = 67
	p521ScalarLength = 66
)

func ScalarLength(c ciphersuite.Identifier) int {
	switch c {
	case ciphersuite.Ristretto255Sha512:
		return 32
	// case ciphersuite.Decaf448Shake256:
	//	return 56
	case ciphersuite.P256Sha256:
		return p256ScalarLength
	case ciphersuite.P384Sha512:
		return p384ScalarLength
	case ciphersuite.P521Sha512:
		return p521ScalarLength
	default:
		panic("invalid suite")
	}
}

func PointLength(c ciphersuite.Identifier) int {
	switch c {
	case ciphersuite.Ristretto255Sha512:
		return 32
	// case ciphersuite.Decaf448Shake256:
	//	return 56
	case ciphersuite.P256Sha256:
		return p256PointLength
	case ciphersuite.P384Sha512:
		return p384PointLength
	case ciphersuite.P521Sha512:
		return p521PointLength
	default:
		panic("invalid suite")
	}
}

func SerializeScalar(s group.Scalar, c ciphersuite.Identifier) []byte {
	length := ScalarLength(c)
	e := s.Bytes()

	for len(e) < length {
		e = append([]byte{0x00}, e...)
	}

	return e
}

func SerializePoint(e group.Element, c ciphersuite.Identifier) []byte {
	length := PointLength(c)
	p := e.Bytes()

	for len(p) < length {
		p = append([]byte{0x00}, p...)
	}

	return p
}
