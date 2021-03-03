package internal

import (
	"errors"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/group/ciphersuite"
)

var errI2OSPLength = errors.New("requested size is too big")

func EncodeVectorLen(in []byte, length int) []byte {
	switch length {
	case 1:
		return append(encoding.I2OSP(len(in), 1), in...)
	case 2:
		return append(encoding.I2OSP(len(in), 2), in...)
	default:
		panic(errI2OSPLength)
	}
}

func EncodeVector(in []byte) []byte {
	return EncodeVectorLen(in, 2)
}

func decodeVectorLen(in []byte, size int) ([]byte, int, error) {
	if len(in) < size {
		return nil, 0, errors.New("insufficient header length for decoding")
	}

	dataLen := encoding.OS2IP(in[0:size])
	total := size + dataLen

	if len(in) < total {
		return nil, 0, errors.New("insufficient total length for decoding")
	}

	return in[size:total], total, nil
}

func DecodeVector(in []byte) ([]byte, int, error) {
	return decodeVectorLen(in, 2)
}

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
	// case ciphersuite.Dec:
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
	// case ciphersuite.Decaf448Sha512:
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
