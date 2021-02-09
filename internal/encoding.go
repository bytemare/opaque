package internal

import (
	"errors"
	"github.com/bytemare/cryptotools/encoding"
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

func decodeVectorLen(in []byte, size int) ([]byte, int) {
	if len(in) < size {
		panic("Insufficient length")
	}

	dataLen := encoding.OS2IP(in[0:size])
	total := size + dataLen

	if len(in) < total {
		panic("Insufficient length (2)")
	}
	return in[size:total], total
}

func DecodeVector(in []byte) ([]byte, int) {
	return decodeVectorLen(in, 2)
}
