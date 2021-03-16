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
