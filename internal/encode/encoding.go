// Package encode provides encoding utilities.
package encode

import (
	"errors"

	"github.com/bytemare/cryptotools/encoding"
)

const (
	MaxEncoding1 = 1
	MaxEncoding2 = 2
)

var (
	errI2OSPLength  = errors.New("requested size is too big")
	errHeaderLength = errors.New("insufficient header length for decoding")
	errTotalLength  = errors.New("insufficient total length for decoding")
)

func EncodeVectorLen(in []byte, length int) []byte {
	switch length {
	case MaxEncoding1:
		return append(encoding.I2OSP(len(in), MaxEncoding1), in...)
	case MaxEncoding2:
		return append(encoding.I2OSP(len(in), MaxEncoding2), in...)
	default:
		panic(errI2OSPLength)
	}
}

func EncodeVector(in []byte) []byte {
	return EncodeVectorLen(in, MaxEncoding2)
}

func decodeVectorLen(in []byte, size int) (data []byte, offset int, err error) {
	if len(in) < size {
		return nil, 0, errHeaderLength
	}

	dataLen := encoding.OS2IP(in[0:size])
	offset = size + dataLen

	if len(in) < offset {
		return nil, 0, errTotalLength
	}

	return in[size:offset], offset, nil
}

func DecodeVector(in []byte) (data []byte, offset int, err error) {
	return decodeVectorLen(in, MaxEncoding2)
}
