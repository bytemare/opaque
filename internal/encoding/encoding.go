// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package encoding provides encoding utilities.
package encoding

import (
	"errors"
)

// Encoding/decoding errors.
var (
	// ErrDecoding indicates a decoding error.
	ErrDecoding = errors.New("decoding error")

	// ErrHeaderLength indicates that the header length is insufficient for decoding.
	ErrHeaderLength = errors.New("insufficient header length for decoding")

	// ErrTotalLength indicates that the total length is insufficient for decoding.
	ErrTotalLength = errors.New("insufficient total length for decoding")

	// ErrMissingOutput indicates that no output slice was provided for decoding.
	ErrMissingOutput = errors.New("missing output slice for decoding")

	// ErrNilOutput indicates that a nil output slice was provided for decoding.
	ErrNilOutput = errors.New("nil output slice for decoding")

	// ErrEmptyEncoded indicates that the decoding returned empty data.
	ErrEmptyEncoded = errors.New("decoding yielded empty data")
)

// EncodeVectorLen returns the input prepended with a byte encoding of its length.
func EncodeVectorLen(input []byte, length uint16) []byte {
	return append(I2OSP(len(input), length), input...)
}

// EncodeVector returns the input with a two-byte encoding of its length.
func EncodeVector(input []byte) []byte {
	return EncodeVectorLen(input, 2)
}

func decodeVectorLen(in []byte, size int) (data []byte, offset int, err error) {
	if len(in) < size {
		return nil, 0, errors.Join(ErrDecoding, ErrHeaderLength)
	}

	dataLen := OS2IP(in[0:size])
	offset = size + dataLen

	if len(in) < offset {
		return nil, 0, errors.Join(ErrDecoding, ErrTotalLength)
	}

	return in[size:offset], offset, nil
}

// DecodeVector returns the byte-slice of length indexed in the first two bytes.
func DecodeVector(in []byte) (data []byte, offset int, err error) {
	return decodeVectorLen(in, 2)
}

// DecodeLongVector decodes a vector of concatenated 2-byte length-prefixed byte slices, and stores the encoded slices
// in the provided output slice.
func DecodeLongVector(in []byte, out ...*[]byte) error {
	if len(in) < 2 {
		return errors.Join(ErrDecoding, ErrHeaderLength)
	}

	if len(out) == 0 {
		return errors.Join(ErrDecoding, ErrMissingOutput)
	}

	var (
		d             []byte
		index, offset int
		err           error
	)

	for _, target := range out {
		if target == nil {
			return errors.Join(ErrDecoding, ErrNilOutput)
		}

		d, offset, err = DecodeVector(in[index:])
		if err != nil {
			return err
		}

		if len(d) == 0 {
			return errors.Join(ErrDecoding, ErrEmptyEncoded)
		}

		*target = d
		index += offset
	}

	return nil
}
