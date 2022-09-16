// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2022 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package encoding provides encoding utilities.
package encoding

import "errors"

var (
	errI2OSPLength  = errors.New("requested size is too big")
	errHeaderLength = errors.New("insufficient header length for decoding")
	errTotalLength  = errors.New("insufficient total length for decoding")
)

// EncodeVectorLen returns the input prepended with a byte encoding of its length.
func EncodeVectorLen(input []byte, length int) []byte {
	if length != 1 && length != 2 {
		panic(errI2OSPLength)
	}

	return append(I2OSP(len(input), length), input...)
}

// EncodeVector returns the input with a two-byte encoding of its length.
func EncodeVector(input []byte) []byte {
	return EncodeVectorLen(input, 2)
}

func decodeVectorLen(in []byte, size int) (data []byte, offset int, err error) {
	if len(in) < size {
		return nil, 0, errHeaderLength
	}

	dataLen := OS2IP(in[0:size])
	offset = size + dataLen

	if len(in) < offset {
		return nil, 0, errTotalLength
	}

	return in[size:offset], offset, nil
}

// DecodeVector returns the byte-slice of length indexed in the first two bytes.
func DecodeVector(in []byte) (data []byte, offset int, err error) {
	return decodeVectorLen(in, 2)
}
