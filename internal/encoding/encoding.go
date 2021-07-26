// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package encoding provides encoding utilities.
package encoding

import (
	"errors"

	"github.com/bytemare/cryptotools/encoding"
)

var (
	errI2OSPLength  = errors.New("requested size is too big")
	errHeaderLength = errors.New("insufficient header length for decoding")
	errTotalLength  = errors.New("insufficient total length for decoding")
)

// OS2IP Octet Stream to Integer Primitive on maximum 4 bytes / 32 bits.
func OS2IP(in []byte) int {
	return encoding.OS2IP(in)
}

// I2OSP 32 bit Integer to Octet Stream Primitive on maximum 4 bytes.
func I2OSP(value, length int) []byte {
	return encoding.I2OSP(value, length)
}

// EncodeVectorLen returns the input prepended with a byte encoding of its length.
func EncodeVectorLen(input []byte, length int) []byte {
	switch length {
	case 1:
		return append(encoding.I2OSP(len(input), 1), input...)
	case 2:
		return append(encoding.I2OSP(len(input), 2), input...)
	default:
		panic(errI2OSPLength)
	}
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
