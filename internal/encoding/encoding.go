// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020 Daniel Bourdrez. All Rights Reserved.
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

func OS2IP(in []byte) int {
	return encoding.OS2IP(in)
}

func I2OSP(value, length int) []byte {
	return encoding.I2OSP(value, length)
}

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
	return decodeVectorLen(in, 2)
}
