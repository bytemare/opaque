// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2022 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package encoding

import (
	"encoding/binary"
	"errors"
)

var (
	errInputNegative  = errors.New("negative input")
	errInputLarge     = errors.New("input is too high for length")
	errLengthNegative = errors.New("length is negative or 0")
	errLengthTooBig   = errors.New("requested length is > 4")

	errInputEmpty    = errors.New("nil or empty input")
	errInputTooLarge = errors.New("input too large for integer")
)

// I2OSP 32-bit Integer to Octet Stream Primitive on maximum 4 bytes.
func I2OSP(value int, length uint16) []byte {
	if length <= 0 {
		panic(errLengthNegative)
	}

	if length > 4 {
		panic(errLengthTooBig)
	}

	out := make([]byte, 4)

	switch v := value; {
	case v < 0:
		panic(errInputNegative)
	case v >= 1<<(8*length):
		panic(errInputLarge)
	case length == 1:
		binary.BigEndian.PutUint16(out, uint16(v))
		return out[1:2]
	case length == 2:
		binary.BigEndian.PutUint16(out, uint16(v))
		return out[:2]
	case length == 3:
		binary.BigEndian.PutUint32(out, uint32(v))
		return out[1:]
	default: // length == 4
		binary.BigEndian.PutUint32(out, uint32(v))
		return out
	}
}

// OS2IP Octet Stream to Integer Primitive on maximum 4 bytes / 32 bits.
func OS2IP(input []byte) int {
	switch length := len(input); {
	case length == 0:
		panic(errInputEmpty)
	case length == 1:
		b := []byte{0, input[0]}
		return int(binary.BigEndian.Uint16(b))
	case length == 2:
		return int(binary.BigEndian.Uint16(input))
	case length == 3:
		b := append([]byte{0}, input...)
		return int(binary.BigEndian.Uint32(b))
	case length == 4:
		return int(binary.BigEndian.Uint32(input))
	default:
		panic(errInputTooLarge)
	}
}
