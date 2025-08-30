// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package encoding

import (
	"encoding/binary"
	"errors"
)

// I2OSP/OS2IP errors.
var (
	// ErrInputNegative happens when the provider integer is negative.
	ErrInputNegative = errors.New("negative input")

	// ErrInputLarge happens when the provider value is too large for the specified length.
	ErrInputLarge = errors.New("input value is too high for length")

	// ErrLengthNegativeOrZero happens when the specified length is negative or 0.
	ErrLengthNegativeOrZero = errors.New("length is negative or 0")

	// ErrLengthTooBig happens when the specified length is > 4.
	ErrLengthTooBig = errors.New("requested length is > 4")

	// ErrInputEmpty happens when the input is nil or empty.
	ErrInputEmpty = errors.New("nil or empty input")

	// ErrInputTooLarge happens when the input is longer than 4 bytes.
	ErrInputTooLarge = errors.New("input too large for integer")
)

// I2OSP 32-bit Integer to Octet Stream Primitive on maximum 4 bytes.
func I2OSP(value int, length uint16) []byte {
	if length <= 0 {
		panic(ErrLengthNegativeOrZero)
	}

	if length > 4 {
		panic(ErrLengthTooBig)
	}

	out := make([]byte, 4)

	switch {
	case value < 0:
		panic(ErrInputNegative)
	case value >= 1<<(8*length):
		panic(ErrInputLarge)
	case length == 1:
		binary.BigEndian.PutUint16(out, uint16(value)) //nolint:gosec // overflow is checked beforehand.
		return out[1:2]
	case length == 2:
		binary.BigEndian.PutUint16(out, uint16(value)) //nolint:gosec // overflow is checked beforehand.
		return out[:2]
	case length == 3:
		binary.BigEndian.PutUint32(out, uint32(value)) //nolint:gosec // overflow is checked beforehand.
		return out[1:]
	default: // length == 4
		binary.BigEndian.PutUint32(out, uint32(value)) //nolint:gosec // overflow is checked beforehand.
		return out
	}
}

// OS2IP Octet Stream to Integer Primitive on maximum 4 bytes / 32 bits.
func OS2IP(input []byte) int {
	switch len(input) {
	case 0:
		panic(ErrInputEmpty)
	case 1:
		b := []byte{0, input[0]}
		return int(binary.BigEndian.Uint16(b))
	case 2:
		return int(binary.BigEndian.Uint16(input))
	case 3:
		b := append([]byte{0}, input...)
		return int(binary.BigEndian.Uint32(b))
	case 4:
		return int(binary.BigEndian.Uint32(input))
	default:
		panic(ErrInputTooLarge)
	}
}
