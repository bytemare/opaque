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

var ErrI2OSPLength = errors.New("requested size is too big")

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
		panic(ErrI2OSPLength)
	}
}

func EncodeVector(in []byte) []byte {
	return EncodeVectorLen(in, 2)
}
