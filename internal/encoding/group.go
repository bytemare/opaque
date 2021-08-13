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
	"github.com/bytemare/crypto/group"
)

const (
	ristrettoPointLength  = 32
	ristrettoScalarLength = 32
	p256PointLength       = 33
	p256ScalarLength      = 32
	p384PointLength       = 49
	p384ScalarLength      = 48
	p521PointLength       = 67
	p521ScalarLength      = 66
)

// ScalarLength indexes the length of scalars.
var ScalarLength = map[group.Group]int{
	group.Ristretto255Sha512: ristrettoScalarLength,
	// group.Decaf448Shake256: 56,
	group.P256Sha256: p256ScalarLength,
	group.P384Sha512: p384ScalarLength,
	group.P521Sha512: p521ScalarLength,
}

// PointLength indexes the length of elements.
var PointLength = map[group.Group]int{
	group.Ristretto255Sha512: ristrettoPointLength,
	// group.Decaf448Shake256: 56,
	group.P256Sha256: p256PointLength,
	group.P384Sha512: p384PointLength,
	group.P521Sha512: p521PointLength,
}

// SerializeScalar pads the given scalar if necessary.
func SerializeScalar(s *group.Scalar, c group.Group) []byte {
	length := ScalarLength[c]

	e := s.Bytes()

	for len(e) < length {
		e = append([]byte{0x00}, e...)
	}

	return e
}

// SerializePoint pads the given element if necessary.
func SerializePoint(e *group.Point, c group.Group) []byte {
	return PadPoint(e.Bytes(), c)
}

// PadPoint pads the encoded element if necessary.
func PadPoint(point []byte, c group.Group) []byte {
	length := PointLength[c]

	for len(point) < length {
		point = append([]byte{0x00}, point...)
	}

	return point
}
