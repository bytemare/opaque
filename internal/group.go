// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package internal provides structures and functions to operate OPAQUE that are not part of the public API.
package internal

import (
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/group/ciphersuite"
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

var ScalarLength = map[ciphersuite.Identifier]int{
	ciphersuite.Ristretto255Sha512: ristrettoPointLength,
	// ciphersuite.Decaf448Shake256: 56,
	ciphersuite.P256Sha256: p256ScalarLength,
	ciphersuite.P384Sha512: p384ScalarLength,
	ciphersuite.P521Sha512: p521ScalarLength,
}

var PointLength = map[ciphersuite.Identifier]int{
	ciphersuite.Ristretto255Sha512: ristrettoScalarLength,
	// ciphersuite.Decaf448Shake256: 56,
	ciphersuite.P256Sha256: p256PointLength,
	ciphersuite.P384Sha512: p384PointLength,
	ciphersuite.P521Sha512: p521PointLength,
}

func SerializeScalar(s group.Scalar, c ciphersuite.Identifier) []byte {
	length, ok := ScalarLength[c]
	if !ok {
		panic("invalid suite")
	}

	e := s.Bytes()

	for len(e) < length {
		e = append([]byte{0x00}, e...)
	}

	return e
}

func SerializePoint(e group.Element, c ciphersuite.Identifier) []byte {
	return PadPoint(e.Bytes(), c)
}

func PadPoint(point []byte, c ciphersuite.Identifier) []byte {
	length, ok := PointLength[c]
	if !ok {
		panic("invalid suite")
	}

	for len(point) < length {
		point = append([]byte{0x00}, point...)
	}

	return point
}
