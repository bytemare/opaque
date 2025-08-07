// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package oprf implements the Elliptic Curve Oblivious Pseudorandom Function (EC-OPRF) from
// https://tools.ietf.org/html/draft-irtf-cfrg-voprf.
package oprf

import (
	"crypto"

	"github.com/bytemare/ecc"

	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/tag"
)

// Identifier of the OPRF compatible cipher suite to be used.
type Identifier string

const (
	// Ristretto255Sha512 is the OPRF cipher suite of the Ristretto255 group and SHA-512.
	Ristretto255Sha512 Identifier = "ristretto255-SHA512"

	// Decaf448Sha512 is the OPRF cipher suite of the Decaf448 group and SHA-512.
	// decaf448Sha512 Identifier = "decaf448-SHAKE256".

	// P256Sha256 is the OPRF cipher suite of the NIST P-256 group and SHA-256.
	P256Sha256 Identifier = "P256-SHA256"

	// P384Sha384 is the OPRF cipher suite of the NIST P-384 group and SHA-384.
	P384Sha384 Identifier = "P384-SHA384"

	// P521Sha512 is the OPRF cipher suite of the NIST P-512 group and SHA-512.
	P521Sha512 Identifier = "P521-SHA512"

	nbIDs                 = 4
	maxDeriveKeyPairTries = 255
)

// Available returns whether the Identifier has been registered of not.
func (i Identifier) Available() bool {
	// Check for invalid identifiers
	return i == Ristretto255Sha512 ||
		i == P256Sha256 ||
		i == P384Sha384 ||
		i == P521Sha512
}

// IDFromGroup returns the OPRF identifier corresponding to the input ecc.
func IDFromGroup(g ecc.Group) Identifier {
	return map[ecc.Group]Identifier{
		ecc.Ristretto255Sha512: Ristretto255Sha512,
		ecc.P256Sha256:         P256Sha256,
		ecc.P384Sha384:         P384Sha384,
		ecc.P521Sha512:         P521Sha512,
	}[g]
}

// Group returns the Group identifier for the cipher suite.
func (i Identifier) Group() ecc.Group {
	return map[Identifier]ecc.Group{
		Ristretto255Sha512: ecc.Ristretto255Sha512,
		P256Sha256:         ecc.P256Sha256,
		P384Sha384:         ecc.P384Sha384,
		P521Sha512:         ecc.P521Sha512,
	}[i]
}

// DeriveKey returns a scalar deterministically generated from the input.
func (i Identifier) DeriveKey(seed, info []byte) *ecc.Scalar {
	dst := encoding.Concat([]byte(tag.DeriveKeyPairInternal), i.contextString())
	deriveInput := encoding.Concat(seed, encoding.EncodeVector(info))

	var (
		counter uint8
		s       *ecc.Scalar
	)

	for s == nil || s.IsZero() {
		if counter > maxDeriveKeyPairTries {
			panic("DeriveKeyPairError")
		}

		s = i.Group().HashToScalar(encoding.Concat(deriveInput, []byte{counter}), dst)
		counter++
	}

	return s
}

// DeriveKeyPair returns a valid keypair deterministically generated from the input.
func (i Identifier) DeriveKeyPair(seed, info []byte) (*ecc.Scalar, *ecc.Element) {
	sk := i.DeriveKey(seed, info)
	return sk, i.Group().Base().Multiply(sk)
}

func (i Identifier) dst(prefix string) []byte {
	return encoding.Concat([]byte(prefix), i.contextString())
}

func (i Identifier) contextString() []byte {
	return encoding.Concatenate([]byte(tag.OPRFVersionPrefix), []byte(i))
}

func (i Identifier) hash(input ...[]byte) []byte {
	h := map[Identifier]crypto.Hash{
		Ristretto255Sha512: crypto.SHA512,
		P256Sha256:         crypto.SHA256,
		P384Sha384:         crypto.SHA384,
		P521Sha512:         crypto.SHA512,
	}[i].New()
	h.Reset()

	for _, i := range input {
		_, _ = h.Write(i)
	}

	return h.Sum(nil)
}
