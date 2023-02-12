// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2022 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package oprf implements the Elliptic Curve Oblivious Pseudorandom Function (EC-OPRF) from
// https://tools.ietf.org/html/draft-irtf-cfrg-voprf.
package oprf

import (
	"crypto"

	group "github.com/bytemare/crypto"

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

var (
	suites = make(map[group.Group]Identifier, nbIDs)
	groups = make(map[Identifier]group.Group, nbIDs)
	hashes = make(map[Identifier]crypto.Hash, nbIDs)
)

func init() {
	Ristretto255Sha512.register(group.Ristretto255Sha512, crypto.SHA512)
	P256Sha256.register(group.P256Sha256, crypto.SHA256)
	P384Sha384.register(group.P384Sha384, crypto.SHA384)
	P521Sha512.register(group.P521Sha512, crypto.SHA512)
}

func (i Identifier) register(g group.Group, h crypto.Hash) {
	suites[g] = i
	groups[i] = g
	hashes[i] = h
}

func (i Identifier) dst(prefix string) []byte {
	return encoding.Concat([]byte(prefix), i.contextString())
}

func (i Identifier) contextString() []byte {
	return encoding.Concatenate([]byte(tag.OPRFVersionPrefix), []byte(i))
}

func (i Identifier) hash(input ...[]byte) []byte {
	h := hashes[i].New()
	h.Reset()

	for _, i := range input {
		_, _ = h.Write(i)
	}

	return h.Sum(nil)
}

// Available returns whether the Identifier has been registered of not.
func (i Identifier) Available() bool {
	// Check for invalid identifiers
	switch i {
	case Ristretto255Sha512, P256Sha256, P384Sha384, P521Sha512:
		break
	default:
		return false
	}

	return true
}

// IDFromGroup returns the OPRF identifier corresponding to the input group.
func IDFromGroup(g group.Group) Identifier {
	return suites[g]
}

// Group returns the Group identifier for the cipher suite.
func (i Identifier) Group() group.Group {
	return groups[i]
}

// DeriveKey returns a scalar mapped from the input.
func (i Identifier) DeriveKey(seed, info []byte) *group.Scalar {
	dst := encoding.Concat([]byte(tag.DeriveKeyPairInternal), i.contextString())
	deriveInput := encoding.Concat(seed, encoding.EncodeVector(info))

	var counter uint8
	var s *group.Scalar

	for s == nil || s.IsZero() {
		if counter > maxDeriveKeyPairTries {
			panic("DeriveKeyPairError")
		}

		s = i.Group().HashToScalar(encoding.Concat(deriveInput, []byte{counter}), dst)
		counter++
	}

	return s
}

// Client returns an OPRF client.
func (i Identifier) Client() *Client {
	return &Client{
		Identifier: i,
		input:      nil,
		blind:      nil,
	}
}
