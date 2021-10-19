// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package oprf implements the Elliptic Curve Oblivious Pseudorandom Function (EC-OPRF) from https://tools.ietf.org/html/draft-irtf-cfrg-voprf.
package oprf

import (
	"crypto"

	"github.com/bytemare/crypto/group"

	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/tag"
)

// mode distinguishes between the OPRF base mode and the Verifiable mode.
type mode byte

// base identifies the OPRF non-verifiable, base mode.
const base mode = iota

// Ciphersuite identifies the OPRF compatible cipher suite to be used.
type Ciphersuite group.Group

const (
	// RistrettoSha512 is the OPRF cipher suite of the Ristretto255 group and SHA-512.
	RistrettoSha512 = Ciphersuite(group.Ristretto255Sha512)

	// P256Sha256 is the OPRF cipher suite of the NIST P-256 group and SHA-256.
	P256Sha256 = Ciphersuite(group.P256Sha256)

	// P384Sha384 is the OPRF cipher suite of the NIST P-384 group and SHA-384.
	P384Sha384 = Ciphersuite(group.P384Sha512)

	// P521Sha512 is the OPRF cipher suite of the NIST P-512 group and SHA-512.
	P521Sha512 = Ciphersuite(group.P521Sha512)
)

var suiteToHash = make(map[group.Group]crypto.Hash)

func (c Ciphersuite) register(h crypto.Hash) {
	suiteToHash[c.Group()] = h
}

// Group returns the casted identifier for the cipher suite.
func (c Ciphersuite) Group() group.Group {
	return group.Group(c)
}

// SerializeScalar returns the byte encoding of the scalar padded accordingly.
func (c Ciphersuite) SerializeScalar(s *group.Scalar) []byte {
	return encoding.SerializeScalar(s, c.Group())
}

// SerializePoint returns the byte encoding of the point padded accordingly.
func (c Ciphersuite) SerializePoint(p *group.Point) []byte {
	return encoding.SerializePoint(p, c.Group())
}

func contextString(id Ciphersuite) []byte {
	return encoding.Concat3([]byte(tag.OPRF), encoding.I2OSP(int(base), 1), encoding.I2OSP(int(id), 2))
}

func (c Ciphersuite) oprf() *oprf {
	return &oprf{
		Group:         c.Group(),
		contextString: contextString(c),
	}
}

type oprf struct {
	group.Group
	contextString []byte
}

func (o *oprf) dst(prefix string) []byte {
	return encoding.Concat([]byte(prefix), o.contextString)
}

// DeriveKey returns a scalar mapped from the input.
func (c Ciphersuite) DeriveKey(input, dst []byte) *group.Scalar {
	return c.Group().HashToScalar(input, dst)
}

// Client returns an OPRF client.
func (c Ciphersuite) Client() *Client {
	return &Client{oprf: c.oprf()}
}

func init() {
	RistrettoSha512.register(crypto.SHA512)
	P256Sha256.register(crypto.SHA256)
	P384Sha384.register(crypto.SHA384)
	P521Sha512.register(crypto.SHA512)
}
