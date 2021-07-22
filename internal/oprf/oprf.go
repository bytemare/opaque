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
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/hash"

	"github.com/bytemare/opaque/internal/encoding"
)

// mode distinguishes between the OPRF base mode and the Verifiable mode.
type mode byte

const (
	// base identifies the OPRF non-verifiable, base mode.
	base mode = iota
)

// Ciphersuite identifies the OPRF compatible cipher suite to be used.
type Ciphersuite byte

const (
	// RistrettoSha512 is the OPRF cipher suite of the Ristretto255 group and SHA-512.
	RistrettoSha512 Ciphersuite = iota + 1

	// P256Sha256 is the OPRF cipher suite of the NIST P-256 group and SHA-256.
	P256Sha256 Ciphersuite = iota + 2

	// P384Sha512 is the OPRF cipher suite of the NIST P-384 group and SHA-512.
	P384Sha512

	// P521Sha512 is the OPRF cipher suite of the NIST P-512 group and SHA-512.
	P521Sha512

	// version is a string explicitly stating the version name.
	version = "VOPRF07-"

	// hash2groupDSTPrefix is the DST prefix to use for HashToGroup operations.
	hash2groupDSTPrefix = "HashToGroup-"
)

var (
	suiteToHash = make(map[Ciphersuite]hash.Hashing)
	oprfToGroup = make(map[Ciphersuite]ciphersuite.Identifier)
)

func (c Ciphersuite) register(g ciphersuite.Identifier, h hash.Hashing) {
	suiteToHash[c] = h
	oprfToGroup[c] = g
}

func (c Ciphersuite) Group() ciphersuite.Identifier {
	return oprfToGroup[c]
}

func (c Ciphersuite) hash() hash.Hashing {
	return suiteToHash[c]
}

func contextString(id Ciphersuite) []byte {
	v := []byte(version)
	ctx := make([]byte, 0, len(v)+1+2)
	ctx = append(ctx, v...)
	ctx = append(ctx, encoding.I2OSP(int(base), 1)...)
	ctx = append(ctx, encoding.I2OSP(int(id), 2)...)

	return ctx
}

type oprf struct {
	id            Ciphersuite
	group         group.Group
	hash          *hash.Hash
	contextString []byte
}

func (o *oprf) dst(prefix string) []byte {
	p := []byte(prefix)
	dst := make([]byte, 0, len(p)+len(o.contextString))
	dst = append(dst, p...)
	dst = append(dst, o.contextString...)

	return dst
}

// Client returns an OPRF client.
func (c Ciphersuite) Client() *Client {
	client := &Client{
		oprf: &oprf{
			id:            c,
			group:         c.Group().Get(),
			hash:          c.hash().Get(),
			contextString: contextString(c),
		},
	}

	return client
}

// Server returns an OPRF server.
func (c Ciphersuite) Server(privateKey group.Scalar) *Server {
	return &Server{
		oprf: &oprf{
			id:            c,
			group:         c.Group().Get(),
			hash:          c.hash().Get(),
			contextString: contextString(c),
		},
		privateKey: privateKey,
	}
}

func init() {
	RistrettoSha512.register(ciphersuite.Ristretto255Sha512, hash.SHA512)
	P256Sha256.register(ciphersuite.P256Sha256, hash.SHA256)
	P384Sha512.register(ciphersuite.P384Sha512, hash.SHA512)
	P521Sha512.register(ciphersuite.P521Sha512, hash.SHA512)
}
