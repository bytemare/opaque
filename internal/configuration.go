// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package internal provides structures and functions to operate OPAQUE that are not part of the public API.
package internal

import (
	cryptorand "crypto/rand"
	"fmt"

	"github.com/bytemare/crypto/group"

	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/oprf"
	"github.com/bytemare/opaque/internal/tag"
)

const (
	// NonceLength is the default length used for nonces.
	NonceLength = 32

	// SeedLength is the default length used for seeds.
	SeedLength = 32
)

// Configuration is the internal representation of the instance runtime parameters.
type Configuration struct {
	KDF             *KDF
	MAC             *Mac
	Hash            *Hash
	KSF             *KSF
	NonceLen        int
	EnvelopeSize    int
	OPRFPointLength int
	AkePointLength  int
	Group           group.Group
	OPRF            oprf.Ciphersuite
	Context         []byte
}

// RandomBytes returns random bytes of length len (wrapper for crypto/rand).
func RandomBytes(length int) []byte {
	r := make([]byte, length)
	if _, err := cryptorand.Read(r); err != nil {
		// We can as well not panic and try again in a loop and a counter to stop.
		panic(fmt.Errorf("unexpected error in generating random bytes : %w", err))
	}

	return r
}

// XorResponse is used to encrypt and decrypt the response in KE2.
func (c *Configuration) XorResponse(key, nonce, in []byte) []byte {
	pad := c.KDF.Expand(
		key,
		encoding.SuffixString(nonce, tag.CredentialResponsePad),
		encoding.PointLength[c.Group]+c.EnvelopeSize,
	)

	return Xor(pad, in)
}
