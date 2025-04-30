// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2022 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package internal provides values, structures, and functions to operate OPAQUE that are not part of the public API.
package internal

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/bytemare/ecc"

	"github.com/bytemare/opaque/internal/oprf"
)

const (
	// NonceLength is the default length used for nonces.
	NonceLength = 32

	// SeedLength is the default length used for seeds.
	SeedLength = oprf.SeedLength
)

// ErrConfigurationInvalidLength happens when deserializing a configuration of invalid length.
var ErrConfigurationInvalidLength = errors.New("invalid encoded configuration length")

// Configuration is the internal representation of the instance runtime parameters.
type Configuration struct {
	KDF          *KDF
	MAC          *Mac
	Hash         *Hash
	KSF          *KSF
	OPRF         oprf.Identifier
	Context      []byte
	NonceLen     int
	EnvelopeSize int
	Group        ecc.Group
}

// RandomBytes returns random bytes of length len (wrapper for crypto/rand).
func RandomBytes(length int) []byte {
	r := make([]byte, length)
	if _, err := rand.Read(r); err != nil {
		// We can as well not panic and try again in a loop and a counter to stop.
		panic(fmt.Errorf("unexpected error in generating random bytes : %w", err))
	}

	return r
}
