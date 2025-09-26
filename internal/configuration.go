// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
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
	"runtime"

	"github.com/bytemare/ecc"

	"github.com/bytemare/opaque/internal/ksf"
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
	KDF          *KDF
	MAC          *Mac
	Hash         *Hash
	KSF          *ksf.KSF
	OPRF         oprf.Identifier
	Context      []byte
	NonceLen     int
	EnvelopeSize int
	Group        ecc.Group
}

// MakeSecretKeyShare generates a secret key share from the provided seed. If the seed is empty, it gets a random one.
func (c *Configuration) MakeSecretKeyShare(seed []byte) *ecc.Scalar {
	if len(seed) == 0 {
		seed = RandomBytes(SeedLength)
	}

	return oprf.IDFromGroup(c.Group).DeriveKey(seed, []byte(tag.DeriveDiffieHellmanKeyPair))
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

var (
	// ErrSliceDifferentLength indicates the provided slice is of different length than the configured value.
	ErrSliceDifferentLength = errors.New("provided slice is different length than the configured value")

	// ErrSliceShorterLength indicates the provided slice is shorter than the configured value.
	ErrSliceShorterLength = errors.New("provided slice is shorter than the configured value")

	// ErrProvidedLengthNegative indicates the provided length is negative.
	ErrProvidedLengthNegative = errors.New("provided length is negative")
)

// ClearScalar attempts to safely clearing the internal secret value of the scalar, by first setting its bytes to a
// random value and then zeroes it out.
func ClearScalar(s **ecc.Scalar) {
	if s != nil {
		if *s != nil {
			(*s).Random()
			(*s).Zero()
			*s = nil
		}

		*s = nil             // clear the scalar reference
		runtime.KeepAlive(s) // prevent early GC and abstracting this call away
	}
}

// ClearSlice attempts to safely clear the internal values (i.e. set to zero) of the slice and sets the pointer to nil.
func ClearSlice(b *[]byte) {
	if b != nil {
		clear(*b)
		*b = nil             // clear the slice reference
		runtime.KeepAlive(b) // prevent early GC and abstracting this call away
	}
}
