// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package internal

import (
	"crypto"
	"crypto/hmac"

	"github.com/bytemare/hash"
	"github.com/bytemare/ksf"
)

// NewKDF returns a newly instantiated KDF.
func NewKDF(id crypto.Hash) *KDF {
	return &KDF{h: hash.FromCrypto(id).GetHashFunction()}
}

// KDF wraps a hash function and exposes KDF methods.
type KDF struct {
	h *hash.Fixed
}

// Extract exposes an Extract only KDF method.
func (k *KDF) Extract(salt, ikm []byte) []byte {
	return k.h.HKDFExtract(ikm, salt)
}

// Expand exposes an Expand only KDF method.
func (k *KDF) Expand(key, info []byte, length int) []byte {
	return k.h.HKDFExpand(key, info, length)
}

// Size returns the output size of the Extract method.
func (k *KDF) Size() int {
	return k.h.Size()
}

// NewMac returns a newly instantiated Mac.
func NewMac(id crypto.Hash) *Mac {
	return &Mac{h: hash.FromCrypto(id).GetHashFunction()}
}

// Mac wraps a hash function and exposes Message Authentication Code methods.
type Mac struct {
	h *hash.Fixed
}

// Equal returns a constant-time comparison of the input.
func (m *Mac) Equal(a, b []byte) bool {
	return hmac.Equal(a, b)
}

// MAC computes a MAC over the message using key.
func (m *Mac) MAC(key, message []byte) []byte {
	return m.h.Hmac(message, key)
}

// Size returns the MAC's output length.
func (m *Mac) Size() int {
	return m.h.Size()
}

// NewHash returns a newly instantiated Hash.
func NewHash(id crypto.Hash) *Hash {
	return &Hash{h: hash.FromCrypto(id).GetHashFunction()}
}

// Hash wraps a hash function and exposes only necessary hashing methods.
type Hash struct {
	h *hash.Fixed
}

// Size returns the output size of the hashing function.
func (h *Hash) Size() int {
	return h.h.Size()
}

// Sum returns the current hash of the running state.
func (h *Hash) Sum() []byte {
	return h.h.Sum(nil)
}

// Write adds input to the running state.
func (h *Hash) Write(p []byte) {
	_, _ = h.h.Write(p)
}

// NewKSF returns a newly instantiated KSF.
func NewKSF(id ksf.Identifier) *KSF {
	if id == 0 {
		return &KSF{&IdentityKSF{}}
	}

	return &KSF{id.Get()}
}

// KSF wraps a key stretching function and exposes its functions.
type KSF struct {
	ksfInterface
}

type ksfInterface interface {
	// Harden uses default parameters for the key derivation function over the input password and salt.
	Harden(password, salt []byte, length int) []byte
	Parameterize(parameters ...int)
}

// IdentityKSF represents a KSF with no operations.
type IdentityKSF struct{}

// Harden returns the password as is.
func (i IdentityKSF) Harden(password, _ []byte, _ int) []byte {
	return password
}

// Parameterize applies KSF parameters if defined.
func (i IdentityKSF) Parameterize(_ ...int) {
	// no-op
}
