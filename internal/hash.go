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
	"crypto/hmac"

	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/mhf"
)

// NewKDF returns a newly instantiated KDF.
func NewKDF(id hash.Hashing) *KDF {
	return &KDF{h: id.Get()}
}

// KDF wraps a hash function and exposes KDF methods.
type KDF struct {
	h *hash.Hash
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
	return k.h.OutputSize()
}

// NewMac returns a newly instantiated Mac.
func NewMac(id hash.Hashing) *Mac {
	return &Mac{h: id.Get()}
}

// Mac wraps a hash function and exposes Message Authentication Code methods.
type Mac struct {
	h *hash.Hash
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
	return m.h.OutputSize()
}

// NewHash returns a newly instantiated Hash.
func NewHash(id hash.Hashing) *Hash {
	return &Hash{h: id.Get()}
}

// Hash wraps a hash function and exposes only necessary hashing methods.
type Hash struct {
	h *hash.Hash
}

// Size returns the output size of the hashing function.
func (h *Hash) Size() int {
	return h.h.OutputSize()
}

// Sum returns the current hash of the running state.
func (h *Hash) Sum() []byte {
	return h.h.Sum(nil)
}

// Write adds input to the running state.
func (h *Hash) Write(p []byte) {
	_, _ = h.h.Write(p)
}

// NewMHF returns a newly instantiated MHF.
func NewMHF(id mhf.Identifier) *MHF {
	if id == 0 {
		return &MHF{&IdentityMHF{}}
	}

	return &MHF{id.Get()}
}

// MHF wraps a MHF and exposes its functions.
type MHF struct {
	mhfInterface
}

type mhfInterface interface {
	// Harden uses default parameters for the key derivation function over the input password and salt.
	Harden(password, salt []byte, length int) []byte
}

// IdentityMHF represents a MHF with no operations.
type IdentityMHF struct{}

// Harden returns the password as is.
func (i IdentityMHF) Harden(password, _ []byte, _ int) []byte {
	return password
}
