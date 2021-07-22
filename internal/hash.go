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
	"crypto/hmac"

	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/mhf"
)

type KDF struct {
	H *hash.Hash
}

func (k *KDF) Extract(salt, ikm []byte) []byte {
	return k.H.HKDFExtract(ikm, salt)
}

func (k *KDF) Expand(key, info []byte, length int) []byte {
	return k.H.HKDFExpand(key, info, length)
}

func (k *KDF) Size() int {
	return k.H.OutputSize()
}

type Mac struct {
	H *hash.Hash
}

func (m *Mac) Equal(a, b []byte) bool {
	return hmac.Equal(a, b)
}

func (m *Mac) MAC(key, message []byte) []byte {
	return m.H.Hmac(message, key)
}

func (m *Mac) Size() int {
	return m.H.OutputSize()
}

type Hash struct {
	H *hash.Hash
}

func (h *Hash) Size() int {
	return h.H.OutputSize()
}

func (h *Hash) Sum() []byte {
	return h.H.Sum(nil)
}

func (h *Hash) Write(p []byte) {
	_, _ = h.H.Write(p)
}

type MHF struct {
	*mhf.MHF
}
