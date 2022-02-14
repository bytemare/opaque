// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package keyrecovery provides utility functions and structures allowing credential management.
package keyrecovery

import (
	"github.com/bytemare/crypto/group"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/oprf"
	"github.com/bytemare/opaque/internal/tag"
)

func deriveAuthKeyPair(p *internal.Parameters, randomizedPwd, nonce []byte) (*group.Scalar, *group.Point) {
	seed := p.KDF.Expand(randomizedPwd, encoding.SuffixString(nonce, tag.ExpandPrivateKey), internal.SeedLength)
	sk := oprf.Ciphersuite(p.Group).DeriveKey(seed, []byte(tag.DerivePrivateKey))

	return sk, p.Group.Base().Mult(sk)
}

func getPubkey(p *internal.Parameters, randomizedPwd, nonce []byte) *group.Point {
	_, pk := deriveAuthKeyPair(p, randomizedPwd, nonce)
	return pk
}

func recoverKeys(p *internal.Parameters,
	randomizedPwd, nonce []byte) (clientSecretKey *group.Scalar, clientPublicKey *group.Point) {
	return deriveAuthKeyPair(p, randomizedPwd, nonce)
}
